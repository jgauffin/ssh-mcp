import { describe, expect, it } from 'vitest';
import { unifiedDiff } from './diff.js';

const lines = (...text: string[]) => `${text.join('\n')}\n`;

const CONF = lines('# postgresql.conf', 'shared_buffers = 128MB', 'work_mem = 4MB', 'max_connections = 100');

describe('unifiedDiff', () => {
  it('is empty when nothing changed', () => {
    expect(unifiedDiff(CONF, CONF)).toMatchObject({ text: '', added: 0, removed: 0, truncated: false });
  });

  it('renders one hunk for one changed line', () => {
    const diff = unifiedDiff(CONF, CONF.replace('128MB', '4GB'), { label: 'etc/pg.conf' });
    expect(diff.text).toBe(
      [
        '--- a/etc/pg.conf',
        '+++ b/etc/pg.conf',
        '@@ -1,4 +1,4 @@',
        ' # postgresql.conf',
        '-shared_buffers = 128MB',
        '+shared_buffers = 4GB',
        ' work_mem = 4MB',
        ' max_connections = 100',
      ].join('\n'),
    );
    expect(diff).toMatchObject({ added: 1, removed: 1, truncated: false });
  });

  it('keeps three lines of context and no more', () => {
    const before = lines(...Array.from({ length: 21 }, (_, index) => `line ${index}`));
    const after = before.replace('line 10', 'CHANGED');
    const diff = unifiedDiff(before, after);
    expect(diff.text).toContain(' line 7');
    expect(diff.text).not.toContain(' line 6');
    expect(diff.text).toContain(' line 13');
    expect(diff.text).not.toContain(' line 14');
    expect(diff.text).toContain('@@ -8,7 +8,7 @@');
  });

  it('splits distant changes into separate hunks', () => {
    const before = lines(...Array.from({ length: 100 }, (_, index) => `line ${index}`));
    const after = before.replace('line 5', 'A').replace('line 80', 'B');
    const diff = unifiedDiff(before, after);
    expect(diff.text.match(/^@@ /gm)).toHaveLength(2);
  });

  it('merges changes that are close enough to abut', () => {
    const before = lines(...Array.from({ length: 20 }, (_, index) => `line ${index}`));
    const after = before.replace('line 5', 'A').replace('line 8', 'B');
    const diff = unifiedDiff(before, after);
    expect(diff.text.match(/^@@ /gm)).toHaveLength(1);
  });

  it('clamps context at the edges of the file', () => {
    const diff = unifiedDiff(lines('a', 'b'), lines('A', 'b'));
    expect(diff.text).toContain('@@ -1,2 +1,2 @@');
  });

  it('renders a pure insertion', () => {
    const diff = unifiedDiff(lines('a', 'b'), lines('a', 'inserted', 'b'));
    expect(diff).toMatchObject({ added: 1, removed: 0 });
    expect(diff.text).toContain('+inserted');
    expect(diff.text).not.toContain('\n-');
  });

  it('renders a pure deletion', () => {
    const diff = unifiedDiff(lines('a', 'gone', 'b'), lines('a', 'b'));
    expect(diff).toMatchObject({ added: 0, removed: 1 });
    expect(diff.text).toContain('-gone');
  });

  it('renders a whole file as added when there was nothing before', () => {
    const diff = unifiedDiff('', lines('a', 'b'), { beforeLabel: '/dev/null', afterLabel: 'b/etc/new.conf' });
    expect(diff.text).toBe(['--- /dev/null', '+++ b/etc/new.conf', '@@ -0,0 +1,2 @@', '+a', '+b'].join('\n'));
    expect(diff).toMatchObject({ added: 2, removed: 0 });
  });

  it('marks a missing final newline on the old side', () => {
    const diff = unifiedDiff('a\nb', 'a\nB\n');
    expect(diff.text).toContain('\\ No newline at end of file');
  });

  it('marks a missing final newline on the new side', () => {
    const diff = unifiedDiff('a\nb\n', 'a\nB');
    expect(diff.text).toContain('\\ No newline at end of file');
  });

  it('shows a change that is only a final newline', () => {
    const diff = unifiedDiff('a\nb', 'a\nb\n');
    expect(diff.text).not.toBe('');
    expect(diff.text).toContain('\\ No newline at end of file');
  });

  it('counts every changed line, not only the ones it renders', () => {
    const before = lines(...Array.from({ length: 50 }, (_, index) => `line ${index}`));
    const after = lines(...Array.from({ length: 50 }, (_, index) => `other ${index}`));
    expect(unifiedDiff(before, after)).toMatchObject({ added: 50, removed: 50 });
  });

  it('truncates rather than rendering an unreadable wall', () => {
    const before = lines(...Array.from({ length: 400 }, (_, index) => `line ${index}`));
    const after = lines(...Array.from({ length: 400 }, (_, index) => `other ${index}`));
    const diff = unifiedDiff(before, after, { maxLines: 40 });
    expect(diff.truncated).toBe(true);
    expect(diff.text).toContain('too many to show');
    expect(diff.text.split('\n').length).toBeLessThan(45);
  });

  it('stays sound when the table guard trips', () => {
    // Two large, wholly unrelated middles: too big to align, still a real diff.
    const before = lines(...Array.from({ length: 2100 }, (_, index) => `left ${index}`));
    const after = lines(...Array.from({ length: 2100 }, (_, index) => `right ${index}`));
    const diff = unifiedDiff(before, after, { maxLines: 100 });
    expect(diff).toMatchObject({ added: 2100, removed: 2100, truncated: true });
  });
});

/**
 * The assertion that makes hand-rolling this defensible.
 *
 * Every hunk must be a faithful window on both files: the ` ` and `-` lines it
 * shows have to be exactly the old file's lines at the offsets the header
 * claims, and ` ` and `+` exactly the new file's. A diff that failed this would
 * be showing someone a change that is not the change about to be written.
 */
describe('unifiedDiff soundness', () => {
  /** Seeded so a failure is reproducible; there is nothing to gain from fresh randomness each run. */
  const random = (seed: number) => () => {
    seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
    return seed / 2_147_483_648;
  };

  const check = (before: string, after: string): void => {
    const diff = unifiedDiff(before, after, { maxLines: 100_000 });
    if (diff.text === '') return;

    const beforeLines = before === '' ? [] : before.replace(/\n$/, '').split('\n');
    const afterLines = after === '' ? [] : after.replace(/\n$/, '').split('\n');

    let expectA: string[] = [];
    let expectB: string[] = [];
    let gotA: string[] = [];
    let gotB: string[] = [];

    const settle = (): void => {
      expect(gotA).toEqual(expectA);
      expect(gotB).toEqual(expectB);
    };

    for (const line of diff.text.split('\n')) {
      if (line.startsWith('--- ') || line.startsWith('+++ ') || line === '\\ No newline at end of file') continue;

      const header = /^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(line);
      if (header) {
        settle();
        const [aStart, aCount, bStart, bCount] = header.slice(1).map(Number) as [number, number, number, number];
        expectA = beforeLines.slice(aCount === 0 ? aStart : aStart - 1, (aCount === 0 ? aStart : aStart - 1) + aCount);
        expectB = afterLines.slice(bCount === 0 ? bStart : bStart - 1, (bCount === 0 ? bStart : bStart - 1) + bCount);
        gotA = [];
        gotB = [];
        continue;
      }

      const body = line.slice(1);
      if (line.startsWith(' ')) {
        gotA.push(body);
        gotB.push(body);
      } else if (line.startsWith('-')) gotA.push(body);
      else if (line.startsWith('+')) gotB.push(body);
    }
    settle();
  };

  it('holds over random line-level edits', () => {
    const next = random(20_260_806);
    for (let round = 0; round < 200; round += 1) {
      const length = 1 + Math.floor(next() * 30);
      const source = Array.from({ length }, () => `line ${Math.floor(next() * 8)}`);
      const target = source.flatMap((line) => {
        const roll = next();
        if (roll < 0.15) return [];
        if (roll < 0.3) return [line, `inserted ${Math.floor(next() * 8)}`];
        if (roll < 0.45) return [`changed ${Math.floor(next() * 8)}`];
        return [line];
      });
      check(`${source.join('\n')}\n`, target.length === 0 ? '' : `${target.join('\n')}\n`);
    }
  });

  it('holds when a file is created or emptied', () => {
    check('', lines('a', 'b', 'c'));
    check(lines('a', 'b', 'c'), '');
  });

  it('holds without trailing newlines on either side', () => {
    check('a\nb\nc', 'a\nB\nc');
    check('a\nb\nc\n', 'a\nB\nc');
    check('a\nb\nc', 'a\nB\nc\n');
  });
});
