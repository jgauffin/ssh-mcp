import { describe, expect, it } from 'vitest';
import { applyEdits, describeFailure, type Edit } from './edits.js';

const edit = (old_string: string, new_string: string, replace_all?: boolean): Edit =>
  replace_all === undefined ? { old_string, new_string } : { old_string, new_string, replace_all };

const applied = (before: string, edits: readonly Edit[], exists = true): string => {
  const outcome = applyEdits(before, edits, exists);
  if (!outcome.ok) throw new Error(`expected success, got ${outcome.failure.kind}`);
  return outcome.text;
};

const failed = (before: string, edits: readonly Edit[], exists = true) => {
  const outcome = applyEdits(before, edits, exists);
  if (outcome.ok) throw new Error('expected a failure');
  return outcome.failure;
};

const CONF = ['# postgresql.conf', 'shared_buffers = 128MB', 'work_mem = 4MB', 'max_connections = 100', ''].join('\n');

describe('applyEdits', () => {
  it('replaces a single match and leaves the rest byte-identical', () => {
    const after = applied(CONF, [edit('shared_buffers = 128MB', 'shared_buffers = 4GB')]);
    expect(after).toBe(CONF.replace('128MB', '4GB'));
  });

  it('applies edits in order, against the result of the last', () => {
    const after = applied('a', [edit('a', 'b'), edit('b', 'c')]);
    expect(after).toBe('c');
  });

  it('reports the number of replacements', () => {
    const outcome = applyEdits('x x x', [edit('x', 'y', true)], true);
    expect(outcome).toMatchObject({ ok: true, text: 'y y y', replacements: 3 });
  });

  it('deletes when new_string is empty', () => {
    expect(applied(CONF, [edit('work_mem = 4MB\n', '')])).toBe(CONF.replace('work_mem = 4MB\n', ''));
  });

  it('treats old_string literally, not as a pattern', () => {
    expect(applied('a.c and abc', [edit('a.c', 'X')])).toBe('X and abc');
  });
});

describe('applyEdits, when the anchor does not fit', () => {
  it('refuses an anchor that is not there', () => {
    expect(failed(CONF, [edit('wal_level = replica', 'wal_level = logical')])).toMatchObject({
      kind: 'not-found',
      index: 0,
    });
  });

  it('names CRLF as the reason when that is the reason', () => {
    const crlf = CONF.replaceAll('\n', '\r\n');
    expect(failed(crlf, [edit('shared_buffers = 128MB\nwork_mem', 'x')])).toMatchObject({
      kind: 'not-found',
      hint: 'the file uses CRLF line endings and old_string has bare LF',
    });
  });

  it('names indentation as the reason when that is the reason', () => {
    expect(failed('root:\n    listen: 80\n', [edit('root:\n  listen: 80', 'x')])).toMatchObject({
      kind: 'not-found',
      hint: 'the text is in the file but the indentation differs',
    });
  });

  it('gives no hint when it has none to give', () => {
    expect(failed(CONF, [edit('nothing like this', 'x')])).toMatchObject({ kind: 'not-found', hint: undefined });
  });

  it('refuses an ambiguous anchor rather than picking one', () => {
    expect(failed('port = 1\nport = 1\n', [edit('port = 1', 'port = 2')])).toMatchObject({
      kind: 'ambiguous',
      count: 2,
    });
  });

  it('replaces every occurrence when told to', () => {
    expect(applied('port = 1\nport = 1\n', [edit('port = 1', 'port = 2', true)])).toBe('port = 2\nport = 2\n');
  });

  it('refuses an edit that would change nothing', () => {
    expect(failed(CONF, [edit('work_mem = 4MB', 'work_mem = 4MB')])).toMatchObject({ kind: 'no-op', index: 0 });
  });

  it('reports which edit failed', () => {
    expect(failed(CONF, [edit('work_mem = 4MB', 'work_mem = 8MB'), edit('absent', 'x')])).toMatchObject({ index: 1 });
  });
});

describe('applyEdits, creating a file', () => {
  it('treats an empty anchor against a missing file as the whole content', () => {
    const outcome = applyEdits('', [edit('', 'hello\n')], false);
    expect(outcome).toMatchObject({ ok: true, text: 'hello\n' });
  });

  it('refuses an empty anchor when the file already exists', () => {
    expect(failed(CONF, [edit('', 'replacement')])).toMatchObject({ kind: 'empty-anchor' });
  });

  it('refuses an empty anchor alongside other edits', () => {
    expect(failed('', [edit('', 'a'), edit('a', 'b')], false)).toMatchObject({
      kind: 'empty-anchor',
      reason: 'an empty old_string must be the only edit',
    });
  });
});

describe('describeFailure', () => {
  const edits = [edit('shared_buffers = 128MB', 'shared_buffers = 4GB')];

  it('quotes the caller’s own anchor, never the file', () => {
    const message = describeFailure(failed(CONF, [edit('absent', 'x')]), [edit('absent', 'x')], '/etc/pg.conf');
    expect(message).toContain('absent');
    expect(message).not.toContain('shared_buffers');
  });

  it('carries the hint when there is one', () => {
    const crlfEdits = [edit('shared_buffers = 128MB\nwork_mem', 'x')];
    const message = describeFailure(failed(CONF.replaceAll('\n', '\r\n'), crlfEdits), crlfEdits, '/etc/pg.conf');
    expect(message).toContain('CRLF');
  });

  it('says how to disambiguate', () => {
    const many = [edit('port = 1', 'port = 2')];
    const message = describeFailure(failed('port = 1\nport = 1', many), many, '/etc/pg.conf');
    expect(message).toContain('replace_all');
  });

  it('always says that nothing was written', () => {
    expect(describeFailure(failed(CONF, [edit('absent', 'x')]), edits, '/etc/pg.conf')).toContain('Nothing was written');
  });

  it('truncates a long anchor instead of echoing it whole', () => {
    const long = [edit(`${'x'.repeat(400)}\ny\nz\nw`, 'q')];
    const message = describeFailure(failed(CONF, long), long, '/etc/pg.conf');
    expect(message.length).toBeLessThan(400);
  });
});
