import { describe, expect, it } from 'vitest';
import {
  executableAsRootCommand,
  existsAsRootCommand,
  oneWriterAtATime,
  readAsRootCommand,
  replaceAsRootCommand,
  SUDO_PROBE,
} from './write.js';

/**
 * The invariants of the privileged path, held to without a host.
 *
 * Both of these were broken in the first version, and neither failure was
 * visible from the outside:
 *
 * - The commands did not say `sudo`. `SudoMode` only makes `exec` prepend a
 *   preamble that *defines* a `sudo` shell function, so a command that never
 *   calls it runs as the connecting user — succeeding quietly on anything the
 *   user happens to own, and only failing once it meets a real root-owned
 *   config. Meanwhile the tool reported "as root via sudo", inventing an owner
 *   the file did not have.
 * - Replacing a file rather than truncating it rewrites its owner and mode. The
 *   approved diff shows the contents and says nothing about either, and a
 *   service that checks them — sshd, sudo, ssh's own `authorized_keys` — simply
 *   stops working afterwards.
 *
 * The end-to-end assertion (owner and mode unchanged after writing a root-owned
 * file) needs a live host and is in the manual checks, not here. These are the
 * part that can be pinned in CI.
 */

const ROOT_COMMANDS = [
  ['the sudo probe', SUDO_PROBE],
  ['the privileged read', readAsRootCommand('/etc/postgresql/17/main/postgresql.conf')],
  ['the existence probe', existsAsRootCommand('/root/host.env')],
  ['the executable probe', executableAsRootCommand('/usr/local/bin/deploy')],
  ['the privileged write', replaceAsRootCommand('/tmp/.ssh-mcp-abc', '/etc/postgresql/17/main/postgresql.conf')],
] as const;

describe('every command this module runs as root', () => {
  it.each(ROOT_COMMANDS)('%s actually invokes sudo', (_name, command) => {
    expect(command.startsWith('sudo ')).toBe(true);
  });

  it('never reaches for a shell to get its work done', () => {
    // The denylist refuses `sudo sh -c` for everyone else, and this module being
    // the one place that bypasses the gate is not a reason to make an exception.
    for (const [, command] of ROOT_COMMANDS) {
      expect(command).not.toMatch(/\b(sh|bash|dash|zsh)\b/);
      expect(command).not.toContain('-c ');
    }
  });
});

describe('the existence probe', () => {
  /**
   * A path under a 0700 directory refuses `stat` to the connecting user whether
   * or not anything is there, so a missing file only becomes visible once the
   * privileged read has already failed. Without this, `ssh_edit /root/host.env`
   * reported "No such file or directory" as an error instead of offering to
   * create the file.
   */
  it('is a predicate, so a missing file can be told from an unreadable one', () => {
    expect(existsAsRootCommand('/root/host.env')).toBe("sudo test -e '/root/host.env'");
  });

  it('changes nothing, whatever the answer', () => {
    const command = existsAsRootCommand('/root/host.env');
    for (const writer of ['cp', 'mv', 'tee', 'touch', 'install', 'rm', '>']) {
      expect(command).not.toContain(writer);
    }
  });
});

describe('the executable probe', () => {
  /**
   * Asked only when the destination cannot be stat'd. `ssh_put` refuses to
   * overwrite a file that runs, and a `0700` parent directory is the one case
   * where the mode is not already in hand.
   */
  it('is a predicate, so an unreadable destination can still be classified', () => {
    expect(executableAsRootCommand('/usr/local/bin/deploy')).toBe("sudo test -x '/usr/local/bin/deploy'");
  });

  it('changes nothing, whatever the answer', () => {
    const command = executableAsRootCommand('/usr/local/bin/deploy');
    for (const writer of ['cp', 'mv', 'tee', 'touch', 'install', 'rm', '>']) {
      expect(command).not.toContain(writer);
    }
  });

  /**
   * No `--`, unlike the read and the write: `test` does not accept one, and
   * does not need it. The path is its *second* argument, after a unary
   * operator, so a file called `-rf` is already unambiguously an operand — and
   * the quoting keeps it one word.
   */
  it('quotes the path, which is all a file called -rf needs here', () => {
    expect(executableAsRootCommand('/etc/-rf')).toBe("sudo test -x '/etc/-rf'");
    expect(executableAsRootCommand("/etc/it's there")).toBe(`sudo test -x '/etc/it'\\''s there'`);
  });
});

describe('the privileged read', () => {
  it('goes through base64, so the bytes survive the text channel', () => {
    expect(readAsRootCommand('/etc/hosts')).toBe("sudo base64 -- '/etc/hosts'");
  });

  it('quotes the path and stops flag parsing, so a file called -rf is a file', () => {
    expect(readAsRootCommand('/etc/-rf')).toContain("-- '/etc/-rf'");
    expect(readAsRootCommand("/etc/it's there")).toBe(`sudo base64 -- '/etc/it'\\''s there'`);
  });
});

describe('the privileged write', () => {
  const command = replaceAsRootCommand('/tmp/.ssh-mcp-abc', '/etc/ssh/sshd_config');

  it('copies onto the destination rather than replacing it', () => {
    expect(command).toBe(`sudo cp -- '/tmp/.ssh-mcp-abc' '/etc/ssh/sshd_config'`);
  });

  /**
   * The ownership-preservation property, as far as it can be checked here.
   * `cp` onto an existing regular file opens and truncates it, so the inode —
   * and with it the owner, group, mode, ACLs and any security label — survives.
   * Every alternative below unlinks or creates instead, and the replacement
   * would arrive owned by root with the temp file's mode.
   */
  it('uses no form of copy that would unlink the destination first', () => {
    expect(command).not.toContain('mv ');
    expect(command).not.toContain('install ');
    expect(command).not.toContain('--remove-destination');
    expect(command).not.toContain('--force');
    expect(command).not.toMatch(/\bcp\s+(-\w*f|\S*\s+)*-\w*f\b/);
  });

  it('puts the destination last, where cp expects it', () => {
    expect(command.endsWith(`'/etc/ssh/sshd_config'`)).toBe(true);
  });

  it('quotes both paths', () => {
    expect(replaceAsRootCommand('/tmp/a b', '/etc/c d')).toBe(`sudo cp -- '/tmp/a b' '/etc/c d'`);
  });
});

/**
 * The queue that makes the re-read before a write authoritative.
 *
 * Two edits approved together used to both re-read the old content, both
 * write, and the second undo the first — with both replies saying "Applied".
 * Found against a real host; pinned here so it does not need one.
 */
describe('one writer at a time per file', () => {
  const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

  it('runs work on the same file in order, never overlapping', async () => {
    const events: string[] = [];
    const work = (name: string) => async () => {
      events.push(`${name}:start`);
      await settle();
      await settle();
      events.push(`${name}:end`);
    };

    await Promise.all([
      oneWriterAtATime('box:/etc/app.conf', work('first')),
      oneWriterAtATime('box:/etc/app.conf', work('second')),
      oneWriterAtATime('box:/etc/app.conf', work('third')),
    ]);

    expect(events).toEqual(['first:start', 'first:end', 'second:start', 'second:end', 'third:start', 'third:end']);
  });

  it('lets different files proceed together', async () => {
    const events: string[] = [];
    const work = (name: string) => async () => {
      events.push(`${name}:start`);
      await settle();
      events.push(`${name}:end`);
    };

    await Promise.all([oneWriterAtATime('box:/etc/one.conf', work('one')), oneWriterAtATime('box:/etc/two.conf', work('two'))]);

    // Interleaved, because a lock per file that serialised the whole host
    // would make an assistant editing two configs pay for nothing.
    expect(events).toEqual(['one:start', 'two:start', 'one:end', 'two:end']);
  });

  it('does not wedge the queue when a write fails', async () => {
    const failing = oneWriterAtATime('box:/etc/app.conf', async () => {
      throw new Error('write failed');
    });

    await expect(failing).rejects.toThrow('write failed');
    await expect(oneWriterAtATime('box:/etc/app.conf', async () => 'next')).resolves.toBe('next');
  });

  it('hands the result of the work straight back', async () => {
    expect(await oneWriterAtATime('box:/etc/app.conf', async () => 'sudo')).toBe('sudo');
  });

  /**
   * Both tools that write share this queue, so the key has to be the only thing
   * that decides what serialises: an `ssh_put` and an `ssh_edit` aimed at one
   * file must not overlap.
   */
  it('serialises two different tools aimed at the same file', async () => {
    const events: string[] = [];
    const work = (name: string) => async () => {
      events.push(`${name}:start`);
      await settle();
      events.push(`${name}:end`);
    };

    await Promise.all([
      oneWriterAtATime('box:/etc/ssl/service.pem', work('put')),
      oneWriterAtATime('box:/etc/ssl/service.pem', work('edit')),
    ]);

    expect(events).toEqual(['put:start', 'put:end', 'edit:start', 'edit:end']);
  });
});
