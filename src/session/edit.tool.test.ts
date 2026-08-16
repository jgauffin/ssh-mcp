import { describe, expect, it } from 'vitest';
import { compilePatterns } from '../secrets/patterns.js';
import { SecretStore } from '../secrets/store.js';
import { applyEdits } from './edits.js';
import {
  existsAsRootCommand,
  expandAnchors,
  oneWriterAtATime,
  readAsRootCommand,
  replaceAsRootCommand,
  SUDO_PROBE,
} from './edit.tool.js';

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
 * The end-to-end assertion (owner and mode unchanged after editing a root-owned
 * file) needs a live host and is in the manual checks, not here. These are the
 * part that can be pinned in CI.
 */

const ROOT_COMMANDS = [
  ['the sudo probe', SUDO_PROBE],
  ['the privileged read', readAsRootCommand('/etc/postgresql/17/main/postgresql.conf')],
  ['the existence probe', existsAsRootCommand('/root/host.env')],
  ['the privileged write', replaceAsRootCommand('/tmp/.ssh-mcp-abc', '/etc/postgresql/17/main/postgresql.conf')],
] as const;

describe('every command ssh_edit runs as root', () => {
  it.each(ROOT_COMMANDS)('%s actually invokes sudo', (_name, command) => {
    expect(command.startsWith('sudo ')).toBe(true);
  });

  it('never reaches for a shell to get its work done', () => {
    // The denylist refuses `sudo sh -c` for everyone else, and this tool being
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

describe('anchoring on a value the model never saw', () => {
  const held = (): { store: SecretStore; marker: string } => {
    const store = new SecretStore({ enabled: true, patterns: compilePatterns([]).patterns, paths: [] });
    const withheld = store.redact('prod', 'db_password = hunter2\n', { writable: true });
    return { store, marker: /\{\{ssh-mcp:secret:[0-9a-f]{8}\}\}/.exec(withheld.text)![0] };
  };

  it('an_anchor_carrying_a_marker_becomes_the_line_that_is_in_the_file', () => {
    const { store, marker } = held();
    const outcome = expandAnchors(store, 'prod', [
      { old_string: `db_password = ${marker}\n`, new_string: `db_password = ${marker}\nssl = on\n` },
    ]);

    expect(outcome).toMatchObject({
      ok: true,
      edits: [{ old_string: 'db_password = hunter2\n', new_string: 'db_password = hunter2\nssl = on\n' }],
    });
  });

  it('the_edits_the_model_wrote_are_left_holding_markers', () => {
    // Load-bearing: `describeFailure` quotes the caller's own anchor back, so an
    // edit that failed to match would otherwise answer with the password.
    const { store, marker } = held();
    const edits = [{ old_string: `db_password = ${marker}\n`, new_string: 'db_password = new\n' }];

    expandAnchors(store, 'prod', edits);

    expect(edits[0]!.old_string).toContain(marker);
    expect(edits[0]!.old_string).not.toContain('hunter2');
  });

  it('a_request_for_a_new_value_is_refused_in_an_anchor', () => {
    const { store } = held();
    const outcome = expandAnchors(store, 'prod', [{ old_string: '{{ssh-mcp:generate:32}}', new_string: 'x' }]);

    expect(outcome).toMatchObject({ ok: false });
    expect(outcome.ok === false && outcome.reason).toContain('new_string');
  });

  it('an_edit_with_no_markers_in_it_is_passed_through_untouched', () => {
    const { store } = held();
    const edits = [{ old_string: 'shared_buffers = 128MB', new_string: 'shared_buffers = 4GB' }];

    expect(expandAnchors(store, 'prod', edits)).toEqual({ ok: true, edits });
  });
});

/**
 * The whole edit path with the host taken out: read the file, withhold what is
 * in it, let the model anchor on what it got back, put the values in, apply.
 *
 * This is the question worth answering — not "does redaction reverse", but
 * "does the file on the host end up holding exactly what it should". The SFTP
 * and sudo write is the same code it was before this existed; what is new is
 * everything between the read and the bytes handed to it.
 */
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

    await Promise.all([
      oneWriterAtATime('box:/etc/one.conf', work('one')),
      oneWriterAtATime('box:/etc/two.conf', work('two')),
    ]);

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
});

describe('a file edited around a value the model never saw', () => {
  const CONF = [
    '# app config',
    'host = db.internal',
    'db_password = hunter2',
    'pool_size = 10',
    'api_key = "abc123XYZ"',
    '',
  ].join('\n');

  /** What `ssh_get` would have returned, and the store holding the real values. */
  const read = (): { store: SecretStore; shown: string } => {
    const store = new SecretStore({ enabled: true, patterns: compilePatterns([]).patterns, paths: [] });
    return { store, shown: store.redact('prod', CONF, { writable: true }).text };
  };

  /** The rest of the pipeline: expand what the model wrote, then apply it. */
  const apply = (store: SecretStore, edits: Array<{ old_string: string; new_string: string; replace_all?: boolean }>): string => {
    const expanded = expandAnchors(store, 'prod', edits);
    if (!expanded.ok) throw new Error(expanded.reason);
    const outcome = applyEdits(CONF, expanded.edits, true);
    if (!outcome.ok) throw new Error(`edit failed: ${outcome.failure.kind}`);
    return outcome.text;
  };

  it('changing_the_line_below_a_password_leaves_the_password_byte_identical', () => {
    const { store } = read();
    const after = apply(store, [{ old_string: 'pool_size = 10', new_string: 'pool_size = 25' }]);

    expect(after).toBe(CONF.replace('pool_size = 10', 'pool_size = 25'));
    expect(after).toContain('db_password = hunter2');
  });

  it('anchoring_on_the_password_line_itself_writes_the_real_value_back', () => {
    const { store, shown } = read();
    const marker = /\{\{ssh-mcp:secret:[0-9a-f]+\}\}/.exec(shown)![0];

    // The model renames the key and carries the value across without holding it.
    const after = apply(store, [
      { old_string: `db_password = ${marker}`, new_string: `database_password = ${marker}` },
    ]);

    expect(after).toBe(CONF.replace('db_password =', 'database_password ='));
    expect(after).toContain('database_password = hunter2');
  });

  it('a_marker_the_model_altered_by_one_character_writes_nothing', () => {
    const { store, shown } = read();
    const marker = /\{\{ssh-mcp:secret:[0-9a-f]+\}\}/.exec(shown)![0];
    const tampered = marker.replace(/[0-9a-f]\}\}$/, '0}}');

    const outcome = expandAnchors(store, 'prod', [{ old_string: `db_password = ${tampered}`, new_string: 'x' }]);

    // Either it is a marker nobody minted, or — if the tampering happened to
    // land on the same character — it expands to the same value and matches.
    // What must never happen is expanding to some *other* value.
    if (tampered !== marker) expect(outcome).toMatchObject({ ok: false });
  });

  it('rotating_a_password_replaces_only_that_value', () => {
    const { store, shown } = read();
    const marker = /\{\{ssh-mcp:secret:[0-9a-f]+\}\}/.exec(shown)![0];

    const requested = store.resolveRequests('prod', [`db_password = {{ssh-mcp:generate:32}}`], 'rotate');
    if (!requested.ok) throw new Error('unresolved request');
    const after = apply(store, [{ old_string: `db_password = ${marker}`, new_string: requested.texts[0]! }]);

    expect(after).not.toContain('hunter2');
    expect(after).toMatch(/^db_password = [A-Za-z0-9._]{32}$/m);
    // Every other line survives the rotation untouched.
    expect(after.split('\n').filter((line) => !line.startsWith('db_password'))).toEqual(
      CONF.split('\n').filter((line) => !line.startsWith('db_password')),
    );
  });

  it('the_new_password_is_readable_again_only_as_a_marker', () => {
    const { store } = read();
    const requested = store.resolveRequests('prod', ['{{ssh-mcp:generate:32}}'], 'rotate');
    if (!requested.ok) throw new Error('unresolved request');
    const written = CONF.replace('hunter2', requested.texts[0]!);

    // Reading the file back must not hand over what was just written.
    const again = store.redact('prod', written, { writable: true });
    expect(again.text).not.toContain(requested.texts[0]!);
    expect(store.expand('prod', again.text)).toEqual({ ok: true, text: written });
  });

  it('two_secrets_in_one_file_never_swap_places', () => {
    const { store, shown } = read();
    const markers = [...shown.matchAll(/\{\{ssh-mcp:secret:[0-9a-f]+\}\}/g)].map((match) => match[0]);
    expect(markers).toHaveLength(2);

    const after = apply(store, [
      { old_string: `db_password = ${markers[0]!}`, new_string: `db_password = ${markers[0]!}\nreplica_password = ${markers[0]!}` },
    ]);

    expect(after).toContain('db_password = hunter2');
    expect(after).toContain('replica_password = hunter2');
    expect(after).toContain('api_key = "abc123XYZ"');
  });
});
