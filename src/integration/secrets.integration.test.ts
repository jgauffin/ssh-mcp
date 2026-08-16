import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  decide,
  dockerAvailable,
  linkIn,
  pageBody,
  provide,
  startHost,
  startSession,
  type Session,
  type TestHost,
} from './host.js';

/**
 * What a host actually ends up holding.
 *
 * The question these exist to answer is the one no unit test can: after the
 * assistant edits a file whose password it was never shown, is the password
 * still there, byte for byte, and does the file still belong to whom it did.
 * Everything is asserted from outside the server — the tools through a real
 * MCP client, the consent through the loopback pages, and the results through
 * `docker exec` on the container itself.
 */

const PASSWORD = 'hunter2-do-not-lose';
const CONF = '/etc/app/app.conf';
const MARKER = /\{\{ssh-mcp:secret:[0-9a-f]+\}\}/;

const available = await dockerAvailable();
const suite = available ? describe : describe.skip;

if (!available) {
  process.stderr.write('ssh-mcp: Docker is not available; the integration suite is skipped.\n');
}

suite('a host whose secrets the model never saw', () => {
  let host: TestHost;
  let session: Session;

  beforeAll(async () => {
    host = await startHost();
    session = await startSession(host, '\n[secrets]\npaths = ["/etc/app/*.env"]\n');
  });

  afterAll(async () => {
    await session?.close();
    await host?.stop();
  });

  /** The file exactly as the container has it. */
  const onHost = (path = CONF): Promise<string> => host.inspect(`cat ${path}`);
  const ownership = (path = CONF): Promise<string> => host.inspect(`stat -c '%U:%G %a' ${path}`);

  /** Reads the file through the server and hands back the marker it withheld. */
  const markerForPassword = async (): Promise<string> => {
    const shown = await session.call('ssh_get', { host: 'box', path: CONF });
    expect(shown).not.toContain(PASSWORD);
    return MARKER.exec(shown)![0];
  };

  /** Applies an edit the way the assistant does: call, answer the page, call again. */
  const applyEdit = async (
    path: string,
    edits: Array<Record<string, unknown>>,
    options: { onPage?: (body: string) => void } = {},
  ): Promise<string> => {
    const pending = await session.call('ssh_edit', { host: 'box', path, edits });
    const link = linkIn(pending);
    if (options.onPage) options.onPage(await pageBody(link));
    await decide(link, 'apply');
    return session.call('ssh_edit', { host: 'box', path, edits });
  };

  it('withholds the password from a file read, and touches nothing', async () => {
    const before = await onHost();
    const shown = await session.call('ssh_get', { host: 'box', path: CONF });

    expect(shown).not.toContain(PASSWORD);
    expect(shown).toMatch(MARKER);
    expect(shown).toContain('pool_size = 10');
    expect(await onHost()).toBe(before);
  });

  it('leaves the password byte-identical when the line beside it is edited', async () => {
    const before = await onHost();
    await markerForPassword();

    const applied = await applyEdit(CONF, [{ old_string: 'pool_size = 10', new_string: 'pool_size = 25' }]);

    expect(applied).toContain('Applied');
    expect(await onHost()).toBe(before.replace('pool_size = 10', 'pool_size = 25'));
    expect(await onHost()).toContain(`db_password = ${PASSWORD}`);
  });

  it('writes the real value back when the anchor is the password line itself', async () => {
    const marker = await markerForPassword();

    await applyEdit(CONF, [
      { old_string: `db_password = ${marker}`, new_string: `database_password = ${marker}` },
    ]);

    const after = await onHost();
    expect(after).toContain(`database_password = ${PASSWORD}`);
    expect(after).not.toContain('db_password =');

    // Put it back, so the rest of the suite reads the file it expects.
    const restored = await markerForPassword();
    await applyEdit(CONF, [
      { old_string: `database_password = ${restored}`, new_string: `db_password = ${restored}` },
    ]);
    expect(await onHost()).toContain(`db_password = ${PASSWORD}`);
  });

  it('shows the user the real value on the page it asks them to approve', async () => {
    const marker = await markerForPassword();
    let shownToUser = '';

    await applyEdit(
      CONF,
      [{ old_string: `db_password = ${marker}\npool_size`, new_string: `db_password = ${marker}\n# pinned\npool_size` }],
      { onPage: (body) => (shownToUser = body) },
    );

    // The diff is a decision only if it says what is really there.
    expect(shownToUser).toContain(PASSWORD);
    expect(await onHost()).toContain('# pinned');
  });

  it('escalates through sudo without changing the file owner or mode', async () => {
    // The invariant that used to be a manual check: `cp` onto the existing
    // inode, never a replacement that would arrive owned by root.
    expect(await ownership()).toBe('root:root 644\n');

    const marker = await markerForPassword();
    const applied = await applyEdit(CONF, [
      { old_string: `db_password = ${marker}`, new_string: `db_password = ${marker}\n# rotated by test` },
    ]);

    expect(applied).toContain('as root via sudo');
    expect(applied).toContain('owner and mode are unchanged');
    expect(await ownership()).toBe('root:root 644\n');
    expect(await onHost()).toContain(`db_password = ${PASSWORD}`);
  });

  it('rotates a password that never existed in the conversation', async () => {
    const marker = await markerForPassword();

    const applied = await applyEdit(CONF, [
      { old_string: `db_password = ${marker}`, new_string: 'db_password = {{ssh-mcp:generate:32}}' },
    ]);

    const after = await onHost();
    const rotated = /db_password = ([A-Za-z0-9._]{32})/.exec(after)?.[1];

    expect(rotated).toBeDefined();
    expect(after).not.toContain(PASSWORD);
    // The value is on the host and in no reply, not even the one that wrote it.
    expect(applied).not.toContain(rotated!);
    expect(session.transcript.join('\n')).not.toContain(rotated!);
    // And reading the file back does not hand it over either.
    expect(await session.call('ssh_get', { host: 'box', path: CONF })).not.toContain(rotated!);

    // Restore, through the marker the rotation handed back.
    const held = MARKER.exec(applied)![0];
    const current = await markerForPassword();
    expect(held).toBeDefined();
    await applyEdit(CONF, [{ old_string: `db_password = ${current}`, new_string: `db_password = ${PASSWORD}` }]);
    expect(await onHost()).toContain(`db_password = ${PASSWORD}`);
  });

  it('writes a value the user typed on a page, and nowhere else', async () => {
    const typed = 'typed-by-a-human-42';
    const path = '/home/deploy/user.conf';

    const asked = await session.call('ssh_edit', {
      host: 'box',
      path,
      edits: [{ old_string: 'password = user-secret-99', new_string: 'password = {{ssh-mcp:ask:new-password}}' }],
    });
    expect(asked).toContain('new-password');
    await provide(linkIn(asked), { 'new-password': typed });

    const applied = await applyEdit(path, [
      { old_string: 'password = user-secret-99', new_string: 'password = {{ssh-mcp:ask:new-password}}' },
    ]);

    expect(await onHost(path)).toContain(`password = ${typed}`);
    // Written as the connecting user, since deploy owns this one.
    expect(applied).toContain('as deploy');
    expect(session.transcript.join('\n')).not.toContain(typed);
  });

  it('gives a marker to a privileged command only through a page the user answers', async () => {
    const marker = await markerForPassword();

    const pending = await session.call('ssh_sudo', {
      host: 'box',
      cmd: `sudo grep -c '${marker}' ${CONF}`,
    });
    const link = linkIn(pending);
    const shownToUser = await pageBody(link);

    // The user reads the expanded line; the model's copy still says marker.
    expect(shownToUser).toContain(PASSWORD);
    expect(pending).not.toContain(PASSWORD);

    await decide(link, 'once');
    const output = await session.call('ssh_sudo', { host: 'box', cmd: `sudo grep -c '${marker}' ${CONF}` });

    // The real password reached the remote grep: it found its line.
    expect(output).toContain('1');
    expect(output).not.toContain(PASSWORD);
    expect(output).toContain(marker);
  });

  it('refuses to expand a marker in ssh_run, which has no page', async () => {
    const marker = await markerForPassword();
    const refused = await session.call('ssh_run', { host: 'box', cmd: `echo ${marker}` });

    expect(refused).toContain('does not expand');
    expect(refused).not.toContain(PASSWORD);
  });

  it('withholds secrets from command output as well as from file reads', async () => {
    const output = await session.call('ssh_run', { host: 'box', cmd: `cat ${CONF}` });

    expect(output).not.toContain(PASSWORD);
    expect(output).toMatch(MARKER);
    expect(output).toContain('pool_size');
  });

  it('masks a known value even where no key name gives it away', async () => {
    await markerForPassword();
    // The escape this closes: put the value somewhere a pattern cannot see it,
    // then read it back.
    const output = await session.call('ssh_run', {
      host: 'box',
      cmd: `grep db_password ${CONF} | cut -d' ' -f3`,
    });

    expect(output).not.toContain(PASSWORD);
    expect(output).toMatch(MARKER);
  });

  it('never returns a file the config says to withhold', async () => {
    const refused = await session.call('ssh_get', { host: 'box', path: '/etc/app/prod.env' });

    expect(refused).toContain('[secrets].paths');
    expect(refused).not.toContain('tok_live_9f3b21');
    // Still there, and still readable by the user who owns the machine.
    expect(await onHost('/etc/app/prod.env')).toContain('tok_live_9f3b21');
  });

  it('keeps every secret out of the audit log', async () => {
    const log = await session.auditLog();

    expect(log).not.toContain(PASSWORD);
    expect(log).not.toContain('typed-by-a-human-42');
    expect(log).toContain('edit');
  });

  it('keeps every secret out of everything the model was ever told', async () => {
    // The whole point, asserted over the entire session rather than call by
    // call: nothing the model received contains a password from this host.
    const everything = session.transcript.join('\n');

    expect(everything).not.toContain(PASSWORD);
    expect(everything).not.toContain('user-secret-99');
    expect(everything).not.toContain('tok_live_9f3b21');
  });
});
