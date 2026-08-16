import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decide, dockerAvailable, linkIn, startHost, startSession, type Session, type TestHost } from './host.js';

/**
 * What happens when the file moves under an approval.
 *
 * `ssh_edit` shows a diff, returns, and is called again once the user has
 * answered. Between those two moments anyone with a shell can change the file,
 * and the thing that must never happen is the approved change being written on
 * top of theirs — the user consented to a diff against content that no longer
 * exists.
 *
 * Two guards do that work, and they are tested here separately because they
 * fire at different moments:
 *
 * - the approval key carries the hashes of the file before *and* after, so an
 *   answer given about one version of the file cannot be spent on another
 * - the file is read once more immediately before the write, and the write is
 *   abandoned if it moved since the diff was drawn
 *
 * What is *not* here, deliberately: the window between that last read and the
 * write itself. Closing it needs a compare-and-swap that neither SFTP nor
 * `cp` offers, so it is a documented limit rather than an untested one. The
 * last case below is written to catch it if it ever bites, by insisting that a
 * reply saying "Applied" is always true of the file afterwards.
 */

const USER_FILE = '/home/deploy/user.conf';
const ROOT_FILE = '/etc/app/app.conf';

const available = await dockerAvailable();
const suite = available ? describe : describe.skip;

suite('a file that moved under the approval', () => {
  let host: TestHost;
  let session: Session;

  beforeAll(async () => {
    host = await startHost();
    session = await startSession(host);
  });

  afterAll(async () => {
    await session?.close();
    await host?.stop();
  });

  const onHost = (path: string): Promise<string> => host.inspect(`cat ${path}`);

  /** Someone else, with their own shell, changing the file mid-decision. */
  const thirdPartyAppends = (path: string, line: string): Promise<string> =>
    host.inspect(`printf '%s\\n' '${line}' >> ${path}`);

  it('refuses to write an approval that was given for content the file no longer has', async () => {
    const edits = [{ old_string: 'name = local', new_string: 'name = production' }];

    // Round one: the diff is drawn against the file as it is now.
    const pending = await session.call('ssh_edit', { host: 'box', path: USER_FILE, edits });
    const link = linkIn(pending);

    // Someone else edits it while the page is on screen.
    await thirdPartyAppends(USER_FILE, 'owner = ops');
    const changed = await onHost(USER_FILE);

    // The user answers the page they were shown.
    await decide(link, 'apply');
    const second = await session.call('ssh_edit', { host: 'box', path: USER_FILE, edits });

    // Nothing is written, and the answer is a fresh page against the real file.
    expect(second).not.toContain('Applied');
    expect(second).toContain('waiting for the user');
    expect(await onHost(USER_FILE)).toBe(changed);
    expect(await onHost(USER_FILE)).toContain('name = local');
  });

  it('draws the new diff against what is really there, and applies that', async () => {
    const edits = [{ old_string: 'name = local', new_string: 'name = production' }];

    // Carrying on from the refusal above: answer the new page.
    const pending = await session.call('ssh_edit', { host: 'box', path: USER_FILE, edits });
    await decide(linkIn(pending), 'apply');
    const applied = await session.call('ssh_edit', { host: 'box', path: USER_FILE, edits });

    expect(applied).toContain('Applied');
    const after = await onHost(USER_FILE);
    expect(after).toContain('name = production');
    // The third party's line survived: this is a change to their file, not a
    // replacement of it with the version this call first read.
    expect(after).toContain('owner = ops');
  });

  it('holds for the privileged path too, where the read and the write both use sudo', async () => {
    const edits = [{ old_string: 'pool_size = 10', new_string: 'pool_size = 50' }];

    const pending = await session.call('ssh_edit', { host: 'box', path: ROOT_FILE, edits });
    const link = linkIn(pending);

    await host.inspect(`printf '%s\\n' 'workers = 4' >> ${ROOT_FILE}`);
    const changed = await onHost(ROOT_FILE);

    await decide(link, 'apply');
    const second = await session.call('ssh_edit', { host: 'box', path: ROOT_FILE, edits });

    expect(second).not.toContain('Applied');
    expect(await onHost(ROOT_FILE)).toBe(changed);
  });

  it('never reports a change it did not make, even with two edits racing', async () => {
    const path = '/home/deploy/race.conf';
    await host.inspect(`printf '%s\\n' 'a = 1' 'b = 2' > ${path} && chown deploy:deploy ${path}`);

    const first = [{ old_string: 'a = 1', new_string: 'a = 100' }];
    const second = [{ old_string: 'b = 2', new_string: 'b = 200' }];

    // Both diffs drawn and both answered before either is applied: two
    // approvals in hand for two different versions of the same file.
    const pages = await Promise.all([
      session.call('ssh_edit', { host: 'box', path, edits: first }),
      session.call('ssh_edit', { host: 'box', path, edits: second }),
    ]);
    await Promise.all(pages.map((page) => decide(linkIn(page), 'apply')));

    const replies = await Promise.all([
      session.call('ssh_edit', { host: 'box', path, edits: first }),
      session.call('ssh_edit', { host: 'box', path, edits: second }),
    ]);

    const after = await onHost(path);

    // Exactly one wins, and the other is told. Before the writer queue both
    // wrote: the second silently undid the first, and both replies said
    // "Applied" — a reply reporting a change the file does not have.
    const applied = replies.filter((reply) => reply.includes('Applied'));
    const refused = replies.filter((reply) => reply.includes('changed after the diff was approved'));

    expect(applied).toHaveLength(1);
    expect(refused).toHaveLength(1);

    // Whichever won, its change is really there and the file is whole.
    if (replies[0]!.includes('Applied')) expect(after).toBe('a = 100\nb = 2\n');
    else expect(after).toBe('a = 1\nb = 200\n');
  });

  it('leaves nothing behind in /tmp, whichever way a write ended', async () => {
    // Every write goes through a uniquely named temp file, and the unlink runs
    // on the failure paths too. A stray copy of a config file in /tmp is a copy
    // of whatever secret it held.
    expect(await host.inspect('ls /tmp | grep -c ssh-mcp || true')).toBe('0\n');
  });
});
