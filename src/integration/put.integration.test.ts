import { createHash } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decide, dockerAvailable, linkIn, pageBody, startHost, startSession, type Session, type TestHost } from './host.js';

/**
 * What the host ends up holding after a file is sent to it.
 *
 * The unit suite proves the refusals fire and the page says the right things.
 * What it cannot reach is the half that matters once consent is given: do the
 * bytes arrive identical, does a root-owned file keep its owner, group and
 * mode, and does the content stay out of everything the model is told. All of
 * it is asserted from outside the server — the tool through a real MCP client,
 * the consent through the loopback page, the result through `docker exec`.
 */

const CERT = '/etc/app/ssl/service.pem';
const HOOK = '/usr/local/bin/deploy-hook';

const available = await dockerAvailable();
const suite = available ? describe : describe.skip;

if (!available) {
  process.stderr.write('ssh-mcp: Docker is not available; the integration suite is skipped.\n');
}

suite('a file sent from this machine to a host', () => {
  let host: TestHost;
  let session: Session;
  let scratch: string;

  beforeAll(async () => {
    host = await startHost();
    session = await startSession(host);
    scratch = await mkdtemp(join(tmpdir(), 'ssh-mcp-put-'));
  });

  afterAll(async () => {
    await session?.close();
    await host?.stop();
  });

  const sha256 = (content: Buffer | string): string => createHash('sha256').update(content).digest('hex');

  /** The hash of the file as the container has it, computed by the container. */
  const hashOnHost = async (path: string): Promise<string> => (await host.inspect(`sha256sum ${path}`)).trim().split(/\s+/)[0]!;
  const ownership = async (path: string): Promise<string> => (await host.inspect(`stat -c '%U:%G %a' ${path}`)).trim();

  /** A local file to send, named so the credential guard has no opinion on it. */
  const local = async (name: string, content: Buffer | string): Promise<string> => {
    const path = join(scratch, name);
    await writeFile(path, content);
    return path;
  };

  /** Sends a file the way the assistant does: call, answer the page, call again. */
  const put = async (
    args: Record<string, unknown>,
    options: { onPage?: (body: string) => void; choice?: string } = {},
  ): Promise<string> => {
    const pending = await session.call('ssh_put', { host: 'box', ...args });
    const link = linkIn(pending);
    if (options.onPage) options.onPage(await pageBody(link));
    await decide(link, options.choice ?? 'send');
    return session.call('ssh_put', { host: 'box', ...args });
  };

  it('a_new_file_arrives_byte_identical_at_the_mode_that_was_approved', async () => {
    // Bytes that no text channel survives by accident: a NUL, a lone 0x80 that
    // is not valid UTF-8, and a CRLF that a line-based path would rewrite.
    const bytes = Buffer.from([0x00, 0x80, 0xff, 0x0d, 0x0a, 0x41, 0x00, 0xfe]);
    const source = await local('payload.bin', bytes);
    const destination = '/home/deploy/payload.bin';

    const result = await put({ local_path: source, remote_path: destination, mode: '600' });

    expect(result).toContain('Wrote 8 bytes');
    expect(await hashOnHost(destination)).toBe(sha256(bytes));
    expect(await ownership(destination)).toBe('deploy:deploy 600');
  });

  /**
   * The property the whole write path is built around. `cp` onto an existing
   * file truncates its inode rather than replacing it, so owner, group and mode
   * survive — and a certificate arriving as root:root 0644 where root:adm 0640
   * was is a change nobody approved and a service that stops trusting it.
   */
  it('a_root_owned_file_keeps_its_owner_group_and_mode_when_it_is_replaced', async () => {
    expect(await ownership(CERT)).toBe('root:adm 640');
    const replacement = '-----BEGIN CERTIFICATE-----\nnew-certificate-body\n-----END CERTIFICATE-----\n';
    const source = await local('service.crt', replacement);

    const result = await put({ local_path: source, remote_path: CERT });

    expect(result).toContain('as root via sudo');
    expect(result).toContain('owner and mode are unchanged');
    expect(await hashOnHost(CERT)).toBe(sha256(replacement));
    expect(await ownership(CERT)).toBe('root:adm 640');
  });

  /**
   * The reason the tool exists. Everything the model is told about this file is
   * a size, a hash and a route; the one thing it must never be told is what is
   * in it.
   */
  it('the_contents_never_appear_in_anything_the_model_is_told', async () => {
    const body = 'tls-private-material-4d8f2a-never-disclose';
    const source = await local('bundle.crt', `${body}\n`);

    await put({ local_path: source, remote_path: '/home/deploy/bundle.crt', mode: '600' });

    expect(await hashOnHost('/home/deploy/bundle.crt')).toBe(sha256(`${body}\n`));
    for (const said of session.transcript) expect(said).not.toContain(body);
  });

  it('the_page_shows_the_hash_the_file_really_has', async () => {
    const content = 'licence-key: 7731-AAAA\n';
    const source = await local('licence.lic', content);
    let shownToUser = '';

    await put(
      { local_path: source, remote_path: '/home/deploy/licence.lic', mode: '600' },
      { onPage: (body) => (shownToUser = body) },
    );

    // The digest on the page is the digest the host computes afterwards, which
    // is what makes "sha256 …" on a page worth reading at all.
    expect(shownToUser).toContain(sha256(content));
    expect(await hashOnHost('/home/deploy/licence.lic')).toBe(sha256(content));
    expect(shownToUser).toContain(source);
  });

  it('sending_the_same_bytes_again_writes_nothing_and_asks_nothing', async () => {
    const content = 'idempotent\n';
    const source = await local('again.crt', content);
    const destination = '/home/deploy/again.crt';
    await put({ local_path: source, remote_path: destination, mode: '600' });
    const stamp = (await host.inspect(`stat -c '%Y' ${destination}`)).trim();

    // No page this time: there is nothing to decide, so the first call answers.
    const second = await session.call('ssh_put', { host: 'box', local_path: source, remote_path: destination, mode: '600' });

    expect(second).toContain('already holds exactly these bytes');
    expect((await host.inspect(`stat -c '%Y' ${destination}`)).trim()).toBe(stamp);
  });

  it('an_executable_destination_is_refused_rather_than_overwritten', async () => {
    const before = await hashOnHost(HOOK);
    const source = await local('hook-replacement.txt', 'echo something else\n');

    const refusal = await session.call('ssh_put', { host: 'box', local_path: source, remote_path: HOOK });

    expect(refusal).toContain('is executable');
    expect(refusal).toContain('Nothing was written');
    expect(await hashOnHost(HOOK)).toBe(before);
    expect(await ownership(HOOK)).toBe('root:root 755');
  });

  it('denying_the_page_leaves_the_destination_untouched', async () => {
    const before = await hashOnHost(CERT);
    const source = await local('unwanted.crt', 'should-never-land\n');

    const pending = await session.call('ssh_put', { host: 'box', local_path: source, remote_path: CERT });
    await decide(linkIn(pending), 'deny');
    const denied = await session.call('ssh_put', { host: 'box', local_path: source, remote_path: CERT });

    expect(denied).toContain('You denied this');
    expect(await hashOnHost(CERT)).toBe(before);
  });

  /**
   * A local file edited while the page was open must not be sent under the
   * answer given for the file as it was: the content hash is in the approval
   * key, so the changed file is a different question.
   */
  it('a_local_file_changed_after_the_page_was_answered_is_not_sent_on_that_answer', async () => {
    const source = await local('moving.crt', 'first-version\n');
    const destination = '/home/deploy/moving.crt';

    const pending = await session.call('ssh_put', { host: 'box', local_path: source, remote_path: destination, mode: '600' });
    await decide(linkIn(pending), 'send');
    await writeFile(source, 'second-version-nobody-approved\n');

    const again = await session.call('ssh_put', { host: 'box', local_path: source, remote_path: destination, mode: '600' });

    // A fresh page for the new bytes, and nothing written on the old answer.
    expect(again).toContain('waiting for the user');
    expect(await host.inspect(`test -e ${destination} && echo exists || echo absent`)).toContain('absent');
  });

  it('the_audit_log_records_the_hash_and_not_the_contents', async () => {
    const body = 'audit-should-not-hold-this-0f1e2d\n';
    const source = await local('audited.crt', body);

    await put({ local_path: source, remote_path: '/home/deploy/audited.crt', mode: '600' });

    const log = await session.auditLog();
    expect(log).toContain(sha256(body));
    expect(log).not.toContain('audit-should-not-hold-this');
  });
});
