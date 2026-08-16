import type { Client, SFTPWrapper } from 'ssh2';

/**
 * The SFTP leaf: opening a channel, and the three questions every caller asks
 * about what came back — was it refused, is it text, is it really UTF-8.
 *
 * It lives on its own because both the read-only tools and `ssh_edit` need it,
 * and `ssh_edit` needs to tell "you may not read this" apart from "there is no
 * such file" to decide whether to escalate.
 */

export const MAX_READ_BYTES = 256 * 1024;

/**
 * ssh2 does not use errno strings. Every SFTP failure is a plain Error carrying
 * a *numeric* `.code` taken straight off the wire — the SSH_FX_* status codes.
 * They are re-exported as `utils.sftp.STATUS_CODE`, but ssh2 is CommonJS and
 * named imports from it do not survive the load (see pool.ts), so the two that
 * matter are restated here rather than pulled in for their own sake.
 */
export const SFTP_NO_SUCH_FILE = 2;
export const SFTP_PERMISSION_DENIED = 3;
/** Servers that do not distinguish return this for a refusal too. */
export const SFTP_FAILURE = 4;

/**
 * One SFTP channel per connection, opened on demand and reused.
 *
 * Not an optimisation. `client.sftp()` opens a *new* channel every call and
 * nothing here ever closed one, so every `ssh_get`, `ssh_ls` and `ssh_edit`
 * left a session open on the far end. OpenSSH allows ten per connection by
 * default, so the eleventh file operation of a conversation — and every
 * command after it, because `exec` needs a session too — failed with
 * `Channel open failure: open failed`, and stayed broken until the vault
 * relocked and took the connection with it.
 *
 * Sharing one channel is safe: SFTP multiplexes requests over it by id, which
 * is what makes concurrent reads on a single channel ordinary rather than
 * clever.
 */
const channels = new WeakMap<Client, Promise<SFTPWrapper>>();

function openChannel(client: Client): Promise<SFTPWrapper> {
  return new Promise((resolve, reject) => {
    client.sftp((error, wrapper) => (error ? reject(error) : resolve(wrapper)));
  });
}

export function sftp(client: Client): Promise<SFTPWrapper> {
  const open = channels.get(client);
  if (open) return open;

  const opening = openChannel(client);
  channels.set(client, opening);

  const forget = (): void => {
    if (channels.get(client) === opening) channels.delete(client);
  };

  opening.then((wrapper) => {
    // A channel-level fault, as opposed to a failed request: every operation
    // in flight still fails through its own callback with its own message.
    // All this does is stop a dead channel being handed out again — and
    // listening at all is what keeps ssh2 from throwing the event at the
    // process instead.
    wrapper.once('close', forget);
    wrapper.once('end', forget);
    wrapper.once('error', forget);
  }, forget);

  return opening;
}

export function sftpErrorCode(error: unknown): number | undefined {
  const code = (error as { code?: unknown } | null | undefined)?.code;
  return typeof code === 'number' ? code : undefined;
}

/** True when the file is simply not there. */
export function missing(error: unknown): boolean {
  return sftpErrorCode(error) === SFTP_NO_SUCH_FILE;
}

/**
 * True when the far end refused for want of privilege, however it spelled it.
 *
 * `FAILURE` is included deliberately: not every server distinguishes, and the
 * cost of guessing wrong is only that a sudo read is attempted and fails with a
 * clearer message than the SFTP one.
 */
export function deniedByPermissions(error: unknown): boolean {
  const code = sftpErrorCode(error);
  return code === SFTP_PERMISSION_DENIED || code === SFTP_FAILURE;
}

export function looksBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 8000);
  return sample.includes(0);
}

/**
 * Decodes only if the bytes really are UTF-8, by re-encoding and comparing.
 *
 * `toString('utf8')` never fails: it substitutes U+FFFD and carries on. That is
 * fine for terminal output and unacceptable for a file that is about to be
 * written back — a latin-1 config would come back with replacement characters
 * in it and go out corrupted, with the diff showing no sign of it.
 */
export function decodeUtf8Strict(buffer: Buffer): string | undefined {
  const text = buffer.toString('utf8');
  return Buffer.from(text, 'utf8').equals(buffer) ? text : undefined;
}
