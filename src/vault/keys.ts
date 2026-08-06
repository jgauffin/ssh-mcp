import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parseFromString } from 'ppk-to-openssh';
// ssh2 is CommonJS: named ESM imports of its exports fail at load time, even
// though its type declarations advertise them.
import ssh2, { type ParsedKey } from 'ssh2';

const { utils: sshUtils } = ssh2;

/**
 * Key decoding, in process and in memory.
 *
 * PuTTY keys go through `ppk-to-openssh` rather than the `puttygen` CLI on
 * purpose: shelling out would write a decrypted key to a temporary file.
 * `ssh2`'s own PPK support is not enough either — its parser only recognises
 * `PuTTY-User-Key-File-2` with RSA/DSA, so PPK v3 (Argon2id) and Ed25519 keys,
 * which modern PuTTY writes by default, would fail.
 *
 * What is held afterwards is ssh2's own parsed key, handed to `authHandler` at
 * connect time. An earlier version re-serialised it with `getPrivatePEM()`,
 * which silently produces something unusable for Ed25519 — there is no
 * traditional PEM form for those keys.
 */

export interface LoadedKey {
  readonly path: string;
  /** ssh2's parsed key, ready to hand to `authHandler`. */
  readonly key: ParsedKey;
  readonly type: string;
  readonly fingerprint: string;
}

export class KeyError extends Error {
  override readonly name = 'KeyError';
  constructor(
    message: string,
    readonly path: string,
    /** True when the failure looks like a wrong passphrase rather than a broken file. */
    readonly likelyWrongPassphrase: boolean,
  ) {
    super(message);
  }
}

function sshFingerprint(publicBlob: Buffer): string {
  return `SHA256:${createHash('sha256').update(publicBlob).digest('base64').replace(/=+$/, '')}`;
}

const WRONG_PASSPHRASE = /passphrase|decrypt|mac|integrity|bad password|incorrect/i;

/** Unwraps ssh2's `parseKey`, which signals failure by returning an Error. */
function parse(material: string | Buffer, path: string, passphrase?: string): ParsedKey {
  const parsed = passphrase === undefined ? sshUtils.parseKey(material) : sshUtils.parseKey(material, passphrase);
  const key = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!key || key instanceof Error) {
    const message = key instanceof Error ? key.message : 'empty result';
    throw new KeyError(message, path, WRONG_PASSPHRASE.test(message));
  }
  return key;
}

async function loadPpk(path: string, text: string, passphrase: string): Promise<LoadedKey> {
  const converted = await parseFromString(text, passphrase);
  // The conversion is already decrypted, so no passphrase is passed on.
  const key = parse(converted.privateKey, path);
  return {
    path,
    key,
    type: key.type,
    fingerprint: converted.fingerprint || sshFingerprint(key.getPublicSSH()),
  };
}

function loadOpenSsh(path: string, text: string, passphrase: string): LoadedKey {
  const key = parse(text, path, passphrase);
  return { path, key, type: key.type, fingerprint: sshFingerprint(key.getPublicSSH()) };
}

/**
 * Decodes one private key with the given passphrase. Unencrypted keys ignore
 * it. The decrypted material never touches disk.
 */
export async function loadKey(path: string, passphrase: string): Promise<LoadedKey> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (cause) {
    throw new KeyError(`cannot read key file: ${(cause as Error).message}`, path, false);
  }

  if (text.startsWith('PuTTY-User-Key-File-')) {
    try {
      return await loadPpk(path, text, passphrase);
    } catch (cause) {
      if (cause instanceof KeyError) throw cause;
      const message = (cause as Error).message;
      throw new KeyError(message, path, WRONG_PASSPHRASE.test(message));
    }
  }

  return loadOpenSsh(path, text, passphrase);
}
