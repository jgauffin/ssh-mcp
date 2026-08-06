import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { KeyError, loadKey } from './keys.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PASSPHRASE = 'test-passphrase';

describe('OpenSSH keys', () => {
  it.each([
    ['id_ed25519', 'ssh-ed25519'],
    ['id_rsa', 'ssh-rsa'],
  ])('decodes an encrypted %s', async (name, type) => {
    const key = await loadKey(join(FIXTURES, name), PASSPHRASE);
    expect(key.type).toBe(type);
    expect(key.fingerprint).toMatch(/^SHA256:/);
    // It must be usable for authentication, which is the whole point.
    expect(key.key.getPublicSSH().length).toBeGreaterThan(0);
    expect(key.key.sign('probe')).not.toBeInstanceOf(Error);
  });

  it('decodes an unencrypted key regardless of the passphrase given', async () => {
    const key = await loadKey(join(FIXTURES, 'id_ed25519_plain'), 'anything at all');
    expect(key.type).toBe('ssh-ed25519');
  });

  it('reports a wrong passphrase as a wrong passphrase, not a broken file', async () => {
    const failure = await loadKey(join(FIXTURES, 'id_ed25519'), 'wrong').catch((cause: KeyError) => cause);
    expect(failure).toBeInstanceOf(KeyError);
    expect((failure as KeyError).likelyWrongPassphrase).toBe(true);
  });

  it('reports a missing file plainly, and not as a passphrase problem', async () => {
    const failure = await loadKey(join(FIXTURES, 'nope'), PASSPHRASE).catch((cause: KeyError) => cause);
    expect((failure as KeyError).likelyWrongPassphrase).toBe(false);
    expect((failure as KeyError).message).toContain('cannot read key file');
  });
});

describe('routing', () => {
  /**
   * The decision this project owns: anything with a PuTTY header goes to the
   * PPK parser, everything else to ssh2. ssh2's own PPK support is not enough
   * — it only handles `PuTTY-User-Key-File-2` with RSA/DSA — so a v3 header
   * reaching ssh2 would be a bug, and the error must come from the PPK side.
   */
  it.each(['2', '3'])('sends a PPK v%s header to the PuTTY parser', async (version) => {
    const path = join(await mkdtemp(join(tmpdir(), 'ssh-mcp-ppk-')), 'key.ppk');
    await writeFile(path, `PuTTY-User-Key-File-${version}: ssh-ed25519\nEncryption: aes256-cbc\n`, 'utf8');

    const failure = await loadKey(path, PASSPHRASE).catch((cause: KeyError) => cause);
    expect(failure).toBeInstanceOf(KeyError);
    // ssh2 answers "Unsupported key format"; a PPK-aware parser complains about
    // the truncated body instead. Either way it must not be ssh2's message.
    expect((failure as KeyError).message).not.toContain('Unsupported key format');
  });

  it('sends an OpenSSH header to ssh2', async () => {
    const path = join(await mkdtemp(join(tmpdir(), 'ssh-mcp-os-')), 'key');
    await writeFile(path, 'not a key at all\n', 'utf8');
    const failure = await loadKey(path, PASSPHRASE).catch((cause: KeyError) => cause);
    expect((failure as KeyError).message).toContain('Unsupported key format');
  });
});
