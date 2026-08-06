import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { Vault } from './vault.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const PASSPHRASE = 'test-passphrase';
const keyPath = join(FIXTURES, 'id_ed25519');
const secondKeyPath = join(FIXTURES, 'id_rsa');

describe('the vault starts locked and stays that way without a human', () => {
  it('is locked the moment it exists', () => {
    expect(new Vault([keyPath], 60_000).locked).toBe(true);
  });

  it('stays locked when the passphrase is wrong', async () => {
    const vault = new Vault([keyPath], 60_000);
    const outcome = await vault.unlock('not the passphrase');
    expect(outcome.unlocked).toBe(false);
    expect(outcome.summary).toContain('did not decrypt');
    expect(vault.locked).toBe(true);
  });

  it('stays locked when the key file is missing', async () => {
    const vault = new Vault([join(tmpdir(), 'ssh-mcp-does-not-exist')], 60_000);
    expect((await vault.unlock(PASSPHRASE)).unlocked).toBe(false);
    expect(vault.locked).toBe(true);
  });

  it('opens with the right passphrase', async () => {
    const vault = new Vault([keyPath], 60_000);
    expect((await vault.unlock(PASSPHRASE)).unlocked).toBe(true);
    expect(vault.locked).toBe(false);
    expect(vault.keyFor(keyPath).type).toBe('ssh-ed25519');
  });

  it('opens every key that shares the one passphrase', async () => {
    const vault = new Vault([keyPath, secondKeyPath], 60_000);
    const outcome = await vault.unlock(PASSPHRASE);
    expect(outcome.unlocked).toBe(true);
    expect(outcome.summary).toContain('2 key(s)');
    expect(vault.keyFor(secondKeyPath).type).toBe('ssh-rsa');
  });

  it('opens on the keys it can, and says which it could not', async () => {
    const vault = new Vault([keyPath, join(tmpdir(), 'ssh-mcp-absent')], 60_000);
    const outcome = await vault.unlock(PASSPHRASE);
    expect(outcome.unlocked).toBe(true);
    expect(outcome.summary).toContain('1 key(s) could not be decrypted');
    expect(() => vault.keyFor(join(tmpdir(), 'ssh-mcp-absent'))).toThrow(/not available/);
  });
});

describe('relocking', () => {
  it('makes the key unreachable', async () => {
    const vault = new Vault([keyPath], 60_000);
    await vault.unlock(PASSPHRASE);
    expect(vault.keyFor(keyPath)).toBeDefined();

    vault.lock('test');

    expect(vault.locked).toBe(true);
    expect(() => vault.keyFor(keyPath)).toThrow();
  });

  it('overwrites the cached sudo password, which is a buffer it owns', async () => {
    const vault = new Vault([keyPath], 60_000);
    await vault.unlock(PASSPHRASE);
    vault.setSudoPassword('prod-1', 'hunter2');
    const held = vault.sudoPasswordFor('prod-1')!;

    vault.lock('test');

    expect(vault.sudoPasswordFor('prod-1')).toBeUndefined();
    expect(held.every((byte) => byte === 0)).toBe(true);
  });

  it('tells its listeners, so connections and grants go too', async () => {
    const vault = new Vault([keyPath], 60_000);
    const reasons: string[] = [];
    vault.onRelock((reason) => reasons.push(reason));

    await vault.unlock(PASSPHRASE);
    vault.lock('ssh_lock');
    expect(reasons).toEqual(['ssh_lock']);
  });

  it('happens on its own after the idle timeout', async () => {
    vi.useFakeTimers();
    try {
      const vault = new Vault([keyPath], 60_000);
      await vault.unlock(PASSPHRASE);
      expect(vault.locked).toBe(false);

      vi.advanceTimersByTime(59_000);
      expect(vault.locked).toBe(false);

      vault.touch();
      vi.advanceTimersByTime(59_000);
      expect(vault.locked).toBe(false);

      vi.advanceTimersByTime(2_000);
      expect(vault.locked).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
