import { KeyError, loadKey, type LoadedKey } from './keys.js';

/**
 * Locked-by-default credential store.
 *
 * There is deliberately no way to unlock this from the environment, a CLI
 * flag, or a file: `unlock()` is only ever reached from a human submitting the
 * loopback page. Every process start therefore begins locked, and relocking on
 * idle means walking away is the same as locking up.
 */

export interface UnlockOutcome {
  readonly unlocked: boolean;
  /** One-line, human-readable summary — safe to show the model. */
  readonly summary: string;
}

export class Vault {
  readonly #keyPaths: readonly string[];
  readonly #idleTimeoutMs: number;
  readonly #keys = new Map<string, LoadedKey>();
  readonly #keyErrors = new Map<string, string>();
  readonly #sudoPasswords = new Map<string, Buffer>();
  readonly #relockListeners: Array<(reason: string) => void> = [];
  #unlockedAt: number | undefined;
  #idleTimer: NodeJS.Timeout | undefined;

  constructor(keyPaths: readonly string[], idleTimeoutMs: number) {
    this.#keyPaths = [...new Set(keyPaths)];
    this.#idleTimeoutMs = idleTimeoutMs;
  }

  get locked(): boolean {
    return this.#unlockedAt === undefined;
  }

  get idleTimeoutMs(): number {
    return this.#idleTimeoutMs;
  }

  /** Called on every successful use; restarts the idle countdown. */
  touch(): void {
    if (this.locked) return;
    this.#armIdleTimer();
  }

  onRelock(listener: (reason: string) => void): void {
    this.#relockListeners.push(listener);
  }

  /** Decrypts every configured key with one passphrase. */
  async unlock(passphrase: string): Promise<UnlockOutcome> {
    this.#keys.clear();
    this.#keyErrors.clear();

    let wrongPassphrase = 0;
    for (const path of this.#keyPaths) {
      try {
        this.#keys.set(path, await loadKey(path, passphrase));
      } catch (cause) {
        const error = cause as KeyError;
        this.#keyErrors.set(path, error.message);
        if (error instanceof KeyError && error.likelyWrongPassphrase) wrongPassphrase += 1;
      }
    }

    if (this.#keys.size === 0) {
      const detail =
        wrongPassphrase > 0
          ? 'the passphrase did not decrypt any key'
          : [...this.#keyErrors].map(([path, message]) => `${path}: ${message}`).join('; ');
      this.#keyErrors.clear();
      return { unlocked: false, summary: `Unlock failed — ${detail}.` };
    }

    this.#unlockedAt = Date.now();
    this.#armIdleTimer();

    const loaded = [...this.#keys.values()].map((key) => `${key.type} ${key.fingerprint.slice(0, 20)}…`).join(', ');
    const failed = this.#keyErrors.size > 0 ? ` ${this.#keyErrors.size} key(s) could not be decrypted.` : '';
    return {
      unlocked: true,
      summary: `Unlocked ${this.#keys.size} key(s): ${loaded}.${failed} Relocks after ${formatDuration(this.#idleTimeoutMs)} idle.`,
    };
  }

  /** The decrypted key for a host, or a clear explanation of why there isn't one. */
  keyFor(path: string): LoadedKey {
    const key = this.#keys.get(path);
    if (key) return key;
    const reason = this.#keyErrors.get(path);
    throw new Error(reason ? `Key ${path} is not available: ${reason}` : `Key ${path} was not loaded by this vault.`);
  }

  sudoPasswordFor(alias: string): Buffer | undefined {
    return this.#sudoPasswords.get(alias);
  }

  setSudoPassword(alias: string, password: string): void {
    this.#sudoPasswords.get(alias)?.fill(0);
    this.#sudoPasswords.set(alias, Buffer.from(password, 'utf8'));
  }

  /**
   * Drops all secrets and notifies listeners (connection pool, sudo grants).
   *
   * The sudo password is a buffer this code owns, so it is overwritten. Key
   * material lives inside ssh2's parsed key and Node offers no way to scrub a
   * third party's internal buffers — what relocking guarantees is that no code
   * path can reach the key again, not that its bytes are gone from the heap.
   */
  lock(reason: string): void {
    if (this.locked && this.#keys.size === 0 && this.#sudoPasswords.size === 0) return;

    for (const password of this.#sudoPasswords.values()) password.fill(0);
    this.#keys.clear();
    this.#keyErrors.clear();
    this.#sudoPasswords.clear();
    this.#unlockedAt = undefined;

    if (this.#idleTimer) {
      clearTimeout(this.#idleTimer);
      this.#idleTimer = undefined;
    }

    for (const listener of this.#relockListeners) listener(reason);
  }

  /** Plain-text status line for the model. */
  status(): string {
    if (this.locked) return 'ssh-mcp is locked. The next command will ask you to unlock it in a browser.';
    const idleFor = Date.now() - this.#unlockedAt!;
    return (
      `ssh-mcp is unlocked with ${this.#keys.size} key(s), ` +
      `unlocked ${formatDuration(idleFor)} ago, relocks after ${formatDuration(this.#idleTimeoutMs)} idle.`
    );
  }

  #armIdleTimer(): void {
    if (this.#idleTimer) clearTimeout(this.#idleTimer);
    this.#idleTimer = setTimeout(() => this.lock('idle timeout'), this.#idleTimeoutMs);
    this.#idleTimer.unref();
  }
}

export function formatDuration(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  const hours = ms / 3_600_000;
  return `${Number.isInteger(hours) ? hours : hours.toFixed(1)}h`;
}
