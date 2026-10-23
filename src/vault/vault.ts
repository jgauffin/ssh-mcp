import { KeyError, loadKey, type LoadedKey } from './keys.js';

/**
 * Locked-by-default credential store.
 *
 * There is deliberately no way to unlock this from the environment, a CLI
 * flag, or a file: `unlock()` is only ever reached from a human submitting the
 * loopback page. Every process start therefore begins locked, and relocking on
 * idle means walking away is the same as locking up.
 *
 * The one exception is keys with no passphrase, when the config says so. They
 * are already readable on disk, so the click guarded presence, not a secret.
 */

/**
 * What unlocking takes: a passphrase, a click (no key is encrypted, but the
 * session still needs a human to open it), nothing at all (no key is encrypted
 * and the config waives the click), or nothing a page could supply.
 */
export type UnlockNeed =
  | { readonly kind: 'passphrase' }
  | { readonly kind: 'consent' }
  | { readonly kind: 'none' }
  | { readonly kind: 'broken'; readonly summary: string };

export interface UnlockOutcome {
  readonly unlocked: boolean;
  /** One-line, human-readable summary — safe to show the model. */
  readonly summary: string;
}

export class Vault {
  readonly #keyPaths: readonly string[];
  readonly #idleTimeoutMs: number;
  readonly #confirmUnencrypted: boolean;
  readonly #keys = new Map<string, LoadedKey>();
  readonly #keyErrors = new Map<string, string>();
  readonly #sudoPasswords = new Map<string, Buffer>();
  readonly #relockListeners: Array<(reason: string) => void> = [];
  #unlockedAt: number | undefined;
  #idleTimer: NodeJS.Timeout | undefined;

  /**
   * `confirmUnencrypted: false` lets keys without a passphrase open without a
   * click. Encrypted keys still need the page: the passphrase is not on disk.
   */
  constructor(keyPaths: readonly string[], idleTimeoutMs: number, confirmUnencrypted = true) {
    this.#keyPaths = [...new Set(keyPaths)];
    this.#idleTimeoutMs = idleTimeoutMs;
    this.#confirmUnencrypted = confirmUnencrypted;
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
    const attempt = await this.#load(passphrase);
    if (attempt.keys.size === 0) {
      return fail(attempt, attempt.wrongPassphrase > 0 ? 'the passphrase did not decrypt any key' : undefined);
    }
    return this.#open(attempt);
  }

  /**
   * Tries every key with an empty passphrase, keeping nothing.
   *
   * One encrypted key means a passphrase. Otherwise a key that fails for any
   * other reason (unreadable, malformed, unsupported) is broken, and a page
   * could not help.
   */
  async unlockNeed(): Promise<UnlockNeed> {
    const attempt = await this.#load('');
    if (attempt.wrongPassphrase > 0) return { kind: 'passphrase' };
    if (attempt.errors.size > 0 || attempt.keys.size === 0) return { kind: 'broken', summary: fail(attempt, undefined).summary };
    return this.#confirmUnencrypted ? { kind: 'consent' } : { kind: 'none' };
  }

  /**
   * Loads every key without touching the vault's own state, so a page submitted
   * while this is in flight is not clobbered half-way.
   */
  async #load(passphrase: string): Promise<LoadAttempt> {
    const attempt: LoadAttempt = { keys: new Map(), errors: new Map(), wrongPassphrase: 0 };
    for (const path of this.#keyPaths) {
      try {
        attempt.keys.set(path, await loadKey(path, passphrase));
      } catch (cause) {
        const error = cause as KeyError;
        attempt.errors.set(path, error.message);
        if (error instanceof KeyError && error.likelyWrongPassphrase) attempt.wrongPassphrase += 1;
      }
    }
    return attempt;
  }

  #open(attempt: LoadAttempt): UnlockOutcome {
    this.#keys.clear();
    this.#keyErrors.clear();
    for (const [path, key] of attempt.keys) this.#keys.set(path, key);
    for (const [path, message] of attempt.errors) this.#keyErrors.set(path, message);
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

interface LoadAttempt {
  readonly keys: Map<string, LoadedKey>;
  readonly errors: Map<string, string>;
  wrongPassphrase: number;
}

function fail(attempt: LoadAttempt, detail: string | undefined): UnlockOutcome {
  detail ??= [...attempt.errors].map(([path, message]) => `${path}: ${message}`).join('; ') || 'no keys are configured';
  return { unlocked: false, summary: `Unlock failed — ${detail}.` };
}

export function formatDuration(ms: number): string {
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
  const hours = ms / 3_600_000;
  return `${Number.isInteger(hours) ? hours : hours.toFixed(1)}h`;
}
