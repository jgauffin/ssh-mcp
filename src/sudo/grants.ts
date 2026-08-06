import { readFile } from 'node:fs/promises';
import { formatPattern, matches, parsePattern, PatternError } from './matcher.js';

/**
 * Where "don't ask me again" lives.
 *
 * Session grants sit in memory and die with the vault — relocking drops them,
 * so the idle timeout is also an approval timeout. They are created by
 * `ssh_sudo` once the user has approved a command at the client's permission
 * prompt.
 *
 * Persistent rules are only ever written by the user, by hand, into a
 * plain-text file they own: one rule per line, greppable, editable with any
 * editor. Nothing in this server appends to it — a permanent grant of root
 * should require a human to type it. `ssh_sudo` prints the exact line to add,
 * and the wider alternatives, but the decision and the keystrokes are theirs.
 * No JSON, because a rule you cannot read at a glance is a rule you cannot
 * audit.
 */

export interface Grant {
  /** Host alias, or `*` for every host. */
  readonly host: string;
  readonly pattern: readonly string[];
  /** Absent for rules that came from the policy file. */
  readonly expiresAt: number | undefined;
}

export class SudoGrants {
  readonly #policyPath: string;
  #persistent: Grant[] = [];
  #session: Grant[] = [];

  constructor(policyPath: string) {
    this.#policyPath = policyPath;
  }

  get policyPath(): string {
    return this.#policyPath;
  }

  /** Reads the policy file. A missing file simply means no persistent rules. */
  async load(): Promise<{ rules: number; problems: string[] }> {
    let text: string;
    try {
      text = await readFile(this.#policyPath, 'utf8');
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code === 'ENOENT') {
        this.#persistent = [];
        return { rules: 0, problems: [] };
      }
      throw cause;
    }

    const rules: Grant[] = [];
    const problems: string[] = [];

    text.split(/\r?\n/).forEach((line, index) => {
      const trimmed = line.trim();
      if (trimmed === '' || trimmed.startsWith('#')) return;

      const separator = /\s+/.exec(trimmed);
      if (!separator) {
        problems.push(`line ${index + 1}: "${trimmed}" has a host but no command pattern`);
        return;
      }

      const host = trimmed.slice(0, separator.index);
      try {
        rules.push({ host, pattern: parsePattern(trimmed.slice(separator.index)), expiresAt: undefined });
      } catch (cause) {
        problems.push(`line ${index + 1}: ${(cause as PatternError).message}`);
      }
    });

    this.#persistent = rules;
    return { rules: rules.length, problems };
  }

  /**
   * Finds a rule covering this command. Callers must only reach here for a
   * simple, single-segment command — see `parseCommandLine().simple`.
   */
  find(alias: string, argv: readonly string[]): Grant | undefined {
    const now = Date.now();
    this.#session = this.#session.filter((grant) => grant.expiresAt === undefined || grant.expiresAt > now);

    return [...this.#session, ...this.#persistent].find(
      (grant) => (grant.host === alias || grant.host === '*') && matches(grant.pattern, argv),
    );
  }

  grantForSession(alias: string, pattern: readonly string[], ttlMs: number): Grant {
    const grant: Grant = { host: alias, pattern, expiresAt: Date.now() + ttlMs };
    this.#session.push(grant);
    return grant;
  }

  /** Called when the vault relocks: an idle timeout revokes approvals too. */
  clearSession(): void {
    this.#session = [];
  }

  /** Plain-text summary for `ssh_status`. */
  describe(): string {
    const now = Date.now();
    const live = this.#session.filter((grant) => grant.expiresAt === undefined || grant.expiresAt > now);
    const lines: string[] = [];

    for (const grant of live) {
      const left = Math.max(0, Math.round(((grant.expiresAt ?? now) - now) / 60_000));
      lines.push(`  session  ${grant.host}  ${formatPattern(grant.pattern)}  (${left}m left)`);
    }
    for (const grant of this.#persistent) {
      lines.push(`  always   ${grant.host}  ${formatPattern(grant.pattern)}`);
    }

    return lines.length === 0 ? '  (no sudo grants)' : lines.join('\n');
  }
}
