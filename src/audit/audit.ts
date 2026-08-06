import { appendFile } from 'node:fs/promises';

/**
 * The one place JSON earns its keep.
 *
 * Everything this server sends the model is plain text, because escaping
 * terminal output into JSON costs tokens and readability. The audit log is the
 * opposite case: it is written for the user and their tools, never sent to the
 * model, and being able to `jq` a year of sudo decisions is worth more than
 * being able to skim it. JSONL is both — one self-contained record per line.
 */

export interface AuditEntry {
  readonly event: 'start' | 'unlock' | 'lock' | 'sudo' | 'run' | 'file' | 'refused';
  readonly outcome: string;
  readonly host?: string;
  readonly command?: string;
  readonly detail?: string;
}

export class AuditLog {
  readonly #path: string;
  #queue: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.#path = path;
  }

  get path(): string {
    return this.#path;
  }

  /**
   * Appends one record. Deliberately fire-and-forget and serialised: an audit
   * write must never delay or fail a command, but records must not interleave.
   */
  write(entry: AuditEntry): void {
    const line = `${JSON.stringify({ at: new Date().toISOString(), ...entry })}\n`;
    this.#queue = this.#queue
      .then(() => appendFile(this.#path, line, 'utf8'))
      .catch((cause: unknown) => {
        process.stderr.write(`ssh-mcp: audit write failed: ${(cause as Error).message}\n`);
      });
  }

  /** Waits for pending writes — used on shutdown so the last record survives. */
  async flush(): Promise<void> {
    await this.#queue;
  }
}
