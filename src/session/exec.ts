import type { Client } from 'ssh2';

/**
 * Runs a command and returns what a terminal would have shown.
 *
 * stdout and stderr are interleaved in arrival order rather than split into
 * labelled fields, and the result is text rather than a JSON envelope. That is
 * the cheaper and the more faithful representation: escaping a hundred lines
 * of `journalctl` into a JSON string doubles every newline and buys nothing,
 * because the model reads it as text either way.
 */

export type SudoMode = { readonly kind: 'none' } | { readonly kind: 'noninteractive' } | { readonly kind: 'password'; readonly password: Buffer };

export interface ExecOptions {
  readonly timeoutMs: number;
  readonly maxBytes: number;
  readonly maxLines: number;
  readonly sudo: SudoMode;
}

export interface ExecResult {
  readonly output: string;
  readonly exitCode: number | null;
  readonly signal: string | undefined;
  readonly timedOut: boolean;
  readonly truncated: string | undefined;
  /** True when the remote sudo refused for want of a password. */
  readonly needsSudoPassword: boolean;
  /**
   * stderr on its own, as well as interleaved into `output`.
   *
   * `ssh_edit` reconstructs file content out of `output`, so it has to be able
   * to prove that nothing but stdout is in there — sudo's lecture would
   * otherwise be written into the file. Capped like the rest: a witness, not a
   * transcript.
   */
  readonly stderr: string;
}

/**
 * Shadowing `sudo` with a shell function is how the flags get added without
 * rewriting the user's command line — `command sudo` bypasses the function, so
 * there is no recursion. It assumes a POSIX-ish login shell on the far end.
 */
const SUDO_NONINTERACTIVE = 'sudo() { command sudo -n "$@"; }\n';

/**
 * The password arrives on the channel's stdin as a single line, and a stream
 * can only be read once. Handing that stdin straight to `sudo -S` therefore
 * feeds exactly one sudo: the first one that actually has to authenticate eats
 * the line, and every later sudo on the same command line reads EOF and dies
 * with `sudo: no password was provided`. Whether a line survived came down to
 * whether sudo's timestamp cache happened to be warm, which is why the same
 * command failed and succeeded on alternate runs.
 *
 * So the line is parked in a file only its owner can read, and sudo is pointed
 * at a helper that prints it. `-A` consults that helper afresh for every
 * invocation and leaves the command's own stdin alone — a hundred sudos in one
 * line all authenticate, and none of the commands they run can read the
 * password, which a pipe into `sudo -S` could not promise: sudo only consumes
 * the line when it decides to prompt, so a NOPASSWD rule would have handed the
 * password to the privileged command's stdin.
 *
 * The helper has to be executable, which a `noexec` /tmp forbids, so the setup
 * is probed with `sudo -A -v` rather than assumed. When the probe fails, the
 * fallback spends the password on a single `sudo -v` — a call that runs no
 * command, so nothing can read what it consumed — and runs the rest with `-n`
 * off the timestamp cache it just validated. That keeps the same guarantee,
 * and gives up only on sudos the cache does not reach: it is keyed by tty or
 * by parent process, and a `pty: false` channel has no tty, so a sudo inside a
 * pipeline or subshell may still be asked to authenticate and fail. Detected
 * and reported rather than silently retried — see `NEEDS_PASSWORD`.
 *
 * Nothing here puts the password in argv (`ps` is world-readable) or in the
 * environment (every child of the command would inherit it, and `env` would
 * print it into the transcript). `head` moves it from stdin to the file
 * without it passing through the shell at all; the `read` behind it is a
 * backstop for a host without `head`, and costs a shell variable rather than a
 * leak. Whichever runs, the invariant is that the line leaves stdin before the
 * user's command starts — a preamble that gave up early and left it there
 * would hand the password to whatever the command reads from.
 */
const SUDO_ASKPASS = `__ssh_mcp_d=$(mktemp -d 2>/dev/null) || __ssh_mcp_d=
trap '__ssh_mcp_rc=$?; [ -n "$__ssh_mcp_d" ] && rm -rf "$__ssh_mcp_d"; exit $__ssh_mcp_rc' EXIT HUP INT TERM
if [ -n "$__ssh_mcp_d" ]; then
{
head -n 1 >"$__ssh_mcp_d/pw" || { IFS= read -r __ssh_mcp_pw; printf '%s\\n' "$__ssh_mcp_pw" >"$__ssh_mcp_d/pw"; unset __ssh_mcp_pw; }
chmod 600 "$__ssh_mcp_d/pw"
printf '%s\\n' '#!/bin/sh' "cat '$__ssh_mcp_d/pw'" >"$__ssh_mcp_d/askpass"
chmod 700 "$__ssh_mcp_d/askpass"
} 2>/dev/null
SUDO_ASKPASS="$__ssh_mcp_d/askpass"
export SUDO_ASKPASS
fi
if [ -n "$__ssh_mcp_d" ] && [ -s "$__ssh_mcp_d/pw" ] && command sudo -A -v >/dev/null 2>&1; then
sudo() { command sudo -A "$@"; }
else
unset SUDO_ASKPASS
if [ -n "$__ssh_mcp_d" ] && [ -s "$__ssh_mcp_d/pw" ]; then
command sudo -S -p '' -v <"$__ssh_mcp_d/pw" >/dev/null 2>&1
rm -f "$__ssh_mcp_d/pw" 2>/dev/null
else
command sudo -S -p '' -v >/dev/null 2>&1
fi
sudo() { command sudo -n "$@"; }
fi
`;

/**
 * What sudo says when it wanted a password and did not get a usable one. The
 * last two matter even when a password *was* supplied: a stale cached password
 * is refused, and a sudo the fallback's timestamp cache did not reach is
 * refused, and both are worth asking the user about rather than reporting raw.
 */
const NEEDS_PASSWORD =
  /password is required|no password was provided|incorrect password attempt|no tty present|a terminal is required|askpass/i;

/** The shell preamble that teaches the far end how to authenticate this run's sudos. */
export function sudoPrefix(mode: SudoMode): string {
  if (mode.kind === 'noninteractive') return SUDO_NONINTERACTIVE;
  if (mode.kind === 'password') return SUDO_ASKPASS;
  return '';
}

/** True when sudo refused for want of a password, whether or not one was sent. */
export function refusedForPassword(stderr: string): boolean {
  return NEEDS_PASSWORD.test(stderr);
}

/** Keeps the beginning and the end of a stream, and forgets the middle. */
class HeadTail {
  readonly #half: number;
  readonly #head: Buffer[] = [];
  readonly #tail: Buffer[] = [];
  #headBytes = 0;
  #tailBytes = 0;
  #dropped = 0;

  constructor(limit: number) {
    this.#half = Math.max(1, Math.floor(limit / 2));
  }

  push(chunk: Buffer): void {
    let rest = chunk;

    if (this.#headBytes < this.#half) {
      const room = this.#half - this.#headBytes;
      const take = rest.subarray(0, room);
      this.#head.push(take);
      this.#headBytes += take.length;
      rest = rest.subarray(take.length);
      if (rest.length === 0) return;
    }

    this.#tail.push(rest);
    this.#tailBytes += rest.length;
    while (this.#tailBytes > this.#half && this.#tail.length > 1) {
      const removed = this.#tail.shift()!;
      this.#tailBytes -= removed.length;
      this.#dropped += removed.length;
    }
  }

  get droppedBytes(): number {
    return this.#dropped;
  }

  toString(): string {
    const head = Buffer.concat(this.#head).toString('utf8');
    if (this.#tail.length === 0) return head;
    const tail = Buffer.concat(this.#tail).toString('utf8');
    return this.#dropped === 0 ? head + tail : `${head}\n… ${this.#dropped} bytes omitted …\n${tail}`;
  }
}

function trimLines(text: string, maxLines: number): { text: string; trimmed: number } {
  const lines = text.split('\n');
  if (lines.length <= maxLines) return { text, trimmed: 0 };

  const half = Math.floor(maxLines / 2);
  const trimmed = lines.length - half * 2;
  return {
    text: [...lines.slice(0, half), `… ${trimmed} lines omitted …`, ...lines.slice(-half)].join('\n'),
    trimmed,
  };
}

export function exec(client: Client, command: string, options: ExecOptions): Promise<ExecResult> {
  const prefix = sudoPrefix(options.sudo);

  return new Promise<ExecResult>((resolve, reject) => {
    client.exec(prefix + command, { pty: false }, (error, stream) => {
      if (error) {
        reject(new Error(`could not start the command: ${error.message}`));
        return;
      }

      const collected = new HeadTail(options.maxBytes);
      const stderrText: string[] = [];
      let timedOut = false;

      const timer = setTimeout(() => {
        timedOut = true;
        stream.close();
      }, options.timeoutMs);
      timer.unref();

      stream.on('data', (chunk: Buffer) => collected.push(chunk));
      stream.stderr.on('data', (chunk: Buffer) => {
        collected.push(chunk);
        // Kept separately only to recognise sudo's own complaints.
        if (stderrText.length < 32) stderrText.push(chunk.toString('utf8'));
      });

      stream.once('close', (code: number | null, signal: string | undefined) => {
        clearTimeout(timer);

        const raw = collected.toString();
        const { text, trimmed } = trimLines(raw, options.maxLines);
        const notes: string[] = [];
        if (collected.droppedBytes > 0) notes.push(`${collected.droppedBytes} bytes`);
        if (trimmed > 0) notes.push(`${trimmed} lines`);

        resolve({
          output: text,
          exitCode: code,
          signal,
          timedOut,
          truncated: notes.length > 0 ? notes.join(' and ') : undefined,
          // Deliberately not conditioned on a password having been withheld: it
          // is precisely the run that *did* send one, and still got refused,
          // that needs the user asked again rather than shown sudo's complaint.
          needsSudoPassword: refusedForPassword(stderrText.join('')),
          stderr: stderrText.join(''),
        });
      });

      stream.once('error', (cause: Error) => {
        clearTimeout(timer);
        reject(cause);
      });

      // No interactive stdin: feed sudo its password if we have one, then close.
      if (options.sudo.kind === 'password') {
        stream.write(options.sudo.password);
        stream.write('\n');
      }
      stream.end();
    });
  });
}

/**
 * The shell prompt a real session would have shown, so the transcript reads as
 * a terminal log rather than as an opaque `ssh_run`. `#` for root and `$` for
 * anyone else is the convention every Linux tutorial uses, and it is worth a
 * reader learning it here.
 */
export function promptLine(user: string, alias: string, command: string): string {
  return `${user}@${alias}${user === 'root' ? '#' : '$'} ${command}`;
}

/**
 * POSIX single-quoting: the only form with no escapes inside it at all.
 *
 * Used by `ssh_edit`, which builds command lines out of paths the model chose.
 * Every path goes through this, and every command it builds puts `--` before
 * the path, so a file called `-rf` is a file and not a flag.
 */
export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

/** Formats a result the way a terminal would, with one trailer line when something is off. */
export function formatExecResult(result: ExecResult): string {
  const trailers: string[] = [];
  if (result.timedOut) trailers.push('timed out');
  if (result.truncated) trailers.push(`truncated ${result.truncated}`);
  if (result.signal) trailers.push(`killed by ${result.signal}`);
  else if (result.exitCode !== 0 && result.exitCode !== null) trailers.push(`exit ${result.exitCode}`);

  const body = result.output.replace(/\s+$/, '');
  if (trailers.length === 0) return body === '' ? '(no output)' : body;
  return `${body === '' ? '(no output)' : body}\n— ${trailers.join(', ')}`;
}
