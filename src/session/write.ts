import { createHash, randomUUID } from 'node:crypto';
import type { CallToolResult, InputRequiredResult, ServerContext } from '@modelcontextprotocol/server';
import type { Client, SFTPWrapper } from 'ssh2';
import type { ResolvedHost } from '../hosts/registry.js';
import type { Runtime } from '../runtime.js';
import { askForSudoPassword, type Capabilities } from '../vault/gate.js';
import { exec, shellQuote, type ExecResult, type SudoMode } from './exec.js';
import { deniedByPermissions, MAX_READ_BYTES } from './sftp.js';

/**
 * How bytes this server has decided on reach a path on a host.
 *
 * Owned by one module because two tools land files — `ssh_edit`, which composes
 * the bytes from anchored edits, and `ssh_put`, which takes them from a local
 * file — and the part that is delicate is the part they share: escalating to
 * root without rewriting the destination's owner or mode, and asking for the
 * sudo password *before* the user is asked to approve anything.
 *
 * It lives apart from `files.tool.ts` so that file can go on saying truthfully
 * that everything in it runs as the connecting user with no sudo path at all.
 */

/** A file this server cannot read back is a file it has no business writing. */
export const MAX_WRITE_BYTES = MAX_READ_BYTES;
/** Base64 inflates by 4/3 and wraps at 76 columns; the slack covers the newlines. */
export const BASE64_CEILING = Math.ceil(MAX_READ_BYTES / 3) * 4 + 16 * 1024;
export const READ_TIMEOUT_MS = 30_000;
export const WRITE_TIMEOUT_MS = 30_000;

export function fingerprint(content: Buffer | string): string {
  return createHash('sha256')
    .update(typeof content === 'string' ? Buffer.from(content, 'utf8') : content)
    .digest('hex');
}

/** The short form, for an approval key or a line on a page. */
export function shortFingerprint(content: Buffer | string): string {
  return fingerprint(content).slice(0, 16);
}

export function textResult(text: string, isError = false): CallToolResult {
  return { content: [{ type: 'text', text }], isError };
}

/** The directory part of a POSIX path, for saying where a new file would land. */
export function parentOf(path: string): string {
  const cut = path.lastIndexOf('/');
  return cut <= 0 ? '/' : path.slice(0, cut);
}

/**
 * The three command lines that run as root, built in one place and exported so
 * the suite can hold them to their invariants without a host.
 *
 * They say `sudo` themselves, and that is not incidental. `SudoMode` only makes
 * `exec` prepend a shell preamble that *defines* a `sudo` function; a command
 * that never calls it runs as the connecting user, silently and successfully,
 * right up until it meets a file it may not touch. That is exactly the bug
 * these exist to make impossible to reintroduce quietly.
 */
export const SUDO_PROBE = 'sudo true';

export function readAsRootCommand(path: string): string {
  return `sudo base64 -- ${shellQuote(path)}`;
}

/**
 * Asked only after a privileged read has failed, to tell "there is no such
 * file" apart from "I could not read it".
 *
 * The distinction is the difference between an error and an ordinary create:
 * a path under a `0700` directory refuses `stat` to the connecting user whether
 * or not anything is there, so by the time the read runs it is the only thing
 * that knows, and `base64` exits 1 for both. Its message would say which, but
 * that message is the remote system's locale and not something to parse.
 */
export function existsAsRootCommand(path: string): string {
  return `sudo test -e ${shellQuote(path)}`;
}

/**
 * Asked when the destination cannot be stat'd, which is the only case where
 * its mode is not already in hand. A file this server would overwrite must not
 * be one that runs.
 */
export function executableAsRootCommand(path: string): string {
  return `sudo test -x ${shellQuote(path)}`;
}

/**
 * `cp`, deliberately, and with the destination last.
 *
 * Onto an existing file `cp` opens and truncates it rather than unlinking it,
 * so the inode survives and the owner, group, mode, ACLs and any security label
 * survive with it. `mv`, `install`, or `cp --remove-destination` would each
 * replace the file instead, and the new one would carry root's ownership and
 * the temp file's mode — a change the approved page says nothing about, and one
 * that stops sshd and sudo from starting.
 */
export function replaceAsRootCommand(temp: string, path: string): string {
  return `sudo cp -- ${shellQuote(temp)} ${shellQuote(path)}`;
}

/**
 * One writer at a time per file.
 *
 * The re-read before the write catches a file that moved while the user was
 * reading the page. It does *not* catch two of this server's own writes landing
 * together: both read the same content, both find it unchanged, both write, and
 * the second one silently undoes the first — while both replies say "Applied".
 * An assistant firing two edits at one config file is not an exotic case, and a
 * reply that reports a change the file does not have is the one failure that
 * makes every other guarantee here worthless.
 *
 * A queue per (host, path) is enough. It cannot serialise a person with their
 * own shell — nothing here can, short of a compare-and-swap neither SFTP nor
 * `cp` offers — but it makes the re-read authoritative for everything this
 * process does, which turns the second writer's lost update into a refusal.
 */
const writers = new Map<string, Promise<void>>();

export async function oneWriterAtATime<T>(key: string, work: () => Promise<T>): Promise<T> {
  const previous = writers.get(key) ?? Promise.resolve();

  let done!: () => void;
  const mine = new Promise<void>((resolve) => {
    done = resolve;
  });
  const chain = previous.then(() => mine);
  writers.set(key, chain);

  // Never rejects: a failed write must not wedge the queue for the next caller.
  await previous.catch(() => {});
  try {
    return await work();
  } finally {
    done();
    // Only if nobody queued behind us, so a live chain is never dropped.
    if (writers.get(key) === chain) writers.delete(key);
  }
}

export type Step<T> =
  | { readonly done: false; readonly value: T }
  | { readonly done: true; readonly result: CallToolResult | InputRequiredResult };

export const carryOn = <T,>(value: T): Step<T> => ({ done: false, value });
export const stop = <T,>(result: CallToolResult | InputRequiredResult): Step<T> => ({ done: true, result });

/**
 * The privileged half of a write, bound to a runtime and to the tool that is
 * asking — the tool name only so the audit log says which one wanted sudo.
 */
export function remoteWrites(runtime: Runtime, capabilities: Capabilities, tool: string) {
  /**
   * Runs one command as root, with whatever credential the vault is holding.
   *
   * `command` must already say `sudo` — see {@linkcode replaceAsRootCommand}.
   * All this adds is the preamble that teaches the far end how to authenticate.
   */
  const asRoot = async (
    client: Client,
    alias: string,
    command: string,
    limits: { timeoutMs: number; maxBytes: number },
  ): Promise<ExecResult> => {
    const cached = runtime.vault.sudoPasswordFor(alias);
    const sudo: SudoMode = cached ? { kind: 'password', password: cached } : { kind: 'noninteractive' };
    return exec(client, command, {
      timeoutMs: limits.timeoutMs,
      maxBytes: limits.maxBytes,
      // Truncation is detected from `truncated`, not enforced by line count: a
      // half-delivered file must be recognised, never quietly shortened.
      maxLines: Number.MAX_SAFE_INTEGER,
      sudo,
    });
  };

  /**
   * Makes sure `sudo` will actually work before the user is asked anything.
   *
   * Without this, a host that wants a password would discover it *after* the
   * approval — and the approval is consumed by the call that reads it, so the
   * user would have to answer the same page twice. `sudo true` runs nothing and
   * changes nothing; it exists only to move the password question in front of
   * the decision instead of behind it.
   */
  const warmSudo = async (ctx: ServerContext, client: Client, host: ResolvedHost): Promise<Step<void>> => {
    if (runtime.vault.sudoPasswordFor(host.alias)) return carryOn(undefined);

    const probe = await asRoot(client, host.alias, SUDO_PROBE, { timeoutMs: READ_TIMEOUT_MS, maxBytes: 8 * 1024 });
    if (!probe.needsSudoPassword) return carryOn(undefined);

    runtime.audit.write({ event: 'sudo', outcome: 'password-required', host: host.alias, detail: tool });
    const pending = await askForSudoPassword(
      ctx,
      runtime.vault,
      (payload) => runtime.mintState(payload, ctx),
      capabilities,
      runtime.config.openBrowser,
      host.alias,
      host.user,
    );
    // `undefined` means the user typed it while we waited, so carry straight on.
    return pending ? stop(pending) : carryOn(undefined);
  };

  /**
   * Reads the file as root and hands back its bytes.
   *
   * `base64` rather than `cat` because `exec` returns a string: it decodes the
   * head and the tail of the stream separately, so a multi-byte character
   * landing on that seam becomes two replacement characters, and any byte that
   * is not valid UTF-8 is lost outright. Both failures are silent, and the
   * result would be written back into `/etc`. Base64 makes the channel ASCII by
   * construction, so the size and content checks run on the file's real bytes
   * exactly as they do on the SFTP path.
   */
  const readAsRoot = async (client: Client, alias: string, path: string): Promise<Step<Buffer | 'absent'>> => {
    const result = await asRoot(client, alias, readAsRootCommand(path), {
      // Sized so the whole reply fits in the head half and the seam is never used.
      timeoutMs: READ_TIMEOUT_MS,
      maxBytes: 2 * BASE64_CEILING,
    });

    if (result.needsSudoPassword) {
      return stop(textResult(`sudo on ${alias} still refuses without a password, so ${path} could not be read. Nothing was written.`, true));
    }
    if (result.timedOut) return stop(textResult(`Reading ${path} on ${alias} timed out. Nothing was written.`, true));
    if (result.truncated !== undefined) {
      return stop(textResult(`${path} on ${alias} is larger than the ${MAX_READ_BYTES / 1024} KiB this tool can handle. Nothing was written.`, true));
    }
    if (result.exitCode !== 0) {
      // A file under a 0700 directory refuses `stat` to the connecting user
      // whether or not it is there, so this is the first point at which "does
      // not exist" can be told from "cannot be read" — and the first is an
      // ordinary create, not an error.
      const probe = await asRoot(client, alias, existsAsRootCommand(path), {
        timeoutMs: READ_TIMEOUT_MS,
        maxBytes: 8 * 1024,
      });
      if (probe.exitCode === 1 && !probe.needsSudoPassword && !probe.timedOut) return carryOn('absent');

      return stop(textResult(`Could not read ${path} on ${alias}: ${result.stderr.trim() || `exit ${result.exitCode}`}. Nothing was written.`, true));
    }
    // Anything on stderr would have been interleaved into `output` and decoded
    // as part of the file — sudo's lecture written into a config file.
    if (result.stderr !== '') {
      return stop(
        textResult(
          `Reading ${path} on ${alias} produced unexpected output on stderr, so its contents cannot be trusted: ${result.stderr.trim()}. Nothing was written.`,
          true,
        ),
      );
    }

    return carryOn(Buffer.from(result.output.replace(/\s+/g, ''), 'base64'));
  };

  /**
   * Whether the connecting user could write this file themselves.
   *
   * `r+` opens for writing without truncating, so this is a question and not a
   * change — which matters, because it is asked before the user has approved
   * anything. Readable-but-not-writable is the ordinary shape of `/etc`, so
   * this cannot be inferred from how the file was read.
   */
  const canWriteDirectly = async (wrapper: SFTPWrapper, path: string): Promise<boolean> =>
    new Promise<boolean>((resolve) => {
      wrapper.open(path, 'r+', (error, handle) => {
        if (error) {
          resolve(false);
          return;
        }
        wrapper.close(handle, () => resolve(true));
      });
    });

  /**
   * Writes over a file the connecting user already owns.
   *
   * No `mode` attribute: the SFTP OPEN carries whatever attributes are given
   * and the far end applies them, so passing one would chmod the file on every
   * write — quietly widening a 0600 config to 0644, which the approved page says
   * nothing about. `w` truncates the existing inode, so the mode and owner that
   * are already there stay.
   */
  const overwriteDirectly = (wrapper: SFTPWrapper, path: string, content: Buffer): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      wrapper.writeFile(path, content, (error) => (error ? reject(error) : resolve()));
    });

  /** Creates a file that is not there yet. `wx` is O_EXCL, so it never follows a planted symlink. */
  const createDirectly = (wrapper: SFTPWrapper, path: string, content: Buffer, mode: number): Promise<void> =>
    new Promise<void>((resolve, reject) => {
      wrapper.writeFile(path, content, { flag: 'wx', mode }, (error) => (error ? reject(error) : resolve()));
    });

  /**
   * Writes the file through sudo, without the content ever touching a command
   * line — quoting, `ARG_MAX`, and a process table every user on the box can
   * read all argue against that.
   *
   * See {@linkcode replaceAsRootCommand} for why it is `cp` and not `mv`: the
   * destination's inode has to survive, or the write silently rewrites the
   * owner and mode of the file it was only supposed to change the contents of.
   * The temp file is created with `wx`, which is `O_EXCL`, so a symlink planted
   * in `/tmp` beforehand cannot be followed.
   */
  const writeAsRoot = async (
    wrapper: SFTPWrapper,
    client: Client,
    alias: string,
    path: string,
    content: Buffer,
    creating: boolean,
    createMode = 0o644,
  ): Promise<Step<void>> => {
    const temp = `/tmp/.ssh-mcp-${randomUUID()}`;
    try {
      // 0600 while it sits in /tmp, because the new content may itself be a
      // secret. Only a *created* file inherits this mode through `cp`, so only
      // a create needs it to be something the finished file should have.
      await createDirectly(wrapper, temp, content, creating ? createMode : 0o600);

      const command = replaceAsRootCommand(temp, path);
      runtime.audit.write({ event: 'sudo', outcome: 'file-write', host: alias, command, detail: `approved on the ${tool} page` });

      const result = await asRoot(client, alias, command, { timeoutMs: WRITE_TIMEOUT_MS, maxBytes: 8 * 1024 });
      if (result.needsSudoPassword) {
        // Rare: the credential worked for the probe and then did not for the
        // write. The approval was consumed by the call that read it, so there
        // is nothing to resume — say plainly that nothing was written.
        return stop(
          textResult(
            `sudo on ${alias} asked for a password again before writing ${path}, so nothing was written. ` +
              `Run ${tool} again — you will be asked for the password and then shown the change.`,
            true,
          ),
        );
      }
      if (result.exitCode !== 0 || result.timedOut) {
        return stop(
          textResult(`Writing ${path} on ${alias} failed: ${result.stderr.trim() || result.output.trim() || `exit ${result.exitCode}`}`, true),
        );
      }
      return carryOn(undefined);
    } finally {
      // Every exit path, including the failures. A `/tmp` file surviving is
      // worse litter than a swallowed unlink error is a bug.
      await new Promise<void>((resolve) => wrapper.unlink(temp, () => resolve()));
    }
  };

  /**
   * Lands the bytes, as the connecting user where that works and as root where
   * it does not, and says which route it took.
   *
   * Which route it *actually* took, rather than which one was predicted. Saying
   * "as root via sudo" on a reply that in fact wrote as the connecting user is
   * worse than saying nothing: it invents an owner and a mode the file does not
   * have.
   */
  const land = async (
    wrapper: SFTPWrapper,
    client: Client,
    host: ResolvedHost,
    path: string,
    content: Buffer,
    plan: { readonly creating: boolean; readonly direct: boolean; readonly createMode: number },
  ): Promise<Step<'user' | 'sudo'>> => {
    try {
      if (plan.creating) {
        // Only a create is decided here rather than probed. There is no
        // non-destructive way to ask SFTP whether a directory is writable, and
        // by this point the user has approved the file being made — so
        // attempting it as themselves first is the cheapest honest answer, and
        // keeps a file in their own home from arriving owned by root.
        try {
          await createDirectly(wrapper, path, content, plan.createMode);
          return carryOn('user');
        } catch (cause) {
          if (!deniedByPermissions(cause) || host.sudo === 'off') throw cause;
          const written = await writeAsRoot(wrapper, client, host.alias, path, content, true, plan.createMode);
          return written.done ? stop(written.result) : carryOn('sudo');
        }
      }

      if (plan.direct) {
        await overwriteDirectly(wrapper, path, content);
        return carryOn('user');
      }

      const written = await writeAsRoot(wrapper, client, host.alias, path, content, false);
      return written.done ? stop(written.result) : carryOn('sudo');
    } catch (cause) {
      return stop(textResult(`Writing ${path} on ${host.alias} failed: ${(cause as Error).message}`, true));
    }
  };

  return { asRoot, warmSudo, readAsRoot, canWriteDirectly, overwriteDirectly, createDirectly, writeAsRoot, land };
}
