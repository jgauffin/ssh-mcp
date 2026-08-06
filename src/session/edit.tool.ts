import { createHash, randomUUID } from 'node:crypto';
import type { CallToolResult, InputRequiredResult, McpServer, ServerContext } from '@modelcontextprotocol/server';
import type { Client, SFTPWrapper } from 'ssh2';
import { z } from 'zod';
import { hostParameter } from '../hosts/hosts.tool.js';
import type { ResolvedHost } from '../hosts/registry.js';
import type { Runtime } from '../runtime.js';
import { askForApproval, askForSudoPassword, collectSudoPassword, ensureUnlocked } from '../vault/gate.js';
import { unifiedDiff } from './diff.js';
import { applyEdits, describeFailure, type Edit } from './edits.js';
import { exec, shellQuote, type ExecResult, type SudoMode } from './exec.js';
import { decodeUtf8Strict, deniedByPermissions, looksBinary, MAX_READ_BYTES, missing, sftp } from './sftp.js';

/**
 * The only way this server changes a file's contents.
 *
 * `ssh_put` used to take a whole file and write it, which asked the model for
 * everything and the user for nothing: approving it meant approving a tool
 * name. This inverts both halves. The model supplies anchors, so it cannot
 * silently drop the parts of the file it never read; the user is shown the
 * exact `+` and `-` lines on a page they have to answer, so what they consent
 * to is the change rather than the intention behind it.
 *
 * It escalates. A config file the connecting user may read but not write — the
 * ordinary shape of `/etc` — is written through sudo, and the page says so.
 * That is deliberately not `ssh_sudo`'s job: there the page can only show a
 * command line, and `sudo tee /etc/nginx/nginx.conf` tells the reader nothing
 * about what the file would end up containing.
 *
 * It lives apart from `files.tool.ts` so that file can go on saying truthfully
 * that everything in it runs as the connecting user with no sudo path at all.
 */

/** A file this tool cannot read back is a file it has no business writing. */
const MAX_WRITE_BYTES = MAX_READ_BYTES;
/** Base64 inflates by 4/3 and wraps at 76 columns; the slack covers the newlines. */
const BASE64_CEILING = Math.ceil(MAX_READ_BYTES / 3) * 4 + 16 * 1024;
const READ_TIMEOUT_MS = 30_000;
const WRITE_TIMEOUT_MS = 30_000;
const MAX_EDITS = 50;

const editSchema = z.object({
  old_string: z
    .string()
    .describe(
      'The exact text to replace, copied from the file including its indentation. It must appear exactly ' +
        'once unless replace_all is set. Empty means "create this file", and is only allowed as the single ' +
        'edit against a path that does not exist yet.',
    ),
  new_string: z.string().describe('What to put in its place. Empty deletes the matched text.'),
  replace_all: z.boolean().optional().describe('Replace every occurrence instead of requiring exactly one.'),
});

function fingerprint(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 16);
}

function textResult(text: string, isError = false): CallToolResult {
  return { content: [{ type: 'text', text }], isError };
}

/** The directory part of a POSIX path, for saying where a new file would land. */
function parentOf(path: string): string {
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
 * `cp`, deliberately, and with the destination last.
 *
 * Onto an existing file `cp` opens and truncates it rather than unlinking it,
 * so the inode survives and the owner, group, mode, ACLs and any security label
 * survive with it. `mv`, `install`, or `cp --remove-destination` would each
 * replace the file instead, and the new one would carry root's ownership and
 * the temp file's mode — a change the approved diff says nothing about, and one
 * that stops sshd and sudo from starting.
 */
export function replaceAsRootCommand(temp: string, path: string): string {
  return `sudo cp -- ${shellQuote(temp)} ${shellQuote(path)}`;
}

/** What was on the host before the edits, and how it had to be read. */
type Existing =
  | { readonly kind: 'absent' }
  | { readonly kind: 'text'; readonly text: string; readonly viaSudo: boolean };

type Step<T> = { readonly done: false; readonly value: T } | { readonly done: true; readonly result: CallToolResult | InputRequiredResult };

const carryOn = <T,>(value: T): Step<T> => ({ done: false, value });
const stop = <T,>(result: CallToolResult | InputRequiredResult): Step<T> => ({ done: true, result });

export function registerEditTool(server: McpServer, runtime: Runtime): void {
  const capabilities = () => server.server.getClientCapabilities();

  /**
   * Runs one command as root, with whatever credential the vault is holding.
   *
   * `command` must already say `sudo` — see {@linkcode replaceAsRootCommand}.
   * All this adds is the preamble that teaches the far end how to authenticate.
   */
  const asRoot = async (client: Client, alias: string, command: string, limits: { timeoutMs: number; maxBytes: number }): Promise<ExecResult> => {
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

    runtime.audit.write({ event: 'sudo', outcome: 'password-required', host: host.alias, detail: 'ssh_edit' });
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
   * construction, so the size, binary and encoding checks below run on the
   * file's real bytes exactly as they do on the SFTP path.
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
      return stop(textResult(`${path} on ${alias} is larger than the ${MAX_READ_BYTES / 1024} KiB this tool can diff. Nothing was written.`, true));
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
      return stop(textResult(`Reading ${path} on ${alias} produced unexpected output on stderr, so its contents cannot be trusted: ${result.stderr.trim()}. Nothing was written.`, true));
    }

    return carryOn(Buffer.from(result.output.replace(/\s+/g, ''), 'base64'));
  };

  /** Everything both read paths have to agree on before the bytes count as a file this tool can edit. */
  const asEditableText = (buffer: Buffer, path: string, alias: string): Step<string> => {
    if (buffer.length > MAX_READ_BYTES) {
      return stop(textResult(`${path} on ${alias} is ${buffer.length} bytes, over the ${MAX_READ_BYTES} byte limit. Nothing was written.`, true));
    }
    if (looksBinary(buffer)) {
      return stop(textResult(`${path} on ${alias} looks binary; ssh_edit only edits text. Nothing was written.`, true));
    }
    const text = decodeUtf8Strict(buffer);
    if (text === undefined) {
      return stop(textResult(`${path} on ${alias} is not valid UTF-8; ssh_edit only edits UTF-8 text. Nothing was written.`, true));
    }
    return carryOn(text);
  };

  /**
   * The file as it is now, read as the connecting user where possible and as
   * root where not.
   *
   * The privileged fallback runs without a separate prompt, and the content it
   * returns never reaches the model: it is used to draw the diff and to check
   * the file has not moved, and the tool's reply carries only line counts. The
   * honest cost is that the model can cause a root-readable file to be read;
   * what it cannot do is see it.
   */
  const readExisting = async (
    ctx: ServerContext,
    wrapper: SFTPWrapper,
    client: Client,
    host: ResolvedHost,
    path: string,
  ): Promise<Step<Existing>> => {
    let size: number;
    try {
      size = await new Promise<number>((resolve, reject) => {
        wrapper.stat(path, (error, stats) => (error ? reject(error) : resolve(stats.size)));
      });
    } catch (cause) {
      if (missing(cause)) return carryOn({ kind: 'absent' });
      if (!deniedByPermissions(cause)) throw cause;
      return readPrivileged(ctx, client, host, path);
    }

    if (size > MAX_READ_BYTES) {
      return stop(textResult(`${path} on ${host.alias} is ${size} bytes, over the ${MAX_READ_BYTES} byte limit. Nothing was written.`, true));
    }

    let buffer: Buffer;
    try {
      buffer = await new Promise<Buffer>((resolve, reject) => {
        wrapper.readFile(path, (error, data) => (error ? reject(error) : resolve(data)));
      });
    } catch (cause) {
      // A file in a readable directory refuses at open, not at stat, so the
      // check has to happen at both call sites.
      if (missing(cause)) return carryOn({ kind: 'absent' });
      if (!deniedByPermissions(cause)) throw cause;
      return readPrivileged(ctx, client, host, path);
    }

    const text = asEditableText(buffer, path, host.alias);
    return text.done ? text : carryOn({ kind: 'text', text: text.value, viaSudo: false });
  };

  const readPrivileged = async (
    ctx: ServerContext,
    client: Client,
    host: ResolvedHost,
    path: string,
  ): Promise<Step<Existing>> => {
    // The host-level switch has to bind here too, or ssh_edit becomes a way
    // around it.
    if (host.sudo === 'off') {
      return stop(
        textResult(
          `${path} is not readable as ${host.user} on ${host.alias}, and sudo is switched off for that host ` +
            `in ssh-mcp.toml. Nothing was written.`,
          true,
        ),
      );
    }

    const warm = await warmSudo(ctx, client, host);
    if (warm.done) return stop(warm.result);

    const buffer = await readAsRoot(client, host.alias, path);
    if (buffer.done) return stop(buffer.result);
    if (buffer.value === 'absent') return carryOn({ kind: 'absent' });

    const text = asEditableText(buffer.value, path, host.alias);
    return text.done ? text : carryOn({ kind: 'text', text: text.value, viaSudo: true });
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
   * edit — quietly widening a 0600 config to 0644, which the approved diff says
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
   * destination's inode has to survive, or the edit silently rewrites the
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
  ): Promise<Step<void>> => {
    const temp = `/tmp/.ssh-mcp-${randomUUID()}`;
    try {
      // 0600 while it sits in /tmp, because the new content may itself be a
      // secret. Only a *created* file inherits this mode through `cp`, so only
      // a create needs it to be something a config file could sensibly have.
      await createDirectly(wrapper, temp, content, creating ? 0o644 : 0o600);

      const command = replaceAsRootCommand(temp, path);
      runtime.audit.write({ event: 'sudo', outcome: 'file-write', host: alias, command, detail: 'approved on the diff page' });

      const result = await asRoot(client, alias, command, { timeoutMs: WRITE_TIMEOUT_MS, maxBytes: 8 * 1024 });
      if (result.needsSudoPassword) {
        // Rare: the credential worked for the probe and then did not for the
        // write. The approval was consumed by the call that read it, so there
        // is nothing to resume — say plainly that nothing was written.
        return stop(
          textResult(
            `sudo on ${alias} asked for a password again before writing ${path}, so nothing was written. ` +
              `Run ssh_edit again — you will be asked for the password and then shown the diff.`,
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

  server.registerTool(
    'ssh_edit',
    {
      title: 'Edit a remote file',
      description:
        'Changes a text file on a host by replacing exact snippets of it. The user is shown a unified diff of ' +
        'the result on a page and must approve it before anything is written — so this is the way to change ' +
        'a config file, including one owned by root, which it writes through sudo. Read the file with ssh_get ' +
        'first so old_string matches it exactly. To create a file, pass a single edit with an empty old_string.',
      inputSchema: z.object({
        host: hostParameter(runtime),
        path: z.string().min(1).describe('Absolute path to the file, e.g. "/etc/postgresql/16/main/postgresql.conf".'),
        edits: z.array(editSchema).min(1).max(MAX_EDITS).describe('Applied in order, each against the result of the last.'),
      }),
      annotations: { openWorldHint: false, destructiveHint: true },
      // Deliberately NOT `anthropic/requiresUserInteraction`, for the same
      // reason ssh_sudo is not: that prompt gates the call without showing the
      // diff, so stacking it on top of the page would mean answering twice for
      // one decision, and only one of the two answers would be informed.
    },
    async ({ host: alias, path, edits }, ctx) => {
      const unlocked = await ensureUnlocked(
        ctx,
        runtime.vault,
        (payload) => runtime.mintState(payload, ctx),
        runtime.hosts.aliases(),
        capabilities,
        runtime.config.openBrowser,
      );
      if (!unlocked.ready) return unlocked.result;

      const declined = await collectSudoPassword(ctx, runtime.vault, alias);
      if (declined) return declined;

      const host = runtime.hosts.require(alias);
      const client = await runtime.pool.get(host);
      const wrapper = await sftp(client);

      const before = await readExisting(ctx, wrapper, client, host, path);
      if (before.done) return before.result;
      const existing = before.value;
      const beforeText = existing.kind === 'absent' ? '' : existing.text;

      const outcome = applyEdits(beforeText, edits as readonly Edit[], existing.kind !== 'absent');
      if (!outcome.ok) {
        runtime.audit.write({ event: 'file', outcome: `edit-rejected: ${outcome.failure.kind}`, host: alias, detail: path });
        return textResult(describeFailure(outcome.failure, edits as readonly Edit[], path), true);
      }

      const content = Buffer.from(outcome.text, 'utf8');
      if (content.length > MAX_WRITE_BYTES) {
        return textResult(`The result would be ${content.length} bytes, over the ${MAX_WRITE_BYTES} byte limit. Nothing was written.`, true);
      }

      const label = path.replace(/^\//, '');
      const diff = unifiedDiff(beforeText, outcome.text, {
        label,
        ...(existing.kind === 'absent' ? { beforeLabel: '/dev/null' } : {}),
      });
      if (diff.text === '') {
        return textResult(`Those edits leave ${path} exactly as it is. Nothing was written.`, true);
      }
      // An elided diff is not a decision. The page exists so the user can read
      // the whole change; if it will not fit, the answer is a smaller change,
      // not a smaller view of this one.
      if (diff.truncated) {
        return textResult(
          `This change touches ${diff.added + diff.removed} lines of ${path} — too many for the user to read on ` +
            `one approval page. Split it into smaller ssh_edit calls. Nothing was written.`,
          true,
        );
      }

      const direct = existing.kind === 'absent' ? false : await canWriteDirectly(wrapper, path);
      runtime.audit.write({
        event: 'file',
        outcome: 'edit-read',
        host: alias,
        detail: `${path}${existing.kind === 'text' && existing.viaSudo ? ' (read with sudo)' : ''}`,
      });

      if (!direct) {
        if (host.sudo === 'off' && existing.kind !== 'absent') {
          return textResult(
            `${path} is not writable by ${host.user} on ${alias}, and sudo is switched off for that host in ` +
              `ssh-mcp.toml. Nothing was written.`,
            true,
          );
        }
        if (host.sudo !== 'off') {
          const warm = await warmSudo(ctx, client, host);
          if (warm.done) return warm.result;
        }
      }

      const writer =
        existing.kind === 'absent'
          ? `created as ${host.user} if ${parentOf(path)} allows it, otherwise as root with sudo`
          : direct
            ? `written as ${host.user}`
            : `written as root with sudo (${host.user} cannot write it)`;

      const decision = await askForApproval({
        // Both hashes, so this answer can only ever mean this change to this
        // file. A path-only key would let an approval of one diff apply a
        // different one — and it is what makes a file that moved under the
        // approval open a fresh page instead of reusing the old answer.
        key: `edit:${alias}:${path}:${fingerprint(beforeText)}:${fingerprint(outcome.text)}`,
        title: existing.kind === 'absent' ? `Create this file on ${alias}?` : `Apply this change on ${alias}?`,
        subject: path,
        diff: diff.text,
        detail: [
          `host: ${alias} (${host.user}@${host.host})`,
          writer,
          `${edits.length} edit(s), +${diff.added} −${diff.removed} lines`,
          ...(existing.kind === 'absent' ? ['this file does not exist yet'] : []),
        ],
        // Two choices, and no "allow for this session". The reasoning that keeps
        // tee, cp and dd off every wildcard applies with more force to a file
        // write: remembering one would be remembering permission over contents
        // the model chooses. Only this diff was ever approved.
        choices: [
          { value: 'deny', label: 'Deny', hint: 'change nothing' },
          { value: 'apply', label: 'Apply', hint: 'write this change now' },
        ],
        openBrowser: runtime.config.openBrowser,
      });

      if (decision.kind === 'pending') {
        runtime.audit.write({ event: 'file', outcome: 'edit-asked', host: alias, detail: `${path} +${diff.added} −${diff.removed}` });
        return textResult(
          `This would change ${path} on ${alias}, and a page showing the diff is waiting for the user.\n\n` +
            (decision.opened
              ? `It has been opened in their browser. Ask them to answer it and say when they have, then run ` +
                `ssh_edit again with the same arguments. If no window appeared:\n\n${decision.url}`
              : `Show them this link, then run ssh_edit again with the same arguments:\n\n${decision.url}`) +
            `\n\nNothing was written.`,
          true,
        );
      }

      if (decision.choice !== 'apply') {
        runtime.audit.write({ event: 'file', outcome: 'edit-denied', host: alias, detail: path });
        return textResult(`You denied this change. ${path} on ${alias} is untouched.`, true);
      }

      // The file could have moved between the diff and the answer. Across
      // rounds the key already covers that — a changed file is a different key
      // and so a different question — but within this one nothing has looked
      // since, and a write on top of someone else's edit is exactly what the
      // diff was supposed to rule out.
      const now = await readExisting(ctx, wrapper, client, host, path);
      if (now.done) return now.result;
      const stillThere = now.value.kind === 'absent' ? '' : now.value.text;
      if (now.value.kind !== existing.kind || fingerprint(stillThere) !== fingerprint(beforeText)) {
        runtime.audit.write({ event: 'file', outcome: 'edit-changed', host: alias, detail: `${path} changed after approval` });
        return textResult(
          `${path} on ${alias} changed after the diff was approved, so nothing was written. Run ssh_edit again ` +
            `to see a diff against the file as it is now.`,
          true,
        );
      }

      // Which route the write actually took, rather than which one was
      // predicted. Saying "as root via sudo" on a reply that in fact wrote as
      // the connecting user is worse than saying nothing: it invents an owner
      // and a mode that the file does not have.
      let route: 'user' | 'sudo';
      try {
        if (existing.kind === 'absent') {
          // Only a create is decided here rather than probed. There is no
          // non-destructive way to ask SFTP whether a directory is writable,
          // and by this point the user has approved the file being made — so
          // attempting it as themselves first is the cheapest honest answer,
          // and keeps a file in their own home from arriving owned by root.
          try {
            await createDirectly(wrapper, path, content, 0o644);
            route = 'user';
          } catch (cause) {
            if (!deniedByPermissions(cause) || host.sudo === 'off') throw cause;
            const written = await writeAsRoot(wrapper, client, alias, path, content, true);
            if (written.done) {
              runtime.audit.write({ event: 'file', outcome: 'edit-failed', host: alias, detail: path });
              return written.result;
            }
            route = 'sudo';
          }
        } else if (direct) {
          await overwriteDirectly(wrapper, path, content);
          route = 'user';
        } else {
          const written = await writeAsRoot(wrapper, client, alias, path, content, false);
          if (written.done) {
            runtime.audit.write({ event: 'file', outcome: 'edit-failed', host: alias, detail: path });
            return written.result;
          }
          route = 'sudo';
        }
      } catch (cause) {
        runtime.audit.write({ event: 'file', outcome: 'edit-failed', host: alias, detail: `${path}: ${(cause as Error).message}` });
        return textResult(`Writing ${path} on ${alias} failed: ${(cause as Error).message}`, true);
      }

      runtime.vault.touch();
      runtime.audit.write({
        event: 'file',
        outcome: 'edit',
        host: alias,
        detail: `${path} +${diff.added} −${diff.removed}${route === 'sudo' ? ' (sudo)' : ''}`,
      });

      // Line counts and nothing else. The old content was read to draw a page,
      // and letting any of it back out here would undo that in one call.
      const created = existing.kind === 'absent';
      return textResult(
        `${created ? 'Created' : 'Applied'} ${edits.length} edit(s) ${created ? 'as' : 'to'} ${path} on ${alias} ` +
          `(+${diff.added} −${diff.removed} lines), ${route === 'sudo' ? 'as root via sudo' : `as ${host.user}`}.` +
          (created && route === 'sudo'
            ? ` It is a new file owned by root with mode 0644 — use ssh_sudo to chown or chmod it if that is wrong.`
            : '') +
          (!created ? ` Its owner and mode are unchanged.` : ''),
      );
    },
  );
}
