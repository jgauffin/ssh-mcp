import type { McpServer, ServerContext } from '@modelcontextprotocol/server';
import type { Client, SFTPWrapper } from 'ssh2';
import { z } from 'zod';
import { hostParameter } from '../hosts/hosts.tool.js';
import type { ResolvedHost } from '../hosts/registry.js';
import type { Runtime } from '../runtime.js';
import type { SecretStore } from '../secrets/store.js';
import { askForApproval, askForSecretValues, collectSudoPassword, ensureUnlocked } from '../vault/gate.js';
import { unifiedDiff } from './diff.js';
import { applyEdits, describeFailure, type Edit } from './edits.js';
import { decodeUtf8Strict, deniedByPermissions, looksBinary, MAX_READ_BYTES, missing, sftp } from './sftp.js';
import {
  carryOn,
  MAX_WRITE_BYTES,
  oneWriterAtATime,
  parentOf,
  remoteWrites,
  shortFingerprint,
  stop,
  textResult,
  type Step,
} from './write.js';

/**
 * The only way content the model wrote reaches a file on a host.
 *
 * An earlier tool called `ssh_put` took a whole file and wrote it, which asked
 * the model for everything and the user for nothing: approving it meant
 * approving a tool name. This inverts both halves. The model supplies anchors,
 * so it cannot silently drop the parts of the file it never read; the user is
 * shown the exact `+` and `-` lines on a page they have to answer, so what they
 * consent to is the change rather than the intention behind it.
 *
 * The name is now `put.tool.ts`, and it earns it by never touching the content:
 * it copies a file from the user's own disk. The division is what each page can
 * honestly show — a diff where the model composed the bytes, a size and a hash
 * where it merely named them.
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

/**
 * Puts withheld values back into the edits, without touching the originals.
 *
 * The copy is the point. Everything said back to the model — every failure
 * message from {@linkcode describeFailure} — is built from the edits as they
 * arrived, so a mistyped anchor cannot answer with the password it did not
 * match. Only the file, the diff page and the user ever see the expanded form.
 */
export function expandAnchors(
  store: SecretStore,
  alias: string,
  edits: readonly Edit[],
): { readonly ok: true; readonly edits: Edit[] } | { readonly ok: false; readonly reason: string } {
  if (store.carriesRequest(edits.map((edit) => edit.old_string))) {
    return {
      ok: false,
      reason:
        'A generate or ask request belongs in new_string, never in old_string: it is a value that does not ' +
        'exist yet, so nothing in the file can match it.',
    };
  }

  const expanded: Edit[] = [];
  for (const edit of edits) {
    const anchor = store.expand(alias, edit.old_string);
    if (!anchor.ok) return { ok: false, reason: anchor.reason };
    const replacement = store.expand(alias, edit.new_string);
    if (!replacement.ok) return { ok: false, reason: replacement.reason };
    expanded.push({ ...edit, old_string: anchor.text, new_string: replacement.text });
  }

  return { ok: true, edits: expanded };
}

/** What was on the host before the edits, and how it had to be read. */
type Existing =
  | { readonly kind: 'absent' }
  | { readonly kind: 'text'; readonly text: string; readonly viaSudo: boolean };

export function registerEditTool(server: McpServer, runtime: Runtime): void {
  const capabilities = () => server.server.getClientCapabilities();
  const { warmSudo, readAsRoot, canWriteDirectly, land } = remoteWrites(runtime, capabilities, 'ssh_edit');

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
   * Turns the edits the model wrote into the edits that will be applied.
   *
   * Three kinds of marker meet here. A `secret` marker is a value withheld from
   * an earlier `ssh_get` and is put back. A `generate` request is a value the
   * server invents, so a rotated password is never authored in the transcript.
   * An `ask` request is one the user types on a page, for a secret that comes
   * from somewhere else entirely.
   *
   * All three are resolved before the diff is drawn, because the page has to
   * show what the file will actually contain. Approving a diff full of markers
   * would be approving a change nobody can read, which is what the old
   * whole-file write was removed for.
   */
  const resolveSecrets = async (
    alias: string,
    path: string,
    edits: readonly Edit[],
  ): Promise<Step<{ edits: Edit[]; markers: readonly string[] }>> => {
    const store = runtime.secrets;

    const anchored = expandAnchors(store, alias, edits);
    if (!anchored.ok) return stop(textResult(`${anchored.reason} Nothing was written.`, true));
    const expanded = anchored.edits;

    const replacements = expanded.map((edit) => edit.new_string);
    const asked = store.pendingAsks(alias, replacements);
    if (asked.length > 0) {
      const outcome = await askForSecretValues({
        key: `secret-values:${alias}:${asked.join(',')}`,
        title: `Values for ${alias}`,
        subject: asked.join(', '),
        detail: [`host: ${alias}`, 'typed here, never sent to the model'],
        names: asked,
        onSubmit: (values) => {
          for (const name of asked) store.remember(alias, name, values.get(name) ?? '');
        },
        openBrowser: runtime.config.openBrowser,
      });

      if (outcome.kind === 'pending') {
        runtime.audit.write({ event: 'file', outcome: 'secret-asked', host: alias, detail: asked.join(', ') });
        return stop(
          textResult(
            `This edit needs value(s) the user must type: ${asked.join(', ')}.\n\n` +
              (outcome.opened
                ? `A page has been opened in their browser. Ask them to fill it in and say when they have, then ` +
                  `run ssh_edit again with the same arguments. If no window appeared:\n\n${outcome.url}`
                : `Show them this link, then run ssh_edit again with the same arguments:\n\n${outcome.url}`) +
              `\n\nNothing was written.`,
            true,
          ),
        );
      }
    }

    // Scoped to the call, not the session: the round that draws the diff and
    // the round that applies it are the same arguments and must produce the
    // same password, while a later, different edit must get its own.
    const requested = store.resolveRequests(alias, replacements, `${path}\0${JSON.stringify(edits)}`);
    if (!requested.ok) {
      // Unreachable while `pendingAsks` and `resolveRequests` read the same
      // map, and loud anyway: the silent version writes the literal request
      // text into the file as if it were the password.
      return stop(
        textResult(`No value has been given for ${requested.missing.join(', ')} on ${alias}. Nothing was written.`, true),
      );
    }

    return carryOn({
      edits: expanded.map((edit, index) => ({ ...edit, new_string: requested.texts[index]! })),
      markers: requested.markers,
    });
  };

  server.registerTool(
    'ssh_edit',
    {
      title: 'Edit a remote file',
      description:
        'Changes a text file on a host by replacing exact snippets of it. The user is shown a unified diff of ' +
        'the result on a page and must approve it before anything is written — so this is the way to change ' +
        'a config file, including one owned by root, which it writes through sudo. Read the file with ssh_get ' +
        'first so old_string matches it exactly, and copy any {{ssh-mcp:secret:…}} marker it returned verbatim: ' +
        'the real value is put back before the file is matched and written. To set a value nobody should have ' +
        'to see, put {{ssh-mcp:generate:32}} in new_string for a random one, or {{ssh-mcp:ask:some-name}} to ' +
        'have the user type it. To create a file, pass a single edit with an empty old_string.',
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

      const host = runtime.hosts.require(alias);

      const declined = await collectSudoPassword(ctx, runtime.vault, alias, host.user, runtime.config.openBrowser);
      if (declined) return declined;

      // Markers become values here, before anything is read or matched. From
      // this line down the edits hold real secrets, and the only things that
      // may see them are the file, the diff page and the user: `edits` — the
      // marker form — is what every message back to the model is built from.
      const resolved = await resolveSecrets(alias, path, edits as readonly Edit[]);
      if (resolved.done) return resolved.result;
      const { edits: realEdits, markers } = resolved.value;

      const client = await runtime.pool.get(host);
      const wrapper = await sftp(client);

      const before = await readExisting(ctx, wrapper, client, host, path);
      if (before.done) return before.result;
      const existing = before.value;
      const beforeText = existing.kind === 'absent' ? '' : existing.text;

      const outcome = applyEdits(beforeText, realEdits, existing.kind !== 'absent');
      if (!outcome.ok) {
        runtime.audit.write({ event: 'file', outcome: `edit-rejected: ${outcome.failure.kind}`, host: alias, detail: path });
        // The marker form deliberately: `describeFailure` quotes the anchor
        // back, and the expanded one would put the secret in the transcript on
        // the one path where nobody approved anything.
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
        key: `edit:${alias}:${path}:${shortFingerprint(beforeText)}:${shortFingerprint(outcome.text)}`,
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

      // Everything from here to the write is one writer at a time, so the
      // re-read below is the last word on what the file holds. Without the
      // queue two edits approved together both re-read the old content, both
      // write, and the second quietly undoes the first while both say
      // "Applied".
      const attempt = await oneWriterAtATime(`${alias}:${path}`, async (): Promise<Step<'user' | 'sudo'>> => {
        // The file could have moved between the diff and the answer. Across
        // rounds the key already covers that — a changed file is a different
        // key and so a different question — but within this one nothing has
        // looked since, and a write on top of someone else's edit is exactly
        // what the diff was supposed to rule out.
        const now = await readExisting(ctx, wrapper, client, host, path);
        if (now.done) return stop(now.result);
        const stillThere = now.value.kind === 'absent' ? '' : now.value.text;
        if (now.value.kind !== existing.kind || shortFingerprint(stillThere) !== shortFingerprint(beforeText)) {
          runtime.audit.write({ event: 'file', outcome: 'edit-changed', host: alias, detail: `${path} changed after approval` });
          return stop(
            textResult(
              `${path} on ${alias} changed after the diff was approved, so nothing was written. Run ssh_edit again ` +
                `to see a diff against the file as it is now.`,
              true,
            ),
          );
        }

        const landed = await land(wrapper, client, host, path, content, {
          creating: existing.kind === 'absent',
          direct,
          createMode: 0o644,
        });
        if (landed.done) {
          runtime.audit.write({ event: 'file', outcome: 'edit-failed', host: alias, detail: path });
          return stop(landed.result);
        }

        return carryOn(landed.value);
      });

      if (attempt.done) return attempt.result;
      const route = attempt.value;

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
          (!created ? ` Its owner and mode are unchanged.` : '') +
          // The handle for a value that was just invented or typed. Without it
          // the second half of a rotation — telling the database about the new
          // password — would have no way to name it but to know it.
          (markers.length === 0
            ? ''
            : `\n\nThe value(s) written are held as ${markers.join(', ')} until the vault relocks. ssh_sudo ` +
              `expands them, and always asks the user to approve the command first.`),
      );
    },
  );
}
