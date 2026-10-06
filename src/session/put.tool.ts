import type { McpServer, ServerContext } from '@modelcontextprotocol/server';
import type { Client, SFTPWrapper } from 'ssh2';
import { z } from 'zod';
import { hostParameter } from '../hosts/hosts.tool.js';
import type { ResolvedHost } from '../hosts/registry.js';
import type { Runtime } from '../runtime.js';
import { askForApproval, collectSudoPassword, ensureUnlocked } from '../vault/gate.js';
import { EXECUTABLE_BITS, readLocalFile, refusedAsCredential, refusedAsExecutable } from './local-file.js';
import { deniedByPermissions, missing, sftp } from './sftp.js';
import {
  carryOn,
  executableAsRootCommand,
  fingerprint,
  oneWriterAtATime,
  parentOf,
  READ_TIMEOUT_MS,
  remoteWrites,
  shortFingerprint,
  stop,
  textResult,
  type Step,
} from './write.js';

/**
 * Sends a file from this machine to a host, without the model holding it.
 *
 * The gap this fills is narrow and real: a certificate, a trust store, a
 * licence file. Every other route puts the bytes through the transcript —
 * `ssh_edit` is given content the model authored, and `ssh_run` cannot write a
 * file at all — so a key the model must not read could not be delivered at all.
 * Here the content goes from the user's disk to the host, and what comes back
 * is a size, a hash and a route.
 *
 * That inverts `ssh_edit`'s bargain rather than repeating it. There, the user
 * is shown a diff, because the model wrote the change and nobody else has seen
 * it. Here the bytes are the user's own and they can read them whenever they
 * like, so a diff would be ceremony; what they cannot otherwise know is *which*
 * local file is leaving, where it is going to land, and whether it arrived
 * intact. That is what the page shows, and the hash is what makes the answer
 * mean one specific set of bytes.
 *
 * An earlier tool of this name took the content as a parameter and was removed
 * for it — see the comment at the top of `edit.tool.ts`. The name is reused
 * because the thing it does is what the name always should have meant.
 */

const MODE = /^0?[0-7]{3}$/;

/** What is already at the destination, and how we found out. */
type Destination =
  | { readonly kind: 'absent' }
  | { readonly kind: 'present'; readonly size: number; readonly hash: string | undefined; readonly executable: boolean };

export function registerPutTool(server: McpServer, runtime: Runtime): void {
  const capabilities = () => server.server.getClientCapabilities();
  const { asRoot, warmSudo, readAsRoot, canWriteDirectly, land: landBytes } = remoteWrites(runtime, capabilities, 'ssh_put');

  /**
   * Whether a file we cannot stat is executable.
   *
   * Only reached when the destination's directory refuses traversal, which is
   * the one case where the mode is not already in hand. Refusing on anything
   * but a clean "no" keeps an unanswerable question from becoming a write.
   */
  const executableAsRoot = async (client: Client, alias: string, path: string): Promise<Step<boolean>> => {
    const probe = await asRoot(client, alias, executableAsRootCommand(path), { timeoutMs: READ_TIMEOUT_MS, maxBytes: 8 * 1024 });
    if (probe.needsSudoPassword || probe.timedOut) {
      return stop(textResult(`Could not check whether ${path} on ${alias} is executable, so nothing was written.`, true));
    }
    return carryOn(probe.exitCode === 0);
  };

  /**
   * What is at the destination now.
   *
   * The hash is why this reads the file at all: without it "this host already
   * holds exactly these bytes" cannot be said, and a re-run of a finished
   * upload would ask the user to approve a write that changes nothing. The
   * content never reaches the model, exactly as on `ssh_edit`'s read path — the
   * honest cost is that the model can cause a root-readable file to be read;
   * what it cannot do is see it.
   */
  const inspect = async (
    ctx: ServerContext,
    wrapper: SFTPWrapper,
    client: Client,
    host: ResolvedHost,
    path: string,
  ): Promise<Step<Destination>> => {
    let size: number;
    let executable: boolean;
    try {
      const stats = await new Promise<{ size: number; mode: number }>((resolve, reject) => {
        wrapper.stat(path, (error, value) => (error ? reject(error) : resolve({ size: value.size, mode: value.mode })));
      });
      size = stats.size;
      executable = (stats.mode & EXECUTABLE_BITS) !== 0;
    } catch (cause) {
      if (missing(cause)) return carryOn({ kind: 'absent' });
      if (!deniedByPermissions(cause)) throw cause;

      if (host.sudo === 'off') {
        return stop(
          textResult(
            `${path} on ${host.alias} cannot be examined as ${host.user}, and sudo is switched off for that host ` +
              `in ssh-mcp.toml. Nothing was written.`,
            true,
          ),
        );
      }
      const warm = await warmSudo(ctx, client, host);
      if (warm.done) return stop(warm.result);

      const bytes = await readAsRoot(client, host.alias, path);
      if (bytes.done) return stop(bytes.result);
      if (bytes.value === 'absent') return carryOn({ kind: 'absent' });

      const runs = await executableAsRoot(client, host.alias, path);
      if (runs.done) return stop(runs.result);
      return carryOn({ kind: 'present', size: bytes.value.length, hash: fingerprint(bytes.value), executable: runs.value });
    }

    // Readable or not, the mode is known by now, so an executable destination
    // is refused before anything is read.
    if (executable) return carryOn({ kind: 'present', size, hash: undefined, executable: true });

    try {
      const buffer = await new Promise<Buffer>((resolve, reject) => {
        wrapper.readFile(path, (error, data) => (error ? reject(error) : resolve(data)));
      });
      return carryOn({ kind: 'present', size: buffer.length, hash: fingerprint(buffer), executable: false });
    } catch (cause) {
      if (missing(cause)) return carryOn({ kind: 'absent' });
      if (!deniedByPermissions(cause)) throw cause;

      if (host.sudo === 'off') {
        // The size is known and the contents are not. Nothing is written
        // blind: without the hash there is no way to tell this upload from one
        // that has already happened.
        return stop(
          textResult(
            `${path} on ${host.alias} already exists and cannot be read as ${host.user}, and sudo is switched off ` +
              `for that host in ssh-mcp.toml, so there is no way to show the user what would be replaced. Nothing was written.`,
            true,
          ),
        );
      }
      const warm = await warmSudo(ctx, client, host);
      if (warm.done) return stop(warm.result);

      const bytes = await readAsRoot(client, host.alias, path);
      if (bytes.done) return stop(bytes.result);
      if (bytes.value === 'absent') return carryOn({ kind: 'absent' });
      return carryOn({ kind: 'present', size: bytes.value.length, hash: fingerprint(bytes.value), executable: false });
    }
  };

  server.registerTool(
    'ssh_put',
    {
      title: 'Send a local file to a host',
      description:
        'Copies a file from the machine this server runs on to a host, over SFTP. The contents are never read ' +
        'into this conversation: you name a local path, and the user approves the destination, the size and a ' +
        'SHA-256 of the bytes on a page before anything is written. Use it for a certificate, a trust store or ' +
        'any file whose contents you should not hold; use ssh_edit to change a file that is already on the host. ' +
        'Executables are refused, as are credential-shaped local paths such as anything under ~/.ssh. A file ' +
        'that already exists keeps its owner and mode.',
      inputSchema: z.object({
        host: hostParameter(runtime),
        local_path: z.string().min(1).describe('Path on the machine running this server, e.g. "/home/me/certs/service.crt".'),
        remote_path: z.string().min(1).describe('Absolute path on the host to write, e.g. "/etc/ssl/certs/service.crt".'),
        mode: z
          .string()
          .regex(MODE, 'an octal mode like "600" or "0644"')
          .optional()
          .describe(
            'Octal mode for a file that does not exist yet; defaults to 0600. Ignored when the file already ' +
              'exists, which keeps its own mode. No execute bit may be set.',
          ),
      }),
      annotations: { openWorldHint: false, destructiveHint: true },
      // Deliberately NOT `anthropic/requiresUserInteraction`, for the same
      // reason ssh_edit is not: that prompt gates the call without showing what
      // is in it, so stacking it on the page would mean answering twice for one
      // decision, and only one of the two answers would be informed.
    },
    async ({ host: alias, local_path: localPath, remote_path: remotePath, mode }, ctx) => {
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
      const createMode = mode === undefined ? 0o600 : Number.parseInt(mode, 8);

      // Before the file is even opened: a refusal that names the path is a
      // refusal that does not read it.
      const credential = refusedAsCredential(localPath, runtime.config.put.paths);
      if (credential !== undefined) {
        runtime.audit.write({ event: 'refused', outcome: 'put-credential', host: alias, detail: `${localPath} matches ${credential}` });
        return textResult(
          `${localPath} will not be sent: this server refuses to read local paths that look like credentials ` +
            `(it matches "${credential}"). Nothing was written. If the user wants this file on ${alias}, they can ` +
            `send it themselves with scp.`,
          true,
        );
      }

      const local = await readLocalFile(localPath);
      if (!local.ok) return textResult(`${local.reason} Nothing was written.`, true);
      const content = local.content;

      const executable = refusedAsExecutable(content, createMode);
      if (executable !== undefined) {
        runtime.audit.write({ event: 'refused', outcome: 'put-executable', host: alias, detail: `${localPath}: ${executable}` });
        return textResult(
          `${localPath} will not be sent: this server does not put executables on a host, and ${executable}. ` +
            `Nothing was written.`,
          true,
        );
      }

      const declined = await collectSudoPassword(ctx, runtime.vault, alias, host.user, runtime.config.openBrowser);
      if (declined) return declined;

      const client = await runtime.pool.get(host);
      const wrapper = await sftp(client);

      const found = await inspect(ctx, wrapper, client, host, remotePath);
      if (found.done) return found.result;
      const destination = found.value;

      if (destination.kind === 'present' && destination.executable) {
        runtime.audit.write({ event: 'refused', outcome: 'put-executable-destination', host: alias, detail: remotePath });
        return textResult(
          `${remotePath} on ${alias} is executable, and overwriting it would make these bytes a program that runs ` +
            `there. Nothing was written.`,
          true,
        );
      }

      const hash = fingerprint(content);
      const approvedHash = destination.kind === 'present' ? destination.hash : undefined;
      if (destination.kind === 'present' && destination.hash === hash) {
        return textResult(`${remotePath} on ${alias} already holds exactly these bytes (${content.length} bytes, sha256 ${hash}). Nothing was written.`);
      }

      const direct = destination.kind === 'absent' ? false : await canWriteDirectly(wrapper, remotePath);

      if (!direct) {
        if (host.sudo === 'off' && destination.kind === 'present') {
          return textResult(
            `${remotePath} is not writable by ${host.user} on ${alias}, and sudo is switched off for that host in ` +
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
        destination.kind === 'absent'
          ? `created as ${host.user} if ${parentOf(remotePath)} allows it, otherwise as root with sudo`
          : direct
            ? `written as ${host.user}`
            : `written as root with sudo (${host.user} cannot write it)`;

      const decision = await askForApproval({
        // The local hash and the destination's, for the same reason ssh_edit
        // carries both: this answer may only ever mean these bytes landing on
        // that file as it is now. A local file edited while the page was open
        // is a different key, and so a fresh page.
        key: `put:${alias}:${remotePath}:${shortFingerprint(content)}:${destination.kind === 'absent' ? 'new' : (destination.hash ?? 'unread')}`,
        title: destination.kind === 'absent' ? `Send this file to ${alias}?` : `Replace this file on ${alias}?`,
        subject: remotePath,
        detail: [
          `host: ${alias} (${host.user}@${host.host})`,
          `from: ${localPath} on this machine`,
          `${content.length} bytes, sha256 ${hash}`,
          writer,
          ...(destination.kind === 'absent'
            ? [`this file does not exist yet; it will be created with mode ${createMode.toString(8).padStart(4, '0')}`]
            : [`replaces ${destination.size} bytes (sha256 ${destination.hash}); its owner and mode are unchanged`]),
        ],
        // Two choices, and no "allow for this session", exactly as for an edit:
        // remembering one would be remembering permission to put arbitrary
        // local files on a host. Only these bytes were ever approved.
        choices: [
          { value: 'deny', label: 'Deny', hint: 'send nothing' },
          { value: 'send', label: 'Send', hint: 'write this file now' },
        ],
        openBrowser: runtime.config.openBrowser,
      });

      if (decision.kind === 'pending') {
        runtime.audit.write({ event: 'file', outcome: 'put-asked', host: alias, detail: `${localPath} → ${remotePath}` });
        return textResult(
          `This would write ${content.length} bytes to ${remotePath} on ${alias}, and a page showing where they come ` +
            `from is waiting for the user.\n\n` +
            (decision.opened
              ? `It has been opened in their browser. Ask them to answer it and say when they have, then run ` +
                `ssh_put again with the same arguments. If no window appeared:\n\n${decision.url}`
              : `Show them this link, then run ssh_put again with the same arguments:\n\n${decision.url}`) +
            `\n\nNothing was written.`,
          true,
        );
      }

      if (decision.choice !== 'send') {
        runtime.audit.write({ event: 'file', outcome: 'put-denied', host: alias, detail: `${localPath} → ${remotePath}` });
        return textResult(`You denied this. ${remotePath} on ${alias} is untouched.`, true);
      }

      const attempt = await oneWriterAtATime(`${alias}:${remotePath}`, async (): Promise<Step<'user' | 'sudo'>> => {
        // The destination could have moved between the page and the answer.
        // Across rounds the key covers that; within this one nothing has
        // looked since.
        const now = await inspect(ctx, wrapper, client, host, remotePath);
        if (now.done) return stop(now.result);
        const stillThere = now.value.kind === 'present' ? now.value.hash : undefined;
        if (now.value.kind !== destination.kind || stillThere !== approvedHash) {
          runtime.audit.write({ event: 'file', outcome: 'put-changed', host: alias, detail: `${remotePath} changed after approval` });
          return stop(
            textResult(
              `${remotePath} on ${alias} changed after the user approved this, so nothing was written. Run ssh_put ` +
                `again to approve it against the file as it is now.`,
              true,
            ),
          );
        }

        const landed = await landBytes(wrapper, client, host, remotePath, content, {
          creating: destination.kind === 'absent',
          direct,
          createMode,
        });
        if (landed.done) {
          runtime.audit.write({ event: 'file', outcome: 'put-failed', host: alias, detail: `${localPath} → ${remotePath}` });
          return stop(landed.result);
        }
        return carryOn(landed.value);
      });

      if (attempt.done) return attempt.result;
      const route = attempt.value;

      runtime.vault.touch();
      runtime.audit.write({
        event: 'file',
        outcome: 'put',
        host: alias,
        detail: `${localPath} → ${remotePath} (${content.length} bytes, sha256 ${hash})${route === 'sudo' ? ' (sudo)' : ''}`,
      });

      const created = destination.kind === 'absent';
      return textResult(
        `Wrote ${content.length} bytes to ${remotePath} on ${alias} (sha256 ${hash}), ` +
          `${route === 'sudo' ? 'as root via sudo' : `as ${host.user}`}. ` +
          (created
            ? `It is a new file with mode ${createMode.toString(8).padStart(4, '0')}${route === 'sudo' ? ', owned by root' : ''}.`
            : `Its owner and mode are unchanged.`),
      );
    },
  );
}
