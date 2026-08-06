import type { McpServer, ServerContext } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { hostParameter } from '../hosts/hosts.tool.js';
import type { Runtime } from '../runtime.js';
import { ensureUnlocked } from '../vault/gate.js';
import { decodeUtf8Strict, looksBinary, MAX_READ_BYTES, sftp } from './sftp.js';

/**
 * SFTP for the everyday read-only cases: list a directory, read a config file.
 * Both run as the connecting user, with no sudo path at all.
 *
 * Writing is not here. It is `ssh_edit`, which reads the file first, shows the
 * user a unified diff of what would change, and only then writes — escalating
 * to sudo when the connecting user cannot.
 */

export function registerFileTools(server: McpServer, runtime: Runtime): void {
  const host = () => hostParameter(runtime);

  const unlock = async (ctx: ServerContext) =>
    ensureUnlocked(
      ctx,
      runtime.vault,
      (payload) => runtime.mintState(payload, ctx),
      runtime.hosts.aliases(),
      () => server.server.getClientCapabilities(),
      runtime.config.openBrowser,
    );

  server.registerTool(
    'ssh_ls',
    {
      title: 'List a remote directory',
      description: 'Lists a directory over SFTP, in `ls -l` form.',
      inputSchema: z.object({ host: host(), path: z.string().min(1) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ host: alias, path }, ctx) => {
      const gate = await unlock(ctx);
      if (!gate.ready) return gate.result;

      const target = runtime.hosts.require(alias);
      const client = await runtime.pool.get(target);
      const wrapper = await sftp(client);

      const entries = await new Promise<string>((resolve, reject) => {
        wrapper.readdir(path, (error, list) =>
          error ? reject(error) : resolve(list.map((entry) => entry.longname).join('\n')),
        );
      });

      runtime.vault.touch();
      runtime.audit.write({ event: 'file', outcome: 'ls', host: alias, detail: path });
      return { content: [{ type: 'text', text: entries === '' ? '(empty directory)' : entries }] };
    },
  );

  server.registerTool(
    'ssh_get',
    {
      title: 'Read a remote file',
      description: `Reads a text file over SFTP. Files larger than ${MAX_READ_BYTES / 1024} KiB and binary files are refused.`,
      inputSchema: z.object({ host: host(), path: z.string().min(1) }),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ host: alias, path }, ctx) => {
      const gate = await unlock(ctx);
      if (!gate.ready) return gate.result;

      const target = runtime.hosts.require(alias);
      const client = await runtime.pool.get(target);
      const wrapper = await sftp(client);

      const size = await new Promise<number>((resolve, reject) => {
        wrapper.stat(path, (error, stats) => (error ? reject(error) : resolve(stats.size)));
      });
      if (size > MAX_READ_BYTES) {
        return {
          content: [{ type: 'text', text: `${path} is ${size} bytes, over the ${MAX_READ_BYTES} byte limit. Use ssh_run with head/tail instead.` }],
          isError: true,
        };
      }

      const buffer = await new Promise<Buffer>((resolve, reject) => {
        wrapper.readFile(path, (error, data) => (error ? reject(error) : resolve(data)));
      });
      if (looksBinary(buffer)) {
        return { content: [{ type: 'text', text: `${path} looks binary; this tool only reads text.` }], isError: true };
      }

      // Not `toString('utf8')`: that silently substitutes U+FFFD, and handing
      // the model a mangled config it might then try to edit is worse than
      // saying plainly that this file is not UTF-8.
      const text = decodeUtf8Strict(buffer);
      if (text === undefined) {
        return { content: [{ type: 'text', text: `${path} is not valid UTF-8; this tool only reads UTF-8 text.` }], isError: true };
      }

      runtime.vault.touch();
      runtime.audit.write({ event: 'file', outcome: 'get', host: alias, detail: path });
      return { content: [{ type: 'text', text }] };
    },
  );
}
