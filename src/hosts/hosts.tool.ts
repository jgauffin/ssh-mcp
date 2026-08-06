import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { Runtime } from '../runtime.js';
import { formatHosts } from './registry.js';

/**
 * The alias list is published two ways: as a tool, and as the enum of every
 * `host` parameter in this server. The enum is the load-bearing one — a host
 * that is not in the config is not merely rejected, it is unrepresentable.
 */

/** The `host` parameter, shared by every tool that reaches a machine. */
export function hostParameter(runtime: Runtime): z.ZodEnum<Record<string, string>> {
  const aliases = runtime.hosts.aliases();
  return z.enum(aliases as [string, ...string[]]).describe('Host alias from this server\'s configuration.');
}

export function registerHostTools(server: McpServer, runtime: Runtime): void {
  const listing = (): string =>
    `${formatHosts(runtime.hosts.all())}\n\nUse the alias in the first column as the "host" argument.`;

  server.registerTool(
    'ssh_hosts',
    {
      title: 'List SSH hosts',
      description:
        'Lists the hosts this server may connect to. These aliases are the only possible targets — ' +
        'no tool accepts a hostname, user, port or key path.',
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => ({ content: [{ type: 'text', text: listing() }] }),
  );

  server.registerResource(
    'hosts',
    'ssh://hosts',
    { title: 'SSH hosts', description: 'The hosts ssh-mcp may connect to.', mimeType: 'text/plain' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'text/plain', text: listing() }] }),
  );
}
