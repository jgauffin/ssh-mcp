import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { Runtime } from '../runtime.js';

export function registerVaultTools(server: McpServer, runtime: Runtime): void {
  server.registerTool(
    'ssh_status',
    {
      title: 'SSH status',
      description: 'Whether ssh-mcp is locked, and which sudo approvals are currently in force.',
      inputSchema: z.object({}),
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => ({
      content: [
        {
          type: 'text',
          text: `${runtime.vault.status()}\n\nsudo grants:\n${runtime.grants.describe()}\n\npolicy file: ${runtime.grants.policyPath}\naudit log:   ${runtime.audit.path}`,
        },
      ],
    }),
  );

  server.registerTool(
    'ssh_lock',
    {
      title: 'Lock ssh-mcp',
      description:
        'Locks ssh-mcp immediately: forgets every decrypted key, closes every connection and revokes ' +
        'all session sudo grants. The next command will ask the user to unlock again.',
      inputSchema: z.object({}),
      annotations: { openWorldHint: false, idempotentHint: true },
    },
    async () => {
      const wasLocked = runtime.vault.locked;
      runtime.vault.lock('ssh_lock');
      return {
        content: [
          {
            type: 'text',
            text: wasLocked
              ? 'ssh-mcp was already locked.'
              : 'Locked. Keys forgotten, connections closed, session sudo grants revoked.',
          },
        ],
      };
    },
  );
}
