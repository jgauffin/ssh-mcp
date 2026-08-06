import type { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import type { Runtime } from '../runtime.js';

/**
 * Prompts, not tools.
 *
 * Claude Code surfaces MCP prompts as `/mcp__<server>__<name>` slash commands,
 * so these are invoked by the user and never by the model. That distinction is
 * why teaching material belongs here rather than in a tool description: a tool
 * description that told the model to explain itself would be this server
 * steering the assistant on every call, whether or not anyone wanted it.
 */

export function registerLearnPrompts(server: McpServer, runtime: Runtime): void {
  server.registerPrompt(
    'explain',
    {
      title: 'Explain the commands you ran',
      description: 'Walk through the shell commands run over SSH in this conversation, and what each part does.',
      argsSchema: z.object({
        focus: z
          .string()
          .optional()
          .describe('Optional: a single command, tool or topic to concentrate on, e.g. "journalctl" or "systemd".'),
      }),
    },
    ({ focus }) => ({
      messages: [
        {
          role: 'user' as const,
          content: {
            type: 'text' as const,
            text:
              (focus
                ? `Focus on ${focus}. `
                : 'Go through the shell commands you have run over SSH in this conversation, in order. ') +
              'For each one:\n' +
              '- write the command out, then say in one sentence what it does\n' +
              '- explain every flag and argument individually, including the short ones\n' +
              '- name the alternative a seasoned admin might reach for instead, and why\n' +
              '- if it reads a file or queries a service, say where that lives on the filesystem\n\n' +
              'Assume I can read a shell prompt but have not used most of these tools. Do not run anything new — ' +
              'this is a review of what already happened. Be concrete about this machine rather than generic.',
          },
        },
      ],
    }),
  );

  server.registerPrompt(
    'audit',
    {
      title: 'Review the ssh-mcp audit log',
      description: 'Read the audit log and summarise what has been run, and which sudo approvals were granted.',
      argsSchema: z.object({}),
    },
    () => ({
      messages: [
        {
          role: 'user' as const,
          content: {
            type: 'text' as const,
            text:
              `Read ${runtime.audit.path} — it is JSONL, one record per line — and summarise it for me:\n` +
              '- which commands ran on which hosts, most recent first\n' +
              '- every sudo decision, and whether it was allowed once, for the session, always, or refused\n' +
              '- anything that was refused outright, and why\n' +
              `Then read ${runtime.grants.policyPath} if it exists and list the standing sudo rules in plain English, ` +
              'flagging any that look wider than they need to be.\n\n' +
              'This is a local file, so read it directly rather than over SSH.',
          },
        },
      ],
    }),
  );
}
