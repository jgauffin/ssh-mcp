import type { CallToolResult, InputRequiredResult, McpServer, ServerContext } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { hostParameter } from '../hosts/hosts.tool.js';
import type { ResolvedHost } from '../hosts/registry.js';
import type { Runtime } from '../runtime.js';
import {
  gatePrivileged,
  gateUnprivileged,
  persistableRules,
  type SudoApproval,
  type SudoGate,
} from '../sudo/approval.js';
import { askForApproval, askForSudoPassword, collectSudoPassword, ensureUnlocked } from '../vault/gate.js';
import { exec, formatExecResult, promptLine, type ExecResult, type SudoMode } from './exec.js';

const DEFAULT_TIMEOUT_MS = 60_000;
const MAX_OUTPUT_BYTES = 64 * 1024;
const MAX_OUTPUT_LINES = 300;

const commandSchema = (runtime: Runtime) =>
  z.object({
    host: hostParameter(runtime),
    cmd: z.string().min(1).describe('The command line to run, e.g. "systemctl status nginx | tail -20".'),
    timeout_seconds: z.number().int().min(1).max(600).optional().describe('Defaults to 60.'),
  });

export function registerRunTool(server: McpServer, runtime: Runtime): void {
  /**
   * Everything after the gate is identical for both tools; only the question
   * "may this run?" differs, which is the whole point of splitting them.
   */
  const execute = async (
    ctx: ServerContext,
    alias: string,
    cmd: string,
    timeoutSeconds: number | undefined,
    gate: (host: ResolvedHost) => SudoGate | Promise<SudoGate>,
  ): Promise<{
    result: CallToolResult | InputRequiredResult;
    /**
     * The command reached the host and produced a result. False while the gate
     * refused it, and false while more input is still being collected — a
     * half-finished call must not be reported as having been allowed to run.
     */
    ran: boolean;
  }> => {
    const host = runtime.hosts.require(alias);

    const unlocked = await ensureUnlocked(
      ctx,
      runtime.vault,
      (payload) => runtime.mintState(payload, ctx),
      runtime.hosts.aliases(),
      () => server.server.getClientCapabilities(),
      runtime.config.openBrowser,
    );
    if (!unlocked.ready) return { result: unlocked.result, ran: false };

    const declined = await collectSudoPassword(ctx, runtime.vault, alias);
    if (declined) return { result: declined, ran: false };

    const verdict = await gate(host);
    if (!verdict.allowed) return { result: verdict.result, ran: false };

    const needsSudo = verdict.invocations.length > 0;
    // Echoing the command back means the conversation itself records what was
    // attempted, instead of the reader having to trust a bare tool name. It goes
    // on the failures too — a command that could not even connect is exactly
    // when you want to see what it was.
    const echo = promptLine(host.user, alias, cmd);

    // Explicitly tagged rather than probed with `in`: `CallToolResult` carries an
    // index signature, so a structural check would not narrow it.
    type Attempt = { kind: 'ran'; exec: ExecResult } | { kind: 'unreachable'; result: CallToolResult };

    const runOnce = async (): Promise<Attempt> => {
      const cached = runtime.vault.sudoPasswordFor(alias);
      const sudo: SudoMode = !needsSudo
        ? { kind: 'none' }
        : cached
          ? { kind: 'password', password: cached }
          : { kind: 'noninteractive' };

      try {
        const client = await runtime.pool.get(host);
        return {
          kind: 'ran',
          exec: await exec(client, cmd, {
            timeoutMs: (timeoutSeconds ?? DEFAULT_TIMEOUT_MS / 1000) * 1000,
            maxBytes: MAX_OUTPUT_BYTES,
            maxLines: MAX_OUTPUT_LINES,
            sudo,
          }),
        };
      } catch (cause) {
        const message = (cause as Error).message;
        runtime.audit.write({ event: 'run', outcome: 'failed', host: alias, command: cmd, detail: message });
        return { kind: 'unreachable', result: { content: [{ type: 'text', text: `${echo}\n${message}` }], isError: true } };
      }
    };

    let attempt = await runOnce();
    if (attempt.kind === 'unreachable') return { result: attempt.result, ran: true };

    // The host wants a password for sudo — either none was sent, or the one
    // that was is stale. Sudo refused, so the privileged command did not run
    // and collecting a password to try again repeats no side effect. The one
    // exception is a line holding several sudos where an earlier one got
    // through; that is why the preamble authenticates once, up front, rather
    // than letting each sudo discover the problem for itself.
    if (attempt.exec.needsSudoPassword) {
      runtime.audit.write({ event: 'sudo', outcome: 'password-required', host: alias, command: cmd });
      const pending = await askForSudoPassword(
        ctx,
        runtime.vault,
        (payload) => runtime.mintState(payload, ctx),
        () => server.server.getClientCapabilities(),
        runtime.config.openBrowser,
        alias,
        host.user,
      );
      // A result means the password is still being collected; `undefined` means
      // the user typed it while we waited, so the command can go now.
      if (pending) return { result: pending, ran: false };

      attempt = await runOnce();
      if (attempt.kind === 'unreachable') return { result: attempt.result, ran: true };
    }

    const finished = attempt.exec;
    runtime.vault.touch();
    runtime.audit.write({
      event: 'run',
      outcome: finished.timedOut ? 'timeout' : `exit ${finished.exitCode ?? '?'}`,
      host: alias,
      command: cmd,
    });

    return {
      result: {
        content: [{ type: 'text', text: `${echo}\n${formatExecResult(finished)}` }],
        isError: finished.timedOut || (finished.exitCode !== 0 && finished.exitCode !== null),
      },
      ran: true,
    };
  };

  server.registerTool(
    'ssh_run',
    {
      title: 'Run a command over SSH',
      description:
        'Runs a shell command on a configured host and returns its output as plain text, the way a terminal ' +
        'would show it. Pipelines work; redirecting onto a file outside /tmp does not, and neither do in-place ' +
        'editors like sed -i or tee — use ssh_edit, which shows the user a diff first. Commands using sudo run ' +
        'only if an approval rule already covers them, otherwise use ssh_sudo, which asks the user first.',
      inputSchema: commandSchema(runtime),
      annotations: { openWorldHint: false },
      // Opt-in: makes Claude Code show its permission dialog — which contains the
      // full command — before every single run, in any permission mode.
      ...(runtime.config.confirmEveryCommand
        ? { _meta: { 'anthropic/requiresUserInteraction': true } }
        : {}),
    },
    async ({ host: alias, cmd, timeout_seconds }, ctx) =>
      (
        await execute(ctx, alias, cmd, timeout_seconds, (host) =>
          gateUnprivileged({
            alias,
            hostSudo: host.sudo,
            command: cmd,
            grants: runtime.grants,
            sessionTtlMs: runtime.vault.idleTimeoutMs,
            policyPath: runtime.grants.policyPath,
            guardFileWrites: host.fileWrites !== 'off',
            record: (outcome, detail) =>
              runtime.audit.write({ event: 'sudo', outcome, host: alias, command: cmd, detail }),
          }),
        )
      ).result,
  );

  server.registerTool(
    'ssh_sudo',
    {
      title: 'Run a privileged command over SSH',
      description:
        'Runs a command that needs sudo. The user is shown the exact command on a page and must approve it ' +
        'before anything runs. They can allow it for the session, in which case repeating that same command ' +
        'later does not ask again. Use ssh_run for anything that does not need sudo, and ssh_edit to change a ' +
        'file — this tool refuses in-place edits, because the page can show the command but not its effect.',
      inputSchema: commandSchema(runtime),
      annotations: { openWorldHint: false, destructiveHint: true },
      // Deliberately NOT `anthropic/requiresUserInteraction`. That prompt gates
      // the call but does not show what is in it, so it asks the user to approve
      // a tool name rather than a command — and stacking it on top of the
      // approval page would mean answering twice for one decision. The page is
      // the gate: it shows the command verbatim, and nothing but a person with a
      // browser can answer it.
    },
    async ({ host: alias, cmd, timeout_seconds }, ctx) => {
      const { result, ran } = await execute(ctx, alias, cmd, timeout_seconds, (host) =>
        gatePrivileged({
          alias,
          hostSudo: host.sudo,
          command: cmd,
          grants: runtime.grants,
          sessionTtlMs: runtime.vault.idleTimeoutMs,
          policyPath: runtime.grants.policyPath,
          guardFileWrites: host.fileWrites !== 'off',
          record: (outcome, detail) => runtime.audit.write({ event: 'sudo', outcome, host: alias, command: cmd, detail }),
          approve: async (eligibility) => {
            const outcome = await askForApproval({
              // Keyed by host and command, so two different commands cannot
              // share a page and have one answer stand for both.
              key: `approve:${alias}:${cmd}`,
              title: `Run this with sudo on ${alias}?`,
              subject: cmd,
              detail: [
                `host: ${alias} (${host.user}@${host.host})`,
                eligibility.extras.length > 0 ? `shell extras: ${eligibility.extras.join(' ')}` : 'shell extras: none',
                ...(eligibility.notGrantableBecause ? [`cannot be remembered: ${eligibility.notGrantableBecause}`] : []),
              ],
              choices: [
                { value: 'deny', label: 'Deny', hint: 'run nothing' },
                { value: 'once', label: 'Allow once', hint: 'this command, right now' },
                ...(eligibility.grantable
                  ? [
                      {
                        value: 'session',
                        label: 'Allow for this session',
                        hint: 'this exact command, until ssh-mcp relocks',
                      },
                    ]
                  : []),
              ],
              openBrowser: runtime.config.openBrowser,
            });

            if (outcome.kind === 'decided') return outcome.choice as SudoApproval;
            return {
              pending: {
                content: [
                  {
                    type: 'text',
                    text:
                      `This needs sudo on ${alias}, and an approval page is waiting for the user.\n\n` +
                      (outcome.opened
                        ? `It has been opened in their browser. Ask them to answer it and say when they have, ` +
                          `then run the command again. If no window appeared:\n\n${outcome.url}`
                        : `Show them this link, then run the command again:\n\n${outcome.url}`) +
                      `\n\nNothing was run.`,
                  },
                ],
                isError: true,
              },
            };
          },
        }),
      );

      // The session grant is made at the gate, so the note belongs on anything
      // that got past it — including a command that then failed to connect.
      // Only once it has actually run: saying "allowed for this session" on a
      // reply that is still asking for a password reads as though it went ahead.
      const rules = ran ? persistableRules(alias, cmd) : undefined;
      if (rules && 'content' in result) {
        const content = result.content as Array<{ type: string; text?: string }>;
        const last = content[content.length - 1];
        if (last?.type === 'text') {
          last.text =
            `${last.text}\n— allowed for this session. To make it permanent, add a line to ` +
            `${runtime.grants.policyPath}:\n    ${rules.exact}` +
            (rules.wider.length > 0 ? `\n  or wider:\n${rules.wider.map((rule) => `    ${rule}`).join('\n')}` : '');
        }
      }
      return result;
    },
  );
}
