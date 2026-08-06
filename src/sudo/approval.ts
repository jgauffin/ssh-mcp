import type { CallToolResult } from '@modelcontextprotocol/server';
import { classify } from './denylist.js';
import type { SudoGrants } from './grants.js';
import { formatPattern, proposePatterns } from './matcher.js';
import { parseCommandLine, sudoInvocations, type SudoInvocation } from './parse.js';
import { detectFileWrite, type FileWrite } from './writes.js';

/**
 * The sudo gate, in two halves.
 *
 * The original design asked with form-mode elicitation. That does not work in
 * Claude Code, which declares form support and then answers `decline` in under
 * ten milliseconds without rendering anything — a refusal the user never saw.
 * Rather than keep asking through a channel that does not arrive, consent now
 * rests on the client's own permission prompt, which demonstrably does:
 *
 * - `ssh_run` permits sudo only when a stored rule already covers it, so
 *   routine approved work is silent.
 * - `ssh_sudo` is marked `anthropic/requiresUserInteraction`, so Claude Code
 *   shows its permission prompt — with the command in it — on every call. On
 *   success the exact command is granted for the session, so the second use of
 *   it flows through `ssh_run` without a prompt.
 *
 * The denylist and the shell-segment analysis still run here, server-side,
 * after that prompt. Approving `sudo -s` in a client dialog does not make it
 * allowed.
 */

export type SudoGate =
  | { readonly allowed: true; readonly invocations: readonly SudoInvocation[] }
  | { readonly allowed: false; readonly result: CallToolResult };

export interface SudoGateOptions {
  readonly alias: string;
  readonly hostSudo: 'off' | 'ask';
  readonly command: string;
  readonly grants: SudoGrants;
  readonly sessionTtlMs: number;
  readonly policyPath: string;
  /** False when this host has file-write guarding switched off in ssh-mcp.toml. */
  readonly guardFileWrites: boolean;
  /** Called when a decision is made, for the audit log. */
  readonly record: (outcome: string, detail: string) => void;
}

function textResult(text: string, isError = false): CallToolResult {
  return { content: [{ type: 'text', text }], isError };
}

export interface Eligibility {
  readonly invocations: readonly SudoInvocation[];
  /** Refusals that no approval can override. */
  readonly denied: { readonly command: string; readonly reason: string } | undefined;
  /** Whether a stored rule may ever cover this line. */
  readonly grantable: boolean;
  /** Why it may not be, when it may not be. */
  readonly notGrantableBecause: string | undefined;
  /** Separators and expansions found outside quotes. */
  readonly extras: readonly string[];
  /**
   * A write that would change a file nobody has seen a diff of.
   *
   * Kept out of `denied` on purpose. `denied` means "not consentable by anyone",
   * and `hardRefusal` says so in as many words; a file edit *is* consentable —
   * that is what `ssh_edit` is for. This is a routing rule, and it needs
   * different wording in each tool.
   */
  readonly fileWrite: FileWrite | undefined;
}

/**
 * The whole "may this be remembered?" decision, with no protocol around it.
 *
 * A stored rule may only ever match a single plain command: one segment, no
 * pipes, no redirects, no expansions, and nothing on the ungrantable list. So
 * a grant for `systemctl restart *` can never be satisfied by
 * `sudo systemctl restart nginx; whoami` — that line is approved every time.
 */
export function assess(command: string): Eligibility {
  const parsed = parseCommandLine(command);
  const invocations = sudoInvocations(parsed);
  const extras = [...parsed.separators, ...parsed.expansions];
  const fileWrite = detectFileWrite(parsed);

  for (const invocation of invocations) {
    const verdict = classify(invocation);
    if (verdict.kind === 'denied') {
      return {
        invocations,
        denied: { command: invocation.segment.text, reason: verdict.reason },
        grantable: false,
        notGrantableBecause: verdict.reason,
        extras,
        fileWrite,
      };
    }
  }

  const ungrantable = invocations
    .map((invocation) => classify(invocation))
    .find((verdict) => verdict.kind === 'ungrantable');

  let notGrantableBecause: string | undefined;
  if (!parsed.simple) notGrantableBecause = `the line contains ${extras.join(' ')}`;
  else if (ungrantable && ungrantable.kind === 'ungrantable') notGrantableBecause = ungrantable.reason;
  else if (invocations.length > 1) notGrantableBecause = 'the line runs sudo more than once';

  return {
    invocations,
    denied: undefined,
    grantable: invocations.length > 0 && notGrantableBecause === undefined,
    notGrantableBecause,
    extras,
    fileWrite,
  };
}

/**
 * Why a file write is refused, and what to do instead.
 *
 * The refusal deliberately says nothing about the per-host switch that could
 * turn this guard off. Naming it in a message the model reads would be handing
 * prompt injection a script for talking someone into disabling it; a person who
 * wants it will find it in the ReadMe.
 */
function writeRefusal(tool: 'ssh_run' | 'ssh_sudo', write: FileWrite): string {
  const backup = write.reason === 'replaces it' ? ' If you are taking a backup, copy it somewhere under /tmp.' : '';

  if (tool === 'ssh_run') {
    return (
      `ssh_run does not write files. \`${write.command}\` ${write.reason}, and ${write.target} would change ` +
      `with nobody seeing what changed.\n\n` +
      `Use ssh_edit for this. It reads the file, applies the edit, and shows the user a unified diff on a page ` +
      `they have to approve before anything is written — including files owned by root.${backup}\n\nNothing was run.`
    );
  }

  return (
    `ssh_sudo does not write files, even with approval. \`${write.command}\` ${write.reason}, and the approval ` +
    `page can only show the command — never what ${write.target} would end up containing. Approving that is ` +
    `approving something you cannot see.\n\n` +
    `Use ssh_edit for this. It shows the user a unified diff of the exact change, and writes through sudo only ` +
    `after they approve it.${backup}\n\nNothing was run.`
  );
}

/**
 * The write check, shared by both gates.
 *
 * Runs after the denylist — `sudo -s > /etc/foo` is a root shell first and a
 * file write second — and before anything is offered for approval, because the
 * whole point is that no page is ever shown for a change nobody can read.
 */
function writeRefusalFor(
  tool: 'ssh_run' | 'ssh_sudo',
  options: SudoGateOptions,
  eligibility: Eligibility,
): CallToolResult | undefined {
  const { fileWrite } = eligibility;
  if (!fileWrite) return undefined;

  if (!options.guardFileWrites) {
    options.record('allowed', `file write, guard off for this host: ${fileWrite.target}`);
    return undefined;
  }

  options.record('refused', `file write: ${fileWrite.target}`);
  return textResult(writeRefusal(tool, fileWrite), true);
}

/** Shared first pass: the refusals that apply however consent was obtained. */
function hardRefusal(options: SudoGateOptions, eligibility: Eligibility): CallToolResult | undefined {
  if (options.hostSudo === 'off') {
    options.record('refused', 'sudo is off for this host');
    return textResult(`sudo is switched off for ${options.alias} in ssh-mcp.toml. Nothing was run.`, true);
  }

  const { denied } = eligibility;
  if (denied) {
    options.record('refused', `denylist: ${denied.reason}`);
    return textResult(
      `Refused: \`${denied.command}\` — ${denied.reason}. This is never permitted, whoever approves it. ` +
        `Nothing was run.`,
      true,
    );
  }

  return undefined;
}

/**
 * The `ssh_run` gate: no sudo, ever.
 *
 * Not "no sudo unless a rule covers it" — a tool that sometimes runs privileged
 * commands is a tool you cannot reason about at a glance. Everything privileged
 * goes through `ssh_sudo`, where the user sees it.
 */
export function gateUnprivileged(options: SudoGateOptions): SudoGate {
  const eligibility = assess(options.command);
  const { invocations } = eligibility;

  // `hardRefusal` only ever speaks about sudo, so a line without any still runs
  // on a host where sudo is switched off.
  if (invocations.length > 0) {
    const refusal = hardRefusal(options, eligibility);
    if (refusal) return { allowed: false, result: refusal };
  }

  // Unlike the sudo checks, this one looks at the whole line: `echo x > /etc/foo`
  // needs no sudo at all, and used to be the widest gap in the consent model.
  const write = writeRefusalFor('ssh_run', options, eligibility);
  if (write) return { allowed: false, result: write };

  if (invocations.length === 0) return { allowed: true, invocations };

  options.record('refused', 'sudo belongs to ssh_sudo');
  return {
    allowed: false,
    result: textResult(
      `ssh_run never runs sudo. Use the ssh_sudo tool for this command — it shows the user the exact command ` +
        `and waits for them to approve it.\n\nNothing was run.`,
      true,
    ),
  };
}

export type SudoApproval = 'deny' | 'once' | 'session';

/**
 * The `ssh_sudo` gate.
 *
 * A stored rule means the user has already agreed to this exact command, so it
 * runs without interrupting them. Anything else needs `approve` to put it in
 * front of them — and whatever they answer, the denylist still governs.
 */
export async function gatePrivileged(
  options: SudoGateOptions & {
    /** Shows the command to the user and returns what they chose. */
    readonly approve: (eligibility: Eligibility) => Promise<SudoApproval | { readonly pending: CallToolResult }>;
  },
): Promise<SudoGate> {
  const eligibility = assess(options.command);
  const { invocations, grantable } = eligibility;

  if (invocations.length > 0) {
    const refusal = hardRefusal(options, eligibility);
    if (refusal) return { allowed: false, result: refusal };
  }

  // Before `approve`, always: a change nobody can read must not be offered for
  // approval at all, however the page words the question.
  const write = writeRefusalFor('ssh_sudo', options, eligibility);
  if (write) return { allowed: false, result: write };

  if (invocations.length === 0) {
    options.record('allowed', 'no sudo in the command');
    return { allowed: true, invocations };
  }

  if (grantable) {
    const grant = options.grants.find(options.alias, invocations[0]!.argv);
    if (grant) {
      options.record('allowed', `grant ${grant.host} ${formatPattern(grant.pattern)}`);
      return { allowed: true, invocations };
    }
  }

  const decision = await options.approve(eligibility);
  if (typeof decision !== 'string') {
    options.record('asked', 'waiting for approval');
    return { allowed: false, result: decision.pending };
  }

  if (decision === 'deny') {
    options.record('denied', 'user denied at the approval page');
    return { allowed: false, result: textResult('You denied this command. Nothing was run.', true) };
  }

  if (decision === 'session' && grantable) {
    const grant = options.grants.grantForSession(options.alias, invocations[0]!.argv, options.sessionTtlMs);
    options.record('allowed', `approved, granted for the session: ${formatPattern(grant.pattern)}`);
  } else {
    options.record('allowed', 'approved once');
  }

  return { allowed: true, invocations };
}

/**
 * The rules that would make a command permanent: the exact one first, then
 * progressively wider, so the choice of width stays the user's and is made with
 * the alternatives in front of them.
 *
 * `undefined` when nothing about the command can safely be stored.
 */
export function persistableRules(alias: string, command: string): { exact: string; wider: string[] } | undefined {
  const { invocations, grantable } = assess(command);
  if (!grantable || invocations.length === 0) return undefined;

  const [exact, ...wider] = proposePatterns(invocations[0]!.argv).map((pattern) => `${alias}\t${formatPattern(pattern)}`);
  return { exact: exact!, wider };
}
