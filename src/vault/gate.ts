import { randomUUID } from 'node:crypto';
import {
  CLIENT_CAPABILITIES_META_KEY,
  inputRequired,
  inputResponse,
  type CallToolResult,
  type ClientCapabilities,
  type InputRequiredResult,
  type ServerContext,
} from '@modelcontextprotocol/server';
import { openInBrowser } from './open-browser.js';
import { openUnlockPage, type SecretField, type UnlockPage, type UnlockPageOptions } from './unlock-page.js';
import type { Vault } from './vault.js';

/**
 * Bridges the vault to the protocol's multi-round-trip flow.
 *
 * A tool handler cannot block waiting for a human, so it returns
 * `inputRequired(...)` with an embedded URL elicitation and is re-entered by
 * the client — same arguments, plus whatever the user did. The loopback page
 * that actually collects the secret outlives that return, so it is parked here
 * and correlated by an id carried in the signed `requestState`.
 */

const PAGE_TIMEOUT_MS = 3 * 60 * 1000;
/** How long a re-entered round waits for the browser POST that is almost certainly already in flight. */
const SETTLE_TIMEOUT_MS = 5_000;
/**
 * How long a call will block while the user fills in a page we just opened for
 * them.
 *
 * Blocking is the whole point: it turns "here is a link, now ask me again" into
 * one seamless call. Claude Code allows it — stdio servers have no per-request
 * timer and the tool-call limit defaults to about 28 hours — but a
 * main-conversation call still moves to a background task after two minutes, so
 * this stays comfortably under that and falls back to relaying the link.
 */
const WAIT_FOR_SUBMIT_MS = 100_000;

export interface RoundState {
  readonly pageId?: string;
  /** When a dialog was requested, so an impossibly fast answer can be recognised. */
  readonly askedAt?: number;
}

/**
 * Below this, no human read the question.
 *
 * A client that cannot render an elicitation answers `decline` immediately, and
 * the server would otherwise report that as "the user declined" — a refusal
 * nobody was ever offered. Observed auto-declines come back in 7–14 ms; a person
 * who has actually read a sudo prompt takes orders of magnitude longer.
 */
export const IMPLAUSIBLY_FAST_MS = 400;

/** True when an answer came back too fast for anyone to have seen the question. */
export function answeredWithoutBeingAsked(askedAt: number | undefined): boolean {
  return askedAt !== undefined && Date.now() - askedAt < IMPLAUSIBLY_FAST_MS;
}

export type GateResult = { readonly ready: true } | { readonly ready: false; readonly result: CallToolResult | InputRequiredResult };

export type MintState = (payload: RoundState) => Promise<string>;

/**
 * Reads the calling client's capabilities as declared on the *2025-era*
 * connection. On 2026-07-28 they arrive per request in the `_meta` envelope
 * instead, and `Server.getClientCapabilities()` is `undefined` there — so the
 * envelope is consulted first and this is only the legacy fallback.
 */
export type Capabilities = () => ClientCapabilities | undefined;

type ElicitationCapability = { url?: unknown; form?: unknown } | undefined;

function declaredElicitation(ctx: ServerContext, fallback: Capabilities): ElicitationCapability {
  const fromEnvelope = (ctx.mcpReq.envelope as Record<string, unknown> | undefined)?.[CLIENT_CAPABILITIES_META_KEY];
  const capabilities = (fromEnvelope as ClientCapabilities | undefined) ?? fallback();
  // The wire type is deliberately loose (clients may add sub-modes); we only
  // care whether `url` and `form` are present.
  return capabilities?.elicitation as ElicitationCapability;
}

/**
 * Why this client cannot be shown a native URL prompt, or `undefined` if it can.
 *
 * URL mode is the only channel through which this server will accept a secret,
 * so a client offering form mode alone is not downgraded to a form — that is
 * precisely the shortcut this design exists to refuse. It is not a dead end
 * either: see {@linkcode manualUnlockUrl}.
 */
function urlElicitationUnavailable(ctx: ServerContext, capabilities: Capabilities, secret: string): string | undefined {
  const elicitation = declaredElicitation(ctx, capabilities);

  if (!elicitation) {
    return 'this client did not declare support for elicitation';
  }

  // Named URL mode is the only thing that counts as URL mode. Anything else is
  // a protocol error the moment the round is returned: the SDK refuses to send
  // a request the client never said it could receive.
  if (elicitation.url !== undefined) {
    return undefined;
  }

  if (elicitation.form !== undefined) {
    return (
      `this client supports form-mode elicitation but not URL mode, and ${secret} will not be collected ` +
      "through a form — form answers travel back through the client and into the model's context"
    );
  }

  // `elicitation: {}` — the capability, with neither sub-mode named. What
  // Claude Code declares, and what made the first command after a restart fail
  // with a capability error instead of asking for the passphrase.
  return 'this client declared elicitation but named no sub-mode, so it cannot be shown a URL prompt';
}

/**
 * The fallback when the client cannot show a native prompt: open the page
 * anyway and let the model relay the link in its reply.
 *
 * Putting the URL in a tool result does place it in the model's context, which
 * is acceptable in a way the passphrase never is. It is a single-use nonce for
 * a loopback listener with a two-minute life, and all it grants is the ability
 * to *submit* a passphrase that the holder still does not know.
 *
 * The page unlocks the vault directly on submit, so no round-trip state is
 * needed — the user's next command simply finds it open.
 */
const manualPages = new Map<string, { page: UnlockPage; expiresAt: number; opened: boolean }>();

/**
 * How much life a cached page must have left to be worth reusing.
 *
 * Reusing one with ten seconds on it is worse than making a new one: the user
 * gets a window they cannot finish reading, and the submit fails on a listener
 * that has already shut down.
 */
const PAGE_REUSE_MARGIN_MS = 45_000;

/**
 * Opens (or reuses) a page for one secret and hands back its link, keyed so the
 * passphrase and a per-host sudo password do not collide.
 *
 * Reuse re-opens the browser. Closing a tab does not close the loopback
 * listener — nothing over HTTP can tell us it happened — so a cached page looks
 * perfectly alive while the user is looking at nothing. Without this, dismissing
 * a prompt and asking again did the one thing it must not: appeared to do
 * nothing at all, then blocked for a minute and a half waiting for an answer to
 * a question no longer on screen.
 */
async function manualSecretPage(
  key: string,
  form: Omit<UnlockPageOptions, 'timeoutMs' | 'onSubmit'>,
  onSubmit: (values: Map<string, string>) => Promise<string | undefined>,
  openBrowser: boolean,
): Promise<{ page: UnlockPage; opened: boolean }> {
  const live = manualPages.get(key);
  if (live && live.expiresAt - PAGE_REUSE_MARGIN_MS > Date.now()) {
    if (openBrowser) openInBrowser(live.page.url);
    return { page: live.page, opened: openBrowser };
  }
  // Too near its deadline to be useful. Shut the old listener down rather than
  // leaving a second one able to accept the same secret.
  if (live) {
    live.page.close();
    manualPages.delete(key);
  }

  const page = await openUnlockPage({ ...form, timeoutMs: PAGE_TIMEOUT_MS, onSubmit });
  if (openBrowser) openInBrowser(page.url);
  manualPages.set(key, { page, expiresAt: Date.now() + PAGE_TIMEOUT_MS, opened: openBrowser });
  void page.accepted.then(() => manualPages.delete(key));

  return { page, opened: openBrowser };
}

/**
 * Opens a page and, when we were able to put it in front of the user, waits for
 * them to finish with it. Resolves `true` once the secret has been accepted.
 *
 * Waiting only makes sense when the browser actually opened; if all we can do is
 * print a link, the user has not seen it yet and there is nothing to wait for.
 */
async function collectNow(
  key: string,
  form: Omit<UnlockPageOptions, 'timeoutMs' | 'onSubmit'>,
  onSubmit: (values: Map<string, string>) => Promise<string | undefined>,
  openBrowser: boolean,
): Promise<{ accepted: boolean; url: string; opened: boolean }> {
  const { page, opened } = await manualSecretPage(key, form, onSubmit, openBrowser);
  const accepted = opened ? ((await settledWithin(page.accepted, WAIT_FOR_SUBMIT_MS)) ?? false) : false;
  return { accepted, url: page.url, opened };
}

function closeManualPages(): void {
  for (const { page } of manualPages.values()) page.close();
  manualPages.clear();
}

export interface ApprovalChoice {
  readonly value: string;
  readonly label: string;
  readonly hint?: string;
}

export type ApprovalOutcome =
  | { readonly kind: 'decided'; readonly choice: string }
  | { readonly kind: 'pending'; readonly url: string; readonly opened: boolean };

/**
 * Puts a decision in front of the user on a page, and waits for it.
 *
 * The client's own permission prompt gates the *call*, but does not reliably
 * show what is in it — approving a tool name is not approving a command. This
 * page shows the command verbatim and cannot be answered by anything but a
 * person with a browser.
 */
/**
 * Decisions submitted while nothing was waiting for them.
 *
 * The call only blocks when the page was opened in front of the user, and even
 * then only for a while. Without this, an answer given after the wait expired —
 * or with `open-browser = false`, where there is no wait at all — would be
 * dropped and the user asked the same question again.
 */
const decisions = new Map<string, { choice: string; at: number }>();
const DECISION_TTL_MS = 10 * 60 * 1000;

function takeDecision(key: string): string | undefined {
  const held = decisions.get(key);
  if (!held) return undefined;
  decisions.delete(key);
  return Date.now() - held.at < DECISION_TTL_MS ? held.choice : undefined;
}

export async function askForApproval(options: {
  /**
   * What the answer will be taken to mean.
   *
   * Load-bearing: a decision submitted while nothing was waiting is parked
   * under this key and consumed by the *next* call that uses it, so anything a
   * separate answer should be required for has to be in here. `ssh_edit` puts
   * the hashes of both the old and the new file content in it for that reason.
   */
  readonly key: string;
  readonly title: string;
  readonly subject: string;
  /** A unified diff to show under the subject, when the decision is about a file. */
  readonly diff?: string;
  readonly detail: readonly string[];
  readonly choices: readonly ApprovalChoice[];
  readonly openBrowser: boolean;
}): Promise<ApprovalOutcome> {
  // An answer given since we last looked counts, however late it arrived.
  const already = takeDecision(options.key);
  if (already !== undefined) return { kind: 'decided', choice: already };

  const { page, opened } = await manualSecretPage(
    options.key,
    {
      title: options.title,
      detail: [...options.detail],
      fields: [],
      choices: [{ name: 'decision', label: 'Decision', options: [...options.choices] }],
      submitLabel: 'Confirm',
      subject: options.subject,
      // Conditional rather than `diff: options.diff`: `exactOptionalPropertyTypes`
      // makes a present-but-undefined property a different thing from an absent one.
      ...(options.diff === undefined ? {} : { diff: options.diff }),
    },
    async (values) => {
      decisions.set(options.key, { choice: values.get('decision')!, at: Date.now() });
      return undefined;
    },
    options.openBrowser,
  );

  if (opened && (await settledWithin(page.accepted, WAIT_FOR_SUBMIT_MS))) {
    const choice = takeDecision(options.key);
    if (choice !== undefined) return { kind: 'decided', choice };
  }
  return { kind: 'pending', url: page.url, opened };
}

/** Wording shared by every relayed-link message, so they read the same way. */
function relayed(what: string, url: string, opened: boolean): string {
  return (
    `${what}\n\n` +
    (opened
      ? `A page has been opened in the user's browser. Ask them to fill it in and say when it is done, then ` +
        `run the command again. If no window appeared, the link is:\n\n${url}`
      : `Show the user this link and ask them to fill it in, then run the command again:\n\n${url}`) +
    `\n\nIt expires in two minutes. Nothing was run.`
  );
}

const pendingPages = new Map<string, UnlockPage>();

function park(page: UnlockPage): string {
  const id = randomUUID();
  pendingPages.set(id, page);
  return id;
}

function collect(id: string | undefined): UnlockPage | undefined {
  if (!id) return undefined;
  const page = pendingPages.get(id);
  if (page) pendingPages.delete(id);
  return page;
}

/** Abandons every open page — used when the vault relocks or the process exits. */
export function closeAllPages(): void {
  for (const page of pendingPages.values()) page.close();
  pendingPages.clear();
  closeManualPages();
  // Relocking revokes approvals, so an unconsumed decision must not outlive it.
  decisions.clear();
}

async function settledWithin<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
  let timer: NodeJS.Timeout;
  const timeout = new Promise<undefined>((resolve) => {
    timer = setTimeout(() => resolve(undefined), ms);
    timer.unref();
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

function textResult(text: string, isError = false): CallToolResult {
  return { content: [{ type: 'text', text }], isError };
}

/** The passphrase form, shared by the native and the relayed-link paths. */
function unlockForm(hostAliases: readonly string[]): { title: string; detail: string[]; fields: SecretField[] } {
  return {
    title: 'Unlock ssh-mcp',
    detail: [`hosts: ${hostAliases.join(', ')}`],
    fields: [{ name: 'passphrase', label: 'Key passphrase' }],
  };
}

/** Consumes a submitted passphrase; the returned message is shown on the page. */
async function unlockWith(vault: Vault, values: Map<string, string>): Promise<string | undefined> {
  const outcome = await vault.unlock(values.get('passphrase') ?? '');
  return outcome.unlocked ? undefined : outcome.summary;
}

interface SecretRoundOptions {
  readonly key: string;
  readonly message: string;
  readonly title: string;
  readonly detail: readonly string[];
  readonly fields: readonly SecretField[];
  readonly onSubmit: (values: Map<string, string>) => Promise<string | undefined>;
}

/** Opens a fresh page and returns the input-required round that points the user at it. */
async function askForSecret(options: SecretRoundOptions, mintState: MintState): Promise<InputRequiredResult> {
  const page = await openUnlockPage({
    title: options.title,
    detail: options.detail,
    fields: options.fields,
    timeoutMs: PAGE_TIMEOUT_MS,
    onSubmit: options.onSubmit,
  });
  const pageId = park(page);
  return inputRequired({
    inputRequests: {
      [options.key]: inputRequired.elicitUrl({ message: options.message, url: page.url }),
    },
    // `askedAt` is signed with the rest, so an implausibly fast answer can be
    // recognised as the client answering rather than the user.
    requestState: await mintState({ pageId, askedAt: Date.now() }),
  });
}

/**
 * Makes sure the vault is unlocked, or returns the round that asks the user to
 * unlock it. Call this at the top of every tool that touches SSH.
 */
export async function ensureUnlocked(
  ctx: ServerContext,
  vault: Vault,
  mintState: MintState,
  hostAliases: readonly string[],
  capabilities: Capabilities,
  openBrowser: boolean,
): Promise<GateResult> {
  if (!vault.locked) {
    vault.touch();
    return { ready: true };
  }

  const noNativePrompt = urlElicitationUnavailable(ctx, capabilities, 'a key passphrase');
  if (noNativePrompt) {
    const { accepted, url, opened } = await collectNow(
      'unlock',
      unlockForm(hostAliases),
      (values) => unlockWith(vault, values),
      openBrowser,
    );
    // The page unlocked the vault itself, so the command can simply continue.
    if (accepted) {
      vault.touch();
      return { ready: true };
    }
    return { ready: false, result: textResult(relayed('ssh-mcp is locked.', url, opened), true) };
  }

  const state = ctx.mcpReq.requestState<RoundState>();
  const page = collect(state?.pageId);

  if (page) {
    const response = inputResponse(ctx.mcpReq.inputResponses, 'unlock');
    if (response.kind === 'elicit' && response.action !== 'accept') {
      page.close();

      // A refusal that arrives in milliseconds came from the client, not the
      // user. Fall back to relaying the link rather than reporting a decline
      // nobody made.
      if (answeredWithoutBeingAsked(state?.askedAt)) {
        const { accepted, url, opened } = await collectNow(
          'unlock',
          unlockForm(hostAliases),
          (values) => unlockWith(vault, values),
          openBrowser,
        );
        if (accepted) {
          vault.touch();
          return { ready: true };
        }
        return {
          ready: false,
          result: textResult(
            relayed('ssh-mcp is locked, and this client dismissed the unlock prompt without showing it.', url, opened),
            true,
          ),
        };
      }

      return { ready: false, result: textResult('Unlock declined. ssh-mcp stays locked and no command was run.', true) };
    }

    // The page unlocked the vault itself, so a wrong passphrase was already
    // reported in the browser and the user could retry there.
    const wasAccepted = await settledWithin(page.accepted, SETTLE_TIMEOUT_MS);
    if (!wasAccepted) {
      page.close();
      return {
        ready: false,
        result: textResult(
          'The unlock page was not completed, so ssh-mcp stays locked. Ask the user to retry the command.',
          true,
        ),
      };
    }

    vault.touch();
    return { ready: true };
  }

  return {
    ready: false,
    result: await askForSecret(
      {
        key: 'unlock',
        message: 'ssh-mcp is locked. Open this page to enter your key passphrase — it is never sent to the model.',
        ...unlockForm(hostAliases),
        onSubmit: (values) => unlockWith(vault, values),
      },
      mintState,
    ),
  };
}

/**
 * Picks up a sudo password the user submitted in the previous round.
 *
 * Returns `undefined` when there is nothing to collect or the collection
 * succeeded — either way the caller carries on. A result means the user
 * declined or never submitted, and that result is what the tool returns.
 *
 * A page id surviving `ensureUnlocked` can only be a sudo-password page: the
 * unlock flow consumes its own id, and only leaves one behind when the vault
 * was already open.
 */
export async function collectSudoPassword(ctx: ServerContext, vault: Vault, alias: string): Promise<CallToolResult | undefined> {
  const page = collect(ctx.mcpReq.requestState<RoundState>()?.pageId);
  if (!page) return undefined;

  const response = inputResponse(ctx.mcpReq.inputResponses, 'sudo-password');
  if (response.kind === 'elicit' && response.action !== 'accept') {
    page.close();
    return textResult(`Declined. No sudo password for ${alias}, so nothing was run.`, true);
  }

  const wasAccepted = await settledWithin(page.accepted, SETTLE_TIMEOUT_MS);
  if (!wasAccepted) {
    page.close();
    return textResult(`The sudo password page for ${alias} was not completed, so nothing was run.`, true);
  }

  return undefined;
}

/**
 * Asks for a remote sudo password out of band, exactly as the passphrase is
 * asked for. Only reached when a host actually refuses `sudo -n`.
 */
export async function askForSudoPassword(
  ctx: ServerContext,
  vault: Vault,
  mintState: MintState,
  capabilities: Capabilities,
  openBrowser: boolean,
  alias: string,
  user: string,
): Promise<CallToolResult | InputRequiredResult | undefined> {
  const form = {
    title: `sudo password for ${alias}`,
    detail: [`host: ${alias}`, `remote user: ${user}`],
    fields: [{ name: 'sudo-password', label: `Password for ${user} on ${alias}` }],
  };
  const onSubmit = async (values: Map<string, string>): Promise<undefined> => {
    vault.setSudoPassword(alias, values.get('sudo-password') ?? '');
    return undefined;
  };

  // Same reasoning as the passphrase: a client without URL-mode elicitation gets
  // the link relayed rather than an error. Asking through a form is not an
  // option — this is a password.
  const noNativePrompt = urlElicitationUnavailable(ctx, capabilities, `${user}'s password`);
  if (noNativePrompt) {
    const { accepted, url, opened } = await collectNow(`sudo:${alias}`, form, onSubmit, openBrowser);
    // `undefined` means the password is in hand and the caller should carry on.
    if (accepted) return undefined;
    return textResult(
      relayed(`${alias} asks for a password before it will run sudo, and ${noNativePrompt}.`, url, opened),
      true,
    );
  }

  return askForSecret(
    {
      key: 'sudo-password',
      message: `${alias} asks for a password before running sudo. Open this page to enter it — it is never sent to the model.`,
      ...form,
      onSubmit,
    },
    mintState,
  );
}
