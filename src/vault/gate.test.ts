import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CallToolResult, ClientCapabilities, ServerContext } from '@modelcontextprotocol/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { askForSudoPassword, closeAllPages, collectSudoPassword, ensureUnlocked, type RoundState } from './gate.js';
import { Vault } from './vault.js';

// Stands in for the browser, so the suite can see which page was opened without
// windows appearing on whoever is running it.
const { openedUrls } = vi.hoisted(() => ({ openedUrls: [] as string[] }));
vi.mock('./open-browser.js', () => ({
  openInBrowser: (url: string) => {
    openedUrls.push(url);
  },
}));

/**
 * A direct test of the secret-request fallback.
 *
 * The end-to-end suite cannot reach this branch: it needs a reachable SSH host
 * whose sudo demands a password, and the test hosts deliberately point at a
 * closed port. So the path that threw in production
 * (`Cannot request input 'sudo-password' (elicitation/create): the client on
 * this 2025-era connection did not declare the required capability`) is covered
 * here instead, where the inputs can be dictated.
 */

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

/** The minimum of a request context these functions actually read. */
function contextWith(envelope: Record<string, unknown> | undefined, signal = new AbortController().signal): ServerContext {
  return { mcpReq: { envelope, signal } } as unknown as ServerContext;
}

/** The page link inside a relayed message or an input-required round. */
function linkIn(result: unknown): string {
  return /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(JSON.stringify(result))![0];
}

const neverMinted = async (): Promise<string> => {
  throw new Error('requestState must not be minted on the relayed-link path');
};

function vault(): Vault {
  return new Vault([join(FIXTURES, 'id_ed25519')], 60_000);
}

describe('ensureUnlocked', () => {
  const formOnly = (): ClientCapabilities => ({ elicitation: { form: {} } }) as ClientCapabilities;
  const textOf = (result: CallToolResult): string => result.content.map((block) => ('text' in block ? block.text : '')).join('');

  beforeEach(() => {
    closeAllPages();
    openedUrls.length = 0;
  });

  it('asks for consent, with nothing to type, when no key is encrypted', async () => {
    const store = new Vault([join(FIXTURES, 'id_ed25519_plain')], 60_000);
    const gate = await ensureUnlocked(contextWith(undefined), store, neverMinted, ['vps'], formOnly, false);

    expect(gate.ready).toBe(false);
    expect(store.locked).toBe(true);
    const url = linkIn((gate as { result: unknown }).result);
    const body = await (await fetch(url)).text();
    expect(body).toContain('nothing to type');
    expect(body).not.toContain('type="password"');

    await fetch(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: '' });
    expect(store.locked).toBe(false);
  });

  it('opens with no page when no key is encrypted and the click is waived', async () => {
    const store = new Vault([join(FIXTURES, 'id_ed25519_plain')], 60_000, false);
    const gate = await ensureUnlocked(contextWith(undefined), store, neverMinted, ['vps'], formOnly, false);

    expect(gate.ready).toBe(true);
    expect(store.locked).toBe(false);
  });

  it('still asks for the passphrase when the click is waived', async () => {
    const store = new Vault([join(FIXTURES, 'id_ed25519_plain'), join(FIXTURES, 'id_ed25519')], 60_000, false);
    const gate = await ensureUnlocked(contextWith(undefined), store, neverMinted, ['vps'], formOnly, false);

    expect(gate.ready).toBe(false);
    const body = await (await fetch(linkIn((gate as { result: unknown }).result))).text();
    expect(body).toContain('type="password"');
  });

  it.each([
    ['an encrypted key', ['id_ed25519']],
    ['encrypted and unencrypted keys', ['id_ed25519_plain', 'id_ed25519']],
  ])('asks for the passphrase on a page given %s', async (_, names) => {
    const store = new Vault(names.map((name) => join(FIXTURES, name)), 60_000);
    const gate = await ensureUnlocked(contextWith(undefined), store, neverMinted, ['vps'], formOnly, false);

    expect(gate.ready).toBe(false);
    const body = await (await fetch(linkIn((gate as { result: unknown }).result))).text();
    expect(body).toContain('type="password"');
    expect(store.locked).toBe(true);
  });

  it('reports a key that cannot be read instead of asking for a passphrase', async () => {
    const store = new Vault([join(FIXTURES, 'nope')], 60_000);
    const gate = await ensureUnlocked(contextWith(undefined), store, neverMinted, ['vps'], formOnly, false);

    expect(gate.ready).toBe(false);
    const text = textOf((gate as { result: CallToolResult }).result);
    expect(text).toContain('cannot read key file');
    expect(text).not.toMatch(/\/unlock\//);
  });
});

describe('askForSudoPassword', () => {
  const formOnly = (): ClientCapabilities => ({ elicitation: { form: {} } }) as ClientCapabilities;

  // Pages are cached per secret for the life of the process, and each one holds
  // a closure over the vault it was made for. One vault per process makes that
  // correct in production; across tests it leaks, so start each one clean.
  beforeEach(() => {
    closeAllPages();
    openedUrls.length = 0;
  });

  it('relays a link instead of throwing when the client has no URL elicitation', async () => {
    const result = await askForSudoPassword(contextWith(undefined), vault(), neverMinted, formOnly, false, 'vps', 'jonas');

    // A CallToolResult, not an input-required round and not an exception.
    expect('content' in result).toBe(true);
    const text = (result as { content: Array<{ text?: string }> }).content.map((block) => block.text).join('');
    expect(text).toMatch(/http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/);
    expect(text).toContain('asks for a password before it will run sudo');
    expect(text).not.toContain('did not declare the required capability');
  });

  it('names the host and remote user, so the user knows what they are typing for', async () => {
    const result = await askForSudoPassword(contextWith(undefined), vault(), neverMinted, formOnly, false, 'vps', 'jonas');
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(
      (result as { content: Array<{ text?: string }> }).content.map((block) => block.text).join(''),
    )![0];

    const body = await (await fetch(url)).text();
    expect(body).toContain('sudo password for vps');
    expect(body).toContain('jonas');
    expect(body).toContain('type="password"');
  });

  it('feeds the submitted password into the vault, not into the reply', async () => {
    const store = vault();
    const result = await askForSudoPassword(contextWith(undefined), store, neverMinted, formOnly, false, 'vps', 'jonas');
    const text = (result as { content: Array<{ text?: string }> }).content.map((block) => block.text).join('');
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(text)![0];

    expect(store.sudoPasswordFor('vps')).toBeUndefined();
    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ 'sudo-password': 'hunter2' }).toString(),
    });

    expect(store.sudoPasswordFor('vps')?.toString()).toBe('hunter2');
    // The secret reached the vault by a route that never touched the result.
    expect(text).not.toContain('hunter2');
  });

  it('reuses one page per host rather than opening one per attempt', async () => {
    const store = vault();
    const link = async (alias: string): Promise<string> => {
      const result = await askForSudoPassword(contextWith(undefined), store, neverMinted, formOnly, false, alias, 'jonas');
      const text = (result as { content: Array<{ text?: string }> }).content.map((block) => block.text).join('');
      return /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(text)![0];
    };

    expect(await link('vps')).toBe(await link('vps'));
    // A different host is a different secret, so it gets its own page.
    expect(await link('other')).not.toBe(await link('vps'));
  });

  /**
   * The difference between "here is a link, now ask me again" and one seamless
   * call. When the page was put in front of the user, the call blocks until they
   * finish with it and then returns `undefined`, meaning "carry on".
   *
   * Claude Code permits the block: stdio servers have no per-request timer, the
   * tool-call limit defaults to about 28 hours, and only calls running past two
   * minutes move to a background task.
   */
  it('waits for the user and then signals carry-on, when the browser was opened', async () => {
    const store = vault();
    const pending = askForSudoPassword(contextWith(undefined), store, neverMinted, formOnly, true, 'vps', 'jonas');

    // Wait for the page to come up, then act as the user filling it in.
    for (let attempt = 0; attempt < 100 && openedUrls.length === 0; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    expect(openedUrls[0], 'the page should have been opened in a browser').toBeDefined();
    await fetch(openedUrls[0]!, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ 'sudo-password': 'hunter2' }).toString(),
    });

    // `undefined` is the signal that the caller may go ahead — no second round.
    await expect(pending).resolves.toBeUndefined();
    expect(store.sudoPasswordFor('vps')?.toString()).toBe('hunter2');
  }, 20_000);

  it('falls back to relaying the link if the user never fills the page in', async () => {
    // No browser was opened, so there is nothing to wait on and the link must
    // come back immediately rather than blocking for a minute and a half.
    const started = Date.now();
    const result = await askForSudoPassword(contextWith(undefined), vault(), neverMinted, formOnly, false, 'vps', 'jonas');

    expect(Date.now() - started).toBeLessThan(5_000);
    expect(result).toBeDefined();
    expect('content' in result!).toBe(true);
  });

  it('uses a native URL elicitation when the client does declare one', async () => {
    const minted = async (): Promise<string> => 'sealed-state';

    const result = await askForSudoPassword(contextWith(undefined), vault(), minted, urlCapable, false, 'vps', 'jonas');

    // The multi-round-trip shape, not a relayed link.
    expect('content' in result).toBe(false);
    expect(result).toHaveProperty('requestState', 'sealed-state');
  });

  /**
   * Two commands on one host at once both meet sudo's refusal. Each used to
   * hand the client a page of its own, and the second arrived as a new window
   * the moment the user submitted the first.
   */
  it('waits on the page already asking for this password instead of opening another', async () => {
    const store = vault();
    const minted = async (): Promise<string> => 'sealed-state';
    const first = await askForSudoPassword(contextWith(undefined), store, minted, urlCapable, false, 'vps', 'jonas');

    const second = askForSudoPassword(contextWith(undefined), store, minted, urlCapable, false, 'vps', 'jonas');
    await fetch(linkIn(first), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ 'sudo-password': 'hunter2' }).toString(),
    });

    // Answered by the first page: no round of its own, so nothing new to open.
    await expect(second).resolves.toBeUndefined();
    expect(store.sudoPasswordFor('vps')?.toString()).toBe('hunter2');
  }, 20_000);

  it('asks afresh once the client gives up on the call that opened the page', async () => {
    const minted = async (): Promise<string> => 'sealed-state';
    const abandoned = new AbortController();
    const first = await askForSudoPassword(contextWith(undefined, abandoned.signal), vault(), minted, urlCapable, false, 'vps', 'jonas');

    abandoned.abort();
    // The abandoned page may never have been shown, so waiting on it would be
    // waiting on nothing. Its link is dead, and the next call gets a page of its own.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect((await fetch(linkIn(first))).status).toBe(404);

    const second = await askForSudoPassword(contextWith(undefined), vault(), minted, urlCapable, false, 'vps', 'jonas');
    expect(second).toHaveProperty('requestState', 'sealed-state');
    expect(linkIn(second)).not.toBe(linkIn(first));
  });
});

const urlCapable = (): ClientCapabilities => ({ elicitation: { url: {} } }) as ClientCapabilities;

describe('collectSudoPassword', () => {
  beforeEach(() => {
    closeAllPages();
    openedUrls.length = 0;
  });

  /** The round that `askForSudoPassword` parked, as the next call would see it. */
  async function afterAsking(store: Vault): Promise<RoundState> {
    let round: RoundState | undefined;
    const minted = async (payload: RoundState): Promise<string> => {
      round = payload;
      return 'sealed-state';
    };
    await askForSudoPassword(contextWith(undefined), store, minted, urlCapable, false, 'vps', 'jonas');
    return round!;
  }

  /** A re-entered round carrying the client's answer to the sudo-password prompt. */
  function roundWith(state: RoundState, action: 'decline' | 'cancel' | 'accept'): ServerContext {
    return {
      mcpReq: {
        envelope: undefined,
        requestState: () => state,
        inputResponses: { 'sudo-password': { action } },
      },
    } as unknown as ServerContext;
  }

  function textOf(result: CallToolResult | undefined): string {
    return ((result?.content ?? []) as Array<{ text?: string }>).map((block) => block.text).join('');
  }

  it('opens the page itself when the client declines the prompt without showing it', async () => {
    const store = vault();
    const asked = await afterAsking(store);

    const result = await collectSudoPassword(roundWith(asked, 'decline'), store, 'vps', 'jonas', false);

    // A refusal here would leave nothing able to ask for the password at all.
    const text = textOf(result);
    expect(text).not.toContain('Declined');
    expect(text).toMatch(/http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/);
    expect(text).toContain('dismissed the prompt without showing it');
  });

  it('reports a decline the user had time to make', async () => {
    const store = vault();
    const asked = await afterAsking(store);
    const readAndRefused: RoundState = { ...asked, askedAt: Date.now() - 30_000 };

    const result = await collectSudoPassword(roundWith(readAndRefused, 'decline'), store, 'vps', 'jonas', false);

    expect(textOf(result)).toContain(`Declined. No sudo password for vps`);
  });
});
