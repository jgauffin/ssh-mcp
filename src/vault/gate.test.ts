import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ClientCapabilities, ServerContext } from '@modelcontextprotocol/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { askForSudoPassword, closeAllPages } from './gate.js';
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
function contextWith(envelope: Record<string, unknown> | undefined): ServerContext {
  return { mcpReq: { envelope } } as unknown as ServerContext;
}

const neverMinted = async (): Promise<string> => {
  throw new Error('requestState must not be minted on the relayed-link path');
};

function vault(): Vault {
  return new Vault([join(FIXTURES, 'id_ed25519')], 60_000);
}

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
    const urlCapable = (): ClientCapabilities => ({ elicitation: { url: {} } }) as ClientCapabilities;
    const minted = async (): Promise<string> => 'sealed-state';

    const result = await askForSudoPassword(contextWith(undefined), vault(), minted, urlCapable, false, 'vps', 'jonas');

    // The multi-round-trip shape, not a relayed link.
    expect('content' in result).toBe(false);
    expect(result).toHaveProperty('requestState', 'sealed-state');
  });
});
