import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { askForApproval, closeAllPages } from './gate.js';

// Stands in for the browser, so the suite can see what was put in front of the
// user without windows appearing on whoever is running it.
const { openedUrls } = vi.hoisted(() => ({ openedUrls: [] as string[] }));
vi.mock('./open-browser.js', () => ({
  openInBrowser: (url: string) => {
    openedUrls.push(url);
  },
}));

/**
 * The consent surface itself.
 *
 * The end-to-end suite cannot reach this: `ssh_edit` reads the file before it
 * asks anything, and the test hosts deliberately point at a closed port. So the
 * page a user actually decides on — the diff, the choices, the escaping — is
 * driven directly here, over real HTTP.
 */

const DIFF = [
  '--- a/etc/postgresql/16/main/postgresql.conf',
  '+++ b/etc/postgresql/16/main/postgresql.conf',
  '@@ -1,3 +1,3 @@',
  ' # tuning',
  '-shared_buffers = 128MB',
  '+shared_buffers = 4GB',
].join('\n');

const ask = (overrides: Partial<Parameters<typeof askForApproval>[0]> = {}) =>
  askForApproval({
    key: 'edit:lab:/etc/postgresql/16/main/postgresql.conf:aaaa:bbbb',
    title: 'Apply this change on lab?',
    subject: '/etc/postgresql/16/main/postgresql.conf',
    diff: DIFF,
    detail: ['host: lab (jonas@10.0.0.4)', 'written as root with sudo (jonas cannot write it)'],
    choices: [
      { value: 'deny', label: 'Deny', hint: 'change nothing' },
      { value: 'apply', label: 'Apply', hint: 'write this change now' },
    ],
    // Nothing to wait for, so the call returns the link at once.
    openBrowser: false,
    ...overrides,
  });

const linkFrom = async (overrides: Parameters<typeof ask>[0] = {}): Promise<string> => {
  const outcome = await ask(overrides);
  if (outcome.kind !== 'pending') throw new Error('expected a pending page');
  return outcome.url;
};

describe('the approval page, when the decision is about a file', () => {
  beforeEach(() => {
    closeAllPages();
    openedUrls.length = 0;
  });

  it('renders the diff with added and removed lines marked apart', async () => {
    const body = await (await fetch(await linkFrom())).text();

    expect(body).toContain('<span class="del">-shared_buffers = 128MB</span>');
    expect(body).toContain('<span class="add">+shared_buffers = 4GB</span>');
    expect(body).toContain('<span class="hunk">@@ -1,3 +1,3 @@</span>');
    expect(body).toContain('/etc/postgresql/16/main/postgresql.conf');
    expect(body).toContain('written as root with sudo');
  });

  it('escapes the file’s own content — a config is not trusted markup', async () => {
    const hostile = ['@@ -1,1 +1,1 @@', '-old', '+<script>alert(1)</script>'].join('\n');
    const body = await (await fetch(await linkFrom({ diff: hostile }))).text();

    expect(body).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(body).not.toContain('<script>alert(1)</script>');
  });

  it('offers only deny and apply — a file write is never remembered', async () => {
    const body = await (await fetch(await linkFrom())).text();

    expect(body).toContain('value="deny"');
    expect(body).toContain('value="apply"');
    expect(body).not.toContain('value="session"');
    expect(body).not.toContain('value="once"');
  });

  it('asks for no secret, because a decision is not one', async () => {
    const body = await (await fetch(await linkFrom())).text();
    expect(body).not.toContain('type="password"');
  });

  it('refuses a decision that was never offered, however it is submitted', async () => {
    const url = await linkFrom();
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ decision: 'session' }).toString(),
    });

    // Redisplayed with a complaint, not accepted as a session-wide grant.
    expect(await response.text()).toContain('is required');
  });

  it('carries an answer forward when the page was not waiting for it', async () => {
    const url = await linkFrom();
    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ decision: 'apply' }).toString(),
    });

    await expect(ask()).resolves.toEqual({ kind: 'decided', choice: 'apply' });
  });

  /**
   * The regression test for the whole key design.
   *
   * Approving one change must never stand for a different one. Because the key
   * carries the hashes of both the old and the new content, a second call with
   * a different change is a different question — a fresh page, and the earlier
   * answer left where it was.
   */
  it('does not let one approval stand for a different change to the same file', async () => {
    const first = await linkFrom();
    await fetch(first, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ decision: 'apply' }).toString(),
    });

    const otherKey = { key: 'edit:lab:/etc/postgresql/16/main/postgresql.conf:aaaa:cccc' };
    const outcome = await ask(otherKey);
    expect(outcome.kind).toBe('pending');
    expect(outcome.kind === 'pending' && outcome.url).not.toBe(first);

    // And the first answer is still there for the question it was given to.
    await expect(ask()).resolves.toEqual({ kind: 'decided', choice: 'apply' });
  });

  it('keeps the sudo page free of diff markup', async () => {
    const body = await (
      await fetch(
        await linkFrom({
          key: 'approve:lab:sudo systemctl restart nginx',
          title: 'Run this with sudo on lab?',
          subject: 'sudo systemctl restart nginx',
          diff: undefined,
        }),
      )
    ).text();

    expect(body).toContain('<pre class="subject">sudo systemctl restart nginx</pre>');
    expect(body).not.toContain('pre class="diff"');
    expect(body).not.toContain('<main class="wide">');
  });
});

/**
 * Closing the tab is the ordinary way to get a prompt wrong, and nothing over
 * HTTP can tell us it happened — the loopback listener stays up either way. So
 * a cached page looks perfectly alive while the user is looking at nothing.
 *
 * Before this, asking again did the worst possible thing: no window appeared,
 * and the call then blocked for a minute and a half waiting for an answer to a
 * question that was no longer on screen.
 */
describe('asking again after the user closed the page', () => {
  beforeEach(() => {
    closeAllPages();
    openedUrls.length = 0;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const askOpening = (overrides: Parameters<typeof ask>[0] = {}) => ask({ openBrowser: true, ...overrides });

  it('puts the same page back in front of them', async () => {
    // `openBrowser: true` makes the call block for the answer, so it is not
    // awaited here — what matters is what reached the browser.
    void askOpening();
    await vi.waitFor(() => expect(openedUrls).toHaveLength(1));

    void askOpening();
    await vi.waitFor(() => expect(openedUrls).toHaveLength(2));

    // The same live page, opened again — not a second listener for one decision.
    expect(openedUrls[1]).toBe(openedUrls[0]);
  });

  it('does not reopen a page nobody asked to see', async () => {
    await ask();
    await ask();
    expect(openedUrls).toEqual([]);
  });

  /**
   * Only `Date` is faked, so the real HTTP server and its real shutdown timer
   * keep running — the clock moves without the page actually expiring, which is
   * the only way to observe the margin from here.
   */
  it('makes a fresh page rather than reusing one about to expire', async () => {
    void askOpening();
    await vi.waitFor(() => expect(openedUrls).toHaveLength(1));

    vi.useFakeTimers({ toFake: ['Date'] });
    // Inside the three-minute life of the page, but under the reuse margin.
    vi.setSystemTime(Date.now() + 2.5 * 60 * 1000);

    void askOpening();
    await vi.waitFor(() => expect(openedUrls).toHaveLength(2));

    // A page with seconds left is a page the user cannot finish reading.
    expect(openedUrls[1]).not.toBe(openedUrls[0]);
  });
});
