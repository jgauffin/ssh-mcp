import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { DEFAULT_PAGE_PORT } from '../config/config.js';

/**
 * A single-use page on 127.0.0.1 for asking the user something directly.
 *
 * It started as a way to collect a passphrase, because the MCP specification
 * forbids asking for secrets through form-mode elicitation: those values travel
 * back through the client, and therefore through the model's context. It now
 * carries the sudo approval too, for a plainer reason — it is the only surface
 * here that reliably renders, and the only one that can guarantee the user sees
 * the exact command they are approving. A consent dialog nobody sees is not
 * consent.
 *
 * Honest scope: this is not a defence against local malware. A process running
 * as you can already read your key files. What it does buy, completely, is that
 * the passphrase never enters the MCP protocol, the transcript, or the model's
 * context.
 *
 * Every page in a process shares one listener on one port. Not for efficiency —
 * for the browser. Chrome's "never save this password" list is keyed on origin,
 * and an origin includes the port, so a fresh port per page meant being asked to
 * save the passphrase forever, once per page. One stable port makes that a
 * single click. The pages stay single-use regardless: each is reachable only at
 * its own nonce path, and that path stops existing the moment it is done with.
 */

export interface SecretField {
  readonly name: string;
  readonly label: string;
}

export interface ChoiceOption {
  readonly value: string;
  readonly label: string;
  readonly hint?: string;
}

/** A decision to make, rendered as radio buttons. Never used for secrets. */
export interface ChoiceField {
  readonly name: string;
  readonly label: string;
  readonly options: readonly ChoiceOption[];
  readonly value?: string;
}

export interface UnlockPageOptions {
  readonly title: string;
  /** Lines describing exactly what is at stake, shown above the form. */
  readonly detail: readonly string[];
  readonly fields: readonly SecretField[];
  readonly choices?: readonly ChoiceField[];
  /** Text on the submit button. Defaults to "Unlock". */
  readonly submitLabel?: string;
  /** Shown fixed-width above the form — the command, or the path, being approved. */
  readonly subject?: string;
  /**
   * A unified diff, rendered below the subject with `+`/`-` lines coloured.
   *
   * Kept apart from `subject` rather than folded into it: the subject is the
   * one line saying what this is about, and a file edit needs both — the path
   * and the change. They also want different typography, and the sudo page
   * should not inherit diff styling it has no use for.
   */
  readonly diff?: string;
  readonly timeoutMs: number;
  /**
   * Consumes the submitted values. Return an error message to reject the
   * submission — the form is redisplayed with it and the page stays open — or
   * `undefined` to accept.
   *
   * The secret is handed straight to this callback and never stored on the
   * page, and because the browser waits for it, a wrong passphrase is reported
   * where the user is actually looking instead of coming back as "Done".
   */
  onSubmit: (values: Map<string, string>) => Promise<string | undefined>;
}

export interface UnlockPage {
  readonly url: string;
  /** Resolves `true` once a submission was accepted, `false` on timeout or close. */
  readonly accepted: Promise<boolean>;
  close(): void;
}

const MAX_BODY_BYTES = 8 * 1024;

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) =>
    char === '&' ? '&amp;' : char === '<' ? '&lt;' : char === '>' ? '&gt;' : char === '"' ? '&quot;' : '&#39;',
  );
}

function formPage(options: UnlockPageOptions, path: string, error?: string): string {
  const detail = options.detail.map((line) => `<li>${escapeHtml(line)}</li>`).join('');
  const banner = error ? `<p class="error">${escapeHtml(error)}</p>` : '';
  const inputs = options.fields
    .map(
      (field, index) => `
      <label for="f${index}">${escapeHtml(field.label)}</label>
      <input id="f${index}" name="${escapeHtml(field.name)}" type="password" autocomplete="off"
             spellcheck="false" required ${index === 0 ? 'autofocus' : ''}>`,
    )
    .join('');

  // The command being approved, verbatim and unmissable. This is the whole
  // reason the approval moved onto a page.
  const subject = options.subject ? `<pre class="subject">${escapeHtml(options.subject)}</pre>` : '';

  // The change being approved, line by line. Only the class name is chosen by
  // the server, and only from a closed set; every byte of the line itself still
  // goes through escapeHtml. That matters more here than anywhere else on this
  // page — a diff is content out of a file the model asked to read, so it is
  // exactly the place someone would put a `<script>`.
  const diffLine = (line: string): string => {
    const kind = line.startsWith('@@')
      ? 'hunk'
      : line.startsWith('+++') || line.startsWith('---') || line.startsWith('\\') || line.startsWith('…')
        ? 'meta'
        : line.startsWith('+')
          ? 'add'
          : line.startsWith('-')
            ? 'del'
            : 'ctx';
    return `<span class="${kind}">${escapeHtml(line)}</span>`;
  };
  // Joined with nothing, not with a newline: the spans are display:block inside
  // a pre, so a newline between them would double-space the whole diff.
  const diff = options.diff ? `<pre class="diff">${options.diff.split('\n').map(diffLine).join('')}</pre>` : '';

  const choices = (options.choices ?? [])
    .map(
      (choice) => `
      <fieldset>
        <legend>${escapeHtml(choice.label)}</legend>
        ${choice.options
          .map(
            (option, index) => `
        <label class="opt"><input type="radio" name="${escapeHtml(choice.name)}" value="${escapeHtml(option.value)}"
               ${(choice.value ?? choice.options[0]?.value) === option.value ? 'checked' : ''}
               ${index === 0 ? 'autofocus' : ''}>
          <span><strong>${escapeHtml(option.label)}</strong>${
            option.hint ? `<em>${escapeHtml(option.hint)}</em>` : ''
          }</span></label>`,
          )
          .join('')}
      </fieldset>`,
    )
    .join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(options.title)}</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fafafa; --card:#fff; --line:#dcdcdc; --muted:#555; --accent:#2f6f4f; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e8e8e8; --bg:#161616; --card:#1f1f1f; --line:#333; --muted:#aaa; --accent:#4f9d75; }
  }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg); color:var(--fg);
         font:15px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; padding:2rem 1rem; }
  main { width:100%; max-width:30rem; background:var(--card); border:1px solid var(--line); border-radius:10px; padding:1.75rem; }
  h1 { margin:0 0 .25rem; font-size:1.15rem; }
  p.sub { margin:0 0 1.25rem; color:var(--muted); font-size:.9rem; }
  ul { margin:0 0 1.25rem; padding-left:1.1rem; color:var(--muted); font-size:.875rem; }
  li { margin:.15rem 0; font-family:ui-monospace, SFMono-Regular, Consolas, monospace; }
  label { display:block; margin:.75rem 0 .3rem; font-size:.85rem; font-weight:600; }
  input { width:100%; padding:.6rem .7rem; font-size:1rem; border:1px solid var(--line); border-radius:6px;
          background:var(--bg); color:var(--fg); }
  button { margin-top:1.25rem; width:100%; padding:.65rem; font-size:1rem; font-weight:600; border:0; border-radius:6px;
           background:var(--accent); color:#fff; cursor:pointer; }
  footer { margin-top:1rem; font-size:.78rem; color:var(--muted); }
  p.error { margin:0 0 1rem; padding:.6rem .7rem; border-radius:6px; font-size:.875rem;
            background:color-mix(in srgb, #c0392b 15%, transparent); border:1px solid #c0392b; }
  pre.subject { margin:0 0 1.25rem; padding:.75rem .85rem; border:1px solid var(--line); border-radius:6px;
                background:var(--bg); font:13px/1.5 ui-monospace, SFMono-Regular, Consolas, monospace;
                white-space:pre-wrap; word-break:break-all; }
  fieldset { margin:0; padding:0; border:0; }
  legend { padding:0; margin:0 0 .5rem; font-size:.85rem; font-weight:600; }
  label.opt { display:flex; gap:.6rem; align-items:flex-start; margin:0; padding:.5rem .6rem; font-weight:400;
              border:1px solid var(--line); border-radius:6px; margin-bottom:.4rem; cursor:pointer; }
  label.opt:has(input:checked) { border-color:var(--accent); background:color-mix(in srgb, var(--accent) 10%, transparent); }
  label.opt input { width:auto; margin-top:.25rem; }
  label.opt em { display:block; font-style:normal; font-size:.8rem; color:var(--muted); }
  main.wide { max-width:52rem; }
  pre.diff { margin:0 0 1.25rem; padding:.5rem 0; border:1px solid var(--line); border-radius:6px;
             background:var(--bg); font:12.5px/1.45 ui-monospace, SFMono-Regular, Consolas, monospace;
             white-space:pre-wrap; overflow-wrap:anywhere; max-height:30rem; overflow:auto; }
  pre.diff span { display:block; padding:0 .85rem; }
  pre.diff .add { background:color-mix(in srgb, #2f9e44 18%, transparent); }
  pre.diff .del { background:color-mix(in srgb, #c0392b 16%, transparent); }
  pre.diff .hunk { color:var(--muted); background:color-mix(in srgb, var(--fg) 7%, transparent); }
  pre.diff .meta { color:var(--muted); }
</style></head>
<body><main${options.diff ? ' class="wide"' : ''}>
  <h1>${escapeHtml(options.title)}</h1>
  <p class="sub">Requested by ssh-mcp on this machine.</p>
  ${banner}
  ${subject}
  ${diff}
  <ul>${detail}</ul>
  <form method="post" action="${path}">${inputs}${choices}
    <button type="submit">${escapeHtml(options.submitLabel ?? 'Unlock')}</button>
  </form>
  <footer>This page is served once from 127.0.0.1 and closes as soon as you submit.${
    options.fields.length > 0
      ? ' What you type here goes straight to the local ssh-mcp process — it is never sent to the model.'
      : ''
  }</footer>
</main></body></html>`;
}

const DONE_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Unlocked</title>
<style>:root{color-scheme:light dark}body{margin:0;min-height:100vh;display:grid;place-items:center;
font:15px/1.5 ui-sans-serif,system-ui,sans-serif}p{color:#666}</style></head>
<body><div><h1>Done</h1><p>You can close this tab and return to Claude Code.</p></div></body></html>`;

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

async function readBody(req: IncomingMessage): Promise<string | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    size += buffer.length;
    if (size > MAX_BODY_BYTES) return undefined;
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Serves one live page. Registered under its nonce path for as long as it lives. */
type Route = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

const routes = new Map<string, Route>();
/** How far to walk up from the configured port before giving up on a stable one. */
const PORT_LADDER = 10;

let configuredPort = DEFAULT_PAGE_PORT;
let listener: Promise<number> | undefined;

/**
 * Sets the port pages are served on. Call once, at startup, before any page is
 * opened — after that the listener is bound and this does nothing.
 *
 * `0` opts back into a random port per run, at the cost of the browser treating
 * every run as a new site.
 */
export function setPagePort(port: number): void {
  configuredPort = port;
}

/** Resolves once a port is bound; every later page reuses it. */
function listen(): Promise<number> {
  listener ??= bind();
  return listener;
}

async function bind(): Promise<number> {
  const server = createServer(dispatch);
  // A page is something the user may or may not get round to. It must never be
  // the reason the process stays alive.
  server.unref();

  // Walking up from the configured port keeps a second ssh-mcp on the same
  // machine off this one's port, rather than failing to start over it. It also
  // keeps that second instance stable at its own port for its whole life.
  // The last resort is 0 — a working page on an awkward port beats no page.
  const candidates =
    configuredPort === 0 ? [0] : [...Array.from({ length: PORT_LADDER }, (_, step) => configuredPort + step), 0];

  for (const candidate of candidates) {
    const port = await tryListen(server, candidate);
    if (port !== undefined) return port;
  }
  throw new Error('could not bind a loopback port for the unlock page');
}

/** Resolves the bound port, or `undefined` if this port is unavailable. */
function tryListen(server: Server, port: number): Promise<number | undefined> {
  return new Promise((resolve, reject) => {
    const onError = (error: NodeJS.ErrnoException): void => {
      server.removeListener('listening', onListening);
      // Only a busy port is worth stepping over; anything else is a real fault
      // and should be seen rather than papered over with a random port.
      if (error.code === 'EADDRINUSE' || error.code === 'EACCES') resolve(undefined);
      else reject(error);
    };
    const onListening = (): void => {
      server.removeListener('error', onError);
      resolve((server.address() as AddressInfo).port);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, '127.0.0.1');
  });
}

/**
 * Finds the page a request is for.
 *
 * Compared one path at a time rather than looked up in the map: the nonce is the
 * only thing standing between a local process and the ability to submit an
 * answer, so it is matched in constant time. There are never more than a handful
 * of live pages.
 */
function routeFor(path: string): Route | undefined {
  for (const [registered, route] of routes) {
    if (safeEqual(registered, path)) return route;
  }
  return undefined;
}

async function dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // Bound to loopback already; this is belt and braces.
  const remote = req.socket.remoteAddress ?? '';
  if (remote !== '127.0.0.1' && remote !== '::1' && remote !== '::ffff:127.0.0.1') {
    res.writeHead(403).end();
    return;
  }

  const route = routeFor((req.url ?? '').split('?')[0] ?? '');
  if (!route) {
    // A wrong, expired or replayed nonce reveals nothing. Now that the listener
    // outlives each page, this is also what a finished page answers with.
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
    return;
  }

  await route(req, res);
}

/** Starts the page and returns as soon as it is listening. */
export async function openUnlockPage(options: UnlockPageOptions): Promise<UnlockPage> {
  const nonce = randomBytes(32).toString('base64url');
  const path = `/unlock/${nonce}`;

  let settle: (wasAccepted: boolean) => void;
  const accepted = new Promise<boolean>((resolve) => {
    settle = resolve;
  });

  let closed = false;
  const shutdown = (wasAccepted: boolean): void => {
    if (closed) return;
    closed = true;
    clearTimeout(timer);
    // Unregistering is what closes the page: the path stops resolving, so a
    // reload or a late POST lands on the same 404 as a forged nonce.
    routes.delete(path);
    settle(wasAccepted);
  };

  const timer = setTimeout(() => shutdown(false), options.timeoutMs);
  timer.unref();

  routes.set(path, async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(formPage(options, path));
      return;
    }

    if (req.method !== 'POST') {
      res.writeHead(405).end();
      return;
    }

    const body = await readBody(req);
    if (body === undefined) {
      res.writeHead(413).end();
      return;
    }

    const parsed = new URLSearchParams(body);
    const values = new Map<string, string>();
    const missing: string[] = [];
    for (const field of options.fields) {
      const value = parsed.get(field.name);
      if (value === null || value === '') missing.push(field.label);
      else values.set(field.name, value);
    }
    for (const choice of options.choices ?? []) {
      const value = parsed.get(choice.name);
      // The submitted value is checked against the offered options rather than
      // trusted: a hand-crafted POST must not be able to invent a decision.
      if (value === null || !choice.options.some((option) => option.value === value)) missing.push(choice.label);
      else values.set(choice.name, value);
    }

    const redisplay = (message: string): void => {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end(formPage(options, path, message));
    };

    if (missing.length > 0) {
      redisplay(`${missing.join(' and ')} is required.`);
      return;
    }

    // A decision page needs no "Done" screen — the outcome is reported where
    // the work is, and the caller's own message says what happened.

    // The browser waits here, so whatever the callback makes of the secret is
    // reported on the page rather than guessed at.
    const failure = await options.onSubmit(values);
    if (failure !== undefined) {
      redisplay(failure);
      return;
    }

    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    res.end(DONE_PAGE, () => shutdown(true));
  });

  let port: number;
  try {
    port = await listen();
  } catch (cause) {
    // No listener means no page. Leaving the route registered would strand it.
    shutdown(false);
    throw cause;
  }

  return {
    url: `http://127.0.0.1:${port}${path}`,
    accepted,
    close: () => shutdown(false),
  };
}
