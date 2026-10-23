import { execFile } from 'node:child_process';

let configuredBrowser: string | undefined;

/**
 * Sets the browser pages are opened in; `undefined` means the system default.
 * Call once, at startup.
 *
 * What the name means is the platform's: an application for `open -a` on macOS,
 * an App Paths name or full path for `start` on Windows, and a command anywhere
 * else.
 */
export function setBrowser(browser: string | undefined): void {
  configuredBrowser = browser;
}

/**
 * Opens the unlock page for the user.
 *
 * Claude Code does not declare URL-mode elicitation, so it will not open the
 * page itself. Rather than making the user copy a link out of the chat on every
 * server start, the server opens its own page — it is a local address on the
 * loopback interface, served by this process, for this user.
 *
 * This is not the client auto-fetching a URL, which the specification forbids:
 * nothing is fetched here, a browser is pointed at a page that then talks
 * directly to us. The passphrase still never touches the protocol.
 */
export function openInBrowser(url: string): void {
  // Failure is not worth reporting to the model: the link is in the tool result
  // either way, and a headless or remote setup simply has no browser to open.
  const done = (): void => {};
  const browser = configuredBrowser;

  if (process.platform === 'win32') {
    // `start` is a cmd builtin, and the empty "" is the window title that
    // `start` would otherwise consume from a quoted URL.
    const target = browser === undefined ? [url] : [browser, url];
    execFile('cmd.exe', ['/c', 'start', '', ...target], { windowsHide: true }, done);
    return;
  }
  if (process.platform === 'darwin') {
    execFile('open', browser === undefined ? [url] : ['-a', browser, url], done);
    return;
  }
  execFile(browser ?? 'xdg-open', [url], done);
}
