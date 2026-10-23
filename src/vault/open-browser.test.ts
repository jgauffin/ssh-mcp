import { afterEach, describe, expect, it, vi } from 'vitest';
import { openInBrowser, setBrowser } from './open-browser.js';

// Records the launch instead of making it, so no window appears.
const { launches } = vi.hoisted(() => ({ launches: [] as { file: string; args: readonly string[] }[] }));
vi.mock('node:child_process', () => ({
  execFile: (file: string, args: readonly string[]) => {
    launches.push({ file, args });
  },
}));

const URL = 'http://127.0.0.1:8765/unlock/abc';
const realPlatform = process.platform;

function on(platform: NodeJS.Platform): void {
  Object.defineProperty(process, 'platform', { value: platform });
}

afterEach(() => {
  Object.defineProperty(process, 'platform', { value: realPlatform });
  setBrowser(undefined);
  launches.length = 0;
});

describe('openInBrowser', () => {
  it.each([
    ['darwin', 'open', [URL]],
    ['win32', 'cmd.exe', ['/c', 'start', '', URL]],
    ['linux', 'xdg-open', [URL]],
  ] as const)('uses the system default on %s when no browser is set', (platform, file, args) => {
    on(platform);
    openInBrowser(URL);
    expect(launches).toEqual([{ file, args }]);
  });

  it.each([
    ['darwin', 'Google Chrome', 'open', ['-a', 'Google Chrome', URL]],
    ['win32', 'chrome', 'cmd.exe', ['/c', 'start', '', 'chrome', URL]],
    ['linux', 'firefox', 'firefox', [URL]],
  ] as const)('uses the configured browser on %s', (platform, browser, file, args) => {
    on(platform);
    setBrowser(browser);
    openInBrowser(URL);
    expect(launches).toEqual([{ file, args }]);
  });
});
