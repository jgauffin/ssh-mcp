import { describe, expect, it } from 'vitest';
import { refusedForPassword, sudoPrefix } from './exec.js';

/**
 * The preamble itself can only be checked against a real sudo on a real host,
 * which the suite has none of. What it can hold down are the properties that
 * made the original bug possible: that the password is spent exactly once, and
 * that when it is refused anyway, the refusal is recognised.
 */

const withPassword = (password: string): string => sudoPrefix({ kind: 'password', password: Buffer.from(password) });

describe('the sudo preamble', () => {
  it('does not carry the password, whatever the password is', () => {
    // The secret travels on stdin. A preamble that varied with it would be a
    // preamble that had interpolated it into the command line, where `ps` is.
    expect(withPassword('hunter2')).toBe(withPassword('correct horse battery staple'));
    expect(withPassword('hunter2')).not.toContain('hunter2');
  });

  it('never lets the wrapped sudo read the command channel', () => {
    // `-S` is the whole bug: it makes sudo take the password off a stdin that
    // holds exactly one line, so the second sudo on a line finds EOF. Worse, a
    // sudo that does not prompt — a NOPASSWD rule — leaves the line for the
    // privileged command to read. Every sudo the wrapper defines authenticates
    // out of band, through the helper or through an already-validated cache.
    const wrappers = withPassword('hunter2')
      .split('\n')
      .filter((line) => line.startsWith('sudo() {'));

    expect(wrappers).toHaveLength(2);
    for (const wrapper of wrappers) expect(wrapper).not.toContain('-S');
    expect(wrappers.some((wrapper) => wrapper.includes('sudo -A'))).toBe(true);
    expect(wrappers.some((wrapper) => wrapper.includes('sudo -n'))).toBe(true);
  });

  it('takes the password off stdin before the command runs, on every path', () => {
    // Whatever else fails, the line must not still be sitting on stdin when the
    // user's command starts reading — see the note on `SUDO_ASKPASS`.
    const preamble = withPassword('hunter2');
    expect(preamble).toContain('head -n 1');
    // The backstop for a host without `head`.
    expect(preamble).toContain('IFS= read -r');
    // And the last resort, for a host where nothing could be written at all.
    expect(preamble).toContain("command sudo -S -p '' -v >/dev/null 2>&1");
  });

  it('cleans up after itself without swallowing the exit code', () => {
    const preamble = withPassword('hunter2');
    expect(preamble).toContain('rm -rf "$__ssh_mcp_d"');
    // Restored explicitly, because whether an EXIT trap's own status leaks into
    // the shell's is not the same across shells — and the exit code is reported.
    expect(preamble).toContain('exit $__ssh_mcp_rc');
  });

  it('asks for nothing when the command needs no sudo', () => {
    expect(sudoPrefix({ kind: 'none' })).toBe('');
    expect(sudoPrefix({ kind: 'noninteractive' })).toBe('sudo() { command sudo -n "$@"; }\n');
  });
});

describe('recognising a sudo that wanted a password', () => {
  /**
   * The first of these is what the old preamble produced on every sudo after
   * the first, and it went unrecognised — so the user was shown sudo's
   * complaint instead of a password page.
   */
  it.each([
    'sudo: no password was provided',
    'sudo: a password is required',
    'sudo: 3 incorrect password attempts',
    'sudo: no tty present and no askpass program specified',
  ])('recognises %j', (stderr) => {
    expect(refusedForPassword(stderr)).toBe(true);
  });

  it.each(['', 'sudo: nginx: command not found', 'deploy is not in the sudoers file.  This incident will be reported.'])(
    'leaves %j alone',
    (stderr) => {
      // Asking for a password would not help with any of these, and asking
      // costs the user a page and the command a second run.
      expect(refusedForPassword(stderr)).toBe(false);
    },
  );
});
