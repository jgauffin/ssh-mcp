import type { SudoInvocation } from './parse.js';

/**
 * Two lists, because "dangerous" has two meanings here.
 *
 * DENIED is not a prompt — it is a refusal. These turn sudo into an
 * interactive root shell or edit the rules themselves, so approving them once
 * would approve everything afterwards. There is no dialog for them.
 *
 * UNGRANTABLE may be approved, but only for this one command, this one time.
 * They can all be talked into spawning a shell, so a `*` wildcard over them
 * would be a wildcard over root. The list is the well-known cases, not an
 * exhaustive one — no denylist of this kind ever is, which is exactly why
 * the closed host world and the once-only default carry the real weight.
 */

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'fish', 'ash', 'busybox']);

const DENIED_COMMANDS = new Set([...SHELLS, 'su', 'visudo', 'sudoedit']);

/** sudo flags that give an interactive root shell or a rewritten environment. */
const DENIED_FLAGS = new Map<string, string>([
  ['-s', 'runs a root shell'],
  ['--shell', 'runs a root shell'],
  ['-i', 'runs a root login shell'],
  ['--login', 'runs a root login shell'],
  ['-E', 'carries the caller environment into root'],
  ['--preserve-env', 'carries the caller environment into root'],
  ['-b', 'detaches, so its output is never seen'],
  ['--background', 'detaches, so its output is never seen'],
  ['-A', 'delegates the password to an external helper'],
  ['--askpass', 'delegates the password to an external helper'],
]);

/** Commands that may run once with approval, but can never be covered by a wildcard. */
const UNGRANTABLE_COMMANDS = new Set([
  'env', 'chroot', 'nsenter', 'unshare', 'setarch', 'docker', 'podman', 'lxc', 'runc',
  'passwd', 'chpasswd', 'useradd', 'usermod', 'userdel', 'groupadd', 'chown', 'chmod',
  'perl', 'python', 'python2', 'python3', 'ruby', 'node', 'lua', 'php', 'awk', 'gawk', 'mawk',
  'find', 'xargs', 'vi', 'vim', 'nvim', 'nano', 'emacs', 'less', 'more', 'man', 'ed',
  'dd', 'tee', 'install', 'cp', 'mv', 'ln', 'rsync', 'tar', 'zip', 'unzip',
  // Belt and braces behind the file-write gate: these are refused outright
  // before they reach a grant, and `sed -i` being wildcardable should not be
  // one refactor away from mattering again.
  'sed', 'gsed', 'truncate', 'sponge', 'patch', 'curl', 'wget',
  'crontab', 'at', 'systemd-run', 'insmod', 'modprobe', 'mount', 'umount',
]);

const SUDOERS = /\/etc\/sudoers/;

export type SudoVerdict =
  | { readonly kind: 'denied'; readonly reason: string }
  | { readonly kind: 'ungrantable'; readonly reason: string }
  | { readonly kind: 'normal' };

function baseName(command: string): string {
  return command.split(/[\\/]/).pop() ?? command;
}

/** Classifies one sudo invocation before any policy or grant is consulted. */
export function classify(invocation: SudoInvocation): SudoVerdict {
  for (const flag of invocation.flags) {
    const name = flag.includes('=') ? flag.slice(0, flag.indexOf('=')) : flag;
    const reason = DENIED_FLAGS.get(name);
    if (reason) return { kind: 'denied', reason: `${name} ${reason}` };
  }

  if (invocation.argv.length === 0) {
    return { kind: 'denied', reason: 'sudo with no command is an interactive root session' };
  }

  const command = baseName(invocation.argv[0]!);

  if (DENIED_COMMANDS.has(command)) {
    return { kind: 'denied', reason: `${command} is a shell or edits sudo's own rules` };
  }

  if (invocation.argv.some((argument) => SUDOERS.test(argument))) {
    return { kind: 'denied', reason: 'it touches /etc/sudoers' };
  }

  if (invocation.unparseableFlag) {
    return { kind: 'ungrantable', reason: `sudo flag ${invocation.unparseableFlag} was not understood, so it cannot be matched against a stored rule` };
  }

  if (UNGRANTABLE_COMMANDS.has(command)) {
    return { kind: 'ungrantable', reason: `${command} can be made to spawn a shell, so it is never covered by a wildcard` };
  }

  return { kind: 'normal' };
}
