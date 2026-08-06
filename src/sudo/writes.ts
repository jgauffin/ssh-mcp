import { sudoInvocations, type CommandSegment, type ParsedCommandLine } from './parse.js';

/**
 * Commands that would change a file's contents without anyone seeing the change.
 *
 * `ssh_edit` shows the user a unified diff and waits for an answer. That is
 * worth nothing if the same edit can be made by another route, and today it
 * can: `ssh_run` runs any non-sudo command with no approval at all, so
 * `echo x > /etc/foo` needs nobody's permission, and `ssh_sudo`'s page can show
 * `sudo tee /etc/hosts` verbatim while telling the reader nothing about what
 * the file would end up containing.
 *
 * So this is the routing rule, not a prohibition: what it finds is refused with
 * a pointer at the tool that *can* show the change.
 *
 * It reads paths, not intent. A write-capable construct naming an absolute path
 * outside the scratch roots is caught; a relative one is not something it tries
 * to reason about, because that would mean tracking the working directory
 * across segments and `cd /etc && sed -i s/a/b/ nginx.conf` would still get
 * through. That hole is real and documented rather than half-closed — the same
 * reasoning the denylist carries: this list is the well-known cases, and the
 * weight is borne by the closed host world and by ssh_edit being pleasant
 * enough to use that nobody has to route around it.
 */

export interface FileWrite {
  /** The segment that would do the writing, as written. */
  readonly command: string;
  /** The path it would write. */
  readonly target: string;
  /** Plain English, dropped into the middle of the refusal. */
  readonly reason: string;
}

/** Paths that are a place to put output, not a file anyone is editing. */
const SCRATCH_FILES = new Set(['/dev/null', '/dev/stdout', '/dev/stderr', '/dev/tty', '/dev/zero', '/tmp', '/var/tmp']);
const SCRATCH_ROOTS = ['/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/', '/run/lock/', '/dev/fd/', '/proc/self/fd/'];

/**
 * Whether writing here is something the user should see first.
 *
 * Absolute only. `echo hi > out.txt`, `> $HOME/log` and `> ~/notes` are the
 * everyday scratch idioms and none of them are absolute, which is what leaves
 * room to guard every absolute path — including `/home/deploy/app.yml`, on
 * purpose: that is an app config where a diff is worth having, and `ssh_edit`
 * reaches it without needing sudo at all.
 */
export function guardedPath(target: string): boolean {
  if (!target.startsWith('/')) return false;
  if (SCRATCH_FILES.has(target)) return false;
  return !SCRATCH_ROOTS.some((root) => target.startsWith(root));
}

function baseName(command: string): string {
  return command.split(/[\\/]/).pop() ?? command;
}

/**
 * The positional arguments, with flags and the values they consume removed.
 *
 * Only the value-taking flags that matter for finding a path are listed per
 * command; an unknown flag is assumed to stand alone, which can leave its value
 * in the operands. That errs towards catching a write that is not there rather
 * than missing one that is, and a false refusal names the tool that will do the
 * job anyway.
 */
function operands(argv: readonly string[], valueFlags: ReadonlySet<string> = new Set()): string[] {
  const found: string[] = [];
  let index = 1;
  let literal = false;

  while (index < argv.length) {
    const argument = argv[index]!;
    if (!literal && argument === '--') {
      literal = true;
      index += 1;
      continue;
    }
    if (!literal && argument.startsWith('-') && argument !== '-') {
      index += !argument.includes('=') && valueFlags.has(argument) ? 2 : 1;
      continue;
    }
    found.push(argument);
    index += 1;
  }

  return found;
}

/** The value of `-o path`, `-opath` or `--output=path`, for the download tools. */
function flagValues(argv: readonly string[], names: ReadonlySet<string>): string[] {
  const found: string[] = [];

  for (let index = 1; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (names.has(argument)) {
      const value = argv[index + 1];
      if (value !== undefined) found.push(value);
      index += 1;
      continue;
    }
    const equals = argument.indexOf('=');
    if (equals > 1 && names.has(argument.slice(0, equals))) {
      found.push(argument.slice(equals + 1));
      continue;
    }
    for (const name of names) {
      if (name.length === 2 && !name.startsWith('--') && argument.length > 2 && argument.startsWith(name)) {
        found.push(argument.slice(2));
      }
    }
  }

  return found;
}

/**
 * Whether an in-place flag is present, including bundled (`-ni`) and
 * suffixed (`-i.bak`) forms.
 */
function inPlace(argv: readonly string[]): boolean {
  return argv.slice(1).some((argument) => {
    if (argument === '--' || !argument.startsWith('-') || argument === '-') return false;
    if (argument.startsWith('--')) return argument === '--in-place' || argument.startsWith('--in-place=');
    return argument.slice(1).includes('i');
  });
}

/** Drops the leading script operand, which `-e`/`-f` replaces when either is given. */
function scriptOperands(argv: readonly string[], valueFlags: ReadonlySet<string>, inlineFlags: readonly string[]): string[] {
  const found = operands(argv, valueFlags);
  const inline = argv.some((argument) => inlineFlags.some((flag) => argument === flag || argument.startsWith(`${flag}=`)));
  return inline ? found : found.slice(1);
}

const SED_VALUE_FLAGS = new Set(['-e', '-f', '--expression', '--file']);
const PERL_VALUE_FLAGS = new Set(['-e', '-E', '-M', '-I', '-m']);
const TRUNCATE_VALUE_FLAGS = new Set(['-s', '--size', '-r', '--reference']);
const INSTALL_VALUE_FLAGS = new Set(['-m', '--mode', '-o', '--owner', '-g', '--group', '-t', '--target-directory', '-S', '--suffix']);

const EDITORS = new Set(['vi', 'vim', 'nvim', 'view', 'ex', 'ed', 'red', 'emacs', 'nano', 'pico', 'sponge']);

/**
 * Commands whose last operand is a destination.
 *
 * Kept apart because this is the judgement call in the list. Including it
 * refuses `sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak`, which is a
 * reasonable thing to do before an edit — so the refusal names `/tmp` as the
 * place to put a backup. Leaving it out would be worse: writing `/tmp/x` and
 * then `sudo cp /tmp/x /etc/nginx/nginx.conf` is the most obvious way round
 * `ssh_edit`, and a guarantee with an obvious way round it is decoration.
 */
const PLACEMENT_COMMANDS = new Set(['cp', 'mv', 'install']);

/** Every path this one segment would write, with why. */
function writesIn(argv: readonly string[]): { targets: string[]; reason: string } | undefined {
  if (argv.length === 0) return undefined;
  const command = baseName(argv[0]!);

  if ((command === 'sed' || command === 'gsed' || command === 'ssed') && inPlace(argv)) {
    return { targets: scriptOperands(argv, SED_VALUE_FLAGS, ['-e', '-f', '--expression', '--file']), reason: 'edits the file in place' };
  }

  if (command === 'perl' && inPlace(argv)) {
    return { targets: scriptOperands(argv, PERL_VALUE_FLAGS, ['-e', '-E']), reason: 'edits the file in place' };
  }

  if (command === 'tee') {
    return { targets: operands(argv, new Set(['--output-error'])), reason: 'writes its input over the file' };
  }

  if (command === 'dd') {
    const of = argv.slice(1).filter((argument) => argument.startsWith('of='));
    return { targets: of.map((argument) => argument.slice(3)), reason: 'writes over it' };
  }

  if (command === 'truncate') {
    return { targets: operands(argv, TRUNCATE_VALUE_FLAGS), reason: 'truncates it' };
  }

  if (command === 'curl') {
    return { targets: flagValues(argv, new Set(['-o', '--output'])), reason: 'downloads over it' };
  }

  if (command === 'wget') {
    return { targets: flagValues(argv, new Set(['-O', '--output-document'])), reason: 'downloads over it' };
  }

  if (command === 'patch') {
    return { targets: operands(argv, new Set(['-i', '--input', '-p', '-d', '--directory', '-o', '--output', '-B', '-z'])), reason: 'patches it in place' };
  }

  if (EDITORS.has(command)) {
    return { targets: operands(argv), reason: 'opens it in an editor' };
  }

  if (PLACEMENT_COMMANDS.has(command)) {
    const positional = operands(argv, INSTALL_VALUE_FLAGS);
    const destination = positional.length > 1 ? positional[positional.length - 1] : undefined;
    return { targets: destination === undefined ? [] : [destination], reason: 'replaces it' };
  }

  return undefined;
}

/**
 * What each segment would really run: `sudo sed -i …` is a `sed -i …`.
 *
 * Reuses `sudoInvocations` rather than skipping sudo's flags again here — it
 * already fails closed on a flag it does not recognise, and two
 * implementations of that would eventually disagree.
 */
function effectiveArgv(parsed: ParsedCommandLine): Map<CommandSegment, readonly string[]> {
  const map = new Map<CommandSegment, readonly string[]>();
  for (const segment of parsed.segments) map.set(segment, segment.argv);
  for (const invocation of sudoInvocations(parsed)) map.set(invocation.segment, invocation.argv);
  return map;
}

/** The first construct on the line that would write a file nobody has seen a diff of. */
export function detectFileWrite(parsed: ParsedCommandLine): FileWrite | undefined {
  const argvFor = effectiveArgv(parsed);

  for (const segment of parsed.segments) {
    for (const redirection of segment.redirections) {
      // `2>&1` and `>&2` name a descriptor, and `<` reads.
      if (redirection.toFd || redirection.operator.includes('<')) continue;
      if (!guardedPath(redirection.target)) continue;
      return {
        command: segment.text,
        target: redirection.target,
        reason: redirection.operator.includes('>>') ? 'appends to it' : 'redirects output onto it',
      };
    }

    const write = writesIn(argvFor.get(segment) ?? segment.argv);
    if (!write) continue;
    const target = write.targets.find(guardedPath);
    if (target !== undefined) return { command: segment.text, target, reason: write.reason };
  }

  return undefined;
}
