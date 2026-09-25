/**
 * Shell-aware enough to be safe, and no more.
 *
 * The command a tool receives is a real shell line — pipelines are half the
 * point of SSH. But a stored approval must never be matched against a line
 * whose meaning can change after the fact. So this splits the line the way a
 * shell would, and records every separator, expansion and redirection it saw
 * *outside* quotes.
 *
 * The two are not equally dangerous, and are reported apart. A separator is
 * resolved before anything runs and resolved the same way by every shell, so
 * the segments either side of it are whole commands that can be judged one at a
 * time — see `settled`. An expansion or a redirection is not: it decides at run
 * time what the command actually is, so a line carrying one is "not settled"
 * and can never satisfy a stored rule. `simple` is narrower still and governs
 * only what may be written into the policy file as a new rule.
 */

export interface Redirection {
  /** As written, including any file-descriptor prefix: `>`, `>>`, `>|`, `2>`, `<<`, `2>&`. */
  readonly operator: string;
  /** The word after the operator, with quoting removed. */
  readonly target: string;
  /** True for descriptor duplication (`2>&1`, `>&2`), where the target is not a path. */
  readonly toFd: boolean;
}

export interface CommandSegment {
  /**
   * The segment split into argv, with quoting removed.
   *
   * Redirections are left in here as well as being reported separately.
   * Removing them would be tidier and wrong: `sudo systemctl restart nginx >
   * /tmp/out` would then present the same argv as the bare command, and a
   * stored rule is matched against argv.
   */
  readonly argv: readonly string[];
  /** The segment's raw text, for display. */
  readonly text: string;
  /** Redirections found outside quotes, with what they point at. */
  readonly redirections: readonly Redirection[];
}

export interface ParsedCommandLine {
  readonly segments: readonly CommandSegment[];
  /** Unquoted separators found: `;`, `&&`, `||`, `|`, `&`, newline. */
  readonly separators: readonly string[];
  /** Unquoted expansions and redirections: `$(`, backtick, `${`, `$`, `<`, `>`. */
  readonly expansions: readonly string[];
  /** One command, no separators, no expansions — the only shape a new rule may be written from. */
  readonly simple: boolean;
  /**
   * Every segment's argv is exactly what is written here, and will still be that
   * when the remote shell runs it.
   *
   * The weaker sibling of `simple`, and the one that governs matching. A
   * separator is not a hazard: a shell splits on `|` and `;` before anything
   * runs, and splits identically wherever it runs, so each segment is a whole
   * command that can be checked on its own — which is exactly what sudo itself
   * sees. An expansion or a redirection is a hazard, because the argv this
   * parser matched a rule against is then not the argv that executes.
   *
   * `&` is excluded with them, for the reason `sudo -b` is: output nobody sees
   * is approval nobody can check.
   */
  readonly settled: boolean;
}

const SEPARATOR_CHARS = new Set([';', '&', '|', '\n']);

/** Longest match first, so `>>` never reads as two `>` and `2>&1` never loses its `&`. */
const REDIRECTION_OPERATORS = ['<<<', '>>', '>|', '>&', '<<', '<&', '<>', '>', '<'];

export function parseCommandLine(input: string): ParsedCommandLine {
  const segments: CommandSegment[] = [];
  const separators: string[] = [];
  const expansions = new Set<string>();

  let argv: string[] = [];
  let redirections: Redirection[] = [];
  let token = '';
  let tokenOpen = false;
  let segmentStart = 0;
  let index = 0;

  /**
   * A redirection operator waiting to learn what it points at.
   *
   * `from` is where in the current token the target begins, which covers the
   * attached form (`>/etc/foo`) directly; for the detached form (`> /etc/foo`)
   * it is rebased to 0 when the operator's own token closes and the target
   * turns out to be the next word.
   */
  let pending: { operator: string; from: number } | undefined;

  const settlePending = (): void => {
    if (!pending) return;
    const target = token.slice(pending.from);
    // Still empty: the target is the next word, not this one.
    if (target === '') return;
    redirections.push({ operator: pending.operator, target, toFd: pending.operator.endsWith('&') });
    pending = undefined;
  };

  const endToken = (): void => {
    if (!tokenOpen) return;
    settlePending();
    if (pending) pending = { operator: pending.operator, from: 0 };
    argv.push(token);
    token = '';
    tokenOpen = false;
  };

  const endSegment = (end: number): void => {
    endToken();
    const text = input.slice(segmentStart, end).trim();
    if (argv.length > 0) segments.push({ argv, text, redirections });
    argv = [];
    redirections = [];
    // A dangling operator with no target is dropped: there is nothing to guard.
    pending = undefined;
    segmentStart = end;
  };

  while (index < input.length) {
    const char = input[index]!;

    if (char === '\\' && index + 1 < input.length) {
      token += input[index + 1];
      tokenOpen = true;
      index += 2;
      continue;
    }

    if (char === "'") {
      const close = input.indexOf("'", index + 1);
      const end = close === -1 ? input.length : close;
      token += input.slice(index + 1, end);
      tokenOpen = true;
      index = end + 1;
      continue;
    }

    if (char === '"') {
      // Expansions inside double quotes still expand, so they are recorded.
      let cursor = index + 1;
      while (cursor < input.length && input[cursor] !== '"') {
        if (input[cursor] === '\\' && cursor + 1 < input.length) {
          token += input[cursor + 1];
          cursor += 2;
          continue;
        }
        if (input[cursor] === '$' || input[cursor] === '`') expansions.add(input[cursor] === '$' ? '$' : '`');
        token += input[cursor];
        cursor += 1;
      }
      tokenOpen = true;
      index = cursor + 1;
      continue;
    }

    if (char === '$') {
      expansions.add(input.startsWith('$(', index) ? '$(' : input.startsWith('${', index) ? '${' : '$');
      token += char;
      tokenOpen = true;
      index += 1;
      continue;
    }

    if (char === '`') {
      expansions.add(char);
      token += char;
      tokenOpen = true;
      index += 1;
      continue;
    }

    if (char === '<' || char === '>') {
      const operator = REDIRECTION_OPERATORS.find((candidate) => input.startsWith(candidate, index)) ?? char;
      // `2>` and `2>&1`: a bare number in front of the operator is the
      // descriptor being redirected, not part of the command.
      const descriptor = tokenOpen && /^\d+$/.test(token) ? token : '';

      settlePending();
      // Only the operator's first character, so `>>` still contributes a single
      // `>` and `simple` means exactly what it meant before.
      expansions.add(char);
      token += operator;
      tokenOpen = true;
      pending = { operator: descriptor + operator, from: token.length };
      index += operator.length;
      continue;
    }

    if (SEPARATOR_CHARS.has(char)) {
      const twoChar = input.slice(index, index + 2);
      const separator = twoChar === '&&' || twoChar === '||' ? twoChar : char;
      endSegment(index);
      separators.push(separator === '\n' ? 'newline' : separator);
      index += separator.length;
      segmentStart = index;
      continue;
    }

    if (char === ' ' || char === '\t' || char === '\r') {
      endToken();
      index += 1;
      continue;
    }

    token += char;
    tokenOpen = true;
    index += 1;
  }

  endSegment(input.length);

  const settled = expansions.size === 0 && !separators.includes('&');

  return {
    segments,
    separators,
    expansions: [...expansions],
    simple: settled && segments.length === 1 && separators.length === 0,
    settled,
  };
}

export interface SudoInvocation {
  /** The segment this sudo call came from. */
  readonly segment: CommandSegment;
  /** sudo's own flags, before the command. */
  readonly flags: readonly string[];
  /** The command sudo would run, as argv. Empty when sudo has no command. */
  readonly argv: readonly string[];
  /**
   * Set when the flags could not be parsed with confidence. Such an invocation
   * is never matched against a stored grant — it can only be approved once.
   */
  readonly unparseableFlag: string | undefined;
}

/**
 * A `sudo` that runs without this parser being able to say what it runs.
 *
 * `sudoInvocations` reads the first word of each segment, which is where sudo
 * stands in every line a rule could be matched against. It is not the only place
 * a shell will execute one, and a sudo it misses is a sudo the denylist never
 * saw and no page ever showed — on a NOPASSWD host, root with nobody asked.
 *
 * Two shapes are recognised, and they are not equally certain:
 *
 * - Inside a command substitution. Syntactically unambiguous: the parser saw the
 *   `$(` or the backtick itself, so `PGPASSWORD=$(sudo sed …)` is a sudo call
 *   whatever else is on the line.
 * - Passed to a command that runs its arguments (`env`, `xargs`, `do …`). This
 *   one cannot be decided in general — nothing syntactic separates
 *   `env FOO=1 sudo systemctl restart nginx` from `grep sudo /var/log/auth.log`,
 *   and refusing both would leave no way to grep for the word. So it is a list of
 *   the forms that occur, not a proof that there are no others.
 */
export interface UnaccountedSudo {
  readonly segment: CommandSegment;
  /** Reads after "…, because it is": `inside an expansion`, `an argument to env`. */
  readonly reason: string;
}

/**
 * `$(sudo …)` or `` `sudo …` ``, with or without a path in front of sudo.
 *
 * Matched against the segment's raw text as well as its tokens, so a space after
 * the `$(` does not hide it. That reads quoting it cannot see, so a literal
 * `'$(sudo'` searched for with grep is refused too — a false refusal that fails
 * closed, which is the right way round.
 */
const SUDO_IN_SUBSTITUTION = /(?:\$\(|`)\s*(?:\S*\/)?(?:sudo|doas)\b/;

/** A word that starts a command line of its own, as `sh -c "sudo …"` does. */
const STARTS_WITH_SUDO = /^\s*(?:\S*\/)?(?:sudo|doas)\b/;

/** Commands that run one of their arguments, so a `sudo` among them is a sudo call. */
const ARGUMENT_RUNNERS = new Set([
  'env', 'xargs', 'nohup', 'timeout', 'time', 'nice', 'ionice', 'stdbuf', 'setsid', 'watch', 'parallel',
  // Shell keywords: the line is split on `;`, so `do` and friends head a segment.
  'do', 'then', 'else', 'elif',
]);

/**
 * Flags whose value is a command, so the word after one is executed.
 *
 * `-c` is deliberately absent: it is `sh -c` and it is also `grep -c`, so the
 * word after it says nothing. `sh -c 'sudo …'` is caught by the quoted-command
 * check instead, which reads what the word actually is.
 */
const COMMAND_VALUED_FLAGS = new Set(['-exec', '-execdir']);

export function unaccountedSudo(parsed: ParsedCommandLine): UnaccountedSudo | undefined {
  for (const segment of parsed.segments) {
    if (SUDO_IN_SUBSTITUTION.test(segment.text)) return { segment, reason: 'inside an expansion' };

    for (const [index, token] of segment.argv.entries()) {
      if (SUDO_IN_SUBSTITUTION.test(token)) return { segment, reason: 'inside an expansion' };
      if (index === 0) continue;

      // A word holding a whole command line: `sh -c "sudo systemctl restart x"`.
      // One word that is just `sudo` is not this — that is `grep sudo`.
      if (/\s/.test(token) && STARTS_WITH_SUDO.test(token)) {
        return { segment, reason: 'inside a quoted command line' };
      }

      if (!isSudo(token)) continue;

      const head = baseCommand(segment.argv[0]!);
      if (ARGUMENT_RUNNERS.has(head)) return { segment, reason: `an argument to ${head}` };

      const before = segment.argv[index - 1]!;
      if (COMMAND_VALUED_FLAGS.has(before)) return { segment, reason: `the command after ${before}` };
    }
  }

  return undefined;
}

function baseCommand(word: string): string {
  return word.split(/[\\/]/).pop() ?? word;
}

/** sudo options that consume the following argument. */
const FLAGS_WITH_VALUE = new Set(['-u', '-g', '-p', '-C', '-h', '-r', '-t', '-U', '-T', '-D', '-R']);
/** sudo options that stand alone. */
const STANDALONE_FLAGS = new Set([
  '-n', '-S', '-k', '-K', '-b', '-E', '-H', '-P', '-s', '-i', '-l', '-v', '-A', '-B', '-N', '--',
]);

function isSudo(command: string): boolean {
  const base = command.split(/[\\/]/).pop() ?? command;
  return base === 'sudo' || base === 'doas';
}

/** Finds every sudo call in a parsed line, and what each would actually run. */
export function sudoInvocations(parsed: ParsedCommandLine): SudoInvocation[] {
  const found: SudoInvocation[] = [];

  for (const segment of parsed.segments) {
    if (segment.argv.length === 0 || !isSudo(segment.argv[0]!)) continue;

    const flags: string[] = [];
    let unparseableFlag: string | undefined;
    let cursor = 1;

    while (cursor < segment.argv.length) {
      const argument = segment.argv[cursor]!;
      if (!argument.startsWith('-') || argument === '-') break;

      if (argument === '--') {
        flags.push(argument);
        cursor += 1;
        break;
      }

      if (argument.startsWith('--')) {
        flags.push(argument);
        // `--user=root` carries its value; `--user root` consumes the next argument.
        if (!argument.includes('=') && LONG_FLAGS_WITH_VALUE.has(argument)) cursor += 1;
        else if (!argument.includes('=') && !LONG_STANDALONE_FLAGS.has(argument)) unparseableFlag ??= argument;
        cursor += 1;
        continue;
      }

      if (FLAGS_WITH_VALUE.has(argument)) {
        flags.push(argument, segment.argv[cursor + 1] ?? '');
        cursor += 2;
        continue;
      }

      if (STANDALONE_FLAGS.has(argument)) {
        flags.push(argument);
        cursor += 1;
        continue;
      }

      // Unknown or bundled short flags (`-nS`) are not guessed at: fail closed.
      flags.push(argument);
      unparseableFlag ??= argument;
      cursor += 1;
    }

    found.push({
      segment,
      flags,
      argv: segment.argv.slice(cursor),
      unparseableFlag,
    });
  }

  return found;
}

const LONG_FLAGS_WITH_VALUE = new Set([
  '--user', '--group', '--prompt', '--close-from', '--host', '--role', '--type', '--other-user', '--command-timeout', '--chdir', '--chroot',
]);
const LONG_STANDALONE_FLAGS = new Set([
  '--non-interactive', '--stdin', '--reset-timestamp', '--remove-timestamp', '--background', '--preserve-env',
  '--set-home', '--preserve-groups', '--shell', '--login', '--list', '--validate', '--askpass', '--bell', '--no-update',
]);
