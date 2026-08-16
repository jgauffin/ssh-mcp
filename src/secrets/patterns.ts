/**
 * What counts as a secret in a file's text, and where it sits.
 *
 * Nothing here reads or writes anything: it turns text into spans, so the rules
 * can be argued with in a test rather than against a live host.
 *
 * Every pattern names a *key* before it captures a *value*. Entropy scoring and
 * bare-string heuristics were left out on purpose — they fire on git hashes,
 * base64 blobs and UUIDs, and a redactor the reader stops believing is worse
 * than none, because the model then routes around it with `ssh_run`.
 */

export interface SecretPattern {
  /** The pattern as written, for the message when it will not compile. */
  readonly source: string;
  /** Compiled with `g` and `d`; group 1 is the value to withhold. */
  readonly regex: RegExp;
}

export interface Span {
  readonly start: number;
  readonly end: number;
}

/** Key names that make whatever follows them a secret. */
const KEY = String.raw`(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|credentials?|auth[_-]?token|private[_-]?key)`;

/**
 * The key with whatever the surrounding format wraps it in.
 *
 * `db_password`, `SA_PASSWORD`, `ConnectionStrings.Password` and `"password"`
 * are all the same key wearing different clothes, and a pattern that only
 * matched the bare word would miss every real config file.
 *
 * The separator's spacing is `[ \t]` and not `\s`: `\s` crosses a newline, so
 * `password =` on a line of its own would reach down and claim the *next*
 * line's key as its value.
 */
const KEY_IN_CONTEXT = String.raw`[\w.-]*${KEY}[\w.-]*["']?[ \t]*[:=][ \t]*`;

/**
 * The built-in set.
 *
 * Order matters only where two could match the same place: the quoted forms
 * come first so the bare-value pattern never claims the opening quote.
 */
const BUILT_IN: readonly { source: string; flags: string }[] = [
  // key = "value" / "key": "value"
  { source: `${KEY_IN_CONTEXT}"([^"\\r\\n]+)"`, flags: 'gdim' },
  // key = 'value'
  { source: `${KEY_IN_CONTEXT}'([^'\\r\\n]+)'`, flags: 'gdim' },
  // key = value, to the end of the value: whitespace, a comment, or the `;` that
  // separates the parts of a connection string.
  { source: `${KEY_IN_CONTEXT}([^\\s"'#;,\\r\\n][^\\s#;,\\r\\n]*)`, flags: 'gdim' },
  // scheme://user:value@host — the password half of a URL's userinfo.
  { source: String.raw`[a-z][a-z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@`, flags: 'gdim' },
  // A private key, whole. Nothing about the inside of one is safe to show.
  { source: String.raw`(-----BEGIN[^\n]*PRIVATE KEY-----[\s\S]*?-----END[^\n]*PRIVATE KEY-----)`, flags: 'gd' },
];

/**
 * Values that match a secret-shaped key and are not secrets.
 *
 * A config saying `password_required = true` or `password = ${DB_PASSWORD}` is
 * telling the model something it needs in order to work, and withholding it
 * buys nothing: there is no secret in either line. Deliberately a short list of
 * certainties rather than a guess at length or entropy.
 */
const NOT_A_SECRET = /^(?:true|false|yes|no|on|off|none|null|nil|nul|empty|-|\d+)$/i;

/** `$FOO` and `${FOO}` name a secret that lives somewhere else. */
const INDIRECTION = /^[$%]/;

function isSecretValue(value: string): boolean {
  return value !== '' && !NOT_A_SECRET.test(value) && !INDIRECTION.test(value);
}

/** How many capture groups a pattern has, without having to match anything. */
function groupCount(source: string): number {
  return new RegExp(`${source}|`).exec('')!.length - 1;
}

/**
 * Compiles one pattern from the config file.
 *
 * A leading `(?i)` is honoured and turned into the flag, because that is how
 * every other tool that reads patterns out of a config file spells it, and JS
 * is the odd one out for not taking it inline.
 */
export function compilePattern(source: string): SecretPattern {
  const insensitive = source.startsWith('(?i)');
  const body = insensitive ? source.slice(4) : source;

  // `m` always: these are matched against whole files, and a pattern anchored
  // with `^` is meant line by line. `d` is what makes the value's position
  // knowable, which is the whole job.
  const regex = new RegExp(body, `gdm${insensitive ? 'i' : ''}`);

  if (groupCount(body) === 0) {
    throw new Error('a secret pattern must have a capture group around the value to withhold, e.g. pw\\s*=\\s*(.+)');
  }

  return { source, regex };
}

/**
 * Compiles the built-ins plus the user's own.
 *
 * A pattern that will not compile is dropped on its own and reported, the way
 * an unparseable line of `sudo-policy.txt` is: one typo costs one pattern, not
 * the whole set.
 */
export function compilePatterns(sources: readonly string[]): { patterns: SecretPattern[]; problems: string[] } {
  const patterns = BUILT_IN.map(({ source, flags }) => ({ source, regex: new RegExp(source, flags) }));
  const problems: string[] = [];

  for (const source of sources) {
    try {
      patterns.push(compilePattern(source));
    } catch (cause) {
      problems.push(`secret pattern ${JSON.stringify(source)}: ${(cause as Error).message}`);
    }
  }

  return { patterns, problems };
}

/**
 * Every span of `text` that holds a secret value, in order and non-overlapping.
 *
 * Overlaps are resolved by taking the first span found and skipping anything
 * inside it, rather than by merging: two patterns matching the same value must
 * produce one marker, not a marker inside a marker.
 */
export function findSecretSpans(text: string, patterns: readonly SecretPattern[]): Span[] {
  const found: Span[] = [];

  for (const { regex } of patterns) {
    // Shared `lastIndex` across calls would make the second scan of a file skip
    // its beginning, so every pass starts from zero explicitly.
    regex.lastIndex = 0;
    for (let match = regex.exec(text); match !== null; match = regex.exec(text)) {
      const at = match.indices?.[1];
      if (at && isSecretValue(text.slice(at[0], at[1]))) {
        found.push({ start: at[0], end: at[1] });
      }
      // A pattern that can match empty would otherwise spin here.
      if (match.index === regex.lastIndex) regex.lastIndex += 1;
    }
  }

  found.sort((left, right) => left.start - right.start || right.end - left.end);

  const spans: Span[] = [];
  for (const span of found) {
    const last = spans[spans.length - 1];
    if (last && span.start < last.end) continue;
    spans.push(span);
  }
  return spans;
}

/**
 * Whether a path is one the config says to withhold entirely.
 *
 * A pattern with no `/` is matched against the last segment, the way every
 * ignore-file works: `id_rsa` means the file wherever it lives. `*` stops at a
 * separator, `**` crosses them.
 */
export function matchesPath(pattern: string, path: string): boolean {
  const subject = pattern.includes('/') ? path : (path.split('/').pop() ?? path);

  const source = pattern
    .split(/(\*\*|\*|\?)/)
    .map((part) => {
      if (part === '**') return '.*';
      if (part === '*') return '[^/]*';
      if (part === '?') return '[^/]';
      return part.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
    })
    .join('');

  return new RegExp(`^${source}$`).test(subject);
}
