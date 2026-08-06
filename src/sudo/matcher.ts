/**
 * Token-wise matching, deliberately not string globbing.
 *
 * `*` stands for exactly one argument and `**` for the rest of them (tail
 * position only). Matching argument-by-argument means an extra argument is a
 * miss, not a match: a grant for `systemctl restart *` covers
 * `systemctl restart nginx` and refuses `systemctl restart nginx --now`.
 * A string glob would have let the second one through.
 */

export class PatternError extends Error {
  override readonly name = 'PatternError';
}

export function parsePattern(text: string): string[] {
  const tokens = text.trim().split(/\s+/).filter((token) => token !== '');
  if (tokens.length === 0) throw new PatternError('pattern is empty');

  const tail = tokens.indexOf('**');
  if (tail !== -1 && tail !== tokens.length - 1) {
    throw new PatternError('`**` may only appear as the last token');
  }

  // A token like `/var/log/*` would silently never match, because wildcards
  // stand for whole arguments and never for part of one. Say so rather than
  // storing a rule that quietly does nothing. (Substring globbing is left out
  // on purpose: `/var/log/*` would otherwise also match `/var/log/../../etc`.)
  for (const token of tokens) {
    if (token !== '*' && token !== '**' && token.includes('*')) {
      throw new PatternError(
        `"${token}" mixes a wildcard into an argument. \`*\` and \`**\` stand for whole arguments only, ` +
          `so write \`${token.replace(/\S*\*\S*/, '*')}\` if that is what you meant`,
      );
    }
  }

  return tokens;
}

export function formatPattern(tokens: readonly string[]): string {
  return tokens.join(' ');
}

export function matches(pattern: readonly string[], argv: readonly string[]): boolean {
  for (let index = 0; index < pattern.length; index += 1) {
    const token = pattern[index]!;

    if (token === '**') return index <= argv.length;
    if (index >= argv.length) return false;
    if (token === '*') continue;
    if (token !== argv[index]) return false;
  }

  return pattern.length === argv.length;
}

/**
 * The choices offered in the approval dialog, narrowest first. The user picks
 * how wide the grant is; nothing widens on its own.
 */
export function proposePatterns(argv: readonly string[]): string[][] {
  const proposals: string[][] = [[...argv]];

  if (argv.length >= 2) {
    proposals.push([...argv.slice(0, -1), '*']);
    if (argv.length >= 3 || argv.length === 2) proposals.push([argv[0]!, '**']);
  }

  const seen = new Set<string>();
  return proposals.filter((tokens) => {
    const key = formatPattern(tokens);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
