/**
 * Splits a shell line into coloured pieces for the approval page.
 *
 * For reading only, never for deciding: what runs and what is allowed is
 * settled by the sudo parser. This one only has to be right often enough to
 * help the eye, and its pieces always join back into the exact line.
 */

export type ShellTokenKind = 'sudo' | 'command' | 'flag' | 'string' | 'operator' | 'variable' | 'text';

export interface ShellToken {
  readonly kind: ShellTokenKind;
  readonly text: string;
}

/** sudo options that take a value, so the value is not mistaken for the command. */
const SUDO_OPTIONS_WITH_VALUE = new Set(['-u', '-g', '-h', '-p', '-C', '-D', '-r', '-t', '-U', '-T']);

const PATTERNS: ReadonlyArray<readonly [RegExp, 'space' | 'separator' | 'redirect' | 'string' | 'variable' | 'word']> = [
  [/\s+/y, 'space'],
  [/&&|\|\||[|;&]/y, 'separator'],
  [/\d*[<>]+&?\d*/y, 'redirect'],
  [/'[^']*'?/y, 'string'],
  [/"(?:\\.|[^"\\])*"?/y, 'string'],
  [/\$\{[^}]*\}?|\$\w+/y, 'variable'],
  [/(?:\\.|[^\s'"|;&<>$\\])+/y, 'word'],
];

export function shellTokens(line: string): ShellToken[] {
  const tokens: ShellToken[] = [];
  let expectingCommand = true;
  let sudoValuePending = false;
  let index = 0;

  const push = (kind: ShellTokenKind, text: string): void => {
    const last = tokens[tokens.length - 1];
    if (kind === 'text' && last?.kind === 'text') tokens[tokens.length - 1] = { kind, text: last.text + text };
    else tokens.push({ kind, text });
  };

  while (index < line.length) {
    let matched: { kind: (typeof PATTERNS)[number][1]; text: string } | undefined;
    for (const [pattern, kind] of PATTERNS) {
      pattern.lastIndex = index;
      const found = pattern.exec(line);
      if (found && found[0].length > 0) {
        matched = { kind, text: found[0] };
        break;
      }
    }
    // A character no pattern claims, such as a lone `$` or trailing backslash.
    if (!matched) matched = { kind: 'space', text: line[index]! };
    index += matched.text.length;

    switch (matched.kind) {
      case 'space':
        push('text', matched.text);
        break;
      case 'separator':
        push('operator', matched.text);
        expectingCommand = true;
        sudoValuePending = false;
        break;
      case 'redirect':
        push('operator', matched.text);
        break;
      case 'string':
      case 'variable':
        push(matched.kind, matched.text);
        if (sudoValuePending) sudoValuePending = false;
        else expectingCommand = false;
        break;
      case 'word':
        if (sudoValuePending) {
          push('text', matched.text);
          sudoValuePending = false;
        } else if (expectingCommand && matched.text === 'sudo') {
          push('sudo', matched.text);
        } else if (matched.text.startsWith('-')) {
          push('flag', matched.text);
          sudoValuePending = expectingCommand && SUDO_OPTIONS_WITH_VALUE.has(matched.text);
        } else if (expectingCommand && /^\w+=/.test(matched.text)) {
          push('text', matched.text);
        } else if (expectingCommand) {
          push('command', matched.text);
          expectingCommand = false;
        } else {
          push('text', matched.text);
        }
        break;
    }
  }
  return tokens;
}
