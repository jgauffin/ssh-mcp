/**
 * Anchored edits: the model says what text to replace, not what the file should
 * end up containing.
 *
 * The difference matters more here than it does in a local editor. A tool that
 * takes whole-file content has to be handed the whole file first, which means
 * the model has to reproduce every line it did not care about — and the failure
 * mode when it does not is silent deletion of the parts it forgot. An anchor
 * can only change what it names. Everything else in the file is untouched by
 * construction, and that is what makes the diff the user is shown short enough
 * to actually read.
 *
 * Nothing here does I/O, so all of it is testable without a host.
 */

export interface Edit {
  readonly old_string: string;
  readonly new_string: string;
  readonly replace_all?: boolean | undefined;
}

export type EditFailure =
  /** The anchor is not in the file. `hint` names the likely reason when there is one. */
  | { readonly kind: 'not-found'; readonly index: number; readonly hint: string | undefined }
  /** The anchor appears more than once and the caller did not say to replace them all. */
  | { readonly kind: 'ambiguous'; readonly index: number; readonly count: number }
  /** The edit would change nothing. */
  | { readonly kind: 'no-op'; readonly index: number }
  /** An empty anchor used as anything other than "create this file". */
  | { readonly kind: 'empty-anchor'; readonly reason: string };

export type EditOutcome =
  | { readonly ok: true; readonly text: string; readonly replacements: number }
  | { readonly ok: false; readonly failure: EditFailure };

/** Non-overlapping occurrences, counted literally — never as a pattern. */
function occurrences(haystack: string, needle: string): number {
  let count = 0;
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) return count;
    count += 1;
    from = at + needle.length;
  }
}

function replaceOnce(haystack: string, needle: string, replacement: string): string {
  const at = haystack.indexOf(needle);
  return haystack.slice(0, at) + replacement + haystack.slice(at + needle.length);
}

function replaceEvery(haystack: string, needle: string, replacement: string): string {
  const parts: string[] = [];
  let from = 0;
  for (;;) {
    const at = haystack.indexOf(needle, from);
    if (at === -1) {
      parts.push(haystack.slice(from));
      return parts.join(replacement);
    }
    parts.push(haystack.slice(from, at));
    from = at + needle.length;
  }
}

/** Every line stripped of leading and trailing blanks, for the indentation hint. */
function ignoringIndentation(text: string): string {
  return text
    .split('\n')
    .map((line) => line.trim())
    .join('\n');
}

/**
 * Why an anchor that looks right did not match.
 *
 * Deliberately only a hint on a refusal, never a fallback that goes ahead
 * anyway. A near-miss replacement is exactly the class of silent wrongness this
 * server exists to refuse — the whole value of showing a diff evaporates if the
 * thing being diffed is a guess.
 */
function whyNotFound(before: string, anchor: string): string | undefined {
  if (before.includes('\r\n') && !anchor.includes('\r\n') && before.replaceAll('\r\n', '\n').includes(anchor)) {
    return 'the file uses CRLF line endings and old_string has bare LF';
  }
  if (anchor.trim() !== '' && ignoringIndentation(before).includes(ignoringIndentation(anchor))) {
    return 'the text is in the file but the indentation differs';
  }
  return undefined;
}

/**
 * Applies the edits in order, each against the result of the last.
 *
 * Sequential rather than all-against-the-original because that is the only
 * order a reader can predict, and because it lets a second edit anchor on text
 * the first one produced.
 *
 * `exists` is what decides whether an empty anchor means "create this file" or
 * is a mistake — see {@linkcode Edit}.
 */
export function applyEdits(before: string, edits: readonly Edit[], exists: boolean): EditOutcome {
  // `ssh_put` is gone, so this is the only way to create a file. It is kept
  // deliberately narrow: an empty anchor is a whole-file write, and a whole-file
  // write to a file that already exists is the blind overwrite this tool exists
  // to replace.
  const empty = edits.findIndex((edit) => edit.old_string === '');
  if (empty !== -1) {
    if (edits.length > 1) {
      return { ok: false, failure: { kind: 'empty-anchor', reason: 'an empty old_string must be the only edit' } };
    }
    if (exists) {
      return {
        ok: false,
        failure: {
          kind: 'empty-anchor',
          reason: 'an empty old_string only means "create this file", and this file already exists',
        },
      };
    }
    return { ok: true, text: edits[0]!.new_string, replacements: 1 };
  }

  let text = before;
  let replacements = 0;

  for (const [index, edit] of edits.entries()) {
    // Caught before counting: an edit that changes nothing would put an empty
    // diff in front of the user, and an empty diff is not a decision.
    if (edit.old_string === edit.new_string) {
      return { ok: false, failure: { kind: 'no-op', index } };
    }

    const count = occurrences(text, edit.old_string);
    if (count === 0) {
      return { ok: false, failure: { kind: 'not-found', index, hint: whyNotFound(text, edit.old_string) } };
    }
    if (count > 1 && edit.replace_all !== true) {
      return { ok: false, failure: { kind: 'ambiguous', index, count } };
    }

    text =
      edit.replace_all === true
        ? replaceEvery(text, edit.old_string, edit.new_string)
        : replaceOnce(text, edit.old_string, edit.new_string);
    replacements += count;
  }

  return { ok: true, text, replacements };
}

/** The first line or two of an anchor, for a message that has to name which edit failed. */
function excerpt(anchor: string): string {
  const lines = anchor.split('\n');
  const head = lines.slice(0, 2).join('\n');
  const shortened = head.length > 120 ? `${head.slice(0, 120)}…` : head;
  return lines.length > 2 ? `${shortened}\n…` : shortened;
}

/**
 * Turns a failure into something the model can act on.
 *
 * Every message quotes the caller's own `old_string` and never the file. The
 * old content is read to draw a diff for the user and for nothing else — an
 * error that leaked a line of `/etc/shadow` back into the transcript would
 * undo that in one call.
 */
export function describeFailure(failure: EditFailure, edits: readonly Edit[], path: string): string {
  if (failure.kind === 'empty-anchor') {
    return `${failure.reason}. Nothing was written to ${path}.`;
  }

  const edit = edits[failure.index]!;
  const which = edits.length > 1 ? `Edit ${failure.index + 1} of ${edits.length}` : 'The edit';

  if (failure.kind === 'no-op') {
    return `${which} has the same old_string and new_string, so it would change nothing. Nothing was written to ${path}.`;
  }

  if (failure.kind === 'ambiguous') {
    return (
      `${which} matches ${failure.count} places in ${path}, so it is ambiguous:\n\n${excerpt(edit.old_string)}\n\n` +
      `Include enough surrounding lines to make it unique, or set replace_all to change every occurrence. ` +
      `Nothing was written.`
    );
  }

  return (
    `${which} does not match anything in ${path}:\n\n${excerpt(edit.old_string)}\n\n` +
    (failure.hint ? `${failure.hint}. ` : 'Read the file with ssh_get and anchor on text that is actually in it. ') +
    `Nothing was written.`
  );
}
