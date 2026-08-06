/**
 * A unified diff, for the approval page and nowhere else.
 *
 * Hand-rolled rather than taken off the shelf, for the same reason the shell
 * parser and the consent server are: this is display-only code with one
 * property that has to hold, and that property is *soundness*, not minimality.
 * The bytes that get written come from `applyEdits`, which splices literal
 * strings; a diff that picks a clumsy alignment is a cosmetic wart, but a diff
 * whose `-` lines are not really consecutive lines of the old file would be a
 * lie told to someone in the middle of consenting. Emitting hunks straight out
 * of the two line arrays makes that sound by construction, whatever the
 * alignment turns out to be, and `diff.test.ts` asserts it over random input.
 */

export interface UnifiedDiff {
  /** The rendered diff. Empty when the two texts are identical. */
  readonly text: string;
  readonly added: number;
  readonly removed: number;
  /** True when the diff was too long to render in full. */
  readonly truncated: boolean;
}

export interface DiffOptions {
  /** Used to build the default `---`/`+++` headers. */
  readonly label?: string | undefined;
  readonly beforeLabel?: string | undefined;
  readonly afterLabel?: string | undefined;
  /** Unchanged lines kept either side of a change. Defaults to 3. */
  readonly context?: number | undefined;
  /** Body lines to render before giving up. Defaults to 600. */
  readonly maxLines?: number | undefined;
}

const DEFAULT_CONTEXT = 3;
const DEFAULT_MAX_LINES = 600;

/**
 * Above this the O(n·m) table is not worth building.
 *
 * Only reachable when a change spans thousands of lines *after* the common
 * prefix and suffix are trimmed, which for an anchored edit means the model
 * rewrote most of the file. The fallback below is still sound; it just stops
 * trying to align anything.
 */
const MAX_TABLE_CELLS = 4_000_000;

const NO_NEWLINE = '\\ No newline at end of file';

interface Lines {
  readonly lines: readonly string[];
  readonly newlineAtEof: boolean;
}

function toLines(text: string): Lines {
  if (text === '') return { lines: [], newlineAtEof: true };
  const lines = text.split('\n');
  if (lines[lines.length - 1] === '') {
    lines.pop();
    return { lines, newlineAtEof: true };
  }
  return { lines, newlineAtEof: false };
}

type OpKind = 'ctx' | 'del' | 'add';
interface Op {
  readonly kind: OpKind;
  readonly text: string;
}

/**
 * The longest-common-subsequence alignment of two line arrays.
 *
 * The table holds the LCS length of the two *suffixes*, so the walk runs
 * forwards and the ops come out in file order with no reversal.
 */
function align(before: readonly string[], after: readonly string[]): Op[] {
  const n = before.length;
  const m = after.length;

  if (n === 0 || m === 0 || n * m > MAX_TABLE_CELLS) {
    return [
      ...before.map((text): Op => ({ kind: 'del', text })),
      ...after.map((text): Op => ({ kind: 'add', text })),
    ];
  }

  const width = m + 1;
  const table = new Int32Array((n + 1) * width);
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      table[i * width + j] =
        before[i] === after[j]
          ? table[(i + 1) * width + j + 1]! + 1
          : Math.max(table[(i + 1) * width + j]!, table[i * width + j + 1]!);
    }
  }

  const ops: Op[] = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && before[i] === after[j]) {
      ops.push({ kind: 'ctx', text: before[i]! });
      i += 1;
      j += 1;
      // Strictly greater, so a tie takes the deletion: a replaced line has to
      // render as `-` then `+`, which is what every reader of a diff expects.
    } else if (j < m && (i === n || table[i * width + j + 1]! > table[(i + 1) * width + j]!)) {
      ops.push({ kind: 'add', text: after[j]! });
      j += 1;
    } else {
      ops.push({ kind: 'del', text: before[i]! });
      i += 1;
    }
  }
  return ops;
}

/** How many leading, then trailing, lines the two arrays share. */
function commonEdges(before: readonly string[], after: readonly string[]): { prefix: number; suffix: number } {
  const shortest = Math.min(before.length, after.length);

  let prefix = 0;
  while (prefix < shortest && before[prefix] === after[prefix]) prefix += 1;

  let suffix = 0;
  while (
    suffix < shortest - prefix &&
    before[before.length - 1 - suffix] === after[after.length - 1 - suffix]
  ) {
    suffix += 1;
  }

  return { prefix, suffix };
}

export function unifiedDiff(before: string, after: string, options: DiffOptions = {}): UnifiedDiff {
  if (before === after) return { text: '', added: 0, removed: 0, truncated: false };

  const context = options.context ?? DEFAULT_CONTEXT;
  const maxLines = options.maxLines ?? DEFAULT_MAX_LINES;
  const a = toLines(before);
  const b = toLines(after);

  // Trimming the shared head and tail first is what keeps this cheap: a
  // one-line change in a four-thousand-line config leaves a table of one cell.
  const { prefix, suffix } = commonEdges(a.lines, b.lines);
  const ops: Op[] = [
    ...a.lines.slice(0, prefix).map((text): Op => ({ kind: 'ctx', text })),
    ...align(a.lines.slice(prefix, a.lines.length - suffix), b.lines.slice(prefix, b.lines.length - suffix)),
    ...a.lines.slice(a.lines.length - suffix).map((text): Op => ({ kind: 'ctx', text })),
  ];

  let added = 0;
  let removed = 0;
  // Where each op sits in each file, so a hunk header can name real line numbers.
  const aAt: number[] = [];
  const bAt: number[] = [];
  let aLine = 0;
  let bLine = 0;
  for (const op of ops) {
    aAt.push(aLine);
    bAt.push(bLine);
    if (op.kind !== 'add') aLine += 1;
    if (op.kind !== 'del') bLine += 1;
    if (op.kind === 'add') added += 1;
    if (op.kind === 'del') removed += 1;
  }

  // The trailing-newline change is a real change with no changed line to hang
  // off, so it has to be noticed here or a diff of "added a final newline"
  // would render as nothing at all.
  const newlineOnly = added === 0 && removed === 0;
  if (newlineOnly && a.newlineAtEof === b.newlineAtEof) {
    return { text: '', added: 0, removed: 0, truncated: false };
  }

  const changed = ops.map((op) => op.kind !== 'ctx');
  const ranges: Array<{ start: number; end: number }> = [];
  for (let index = 0; index < ops.length; index += 1) {
    if (!changed[index]) continue;
    let end = index;
    while (end + 1 < ops.length && changed[end + 1]) end += 1;
    const start = Math.max(0, index - context);
    const stop = Math.min(ops.length, end + 1 + context);
    const last = ranges[ranges.length - 1];
    // Abutting as well as overlapping: two hunks with no gap between them read
    // as one change, and git merges them for the same reason.
    if (last && start <= last.end) last.end = stop;
    else ranges.push({ start, end: stop });
    index = end;
  }

  // A pure trailing-newline change leaves nothing marked, so show the tail.
  if (ranges.length === 0 && ops.length > 0) {
    ranges.push({ start: Math.max(0, ops.length - context), end: ops.length });
  }

  const label = options.label ?? 'file';
  const out: string[] = [`--- ${options.beforeLabel ?? `a/${label}`}`, `+++ ${options.afterLabel ?? `b/${label}`}`];
  let truncated = false;

  outer: for (const range of ranges) {
    let aCount = 0;
    let bCount = 0;
    for (let index = range.start; index < range.end; index += 1) {
      if (ops[index]!.kind !== 'add') aCount += 1;
      if (ops[index]!.kind !== 'del') bCount += 1;
    }
    const aStart = aCount === 0 ? aAt[range.start]! : aAt[range.start]! + 1;
    const bStart = bCount === 0 ? bAt[range.start]! : bAt[range.start]! + 1;
    out.push(`@@ -${aStart},${aCount} +${bStart},${bCount} @@`);

    for (let index = range.start; index < range.end; index += 1) {
      if (out.length >= maxLines) {
        truncated = true;
        break outer;
      }
      const op = ops[index]!;
      out.push(`${op.kind === 'add' ? '+' : op.kind === 'del' ? '-' : ' '}${op.text}`);

      const lastOfA = op.kind !== 'add' && aAt[index]! === a.lines.length - 1;
      const lastOfB = op.kind !== 'del' && bAt[index]! === b.lines.length - 1;
      if ((lastOfA && !a.newlineAtEof) || (lastOfB && !b.newlineAtEof)) out.push(NO_NEWLINE);
    }
  }

  if (truncated) out.push(`… ${added + removed} changed lines in total; too many to show …`);

  return { text: out.join('\n'), added, removed, truncated };
}
