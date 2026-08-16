import { createHmac, randomBytes } from 'node:crypto';
import { findSecretSpans, matchesPath, type SecretPattern } from './patterns.js';

/**
 * The one place a secret value and the model's view of it are kept apart.
 *
 * Everything this server hands the model goes into a transcript, an on-disk
 * session log and a model provider. `ssh_edit` already reads root-owned files
 * without letting a byte of them out, and then `ssh_get` handed the same file
 * over wholesale, because an anchored edit needs an anchor the model can copy.
 *
 * So the anchor stops being the text. A withheld value leaves as an opaque
 * marker, the real one stays here, and `ssh_edit` puts it back before matching.
 * The model can rewrite the line above a password without ever holding it.
 *
 * Two rules carry the weight, and both are enforced here rather than at the
 * call sites:
 *
 * - A marker minted from **command output** can never be written back. Output
 *   is truncated by byte and line budget, so what was captured may be a prefix
 *   of the real value, and putting a prefix into a config file is silent
 *   corruption dressed as a successful edit.
 * - A marker belongs to the host it came from. Without that, reading prod and
 *   editing staging would move a password between machines through a token
 *   nobody could read.
 *
 * What this is not: containment. `ssh_run "base64 /etc/app.conf"` returns the
 * bytes and no pattern will ever see them. It removes the exposure the ordinary
 * read-then-edit workflow *forces*; a model that means to have the value has
 * the same shell it always had. What stops that is the connecting user's own
 * permissions.
 */

export const MARKER_PREFIX = '{{ssh-mcp:secret:';
const VALUE_MARKER = /\{\{ssh-mcp:secret:[0-9a-f]{8,64}\}\}/g;
/** Digest lengths tried in turn, so a collision widens instead of aliasing. */
const MARKER_WIDTHS = [8, 16, 32, 64] as const;
const GENERATE_REQUEST = /\{\{ssh-mcp:generate:(\d{1,3})\}\}/g;
const ASK_REQUEST = /\{\{ssh-mcp:ask:([A-Za-z0-9._-]{1,40})\}\}/g;

/** Long enough to be a password, short enough to be typed if it ever must be. */
const MIN_GENERATED = 8;
const MAX_GENERATED = 128;
/**
 * Below this, a known value is not masked wherever it appears.
 *
 * A three-character password is still withheld where a pattern finds it. What
 * this avoids is rewriting every occurrence of `abc` in unrelated output, which
 * would make the tool useless in exchange for nothing: the value is already in
 * the transcript by the time it is that guessable.
 */
const MIN_MASKABLE = 6;

/** No shell metacharacter, no quote, nothing SQL escapes differently. */
const GENERATED_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._';

interface StoredSecret {
  readonly alias: string;
  readonly value: string;
  /** False for anything learned from command output; see the class comment. */
  writable: boolean;
}

export interface Redaction {
  readonly text: string;
  /** How many values were replaced, for the line that tells the model it happened. */
  readonly count: number;
}

export type Expansion = { readonly ok: true; readonly text: string } | { readonly ok: false; readonly reason: string };

export interface StoreOptions {
  readonly enabled: boolean;
  readonly patterns: readonly SecretPattern[];
  /** Paths whose contents are never returned at all. */
  readonly paths: readonly string[];
  /**
   * How a marker is named, as hex of the requested length.
   *
   * The default is an HMAC under a per-process key. It is an option so the
   * collision path below can be exercised: a branch that only runs once in
   * billions is a branch nobody has ever run, and this one decides whether a
   * marker can come to mean two different passwords.
   */
  readonly markerDigest?: (input: string, length: number) => string;
}

export class SecretStore {
  readonly #options: StoreOptions;
  /** Keyed by marker. */
  readonly #secrets = new Map<string, StoredSecret>();
  /** `alias\0name` for a value the user typed on a page, to its marker. */
  readonly #named = new Map<string, string>();
  /** `scope\0request` for a value this server invented, to its marker. */
  readonly #generated = new Map<string, string>();
  #key = randomBytes(32);

  constructor(options: StoreOptions) {
    this.#options = options;
  }

  get enabled(): boolean {
    return this.#options.enabled;
  }

  /**
   * The marker for a value on a host.
   *
   * An HMAC under a per-process key rather than a hash of the value: a marker
   * travels through the transcript, and a plain digest of a password is an
   * offline guessing target. Keyed by host as well, so the same password on two
   * machines gets two markers and neither can be replayed onto the other.
   */
  #markerFor(alias: string, value: string, length: number): string {
    const input = `${alias}\0${value}`;
    const digest = this.#options.markerDigest
      ? this.#options.markerDigest(input, length)
      : createHmac('sha256', this.#key).update(input, 'utf8').digest('hex').slice(0, length);
    return `${MARKER_PREFIX}${digest}}}`;
  }

  /**
   * The marker for a value, minting one if this is the first sighting.
   *
   * The digest widens on collision rather than trusting 32 bits. Two values
   * sharing a marker is not a redaction bug, it is a *write* bug: the second
   * one would be handed back as the first, and `ssh_edit` would put the wrong
   * password into the file with nobody able to see why. Rare is not the same as
   * impossible, and the cost of ruling it out is one map lookup.
   */
  #keep(alias: string, value: string, writable: boolean): string {
    for (const length of MARKER_WIDTHS) {
      const marker = this.#markerFor(alias, value, length);
      const held = this.#secrets.get(marker);

      if (!held) {
        this.#secrets.set(marker, { alias, value, writable });
        return marker;
      }
      if (held.alias === alias && held.value === value) {
        // Seen in command output first and in a file since: the file read is
        // the one that knows the value is whole, so this only ever widens.
        held.writable ||= writable;
        return marker;
      }
    }

    // 256 bits of HMAC collided with a different value. Failing loudly beats
    // handing back a marker that means something else.
    throw new Error('ssh-mcp: could not mint a unique marker for a withheld value');
  }

  /** True for a path the config says to withhold entirely. */
  isWithheldPath(path: string): boolean {
    return this.#options.enabled && this.#options.paths.some((pattern) => matchesPath(pattern, path));
  }

  /** True if `text` already contains something shaped like one of our markers. */
  containsMarker(text: string): boolean {
    return text.includes(MARKER_PREFIX);
  }

  /**
   * Values already known for this host, masked wherever they appear.
   *
   * Exact, not pattern-based, and that is the point: `ssh_sudo` will expand a
   * marker into a command the user approved, and `echo … > /tmp/x` followed by
   * `cat /tmp/x` would otherwise hand the value straight back — there is no key
   * name on that line for a pattern to catch.
   *
   * Longest first, so a value that contains another is masked whole. Short
   * values are left to the patterns: replacing every `a` in a directory listing
   * would destroy the output to protect a password nobody chose.
   */
  #maskKnown(alias: string, text: string, writable: boolean): { text: string; count: number } {
    const known = [...this.#secrets.entries()]
      .filter(([, held]) => held.alias === alias && held.value.length >= MIN_MASKABLE)
      .sort(([, left], [, right]) => right.value.length - left.value.length);

    let masked = text;
    let count = 0;
    for (const [marker, held] of known) {
      if (!masked.includes(held.value)) continue;
      masked = masked.replaceAll(held.value, marker);
      // Found verbatim in a file read, so it is the whole value after all and
      // may be written back. Without this a value glimpsed in truncated output
      // first would stay unwritable however often the file was read.
      held.writable ||= writable;
      count += 1;
    }

    return { text: masked, count };
  }

  /**
   * Replaces every secret value in `text` with its marker.
   *
   * `writable` says whether what came back can be trusted to be the whole value:
   * true for a file read over SFTP, false for command output.
   */
  redact(alias: string, text: string, options: { writable: boolean }): Redaction {
    if (!this.#options.enabled) return { text, count: 0 };

    const known = this.#maskKnown(alias, text, options.writable);

    // Where the markers already are, so the pattern scan cannot reach inside
    // one. A marker reads `{{ssh-mcp:secret:…}}`, and `secret:` followed by a
    // value is exactly what the built-in patterns look for — left alone, the
    // scan would withhold half of a marker and make it unexpandable.
    const markers: Array<[number, number]> = [];
    VALUE_MARKER.lastIndex = 0;
    for (let match = VALUE_MARKER.exec(known.text); match !== null; match = VALUE_MARKER.exec(known.text)) {
      markers.push([match.index, match.index + match[0].length]);
    }
    const insideMarker = (start: number, end: number): boolean => markers.some(([from, to]) => start < to && end > from);

    const spans = findSecretSpans(known.text, this.#options.patterns).filter((span) => !insideMarker(span.start, span.end));
    if (spans.length === 0) return { text: known.text, count: known.count };

    const parts: string[] = [];
    let from = 0;
    for (const span of spans) {
      parts.push(known.text.slice(from, span.start), this.#keep(alias, known.text.slice(span.start, span.end), options.writable));
      from = span.end;
    }
    parts.push(known.text.slice(from));

    return { text: parts.join(''), count: known.count + spans.length };
  }

  /** True if `text` carries at least one marker this server minted. */
  carriesMarker(text: string): boolean {
    VALUE_MARKER.lastIndex = 0;
    return VALUE_MARKER.test(text);
  }

  /**
   * Puts the real values back.
   *
   * Every refusal names the marker and what to do instead: this is read by the
   * model, and "expansion failed" would only make it guess.
   */
  expand(alias: string, text: string): Expansion {
    let reason: string | undefined;

    const expanded = text.replaceAll(VALUE_MARKER, (marker) => {
      const held = this.#secrets.get(marker);
      if (!held) {
        reason ??=
          `${marker} is not a value this server is holding. Markers do not survive a relock, and they are not ` +
          `guessable — read the file again with ssh_get and use the marker it returns.`;
        return marker;
      }
      if (held.alias !== alias) {
        reason ??= `${marker} was withheld from a different host, and a secret is not moved between machines by a marker.`;
        return marker;
      }
      if (!held.writable) {
        reason ??=
          `${marker} came from command output, which is truncated to a byte and line budget, so it may be only ` +
          `part of the real value. Read the file with ssh_get and use the marker from there.`;
        return marker;
      }
      return held.value;
    });

    return reason === undefined ? { ok: true, text: expanded } : { ok: false, reason };
  }

  /** Names in `{{ssh-mcp:ask:…}}` requests that nobody has typed a value for yet. */
  pendingAsks(alias: string, texts: readonly string[]): string[] {
    const names = new Set<string>();
    for (const text of texts) {
      ASK_REQUEST.lastIndex = 0;
      for (let match = ASK_REQUEST.exec(text); match !== null; match = ASK_REQUEST.exec(text)) {
        const name = match[1]!;
        if (!this.#named.has(`${alias}\0${name}`)) names.add(name);
      }
    }
    return [...names];
  }

  /** Takes a value the user typed on a page. It never passes through the model. */
  remember(alias: string, name: string, value: string): void {
    this.#named.set(`${alias}\0${name}`, this.#keep(alias, value, true));
  }

  #generate(length: number): string {
    const size = Math.min(Math.max(length, MIN_GENERATED), MAX_GENERATED);
    const bytes = randomBytes(size);
    // The alphabet is exactly 64 characters, and 64 divides 256, so `% length`
    // is uniform. A 65th character would quietly bias the first one.
    return Array.from(bytes, (byte) => GENERATED_ALPHABET[byte % GENERATED_ALPHABET.length]).join('');
  }

  /**
   * Resolves `{{ssh-mcp:generate:N}}` and `{{ssh-mcp:ask:name}}` into real
   * values, across a whole call at once.
   *
   * At once, because the same request repeated in one call has to resolve to
   * the same value: a password written into a config file and a connection
   * string in the same edit is one password, not two.
   *
   * `scope` is what makes a generated value stable, and it is load-bearing
   * rather than tidy. `ssh_edit` shows the user a diff and is then called a
   * second time with the same arguments to apply it; if the second call
   * invented a different password, the diff they approved would no longer be
   * the diff on offer, and the call would answer with a fresh approval page
   * forever. The same arguments must resolve to the same value, and different
   * arguments must not.
   *
   * Call `pendingAsks` first. A name nobody has answered is reported rather
   * than left in the text: the alternative is writing the literal
   * `{{ssh-mcp:ask:db-password}}` into a config file as though it were a
   * password, which is the worst outcome this whole mechanism can produce.
   */
  resolveRequests(
    alias: string,
    texts: readonly string[],
    scope: string,
  ): { readonly ok: true; readonly texts: string[]; readonly markers: string[] } | { readonly ok: false; readonly missing: string[] } {
    const markers = new Set<string>();
    const missing = new Set<string>();

    const resolved = texts.map((text) =>
      text
        .replaceAll(GENERATE_REQUEST, (request, length: string) => {
          const key = `${alias}\0${scope}\0${request}`;
          const remembered = this.#generated.get(key);
          const marker = remembered ?? this.#keep(alias, this.#generate(Number(length)), true);
          this.#generated.set(key, marker);
          markers.add(marker);
          return this.#secrets.get(marker)!.value;
        })
        .replaceAll(ASK_REQUEST, (request, name: string) => {
          const marker = this.#named.get(`${alias}\0${name}`);
          if (marker === undefined) {
            missing.add(name);
            return request;
          }
          markers.add(marker);
          return this.#secrets.get(marker)!.value;
        }),
    );

    return missing.size > 0 ? { ok: false, missing: [...missing] } : { ok: true, texts: resolved, markers: [...markers] };
  }

  /** True if any of `texts` asks for a value to be generated or typed. */
  carriesRequest(texts: readonly string[]): boolean {
    // `lastIndex` is reset for every subject: a global regex carries its
    // position between calls, so the second text would be scanned from where
    // the first one matched.
    return texts.some((text) => {
      GENERATE_REQUEST.lastIndex = 0;
      ASK_REQUEST.lastIndex = 0;
      return GENERATE_REQUEST.test(text) || ASK_REQUEST.test(text);
    });
  }

  /**
   * Called when the vault relocks: walking away forgets the values too.
   *
   * The key is replaced as well, so the markers themselves stop meaning
   * anything. A marker left in an old transcript then does not name a live
   * secret even if the same password is read again later.
   */
  clear(): void {
    this.#secrets.clear();
    this.#named.clear();
    this.#generated.clear();
    this.#key = randomBytes(32);
  }
}
