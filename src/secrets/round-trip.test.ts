import { describe, expect, it } from 'vitest';
import { compilePatterns } from './patterns.js';
import { SecretStore } from './store.js';

/**
 * The invariant every write depends on: `expand(redact(text)) === text`, byte
 * for byte.
 *
 * `ssh_edit` matches the model's anchors against the file after expanding them.
 * If expansion is not the exact inverse of redaction, an anchor either fails to
 * match — noisy, harmless — or matches and writes back something that is not
 * what was there. The second one is a config file quietly corrupted by a tool
 * whose whole purpose is to be safer than `sed -i`.
 *
 * So these are not examples. Each case is a shape that could break the
 * inversion: a value that is a substring of another, a value that looks like a
 * marker, regex metacharacters, CRLF, non-ASCII, and the same value in several
 * places.
 */

const store = (): SecretStore =>
  new SecretStore({ enabled: true, patterns: compilePatterns([]).patterns, paths: [] });

/** Reads a file, then anchors on what came back. Both halves, as the tools do them. */
const roundTrip = (text: string, options: { writable?: boolean } = {}): string => {
  const held = store();
  const withheld = held.redact('prod', text, { writable: options.writable ?? true });
  const back = held.expand('prod', withheld.text);
  if (!back.ok) throw new Error(back.reason);
  return back.text;
};

const CASES: ReadonlyArray<readonly [string, string]> = [
  ['a plain assignment', 'db_password = hunter2\nport = 5432\n'],
  ['no secret at all', '# nothing to see\nshared_buffers = 128MB\n'],
  ['the same value twice', 'password = hunter2\nbackup_password = hunter2\n'],
  [
    'a value that is a prefix of another',
    'password = hunter\nadmin_password = hunter2\nroot_password = hunter22\n',
  ],
  ['regex metacharacters in the value', String.raw`password = a.*b[c]$d\e+f?g`],
  ['a value that looks like a template', 'password = {{not-a-marker}}\n'],
  ['a value with a brace run', 'password = }}}}{{{{\n'],
  ['CRLF line endings', 'db_password = hunter2\r\nport = 5432\r\n'],
  ['no trailing newline', 'db_password = hunter2'],
  ['non-ASCII around and inside the value', '# lösenord\npassword = hämtä2Ω\nport = 5432\n'],
  ['a quoted value with an escaped quote inside', '"password": "he said \\"hi\\"",\n'],
  ['a URL and an assignment naming the same value', 'url = postgres://app:hunter2@db/app\npassword = hunter2\n'],
  ['a private key beside an assignment', '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\ntoken = abc123\n'],
  ['an empty file', ''],
  ['a value on the last line with no separator after it', 'a = 1\npassword = hunter2'],
  ['several distinct secrets', 'password = one\ntoken = two\napi_key = three\nclient_secret = four\n'],
  ['a value containing an equals sign', 'password = a=b=c\n'],
  ['a JSON connection string', '{"Db":"Host=db;Username=app;Password=p@ss w0rd;"}\n'],
  ['tabs as separators', 'password\t=\thunter2\n'],
  ['a comment that mentions a password', '# password = example\npassword = real\n'],
];

describe('redaction is exactly reversible', () => {
  it.each(CASES)('%s', (_name, text) => {
    expect(roundTrip(text)).toBe(text);
  });

  it.each(CASES)('%s, read twice', (_name, text) => {
    // The second read of a file meets values it already knows, and masks them
    // itself before any pattern runs. That path has to invert too.
    const held = store();
    held.redact('prod', text, { writable: true });
    const second = held.redact('prod', text, { writable: true });

    expect(held.expand('prod', second.text)).toEqual({ ok: true, text });
  });

  it('holds for a file assembled from every case at once', () => {
    const everything = CASES.map(([, text]) => text).join('\n');
    expect(roundTrip(everything)).toBe(everything);
  });

  it('holds when a value was seen in truncated output first', () => {
    // The dangerous ordering: `ssh_run` captured a prefix, and the file has the
    // whole thing. Whatever the marker stands for, putting it back must give
    // the file's own bytes.
    const held = store();
    held.redact('prod', 'db_password = hunt', { writable: false });

    const file = 'db_password = hunter2\nport = 5432\n';
    const withheld = held.redact('prod', file, { writable: true });
    expect(held.expand('prod', withheld.text)).toEqual({ ok: true, text: file });
  });
});

describe('every withheld value is recoverable', () => {
  it.each(CASES)('%s leaves nothing unexpandable behind', (_name, text) => {
    const held = store();
    const withheld = held.redact('prod', text, { writable: true });

    // A marker that will not expand is an anchor the model can never use, and
    // the failure would only surface as "does not match anything in the file".
    expect(held.expand('prod', withheld.text)).toMatchObject({ ok: true });
  });

  it('no marker is ever nested inside another', () => {
    const held = store();
    const withheld = held.redact('prod', 'password = hunter2\ntoken = abc123\n', { writable: true });

    expect(withheld.text).not.toMatch(/\{\{ssh-mcp:secret:[^}]*\{\{/);
  });

  it('a secret is never left in the text it was redacted from', () => {
    for (const [, text] of CASES) {
      const held = store();
      const withheld = held.redact('prod', text, { writable: true });
      if (withheld.count === 0) continue;

      // Whatever was replaced must be gone: a marker beside a surviving copy of
      // the same value protects nothing.
      const back = held.expand('prod', withheld.text);
      const values = back.ok ? back.text : '';
      expect(values).toBe(text);
      expect(withheld.text).not.toBe(text);
    }
  });
});

describe('a marker never stands for two different values', () => {
  const markerIn = (text: string): string => /\{\{ssh-mcp:secret:[0-9a-f]+\}\}/.exec(text)![0];

  /**
   * A digest that collides at eight hex characters and separates at sixteen.
   *
   * The real one is HMAC-SHA256, which collides once in billions, so the branch
   * that widens the marker would otherwise never have run — and the failure it
   * guards against is `ssh_edit` writing one value where another was expected,
   * silently, with an approved diff that looked right.
   */
  const collidingDigest = (input: string, length: number): string =>
    `aaaaaaaa${(/alpha/.test(input) ? '1' : '2').repeat(56)}`.slice(0, length);

  const colliding = (): SecretStore =>
    new SecretStore({
      enabled: true,
      patterns: compilePatterns([]).patterns,
      paths: [],
      markerDigest: collidingDigest,
    });

  it('a second value colliding at eight characters gets a wider marker', () => {
    const held = colliding();
    const alpha = markerIn(held.redact('prod', 'password = alpha\n', { writable: true }).text);
    const beta = markerIn(held.redact('prod', 'password = beta\n', { writable: true }).text);

    expect(alpha).not.toBe(beta);
    expect(held.expand('prod', alpha)).toEqual({ ok: true, text: 'alpha' });
    expect(held.expand('prod', beta)).toEqual({ ok: true, text: 'beta' });
  });

  it('the same value still gets the same marker when another one collided with it', () => {
    const held = colliding();
    const first = markerIn(held.redact('prod', 'password = alpha\n', { writable: true }).text);
    held.redact('prod', 'password = beta\n', { writable: true });
    const again = markerIn(held.redact('prod', 'backup_password = alpha\n', { writable: true }).text);

    expect(again).toBe(first);
  });

  it('a digest that cannot separate values at any width fails loudly rather than aliasing', () => {
    // Every value hashes the same at every width, so the four widths fill up
    // and the fifth value has nowhere to go. Handing back a marker that already
    // means something else is the one outcome not on the table.
    const held = new SecretStore({
      enabled: true,
      patterns: compilePatterns([]).patterns,
      paths: [],
      markerDigest: (_input, length) => 'a'.repeat(length),
    });

    for (const value of ['alpha', 'beta', 'gamma', 'delta']) {
      held.redact('prod', `password = ${value}\n`, { writable: true });
    }

    expect(() => held.redact('prod', 'password = epsilon\n', { writable: true })).toThrow(/unique marker/);
  });

  it('every distinct value keeps its own marker under the real digest', () => {
    const held = store();
    for (const value of ['alpha', 'beta', 'gamma', 'delta', 'alpha']) {
      const marker = markerIn(held.redact('prod', `password = ${value}\n`, { writable: true }).text);
      expect(held.expand('prod', marker)).toEqual({ ok: true, text: value });
    }
  });
});

describe('a request nobody answered is refused, never written', () => {
  it('an unanswered ask does not resolve to its own request text', () => {
    const outcome = store().resolveRequests('prod', ['password = {{ssh-mcp:ask:db-password}}\n'], 'scope');

    expect(outcome).toEqual({ ok: false, missing: ['db-password'] });
  });

  it('an answered ask resolves and reports no missing names', () => {
    const held = store();
    held.remember('prod', 'db-password', 'typed-by-hand');

    expect(held.resolveRequests('prod', ['password = {{ssh-mcp:ask:db-password}}\n'], 'scope')).toMatchObject({
      ok: true,
      texts: ['password = typed-by-hand\n'],
    });
  });
});

/**
 * `ssh_edit` is called twice for one change: once to draw the diff, once to
 * apply it after the user has answered. A generated password that differed
 * between those two rounds would mean the approved diff was never the diff on
 * offer, and the call would answer with a fresh page every time — an edit that
 * can never be completed, only re-approved.
 */
describe('a generated value survives the round trip through the approval page', () => {
  const resolve = (held: SecretStore, scope: string): string => {
    const outcome = held.resolveRequests('prod', ['password = {{ssh-mcp:generate:32}}'], scope);
    if (!outcome.ok) throw new Error(`unresolved: ${outcome.missing.join(', ')}`);
    return outcome.texts[0]!;
  };

  it('the same call resolves to the same password on the second round', () => {
    const held = store();
    const scope = '/etc/app.conf\0[{"old_string":"a","new_string":"b"}]';

    expect(resolve(held, scope)).toBe(resolve(held, scope));
  });

  it('a different edit gets a password of its own', () => {
    const held = store();

    expect(resolve(held, '/etc/app.conf\0first')).not.toBe(resolve(held, '/etc/app.conf\0second'));
  });

  it('nothing survives a relock', () => {
    const held = store();
    const scope = '/etc/app.conf\0same';
    const first = resolve(held, scope);

    held.clear();

    expect(resolve(held, scope)).not.toBe(first);
  });
});
