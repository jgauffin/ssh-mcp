import { describe, expect, it } from 'vitest';
import { compilePatterns } from './patterns.js';
import { SecretStore, type StoreOptions } from './store.js';

const store = (options: Partial<StoreOptions> = {}): SecretStore =>
  new SecretStore({ enabled: true, patterns: compilePatterns([]).patterns, paths: [], ...options });

const CONF = 'host = db.internal\ndb_password = hunter2\nport = 5432\n';
const MARKER = /\{\{ssh-mcp:secret:[0-9a-f]{8}\}\}/;

/** The marker a file read would hand the model for its one secret. */
const markerIn = (text: string): string => MARKER.exec(text)![0];

describe('redact', () => {
  it('a_password_assignment_is_replaced_by_a_marker', () => {
    const withheld = store().redact('prod', CONF, { writable: true });

    expect(withheld.count).toBe(1);
    expect(withheld.text).not.toContain('hunter2');
    expect(withheld.text).toContain('db_password = {{ssh-mcp:secret:');
    // Everything that is not a secret is byte-identical; an edit anchors on it.
    expect(withheld.text).toContain('host = db.internal\n');
    expect(withheld.text).toContain('port = 5432\n');
  });

  it('the_same_value_gets_the_same_marker_within_a_process', () => {
    const held = store();
    const first = held.redact('prod', CONF, { writable: true });
    const second = held.redact('prod', 'password = hunter2', { writable: true });

    expect(markerIn(second.text)).toBe(markerIn(first.text));
  });

  it('the_same_value_on_two_hosts_gets_two_markers', () => {
    const held = store();
    const prod = held.redact('prod', CONF, { writable: true });
    const lab = held.redact('lab', CONF, { writable: true });

    expect(markerIn(lab.text)).not.toBe(markerIn(prod.text));
  });

  it('a_known_value_is_masked_even_where_no_pattern_would_find_it', () => {
    // The escape this closes: ssh_sudo expands a marker into an approved
    // command, `echo … > /tmp/x` puts the value on a line of its own, and
    // there is no key name there for a pattern to catch.
    const held = store();
    const marker = markerIn(held.redact('prod', CONF, { writable: true }).text);

    const output = held.redact('prod', 'hunter2\n', { writable: false });
    expect(output.text).toBe(`${marker}\n`);
  });

  it('a_known_value_is_not_masked_on_another_host', () => {
    const held = store();
    held.redact('prod', CONF, { writable: true });
    expect(held.redact('lab', 'hunter2\n', { writable: false }).text).toBe('hunter2\n');
  });

  it('a_marker_is_never_given_a_marker_of_its_own', () => {
    const held = store();
    const marker = markerIn(held.redact('prod', CONF, { writable: true }).text);

    // The same file read twice: the second pass sees a line whose value is
    // already a marker, and a marker withheld again could not be expanded.
    const again = held.redact('prod', `db_password = ${marker}\n`, { writable: true });
    expect(again.text).toBe(`db_password = ${marker}\n`);
    expect(held.expand('prod', again.text)).toEqual({ ok: true, text: 'db_password = hunter2\n' });
  });

  it('redaction_switched_off_returns_the_file_unchanged', () => {
    const held = store({ enabled: false });
    expect(held.redact('prod', CONF, { writable: true })).toEqual({ text: CONF, count: 0 });
  });
});

describe('expand', () => {
  it('an_anchor_carrying_a_marker_matches_the_real_file', () => {
    const held = store();
    const marker = markerIn(held.redact('prod', CONF, { writable: true }).text);

    const anchor = held.expand('prod', `db_password = ${marker}\nport = 5432`);
    expect(anchor).toEqual({ ok: true, text: 'db_password = hunter2\nport = 5432' });
  });

  it('a_marker_minted_for_one_host_is_refused_on_another', () => {
    const held = store();
    const marker = markerIn(held.redact('prod', CONF, { writable: true }).text);

    const outcome = held.expand('lab', `db_password = ${marker}`);
    expect(outcome).toMatchObject({ ok: false });
    expect(outcome.ok === false && outcome.reason).toMatch(/different host/);
  });

  it('a_marker_from_command_output_cannot_be_written_back', () => {
    // Output is truncated to a byte and line budget, so what was captured may
    // be a prefix, and a prefix written into a config is silent corruption.
    const held = store();
    const marker = markerIn(held.redact('prod', 'db_password = hunter2', { writable: false }).text);

    const outcome = held.expand('prod', marker);
    expect(outcome).toMatchObject({ ok: false });
    expect(outcome.ok === false && outcome.reason).toMatch(/command output/);
  });

  it('a_value_seen_in_output_first_becomes_writable_once_the_file_is_read', () => {
    const held = store();
    held.redact('prod', 'db_password = hunter2', { writable: false });
    const marker = markerIn(held.redact('prod', CONF, { writable: true }).text);

    expect(held.expand('prod', marker)).toEqual({ ok: true, text: 'hunter2' });
  });

  it('an_invented_marker_expands_to_nothing_and_says_why', () => {
    const outcome = store().expand('prod', '{{ssh-mcp:secret:deadbeef}}');
    expect(outcome).toMatchObject({ ok: false });
    expect(outcome.ok === false && outcome.reason).toMatch(/not a value this server is holding/);
  });

  it('markers_are_forgotten_when_the_vault_relocks', () => {
    const held = store();
    const marker = markerIn(held.redact('prod', CONF, { writable: true }).text);

    held.clear();

    expect(held.expand('prod', marker)).toMatchObject({ ok: false });
    // And the marker itself stops meaning anything: reading the same value
    // again does not resurrect the one left behind in an old transcript.
    expect(markerIn(held.redact('prod', CONF, { writable: true }).text)).not.toBe(marker);
  });
});

describe('resolveRequests', () => {
  /** Every call in one test is one edit, so they share a scope. */
  const SCOPE = '/etc/app.conf\0one-edit';

  const resolved = (held: SecretStore, texts: readonly string[], scope = SCOPE) => {
    const outcome = held.resolveRequests('prod', texts, scope);
    if (!outcome.ok) throw new Error(`unresolved: ${outcome.missing.join(', ')}`);
    return outcome;
  };

  it('a_generated_value_carries_no_shell_or_quoting_metacharacters', () => {
    const { texts } = resolved(store(), ['password = {{ssh-mcp:generate:32}}']);
    const value = texts[0]!.replace('password = ', '');

    expect(value).toHaveLength(32);
    expect(value).toMatch(/^[A-Za-z0-9._]+$/);
  });

  it('the_same_generate_request_in_one_call_is_one_value', () => {
    // A password written into a config file and into the connection string
    // beside it is one password, not two.
    const { texts } = resolved(store(), ['pw = {{ssh-mcp:generate:16}}', 'url = u:{{ssh-mcp:generate:16}}@db']);
    expect(texts[0]!.replace('pw = ', '')).toBe(texts[1]!.replace('url = u:', '').replace('@db', ''));
  });

  it('a_generated_value_is_held_under_a_marker_for_the_rest_of_the_session', () => {
    const held = store();
    const { texts, markers } = resolved(held, ['{{ssh-mcp:generate:20}}']);

    expect(markers).toHaveLength(1);
    expect(held.expand('prod', markers[0]!)).toEqual({ ok: true, text: texts[0] });
  });

  it('a_value_the_user_typed_resolves_by_name_and_never_by_value', () => {
    const held = store();
    expect(held.pendingAsks('prod', ['pw = {{ssh-mcp:ask:db-password}}'])).toEqual(['db-password']);

    held.remember('prod', 'db-password', 'typed-by-hand');

    expect(held.pendingAsks('prod', ['pw = {{ssh-mcp:ask:db-password}}'])).toEqual([]);
    expect(resolved(held, ['pw = {{ssh-mcp:ask:db-password}}']).texts).toEqual(['pw = typed-by-hand']);
  });

  it('an_asked_name_is_scoped_to_its_host', () => {
    const held = store();
    held.remember('prod', 'db-password', 'typed-by-hand');
    expect(held.pendingAsks('lab', ['{{ssh-mcp:ask:db-password}}'])).toEqual(['db-password']);
  });
});

describe('carriesMarker', () => {
  it('a_command_naming_a_withheld_value_is_recognised', () => {
    const held = store();
    const marker = markerIn(held.redact('prod', CONF, { writable: true }).text);

    expect(held.carriesMarker(`psql -c "ALTER USER app PASSWORD '${marker}'"`)).toBe(true);
    expect(held.carriesMarker('systemctl restart nginx')).toBe(false);
  });

  it('a_file_already_containing_the_marker_prefix_is_recognised', () => {
    expect(store().containsMarker('note = see {{ssh-mcp:secret:whatever')).toBe(true);
  });
});

describe('isWithheldPath', () => {
  it('a_path_listed_in_the_config_is_never_returned', () => {
    const held = store({ paths: ['/etc/app/*.env', 'id_rsa'] });

    expect(held.isWithheldPath('/etc/app/prod.env')).toBe(true);
    expect(held.isWithheldPath('/home/deploy/.ssh/id_rsa')).toBe(true);
    expect(held.isWithheldPath('/etc/app/prod.conf')).toBe(false);
  });

  it('nothing_is_withheld_by_path_when_redaction_is_off', () => {
    expect(store({ enabled: false, paths: ['id_rsa'] }).isWithheldPath('/root/id_rsa')).toBe(false);
  });
});
