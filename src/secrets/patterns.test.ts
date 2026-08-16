import { describe, expect, it } from 'vitest';
import { compilePattern, compilePatterns, findSecretSpans, matchesPath } from './patterns.js';

const BUILT_IN = compilePatterns([]).patterns;

/** The values a scan would withhold, in the order they appear. */
const found = (text: string, extra: readonly string[] = []): string[] => {
  const { patterns } = compilePatterns(extra);
  return findSecretSpans(text, patterns).map((span) => text.slice(span.start, span.end));
};

describe('findSecretSpans', () => {
  it('a_bare_assignment_is_a_secret', () => {
    expect(found('db_password = hunter2\nport = 5432')).toEqual(['hunter2']);
  });

  it('a_quoted_value_is_a_secret_without_its_quotes', () => {
    expect(found('  "ClientSecret": "s3cr3t",')).toEqual(['s3cr3t']);
    expect(found("api_key: 'abc123'")).toEqual(['abc123']);
  });

  it('a_connection_string_password_ends_at_the_semicolon', () => {
    expect(found('ConnectionString = Server=db;Password=hunter2;Database=app')).toEqual(['hunter2']);
  });

  it('the_password_half_of_a_url_is_a_secret', () => {
    expect(found('upstream = postgres://app:hunter2@db.internal:5432/app')).toEqual(['hunter2']);
  });

  it('a_private_key_is_withheld_whole', () => {
    const key = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz\naC1rZXk=\n-----END OPENSSH PRIVATE KEY-----';
    expect(found(`# id\n${key}\n`)).toEqual([key]);
  });

  it('a_setting_that_only_mentions_a_password_is_not_one', () => {
    // Withholding these would cost the model what it needs to reason about the
    // file and protect nothing: there is no secret on either line.
    expect(found('password_required = true\nauth_token_enabled = yes\npassword_retries = 3')).toEqual([]);
  });

  it('a_value_naming_an_environment_variable_is_not_a_secret', () => {
    expect(found('password = $DB_PASSWORD\nsecret = ${VAULT_SECRET}')).toEqual([]);
  });

  it('a_key_with_no_value_is_left_alone', () => {
    expect(found('password =\ntoken = ""')).toEqual([]);
  });

  it('two_patterns_matching_one_value_produce_one_span', () => {
    // The quoted and the bare pattern both reach for this line; a span inside
    // a span would end up as a marker inside a marker.
    const spans = findSecretSpans('password = "hunter2"', BUILT_IN);
    expect(spans).toHaveLength(1);
  });

  it('a_config_pattern_extends_the_built_in_set', () => {
    expect(found('ldap_bind_pw = topsecret', [String.raw`(?i)^\s*ldap_bind_pw\s*=\s*(.+)$`])).toEqual(['topsecret']);
  });
});

describe('compilePatterns', () => {
  it('a_pattern_without_a_capture_group_is_dropped_with_a_reason', () => {
    const { patterns, problems } = compilePatterns(['bind_pw\\s*=\\s*.+']);
    expect(patterns).toHaveLength(BUILT_IN.length);
    expect(problems[0]).toMatch(/capture group/);
  });

  it('a_pattern_that_does_not_compile_costs_only_itself', () => {
    const { patterns, problems } = compilePatterns(['(unclosed', String.raw`pw=(.+)`]);
    expect(patterns).toHaveLength(BUILT_IN.length + 1);
    expect(problems).toHaveLength(1);
  });

  it('a_leading_case_insensitive_flag_is_honoured', () => {
    expect(compilePattern(String.raw`(?i)bind_pw=(.+)`).regex.flags).toContain('i');
    expect(found('BIND_PW=topsecret', [String.raw`(?i)bind_pw=(.+)`])).toEqual(['topsecret']);
  });
});

describe('matchesPath', () => {
  it('a_pattern_without_a_separator_matches_the_file_name_anywhere', () => {
    expect(matchesPath('id_rsa', '/home/deploy/.ssh/id_rsa')).toBe(true);
    expect(matchesPath('id_rsa', '/home/deploy/.ssh/id_rsa.pub')).toBe(false);
  });

  it('a_star_stops_at_a_separator_and_a_double_star_crosses_it', () => {
    expect(matchesPath('/etc/app/*.env', '/etc/app/prod.env')).toBe(true);
    expect(matchesPath('/etc/app/*.env', '/etc/app/live/prod.env')).toBe(false);
    expect(matchesPath('/etc/app/**.env', '/etc/app/live/prod.env')).toBe(true);
  });

  it('a_dot_in_a_pattern_is_a_dot', () => {
    expect(matchesPath('/etc/a.conf', '/etc/axconf')).toBe(false);
  });
});
