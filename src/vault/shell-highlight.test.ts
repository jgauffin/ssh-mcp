import { describe, expect, it } from 'vitest';
import { shellTokens, type ShellTokenKind } from './shell-highlight.js';

const kindsOf = (line: string, kind: ShellTokenKind): string[] =>
  shellTokens(line)
    .filter((token) => token.kind === kind)
    .map((token) => token.text);

describe('shellTokens', () => {
  it.each([
    'sudo apt update && sudo systemctl restart nginx',
    `sudo -u postgres psql -d kiwipow_server -At -c "DO \\$\\$ DECLARE r record; END \\$\\$"`,
    "echo 'unterminated",
    'cat /var/log/x 2>&1 | tail -50; echo $HOME ${PATH} $',
    'trailing backslash \\',
  ])('the_pieces_join_back_into_the_exact_line: %s', (line) => {
    expect(shellTokens(line).map((token) => token.text).join('')).toBe(line);
  });

  it('the_command_after_sudo_and_after_each_separator_is_marked_as_a_command', () => {
    const line = 'sudo journalctl -u nginx | tail -30; FOO=1 uptime';
    expect(kindsOf(line, 'sudo')).toEqual(['sudo']);
    expect(kindsOf(line, 'command')).toEqual(['journalctl', 'tail', 'uptime']);
    expect(kindsOf(line, 'operator')).toEqual(['|', ';']);
  });

  it('the_value_of_a_sudo_option_is_not_mistaken_for_the_command', () => {
    const line = 'sudo -u postgres psql -c "SELECT 1"';
    expect(kindsOf(line, 'command')).toEqual(['psql']);
    expect(kindsOf(line, 'flag')).toEqual(['-u', '-c']);
    expect(kindsOf(line, 'string')).toEqual(['"SELECT 1"']);
  });

  it('a_separator_inside_quotes_stays_part_of_the_string', () => {
    const line = `psql -c "SELECT 1; SELECT 2" && echo 'a | b'`;
    expect(kindsOf(line, 'operator')).toEqual(['&&']);
    expect(kindsOf(line, 'string')).toEqual(['"SELECT 1; SELECT 2"', "'a | b'"]);
  });
});
