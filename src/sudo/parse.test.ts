import { describe, expect, it } from 'vitest';
import { parseCommandLine, sudoInvocations } from './parse.js';

describe('parseCommandLine', () => {
  it('treats a plain command as simple', () => {
    const parsed = parseCommandLine('systemctl restart nginx');
    expect(parsed.simple).toBe(true);
    expect(parsed.segments).toHaveLength(1);
    expect(parsed.segments[0]!.argv).toEqual(['systemctl', 'restart', 'nginx']);
  });

  it.each([
    ['a; b', ';'],
    ['a && b', '&&'],
    ['a || b', '||'],
    ['a | b', '|'],
    ['a & b', '&'],
    ['a\nb', 'newline'],
  ])('splits on %s', (input, separator) => {
    const parsed = parseCommandLine(input);
    expect(parsed.separators).toContain(separator);
    expect(parsed.segments).toHaveLength(2);
    expect(parsed.simple).toBe(false);
  });

  it('does not split on separators inside quotes', () => {
    const parsed = parseCommandLine('echo "a; b && c"');
    expect(parsed.segments).toHaveLength(1);
    expect(parsed.segments[0]!.argv).toEqual(['echo', 'a; b && c']);
    expect(parsed.simple).toBe(true);
  });

  it('does not split on separators inside single quotes', () => {
    const parsed = parseCommandLine("grep 'a|b' file");
    expect(parsed.segments).toHaveLength(1);
    expect(parsed.segments[0]!.argv).toEqual(['grep', 'a|b', 'file']);
  });

  it.each([
    ['echo $(whoami)', '$('],
    ['echo `whoami`', '`'],
    ['echo ${HOME}', '${'],
    ['echo $HOME', '$'],
    ['cat < file', '<'],
    ['echo x > file', '>'],
  ])('records the expansion in %s', (input, expansion) => {
    const parsed = parseCommandLine(input);
    expect(parsed.expansions).toContain(expansion);
    expect(parsed.simple).toBe(false);
  });

  it('records expansions that would still expand inside double quotes', () => {
    expect(parseCommandLine('echo "$(id)"').simple).toBe(false);
    expect(parseCommandLine('echo "$HOME"').expansions).toContain('$');
  });

  it('treats a single-quoted dollar as literal', () => {
    const parsed = parseCommandLine("echo '$HOME'");
    expect(parsed.simple).toBe(true);
    expect(parsed.segments[0]!.argv).toEqual(['echo', '$HOME']);
  });

  it('honours backslash escapes', () => {
    expect(parseCommandLine('echo a\\;b').segments[0]!.argv).toEqual(['echo', 'a;b']);
  });
});

describe('parseCommandLine redirections', () => {
  const redirections = (line: string) => parseCommandLine(line).segments.flatMap((segment) => segment.redirections);

  it('records a detached target', () => {
    expect(redirections('echo x > /etc/foo')).toEqual([{ operator: '>', target: '/etc/foo', toFd: false }]);
  });

  it('records an attached target', () => {
    expect(redirections('echo x >/etc/foo')).toEqual([{ operator: '>', target: '/etc/foo', toFd: false }]);
  });

  it('records a target glued to the command word', () => {
    expect(redirections('echo a>b')).toEqual([{ operator: '>', target: 'b', toFd: false }]);
  });

  it.each([
    ['echo x >> /var/log/app.log', '>>'],
    ['echo x >| /etc/foo', '>|'],
    ['cat < /etc/hosts', '<'],
    ['cat <<EOF', '<<'],
    ['cat <<< here', '<<<'],
  ])('reads the operator in %s as %s', (line, operator) => {
    expect(redirections(line)[0]!.operator).toBe(operator);
  });

  it('unquotes the target', () => {
    expect(redirections('echo x > "/etc/foo"')[0]!.target).toBe('/etc/foo');
    expect(redirections("echo x > '/etc/foo'")[0]!.target).toBe('/etc/foo');
  });

  it('records several redirections on one segment', () => {
    expect(redirections('cmd > /etc/out 2> /etc/err')).toEqual([
      { operator: '>', target: '/etc/out', toFd: false },
      { operator: '2>', target: '/etc/err', toFd: false },
    ]);
  });

  it('keeps redirections with the segment they belong to', () => {
    const parsed = parseCommandLine('uptime && echo x > /etc/foo');
    expect(parsed.segments[0]!.redirections).toEqual([]);
    expect(parsed.segments[1]!.redirections).toHaveLength(1);
  });

  it('sees no redirection where the shell would see none', () => {
    expect(redirections("echo 'a > b'")).toEqual([]);
    expect(redirections('echo "a > b"')).toEqual([]);
    expect(redirections('echo a \\> b')).toEqual([]);
    expect(redirections('echo x >')).toEqual([]);
  });

  /**
   * `2>&1` and `>&2` duplicate a descriptor; the target is a number, not a
   * path. Marked so the write guard never mistakes one for a file.
   */
  it('marks descriptor duplication as such', () => {
    expect(redirections('ls 2>&1')).toEqual([{ operator: '2>&', target: '1', toFd: true }]);
    expect(redirections('ls >&2')).toEqual([{ operator: '>&', target: '2', toFd: true }]);
  });

  /**
   * Consuming the `&` of `2>&1` means it is no longer read as a background
   * separator — which it never was. The phantom second segment it used to
   * produce was walked by `sudoInvocations` as though it were a command.
   */
  it('no longer mistakes the & of 2>&1 for a separator', () => {
    const parsed = parseCommandLine('ls 2>&1');
    expect(parsed.segments).toHaveLength(1);
    expect(parsed.separators).not.toContain('&');
    // Still not simple: the `>` is still an expansion, so nothing about
    // grantability moves.
    expect(parsed.expansions).toContain('>');
    expect(parsed.simple).toBe(false);
  });

  it('leaves argv, expansions and simple exactly as they were', () => {
    const parsed = parseCommandLine('echo x > /etc/foo');
    // A stored rule is matched against argv, so the operator and its target
    // must stay in it — otherwise this line would present the same argv as a
    // bare `echo x`.
    expect(parsed.segments[0]!.argv).toEqual(['echo', 'x', '>', '/etc/foo']);
    expect(parsed.expansions).toEqual(['>']);
    expect(parsed.simple).toBe(false);

    // `>>` is one operator, and still contributes exactly one expansion.
    expect(parseCommandLine('echo x >> /etc/foo').expansions).toEqual(['>']);
  });
});

describe('sudoInvocations', () => {
  const invoke = (line: string) => sudoInvocations(parseCommandLine(line));

  it('finds nothing when sudo is absent', () => {
    expect(invoke('systemctl status nginx')).toHaveLength(0);
  });

  it('extracts the command sudo would run', () => {
    const [invocation] = invoke('sudo systemctl restart nginx');
    expect(invocation!.argv).toEqual(['systemctl', 'restart', 'nginx']);
    expect(invocation!.flags).toEqual([]);
    expect(invocation!.unparseableFlag).toBeUndefined();
  });

  it('consumes flags that take a value', () => {
    const [invocation] = invoke('sudo -u postgres psql -c "select 1"');
    expect(invocation!.flags).toEqual(['-u', 'postgres']);
    expect(invocation!.argv).toEqual(['psql', '-c', 'select 1']);
  });

  it('consumes standalone flags', () => {
    const [invocation] = invoke('sudo -n -H systemctl status sshd');
    expect(invocation!.flags).toEqual(['-n', '-H']);
    expect(invocation!.argv).toEqual(['systemctl', 'status', 'sshd']);
  });

  it('handles long flags with an inline value', () => {
    const [invocation] = invoke('sudo --user=postgres psql');
    expect(invocation!.argv).toEqual(['psql']);
    expect(invocation!.unparseableFlag).toBeUndefined();
  });

  it('refuses to guess at bundled short flags', () => {
    const [invocation] = invoke('sudo -nS systemctl restart nginx');
    expect(invocation!.unparseableFlag).toBe('-nS');
  });

  it('refuses to guess at unknown long flags', () => {
    const [invocation] = invoke('sudo --made-up-flag systemctl restart nginx');
    expect(invocation!.unparseableFlag).toBe('--made-up-flag');
  });

  it('finds sudo in a later segment, not just the first', () => {
    const found = invoke('echo hi && sudo systemctl restart nginx');
    expect(found).toHaveLength(1);
    expect(found[0]!.argv).toEqual(['systemctl', 'restart', 'nginx']);
  });

  it('finds every sudo call on the line', () => {
    expect(invoke('sudo a; sudo b')).toHaveLength(2);
  });

  it('sees through an absolute path to sudo', () => {
    expect(invoke('/usr/bin/sudo systemctl restart nginx')).toHaveLength(1);
  });

  it('treats doas as sudo for gating purposes', () => {
    expect(invoke('doas systemctl restart nginx')).toHaveLength(1);
  });
});
