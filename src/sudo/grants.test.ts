import { existsSync } from 'node:fs';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { SudoGrants } from './grants.js';

let policyPath: string;

beforeEach(async () => {
  policyPath = join(await mkdtemp(join(tmpdir(), 'ssh-mcp-')), 'sudo-policy.txt');
});

describe('policy file', () => {
  it('treats a missing file as no rules', async () => {
    const grants = new SudoGrants(policyPath);
    expect(await grants.load()).toEqual({ rules: 0, problems: [] });
    expect(grants.find('prod', ['systemctl', 'restart', 'nginx'])).toBeUndefined();
  });

  it('reads rules, comments and blank lines', async () => {
    await writeFile(
      policyPath,
      ['# a comment', '', 'prod-1  systemctl restart *', '*       tail *', ''].join('\n'),
      'utf8',
    );
    const grants = new SudoGrants(policyPath);
    expect((await grants.load()).rules).toBe(2);

    expect(grants.find('prod-1', ['systemctl', 'restart', 'nginx'])).toBeDefined();
    expect(grants.find('prod-2', ['systemctl', 'restart', 'nginx'])).toBeUndefined();
    expect(grants.find('anything', ['tail', '/var/log/syslog'])).toBeDefined();
  });

  it('reports a broken rule instead of silently dropping it', async () => {
    await writeFile(policyPath, 'prod-1  systemctl ** restart\n', 'utf8');
    const { rules, problems } = await new SudoGrants(policyPath).load();
    expect(rules).toBe(0);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('line 1');
  });

  it('rejects a rule that mixes a wildcard into an argument, rather than never matching it', async () => {
    await writeFile(policyPath, 'prod-1  tail /var/log/*\n', 'utf8');
    const { rules, problems } = await new SudoGrants(policyPath).load();
    expect(rules).toBe(0);
    expect(problems[0]).toContain('whole arguments only');
  });

  // Nothing in the server writes this file. A permanent grant of root should
  // take a human typing it, so `ssh_sudo` prints the line and stops there.
  it('is never written to by the server', async () => {
    const grants = new SudoGrants(policyPath);
    await grants.load();
    expect('grantForever' in grants).toBe(false);
    expect(existsSync(policyPath)).toBe(false);
  });

  it('honours a hand-written rule with either tabs or spaces', async () => {
    await writeFile(policyPath, 'prod-1\tsystemctl restart *\nprod-2    apt update\n', 'utf8');
    const grants = new SudoGrants(policyPath);
    expect((await grants.load()).rules).toBe(2);
    expect(grants.find('prod-1', ['systemctl', 'restart', 'nginx'])).toBeDefined();
    expect(grants.find('prod-2', ['apt', 'update'])).toBeDefined();
  });
});

describe('session grants', () => {
  it('applies only to the host they were given for', async () => {
    const grants = new SudoGrants(policyPath);
    grants.grantForSession('prod-1', ['systemctl', 'restart', '*'], 60_000);

    expect(grants.find('prod-1', ['systemctl', 'restart', 'nginx'])).toBeDefined();
    expect(grants.find('prod-2', ['systemctl', 'restart', 'nginx'])).toBeUndefined();
  });

  it('expires', async () => {
    const grants = new SudoGrants(policyPath);
    grants.grantForSession('prod-1', ['systemctl', 'restart', '*'], -1);
    expect(grants.find('prod-1', ['systemctl', 'restart', 'nginx'])).toBeUndefined();
  });

  it('is dropped wholesale when the vault relocks', async () => {
    const grants = new SudoGrants(policyPath);
    grants.grantForSession('prod-1', ['systemctl', 'restart', '*'], 60_000);
    grants.clearSession();
    expect(grants.find('prod-1', ['systemctl', 'restart', 'nginx'])).toBeUndefined();
  });

  it('survives clearSession when it came from the policy file', async () => {
    await writeFile(policyPath, 'prod-1  systemctl restart *\n', 'utf8');
    const grants = new SudoGrants(policyPath);
    await grants.load();
    grants.clearSession();
    expect(grants.find('prod-1', ['systemctl', 'restart', 'nginx'])).toBeDefined();
  });
});
