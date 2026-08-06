import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { matchesHostPattern, resolveSshConfig } from './ssh-config.js';

let configPath: string;

beforeEach(async () => {
  configPath = join(await mkdtemp(join(tmpdir(), 'ssh-mcp-cfg-')), 'config');
});

const write = (text: string) => writeFile(configPath, text, 'utf8');

describe('matchesHostPattern', () => {
  it('matches literally', () => {
    expect(matchesHostPattern(['prod-1'], 'prod-1')).toBe(true);
    expect(matchesHostPattern(['prod-1'], 'prod-2')).toBe(false);
  });

  it('supports * and ?', () => {
    expect(matchesHostPattern(['prod-*'], 'prod-1')).toBe(true);
    expect(matchesHostPattern(['prod-?'], 'prod-12')).toBe(false);
  });

  it('lets a negation win', () => {
    expect(matchesHostPattern(['prod-*', '!prod-9'], 'prod-9')).toBe(false);
    expect(matchesHostPattern(['prod-*', '!prod-9'], 'prod-1')).toBe(true);
  });
});

describe('resolveSshConfig', () => {
  it('returns undefined for an unknown alias with no wildcard block', async () => {
    await write('Host prod-1\n  HostName 10.0.0.1\n');
    expect(await resolveSshConfig('other', configPath)).toBeUndefined();
  });

  it('reads the four settings it cares about', async () => {
    await write('Host prod-1\n  HostName 10.0.0.1\n  User deploy\n  Port 2222\n  IdentityFile ~/.ssh/prod\n');
    expect(await resolveSshConfig('prod-1', configPath)).toEqual({
      hostName: '10.0.0.1',
      user: 'deploy',
      port: 2222,
      identityFile: '~/.ssh/prod',
    });
  });

  it('accepts key=value and quoted values', async () => {
    await write('Host prod-1\n  HostName=10.0.0.1\n  User="deploy user"\n');
    const entry = await resolveSshConfig('prod-1', configPath);
    expect(entry?.hostName).toBe('10.0.0.1');
    expect(entry?.user).toBe('deploy user');
  });

  it('gives the first matching value priority, as OpenSSH does', async () => {
    await write('Host prod-1\n  User first\nHost *\n  User fallback\n  Port 2200\n');
    const entry = await resolveSshConfig('prod-1', configPath);
    expect(entry?.user).toBe('first');
    expect(entry?.port).toBe(2200);
  });

  it('applies settings that appear before the first Host line', async () => {
    await write('Port 2020\nHost prod-1\n  HostName 10.0.0.1\n');
    expect((await resolveSshConfig('prod-1', configPath))?.port).toBe(2020);
  });

  it('ignores Match blocks rather than misapplying them', async () => {
    await write('Match exec "true"\n  User wrong\nHost prod-1\n  HostName 10.0.0.1\n');
    const entry = await resolveSshConfig('prod-1', configPath);
    expect(entry?.user).toBeUndefined();
    expect(entry?.hostName).toBe('10.0.0.1');
  });

  it('follows Include', async () => {
    const included = join(configPath, '..', 'extra');
    await writeFile(included, 'Host prod-1\n  HostName included.example\n', 'utf8');
    await write(`Include ${included}\n`);
    expect((await resolveSshConfig('prod-1', configPath))?.hostName).toBe('included.example');
  });

  it('survives an Include cycle', async () => {
    await write(`Include ${configPath}\nHost prod-1\n  HostName 10.0.0.1\n`);
    expect((await resolveSshConfig('prod-1', configPath))?.hostName).toBe('10.0.0.1');
  });
});
