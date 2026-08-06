import { readdir, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';

/**
 * A deliberately small reader for ~/.ssh/config: enough to resolve the four
 * settings we need for an alias the user has explicitly allowed in
 * ssh-mcp.toml. It is not a general-purpose ssh_config implementation and
 * makes no attempt to evaluate `Match` blocks.
 */

export interface SshConfigEntry {
  readonly hostName: string | undefined;
  readonly user: string | undefined;
  readonly port: number | undefined;
  readonly identityFile: string | undefined;
}

interface Block {
  readonly patterns: readonly string[];
  readonly settings: ReadonlyMap<string, string>;
}

const INTERESTING = new Set(['hostname', 'user', 'port', 'identityfile']);

export function defaultSshConfigPath(): string {
  return join(homedir(), '.ssh', 'config');
}

/** Splits a config line into keyword and value, honouring `key value`, `key=value` and quotes. */
function splitLine(line: string): [string, string] | undefined {
  const trimmed = line.trim();
  if (trimmed === '' || trimmed.startsWith('#')) return undefined;

  const separator = /[\s=]+/.exec(trimmed);
  if (!separator || separator.index === 0) return undefined;

  const keyword = trimmed.slice(0, separator.index).toLowerCase();
  let value = trimmed.slice(separator.index + separator[0].length).trim();
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    value = value.slice(1, -1);
  }
  return [keyword, value];
}

/** Splits a value into whitespace-separated tokens, honouring double quotes. */
function tokenize(value: string): string[] {
  const tokens: string[] = [];
  const pattern = /"([^"]*)"|(\S+)/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(value)) !== null) {
    tokens.push(match[1] ?? match[2] ?? '');
  }
  return tokens;
}

/** OpenSSH host pattern matching: `*` (any run), `?` (one char), leading `!` negates. */
export function matchesHostPattern(patterns: readonly string[], alias: string): boolean {
  let matched = false;
  for (const pattern of patterns) {
    const negated = pattern.startsWith('!');
    const body = negated ? pattern.slice(1) : pattern;
    if (!globMatches(body, alias)) continue;
    if (negated) return false;
    matched = true;
  }
  return matched;
}

function globMatches(pattern: string, value: string): boolean {
  const source = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${source}$`).test(value);
}

async function expandInclude(spec: string, relativeTo: string): Promise<string[]> {
  const raw = spec.startsWith('~/') || spec.startsWith('~\\') ? join(homedir(), spec.slice(2)) : spec;
  const absolute = isAbsolute(raw) ? raw : resolve(relativeTo, raw);
  const name = basename(absolute);
  if (!name.includes('*') && !name.includes('?')) return [absolute];

  const directory = dirname(absolute);
  try {
    const names = await readdir(directory);
    return names.filter((candidate) => globMatches(name, candidate)).sort().map((candidate) => join(directory, candidate));
  } catch {
    return [];
  }
}

async function readBlocks(path: string, seen: Set<string>): Promise<Block[]> {
  const key = resolve(path).toLowerCase();
  if (seen.has(key)) return [];
  seen.add(key);

  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch {
    return [];
  }

  const blocks: Block[] = [];
  // Settings before the first `Host` line apply to every host, as OpenSSH does.
  let patterns: string[] = ['*'];
  let settings = new Map<string, string>();
  let skipping = false;

  const flush = (): void => {
    if (settings.size > 0) blocks.push({ patterns, settings });
  };

  for (const line of text.split(/\r?\n/)) {
    const parsed = splitLine(line);
    if (!parsed) continue;
    const [keyword, value] = parsed;

    if (keyword === 'host') {
      flush();
      patterns = tokenize(value);
      settings = new Map();
      skipping = false;
      continue;
    }

    // We cannot evaluate Match conditions, so everything inside one is ignored
    // rather than silently misapplied.
    if (keyword === 'match') {
      flush();
      patterns = [];
      settings = new Map();
      skipping = true;
      continue;
    }

    if (skipping) continue;

    if (keyword === 'include') {
      flush();
      const carried = patterns;
      settings = new Map();
      for (const token of tokenize(value)) {
        for (const included of await expandInclude(token, dirname(path))) {
          blocks.push(...(await readBlocks(included, seen)));
        }
      }
      patterns = carried;
      continue;
    }

    if (INTERESTING.has(keyword) && !settings.has(keyword)) {
      settings.set(keyword, value);
    }
  }

  flush();
  return blocks;
}

/**
 * Resolves one alias against ~/.ssh/config. Returns `undefined` when the file
 * has nothing to say about it — first value wins across matching blocks, as
 * OpenSSH resolves.
 */
export async function resolveSshConfig(alias: string, path: string = defaultSshConfigPath()): Promise<SshConfigEntry | undefined> {
  const blocks = await readBlocks(path, new Set());
  const resolved = new Map<string, string>();
  let anyMatch = false;

  for (const block of blocks) {
    if (!matchesHostPattern(block.patterns, alias)) continue;
    anyMatch = true;
    for (const [keyword, value] of block.settings) {
      if (!resolved.has(keyword)) resolved.set(keyword, value);
    }
  }

  if (!anyMatch) return undefined;

  const port = resolved.get('port');
  const parsedPort = port === undefined ? undefined : Number.parseInt(port, 10);
  return {
    hostName: resolved.get('hostname'),
    user: resolved.get('user'),
    port: parsedPort !== undefined && Number.isInteger(parsedPort) ? parsedPort : undefined,
    identityFile: resolved.get('identityfile'),
  };
}
