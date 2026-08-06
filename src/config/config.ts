import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { parse as parseToml } from 'smol-toml';
import { z } from 'zod';

/**
 * The config file is the entire attack surface of this server. Nothing reaches
 * SSH that is not named here: no host, no key, no sudo permission. The model
 * cannot add to it, because no tool takes a hostname, user, port or key path —
 * only an alias defined below.
 */

const DURATION = /^(\d+)\s*(s|m|h)$/;

const durationMs = z.string().transform((value, ctx) => {
  const match = DURATION.exec(value.trim());
  if (!match) {
    ctx.addIssue({ code: 'custom', message: `expected a duration like "30s", "60m" or "2h", got ${JSON.stringify(value)}` });
    return z.NEVER;
  }
  const amount = Number(match[1]);
  const unit = match[2] as 's' | 'm' | 'h';
  const scale = unit === 's' ? 1_000 : unit === 'm' ? 60_000 : 3_600_000;
  return amount * scale;
});

const hostSchema = z
  .object({
    /** "ssh-config:<name>" or "putty:<name>" — import connection details from an existing entry. */
    from: z.string().optional(),
    host: z.string().optional(),
    user: z.string().optional(),
    port: z.number().int().min(1).max(65535).optional(),
    /** Path to a private key: OpenSSH or PuTTY .ppk. */
    key: z.string().optional(),
    /** "off" forbids sudo on this host outright; "ask" runs it through the approval gate. */
    sudo: z.enum(['off', 'ask']).default('ask'),
    /**
     * "guard" refuses in-place file edits in ssh_run and ssh_sudo and points at
     * ssh_edit, which shows the user a diff; "off" lets them through.
     *
     * A lever a person can pull and the model cannot: there is no tool
     * parameter for it, and the refusals never mention it.
     */
    'file-writes': z.enum(['guard', 'off']).default('guard'),
    description: z.string().optional(),
  })
  .strict();

const fileSchema = z
  .object({
    vault: z
      .object({
        'idle-timeout': durationMs.optional(),
      })
      .strict()
      .optional(),
    approval: z
      .object({
        /** Force Claude Code to show its permission dialog, with the command in it, on every ssh_run. */
        'confirm-every-command': z.boolean().optional(),
        /** Open the unlock page in the default browser instead of only printing its link. */
        'open-browser': z.boolean().optional(),
      })
      .strict()
      .optional(),
    hosts: z.record(z.string(), hostSchema).optional(),
  })
  .strict();

const DEFAULT_IDLE_TIMEOUT_MS = 60 * 60 * 1000;

export interface HostConfig {
  readonly alias: string;
  /** Source to import connection details from, e.g. `ssh-config:prod-1`. */
  readonly from: string | undefined;
  readonly host: string | undefined;
  readonly user: string | undefined;
  readonly port: number | undefined;
  readonly key: string | undefined;
  readonly sudo: 'off' | 'ask';
  readonly fileWrites: 'guard' | 'off';
  readonly description: string | undefined;
}

export interface Config {
  readonly configPath: string;
  /** Sibling files (sudo-policy.txt, audit.jsonl) live here. */
  readonly configDir: string;
  readonly idleTimeoutMs: number;
  /** When true, every `ssh_run` shows Claude Code's permission dialog with the command in it. */
  readonly confirmEveryCommand: boolean;
  /** When true, the unlock page is opened in the default browser as well as linked. */
  readonly openBrowser: boolean;
  readonly hosts: readonly HostConfig[];
}

export class ConfigError extends Error {
  override readonly name = 'ConfigError';
}

/** Expands a leading `~` and resolves relative paths against `baseDir`. */
export function expandPath(value: string, baseDir: string): string {
  if (value === '~') return homedir();
  if (value.startsWith('~/') || value.startsWith('~\\')) return join(homedir(), value.slice(2));
  return isAbsolute(value) ? value : resolve(baseDir, value);
}

/** Default config location, overridable with SSH_MCP_CONFIG. */
export function defaultConfigPath(): string {
  const fromEnv = process.env['SSH_MCP_CONFIG'];
  if (fromEnv && fromEnv.trim() !== '') return resolve(fromEnv);
  return join(homedir(), '.ssh-mcp', 'ssh-mcp.toml');
}

export const SAMPLE_CONFIG = `# ssh-mcp.toml — every host this server may ever reach.
# Entries in ~/.ssh/config or PuTTY that are not named here do not exist to it.

[vault]
idle-timeout = "60m"     # relock (and drop sudo grants) after this much idle time

[approval]
# Show Claude Code's permission dialog, with the full command in it, before every
# run. Useful while you are learning what the assistant actually does.
confirm-every-command = false

[hosts.prod-1]
from = "ssh-config:prod-1"   # import HostName/User/Port/IdentityFile from ~/.ssh/config
sudo = "ask"

[hosts.build]
from = "putty:Build Server"  # import from a saved PuTTY session
sudo = "ask"

[hosts.lab]                  # or spell it out inline
host = "192.168.1.9"
user = "root"
key  = "~/.ssh/id_ed25519"
sudo = "off"                 # sudo refused outright on this host

[hosts.scratch]
host = "10.0.0.9"
user = "dev"
key  = "~/.ssh/id_ed25519"
# ssh_run and ssh_sudo normally refuse in-place edits (sed -i, tee, redirection
# onto an absolute path) and point at ssh_edit, which shows you a diff first.
# "off" lets them through on this host.
file-writes = "off"
`;

export async function loadConfig(path: string = defaultConfigPath()): Promise<Config> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new ConfigError(
        `No config at ${path}.\n\nCreate it (or point SSH_MCP_CONFIG elsewhere) with something like:\n\n${SAMPLE_CONFIG}`,
      );
    }
    throw new ConfigError(`Cannot read ${path}: ${(cause as Error).message}`);
  }

  let parsed: unknown;
  try {
    parsed = parseToml(raw);
  } catch (cause) {
    throw new ConfigError(`${path} is not valid TOML: ${(cause as Error).message}`);
  }

  const result = fileSchema.safeParse(parsed);
  if (!result.success) {
    const problems = result.error.issues.map((issue) => `  ${issue.path.join('.') || '(root)'}: ${issue.message}`);
    throw new ConfigError(`${path} is not a valid ssh-mcp config:\n${problems.join('\n')}`);
  }

  const hosts = Object.entries(result.data.hosts ?? {}).map(([alias, entry]): HostConfig => {
    if (!entry.from && !entry.host) {
      throw new ConfigError(`${path}: host "${alias}" needs either "from" (ssh-config:… / putty:…) or an inline "host".`);
    }
    return {
      alias,
      from: entry.from,
      host: entry.host,
      user: entry.user,
      port: entry.port,
      key: entry.key,
      sudo: entry.sudo,
      fileWrites: entry['file-writes'],
      description: entry.description,
    };
  });

  if (hosts.length === 0) {
    throw new ConfigError(`${path} defines no hosts. Add at least one [hosts.<alias>] section.`);
  }

  return {
    configPath: path,
    configDir: dirname(path),
    idleTimeoutMs: result.data.vault?.['idle-timeout'] ?? DEFAULT_IDLE_TIMEOUT_MS,
    confirmEveryCommand: result.data.approval?.['confirm-every-command'] ?? false,
    openBrowser: result.data.approval?.['open-browser'] ?? true,
    hosts,
  };
}
