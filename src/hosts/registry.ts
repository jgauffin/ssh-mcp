import { expandPath, type Config, type HostConfig } from '../config/config.js';
import { resolvePuttySession } from './putty-sessions.js';
import { resolveSshConfig } from './ssh-config.js';

/**
 * The closed world. Every alias here was named by the user in ssh-mcp.toml;
 * anything else is not reachable, because no tool accepts a hostname, user,
 * port or key path — only an alias from this registry.
 */

export interface ResolvedHost {
  readonly alias: string;
  readonly host: string;
  readonly user: string;
  readonly port: number;
  /** Absolute path to an OpenSSH or PuTTY private key. */
  readonly keyPath: string;
  readonly sudo: 'off' | 'ask';
  /** Whether ssh_run and ssh_sudo refuse in-place file edits on this host. */
  readonly fileWrites: 'guard' | 'off';
  readonly description: string | undefined;
  /** Where the connection details came from, for the host listing. */
  readonly source: string;
}

export class HostError extends Error {
  override readonly name = 'HostError';
}

async function importFrom(spec: string, alias: string): Promise<Partial<ResolvedHost> & { source: string }> {
  const separator = spec.indexOf(':');
  if (separator < 0) {
    throw new HostError(`host "${alias}": from = ${JSON.stringify(spec)} must look like "ssh-config:<name>" or "putty:<name>".`);
  }
  const kind = spec.slice(0, separator).trim();
  const name = spec.slice(separator + 1).trim();

  if (kind === 'ssh-config') {
    const entry = await resolveSshConfig(name);
    if (!entry) throw new HostError(`host "${alias}": no entry for "${name}" in ~/.ssh/config.`);
    return {
      source: `ssh-config:${name}`,
      ...(entry.hostName !== undefined ? { host: entry.hostName } : {}),
      ...(entry.user !== undefined ? { user: entry.user } : {}),
      ...(entry.port !== undefined ? { port: entry.port } : {}),
      ...(entry.identityFile !== undefined ? { keyPath: entry.identityFile } : {}),
    };
  }

  if (kind === 'putty') {
    const session = await resolvePuttySession(name);
    if (!session) throw new HostError(`host "${alias}": no saved PuTTY session named "${name}".`);
    return {
      source: `putty:${name}`,
      ...(session.hostName !== undefined ? { host: session.hostName } : {}),
      ...(session.user !== undefined ? { user: session.user } : {}),
      ...(session.port !== undefined ? { port: session.port } : {}),
      ...(session.keyFile !== undefined ? { keyPath: session.keyFile } : {}),
    };
  }

  throw new HostError(`host "${alias}": unknown source "${kind}". Use "ssh-config:<name>" or "putty:<name>".`);
}

async function resolveOne(entry: HostConfig, configDir: string): Promise<ResolvedHost> {
  const imported = entry.from ? await importFrom(entry.from, entry.alias) : { source: 'inline' };

  // Inline values always win over anything imported.
  const host = entry.host ?? imported.host;
  const user = entry.user ?? imported.user;
  const port = entry.port ?? imported.port ?? 22;
  const keyPath = entry.key ?? imported.keyPath;

  const missing: string[] = [];
  if (!host) missing.push('host');
  if (!user) missing.push('user');
  if (!keyPath) missing.push('key');
  if (missing.length > 0) {
    throw new HostError(
      `host "${entry.alias}": missing ${missing.join(', ')}. ` +
        `Add them to the [hosts.${entry.alias}] section${entry.from ? ` — ${imported.source} did not supply them` : ''}. ` +
        `This server authenticates with keys only; there is no password option.`,
    );
  }

  return {
    alias: entry.alias,
    host: host!,
    user: user!,
    port,
    keyPath: expandPath(keyPath!, configDir),
    sudo: entry.sudo,
    fileWrites: entry.fileWrites,
    description: entry.description,
    source: imported.source,
  };
}

export class HostRegistry {
  private constructor(private readonly hosts: ReadonlyMap<string, ResolvedHost>) {}

  /** Resolves every configured alias up front, so a broken config fails loudly at startup. */
  static async load(config: Config): Promise<HostRegistry> {
    const resolved = new Map<string, ResolvedHost>();
    for (const entry of config.hosts) {
      resolved.set(entry.alias, await resolveOne(entry, config.configDir));
    }
    return new HostRegistry(resolved);
  }

  aliases(): string[] {
    return [...this.hosts.keys()].sort();
  }

  all(): ResolvedHost[] {
    return this.aliases().map((alias) => this.hosts.get(alias)!);
  }

  /** Throws for anything not in the config — the model cannot invent a target. */
  require(alias: string): ResolvedHost {
    const host = this.hosts.get(alias);
    if (!host) {
      const known = this.aliases();
      throw new HostError(
        `Unknown host "${alias}". This server only reaches hosts named in its config: ${known.join(', ')}.`,
      );
    }
    return host;
  }
}

/** The plain-text host listing shown to the model. No JSON — it is a table. */
export function formatHosts(hosts: readonly ResolvedHost[]): string {
  if (hosts.length === 0) return 'No hosts configured.';

  const rows = hosts.map((host) => [
    host.alias,
    `${host.user}@${host.host}${host.port === 22 ? '' : `:${host.port}`}`,
    // Only the non-default is shown: a guard that is on everywhere is not news,
    // but a host where it has been turned off must not be able to hide.
    `${host.sudo === 'off' ? 'sudo:no' : 'sudo:ask'}${host.fileWrites === 'off' ? ' writes:unguarded' : ''}`,
    host.description ?? host.source,
  ]);

  const widths = [0, 1, 2].map((column) => Math.max(...rows.map((row) => row[column]!.length)));
  return rows
    .map((row) => `${row[0]!.padEnd(widths[0]!)}  ${row[1]!.padEnd(widths[1]!)}  ${row[2]!.padEnd(widths[2]!)}  ${row[3]!}`)
    .join('\n');
}
