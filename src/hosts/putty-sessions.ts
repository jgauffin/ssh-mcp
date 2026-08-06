import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

/**
 * Reads PuTTY's saved sessions out of the registry so a host that already
 * works in PuTTY needs no second definition here. Only sessions explicitly
 * named in ssh-mcp.toml are ever looked up.
 */

const run = promisify(execFile);

const SESSIONS_KEY = 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions';

export interface PuttySession {
  readonly name: string;
  readonly hostName: string | undefined;
  readonly user: string | undefined;
  readonly port: number | undefined;
  /** PuTTY's "Private key file for authentication" — usually a .ppk. */
  readonly keyFile: string | undefined;
}

export class PuttyError extends Error {
  override readonly name = 'PuttyError';
}

/** PuTTY escapes session names for the registry; `%20` for space and so on. */
function unmunge(name: string): string {
  return name.replace(/%([0-9A-Fa-f]{2})/g, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
}

async function reg(args: readonly string[]): Promise<string> {
  if (process.platform !== 'win32') {
    throw new PuttyError('PuTTY saved sessions are only readable on Windows.');
  }
  try {
    const { stdout } = await run('reg.exe', [...args], { windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    return stdout;
  } catch (cause) {
    const error = cause as { code?: number | string; stderr?: string };
    // reg.exe exits 1 for "key not found", which is a normal outcome here.
    if (error.code === 1) return '';
    throw new PuttyError(`reg.exe failed: ${error.stderr?.trim() || (cause as Error).message}`);
  }
}

/** Every saved PuTTY session name, decoded. */
export async function listPuttySessions(): Promise<string[]> {
  const stdout = await reg(['query', SESSIONS_KEY]);
  const prefix = 'HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\';
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith(prefix))
    .map((line) => unmunge(line.slice(prefix.length)))
    .filter((name) => name !== 'Default Settings')
    .sort();
}

function parseValues(stdout: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const line of stdout.split(/\r?\n/)) {
    // "    Name    REG_SZ    data" — data may itself contain runs of spaces.
    const match = /^\s{4,}(\S+)\s{4,}(REG_\w+)\s{4,}(.*)$/.exec(line);
    if (!match) continue;
    values.set(match[1]!.toLowerCase(), match[3]!.trimEnd());
  }
  return values;
}

/**
 * Looks up one saved session by its display name. Returns `undefined` when no
 * such session exists — the caller turns that into a clear config error.
 */
export async function resolvePuttySession(name: string): Promise<PuttySession | undefined> {
  // Rather than reimplementing PuTTY's escaping rules we list the subkeys and
  // match on the decoded name, which cannot drift from what PuTTY wrote.
  const stdout = await reg(['query', SESSIONS_KEY]);
  const prefix = 'HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\';
  const subkey = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith(prefix))
    .find((line) => unmunge(line.slice(prefix.length)) === name);

  if (!subkey) return undefined;

  const values = parseValues(await reg(['query', subkey]));
  const portRaw = values.get('portnumber');
  // REG_DWORD arrives as "0x16".
  const port = portRaw === undefined ? undefined : Number.parseInt(portRaw, portRaw.startsWith('0x') ? 16 : 10);

  return {
    name,
    hostName: values.get('hostname') || undefined,
    user: values.get('username') || undefined,
    port: port !== undefined && Number.isInteger(port) && port > 0 ? port : undefined,
    keyFile: values.get('publickeyfile') || undefined,
  };
}
