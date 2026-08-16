import { execFile } from 'node:child_process';
import { readFile, mkdtemp, writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

/**
 * A real SSH host in a container, and a real client talking to the built server.
 *
 * The unit suite proves that redaction inverts and that the gates refuse what
 * they should. What it cannot reach is the half that decides whether a *host*
 * ends up holding the right bytes: SFTP, `sudo base64`, `sudo cp`, and the
 * ownership and mode of the file afterwards. That needs a host, and a
 * throwaway container is the only kind worth writing a destructive test
 * against.
 *
 * Everything here drives the same surfaces a person would: the MCP client for
 * the tools, and `fetch` against the loopback pages for consent. Nothing
 * reaches inside the server.
 */

const run = promisify(execFile);

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
const DIST = join(ROOT, 'dist', 'main.js');
const DOCKER = join(ROOT, 'docker');
export const FIXTURES = join(ROOT, 'src', 'vault', 'fixtures');
export const PASSPHRASE = 'test-passphrase';

const IMAGE = 'ssh-mcp-integration';

export interface TestHost {
  readonly port: number;
  readonly containerId: string;
  /** Runs a command in the container as root, for asserting on the real files. */
  inspect(command: string): Promise<string>;
  stop(): Promise<void>;
}

/** True when Docker is running and can be talked to. */
export async function dockerAvailable(): Promise<boolean> {
  try {
    await run('docker', ['version', '--format', '{{.Server.Version}}']);
    return true;
  } catch {
    return false;
  }
}

async function reachable(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host: '127.0.0.1', port });
    const finish = (answer: boolean): void => {
      socket.destroy();
      resolve(answer);
    };
    socket.setTimeout(1_000);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
  });
}

/** Builds the image and starts a container with sshd listening on a free port. */
export async function startHost(): Promise<TestHost> {
  const publicKey = (await readFile(join(FIXTURES, 'id_ed25519.pub'), 'utf8')).trim();
  await run('docker', ['build', '--build-arg', `PUBKEY=${publicKey}`, '-t', IMAGE, DOCKER], {
    maxBuffer: 32 * 1024 * 1024,
  });

  const { stdout: created } = await run('docker', ['run', '--rm', '-d', '-p', '127.0.0.1::22', IMAGE]);
  const containerId = created.trim();

  const { stdout: mapping } = await run('docker', ['port', containerId, '22/tcp']);
  const port = Number(mapping.trim().split('\n')[0]!.split(':').pop());

  const host: TestHost = {
    port,
    containerId,
    inspect: async (command) => {
      const { stdout } = await run('docker', ['exec', containerId, 'sh', '-c', command]);
      return stdout;
    },
    stop: async () => {
      await run('docker', ['rm', '-f', containerId]);
    },
  };

  // sshd needs a moment after the container is up, and a test that starts
  // talking too early fails as a connection refused two files away from here.
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (await reachable(port)) return host;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  await host.stop();
  throw new Error(`sshd in ${containerId} never accepted a connection on port ${port}`);
}

export interface Session {
  readonly client: Client;
  readonly configDir: string;
  /** Every text block every tool has returned, for asserting on what leaked. */
  readonly transcript: string[];
  call(name: string, args: Record<string, unknown>): Promise<string>;
  auditLog(): Promise<string>;
  close(): Promise<void>;
}

/** Answers a URL elicitation by driving the page, as a person with a browser would. */
async function submit(url: string, values: Record<string, string>): Promise<void> {
  await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(values).toString(),
  });
}

/**
 * Starts the built server against a config naming only the container, and
 * unlocks it by typing the passphrase on the page.
 */
export async function startSession(host: TestHost, extraConfig = ''): Promise<Session> {
  const configDir = await mkdtemp(join(tmpdir(), 'ssh-mcp-integration-'));
  const configPath = join(configDir, 'ssh-mcp.toml');

  await writeFile(
    configPath,
    `
[vault]
idle-timeout = "60m"

[approval]
open-browser = false
# A fresh port per run, so a test never collides with an ssh-mcp the developer
# happens to be running for real.
page-port = 0

[hosts.box]
host = "127.0.0.1"
port = ${host.port}
user = "deploy"
key = ${JSON.stringify(join(FIXTURES, 'id_ed25519'))}
sudo = "ask"
${extraConfig}
`,
    'utf8',
  );

  const client = new Client(
    { name: 'ssh-mcp-integration', version: '0' },
    { capabilities: { elicitation: { url: {} } }, versionNegotiation: { mode: { pin: '2026-07-28' } as const } },
  );

  client.setRequestHandler('elicitation/create', async (request) => {
    const params = request.params as { url?: string };
    // The only secret this ever answers with is the key passphrase. Anything
    // else the tests drive themselves, so a page that asked for something
    // unexpected fails rather than being fed a passphrase.
    if (params.url?.includes('/unlock/')) await submit(params.url, { passphrase: PASSPHRASE });
    return { action: 'accept' };
  });

  await client.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [DIST],
      env: { ...process.env, SSH_MCP_CONFIG: configPath } as Record<string, string>,
      stderr: 'ignore',
    }),
  );

  const transcript: string[] = [];

  const session: Session = {
    client,
    configDir,
    transcript,
    call: async (name, args) => {
      const result = await client.callTool({ name, arguments: args });
      const content = (result as { content?: Array<{ type: string; text?: string }> }).content ?? [];
      const text = content.map((block) => block.text ?? '').join('\n');
      transcript.push(text);
      return text;
    },
    auditLog: async () => {
      try {
        return await readFile(join(configDir, 'audit.jsonl'), 'utf8');
      } catch {
        return '';
      }
    },
    close: async () => {
      await client.close();
    },
  };

  // The first call unlocks: the elicitation handler above types the passphrase.
  const status = await session.call('ssh_status', {});
  if (status.includes('locked') && !status.includes('unlocked')) {
    await session.call('ssh_run', { host: 'box', cmd: 'true' });
  }

  return session;
}

/** The loopback link an approval or value page was relayed as. */
export function linkIn(text: string): string {
  const url = /http:\/\/127\.0\.0\.1:\d+\/\S+/.exec(text);
  if (!url) throw new Error(`no page link in:\n${text}`);
  return url[0];
}

/** Reads a relayed page, so a test can assert on what the user is shown. */
export async function pageBody(url: string): Promise<string> {
  const response = await fetch(url);
  return response.text();
}

/** Answers a relayed approval page. */
export async function decide(url: string, choice: string): Promise<void> {
  await submit(url, { decision: choice });
}

/** Fills in a relayed page that asks for values. */
export async function provide(url: string, values: Record<string, string>): Promise<void> {
  await submit(url, values);
}
