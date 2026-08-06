import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

/**
 * End-to-end against the built server over real stdio.
 *
 * The point of these is the multi-round-trip flow: a locked server must answer
 * a tool call with an `input_required` result, the client must be able to
 * fulfil it and retry, and the signed `requestState` must survive the round
 * trip. None of that can be checked from inside the process.
 */

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'main.js');
const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), 'vault', 'fixtures');

type ElicitRequest = { mode?: string; message: string; url?: string; requestedSchema?: Record<string, unknown> };
type ElicitAnswer = { action: 'accept' | 'decline' | 'cancel'; content?: Record<string, unknown> };

let client: Client;
let elicitations: ElicitRequest[];
let answer: (request: ElicitRequest) => ElicitAnswer | Promise<ElicitAnswer>;

async function start(
  config: string,
  elicitation: Record<string, unknown> = { url: {}, form: {} },
  era: 'modern' | 'legacy' = 'modern',
): Promise<Client> {
  const directory = await mkdtemp(join(tmpdir(), 'ssh-mcp-e2e-'));
  const configPath = join(directory, 'ssh-mcp.toml');
  await writeFile(configPath, config, 'utf8');

  const connected = new Client(
    { name: 'ssh-mcp-test', version: '0' },
    {
      // On 2026-07-28 the elicitation capability is split into sub-modes. A
      // bare `elicitation: {}` declares neither, and this server needs `url`.
      capabilities: { elicitation },
      // Pinned rather than probed, so a silent fallback cannot turn a real
      // regression into a passing test. `legacy` omits the option entirely,
      // which is the SDK default and what Claude Code does — nothing puts a
      // 2026-07-28 byte on the wire unless a client opts in.
      ...(era === 'modern' ? { versionNegotiation: { mode: { pin: '2026-07-28' } as const } } : {}),
    },
  );
  connected.setRequestHandler('elicitation/create', async (request) => {
    const params = request.params as ElicitRequest;
    elicitations.push(params);
    return await answer(params);
  });

  await connected.connect(
    new StdioClientTransport({
      command: process.execPath,
      args: [DIST],
      env: { ...process.env, SSH_MCP_CONFIG: configPath } as Record<string, string>,
      stderr: 'ignore',
    }),
  );
  return connected;
}

const CONFIG = `
[vault]
idle-timeout = "60m"

[approval]
# A test suite must not open browser windows.
open-browser = false

# Port 1 on loopback refuses instantly, so a test that reaches the network
# fails fast and unmistakably instead of hanging on a connect timeout.
[hosts.lab]
host = "127.0.0.1"
port = 1
user = "root"
key = ${JSON.stringify(join(FIXTURES, 'id_ed25519'))}
sudo = "ask"

[hosts.locked-down]
host = "127.0.0.1"
port = 1
user = "deploy"
key = ${JSON.stringify(join(FIXTURES, 'id_rsa'))}
sudo = "off"
description = "sudo refused here"
`;

beforeEach(async () => {
  elicitations = [];
  answer = () => ({ action: 'decline' });
  client = await start(CONFIG);
});

afterEach(async () => {
  await client.close();
});

function textOf(result: unknown): string {
  const content = (result as { content: Array<{ type: string; text?: string }> }).content;
  return content.map((block) => block.text ?? '').join('\n');
}

describe('the tool surface', () => {
  it('offers exactly the eight tools', async () => {
    const { tools } = await client.listTools();
    expect(tools.map((tool) => tool.name).sort()).toEqual([
      'ssh_edit',
      'ssh_get',
      'ssh_hosts',
      'ssh_lock',
      'ssh_ls',
      'ssh_run',
      'ssh_status',
      'ssh_sudo',
    ]);
  });

  /**
   * `ssh_edit` replaced `ssh_put`, and the shape is the point: it takes anchors
   * and not content. A `content` parameter creeping back in would restore the
   * blind overwrite this tool exists to remove — the model would be handed the
   * whole file again, and the user a tool name again.
   */
  it('takes anchors rather than file content', async () => {
    const { tools } = await client.listTools();
    const edit = tools.find((tool) => tool.name === 'ssh_edit')!;
    const schema = edit.inputSchema as {
      properties: { edits: { items: { properties: object } } };
    };

    expect(Object.keys(schema.properties).sort()).toEqual(['edits', 'host', 'path']);
    expect(Object.keys(schema.properties.edits.items.properties).sort()).toEqual([
      'new_string',
      'old_string',
      'replace_all',
    ]);
  });

  it('does not lean on the client prompt for sudo consent', async () => {
    const { tools } = await client.listTools();
    const flagged = tools
      .filter((tool) => tool._meta?.['anthropic/requiresUserInteraction'] === true)
      .map((tool) => tool.name);
    // That prompt gates the call without showing what is in it, so approving it
    // means approving a tool name. The approval page is the gate instead.
    expect(flagged).toEqual([]);
  });

  it('makes an unconfigured host unrepresentable rather than merely rejected', async () => {
    const { tools } = await client.listTools();
    const run = tools.find((tool) => tool.name === 'ssh_run')!;
    const host = (run.inputSchema as { properties: { host: { enum?: string[] } } }).properties.host;

    expect(host.enum).toEqual(['lab', 'locked-down']);
    // There is no parameter through which a hostname could be supplied at all.
    expect(Object.keys((run.inputSchema as { properties: object }).properties).sort()).toEqual([
      'cmd',
      'host',
      'timeout_seconds',
    ]);
  });

  it('declares itself closed-world', async () => {
    const { tools } = await client.listTools();
    for (const tool of tools) {
      expect(tool.annotations?.openWorldHint, tool.name).toBe(false);
    }
  });

  it('publishes the host list as a resource, in plain text', async () => {
    const resource = await client.readResource({ uri: 'ssh://hosts' });
    const contents = resource.contents[0] as { mimeType?: string; text?: string };
    expect(contents.mimeType).toBe('text/plain');
    expect(contents.text).toContain('lab');
    expect(contents.text).toContain('root@127.0.0.1:1');
    expect(contents.text).toContain('sudo:no');
  });
});

describe('locked on every start', () => {
  it('says so before anything has happened', async () => {
    expect(textOf(await client.callTool({ name: 'ssh_status', arguments: {} }))).toContain('locked');
  });

  it('answers a command with a URL elicitation, not a passphrase prompt', async () => {
    // Answer slowly, so this reads as a real human decline rather than a client
    // dismissing the prompt.
    answer = async () => {
      await new Promise((resolve) => setTimeout(resolve, 600));
      return { action: 'decline' };
    };
    const result = await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'uptime' } });

    expect(elicitations).toHaveLength(1);
    // The passphrase must be collected out of band. A form-mode request here
    // would mean the secret travels back through the client.
    expect(elicitations[0]!.mode).toBe('url');
    expect(elicitations[0]!.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+$/);
    expect(elicitations[0]!.message).not.toMatch(/passphrase\W*:/i);
    expect(textOf(result)).toContain('Unlock declined');
  });

  it('relays a link when the client dismisses the unlock prompt without showing it', async () => {
    // The default `answer` declines instantly, which is what a client that
    // cannot render the prompt does.
    const result = textOf(await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'uptime' } }));

    expect(result).toContain('without showing it');
    expect(result).toMatch(/http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/);
  });

  // Confirming in the CLI without submitting the form makes the server wait out
  // its settle window for a POST that never arrives, so this one is slow by
  // design rather than by accident.
  it('stays locked when the user accepts but never submits the page', async () => {
    answer = () => ({ action: 'accept' });
    const result = await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'uptime' } });

    expect(textOf(result)).toContain('not completed');
    expect(textOf(await client.callTool({ name: 'ssh_status', arguments: {} }))).toContain('locked');
  }, 20_000);

  it('gates the file tools too', async () => {
    await client.callTool({ name: 'ssh_ls', arguments: { host: 'lab', path: '/etc' } });
    expect(elicitations).toHaveLength(1);
    expect(elicitations[0]!.mode).toBe('url');
  });

  it('gates ssh_edit before it reads anything', async () => {
    await client.callTool({
      name: 'ssh_edit',
      arguments: { host: 'lab', path: '/etc/hosts', edits: [{ old_string: 'a', new_string: 'b' }] },
    });
    expect(elicitations).toHaveLength(1);
    expect(elicitations[0]!.mode).toBe('url');
  });

  it('answers ssh_hosts without unlocking anything', async () => {
    const result = await client.callTool({ name: 'ssh_hosts', arguments: {} });
    expect(elicitations).toHaveLength(0);
    expect(textOf(result)).toContain('lab');
  });
});

let pageBodies: Array<{ status: number; body: string }>;

/** Answers a URL elicitation by actually driving the page, as a human would. */
function submitting(values: Record<string, string>, options: { nonce?: 'wrong' } = {}) {
  return async (request: ElicitRequest): Promise<ElicitAnswer> => {
    const url = options.nonce === 'wrong' ? `${request.url!.slice(0, -4)}zzzz` : request.url!;
    const page = await fetch(url);
    pageBodies.push({ status: page.status, body: await page.text() });

    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(values).toString(),
    });
    return { action: 'accept' };
  };
}

describe('the unlock page', () => {
  beforeEach(() => {
    pageBodies = [];
  });

  it('unlocks the vault when the passphrase is submitted in the browser', async () => {
    answer = submitting({ passphrase: 'test-passphrase' });
    const result = await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } });

    const status = textOf(await client.callTool({ name: 'ssh_status', arguments: {} }));
    expect(status).toContain('unlocked');
    // Both configured keys share the one passphrase.
    expect(status).toContain('2 key(s)');
    // The command cannot succeed — nothing listens on port 1 — but the failure
    // must be a connection failure, not a lock.
    expect(textOf(result)).toMatch(/cannot connect/i);
  });

  it('serves a password field and says the secret stays local', async () => {
    answer = submitting({ passphrase: 'test-passphrase' });
    await client.callTool({ name: 'ssh_ls', arguments: { host: 'lab', path: '/' } }).catch(() => undefined);

    expect(pageBodies).toHaveLength(1);
    expect(pageBodies[0]!.status).toBe(200);
    expect(pageBodies[0]!.body).toContain('type="password"');
    expect(pageBodies[0]!.body).toContain('never sent to the model');
    // The page must name what is being unlocked, so consent is specific.
    expect(pageBodies[0]!.body).toContain('lab');
  });

  it('serves nothing on a wrong nonce, and the vault stays locked', async () => {
    answer = submitting({ passphrase: 'test-passphrase' }, { nonce: 'wrong' });
    await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } });

    expect(pageBodies[0]!.status).toBe(404);
    expect(textOf(await client.callTool({ name: 'ssh_status', arguments: {} }))).toContain('locked');
  }, 20_000);
});

/**
 * The era Claude Code actually opens with.
 *
 * Everything above pins `2026-07-28`, which is the era the multi-round-trip
 * design targets — and which no shipping Claude Code negotiates. That mismatch
 * is why this suite stayed green while the real client failed three different
 * ways. These tests walk the same ground over a default (2025-era) connection
 * declaring form-only elicitation, which is what Claude Code presents.
 */
describe('on a 2025-era connection, which is what Claude Code opens', () => {
  let legacy: Client;

  beforeEach(async () => {
    pageBodies = [];
    legacy = await start(CONFIG, { form: {} }, 'legacy');
  });

  afterEach(async () => {
    await legacy.close();
  });

  const unlockVia = async (text: string): Promise<void> => {
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(text)![0];
    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'passphrase=test-passphrase',
    });
  };

  it('serves the same eight tools', async () => {
    const { tools } = await legacy.listTools();
    expect(tools).toHaveLength(8);
  });

  it('relays an unlock link rather than erroring, and the link works', async () => {
    const locked = textOf(await legacy.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } }));
    expect(locked).toContain('ssh-mcp is locked');
    expect(locked).toMatch(/http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/);

    await unlockVia(locked);
    expect(textOf(await legacy.callTool({ name: 'ssh_status', arguments: {} }))).toContain('unlocked');
  });

  it('refuses sudo from ssh_run and names ssh_sudo', async () => {
    await unlockVia(textOf(await legacy.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } })));

    const result = textOf(await legacy.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'sudo apt update' } }));
    expect(result).toContain('never runs sudo');
    expect(result).toContain('ssh_sudo');
  });

  // The exact failure seen in the wild: on this era the SDK's legacy shim turns
  // an input request into a push-style `elicitation/create`, which throws when
  // the client has not declared the capability.
  it('never surfaces a capability error from ssh_sudo', async () => {
    await unlockVia(textOf(await legacy.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } })));

    const result = await legacy.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update' } });
    expect(Array.isArray((result as { content: unknown }).content)).toBe(true);
    expect(textOf(result)).not.toContain('did not declare the required capability');
    expect(textOf(result)).not.toContain('elicitation/create');
  });

  it('still enforces the denylist and the closed host world', async () => {
    await unlockVia(textOf(await legacy.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } })));

    expect(textOf(await legacy.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo -s' } }))).toContain(
      'never permitted',
    );
    const { tools } = await legacy.listTools();
    const run = tools.find((tool) => tool.name === 'ssh_run')!;
    expect((run.inputSchema as { properties: { host: { enum?: string[] } } }).properties.host.enum).toEqual([
      'lab',
      'locked-down',
    ]);
  });

  it('echoes the command, so the transcript still records what ran', async () => {
    await unlockVia(textOf(await legacy.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } })));

    const result = textOf(await legacy.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'uptime -p' } }));
    expect(result.split('\n')[0]).toBe('root@lab# uptime -p');
  });
});

describe('seeing what actually ran', () => {
  beforeEach(async () => {
    pageBodies = [];
    answer = submitting({ passphrase: 'test-passphrase' });
    await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } });
  });

  it('echoes the command as a shell prompt line, so the transcript is a terminal log', async () => {
    const result = textOf(await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'uptime -p' } }));
    // root gets `#`, as every Linux tutorial writes it.
    expect(result.split('\n')[0]).toBe('root@lab# uptime -p');
  });

  it('uses $ for a non-root user', async () => {
    const result = textOf(
      await client.callTool({ name: 'ssh_run', arguments: { host: 'locked-down', cmd: 'id -un' } }),
    );
    expect(result.split('\n')[0]).toBe('deploy@locked-down$ id -un');
  });

  it('offers the learning prompts as commands', async () => {
    const { prompts } = await client.listPrompts();
    expect(prompts.map((prompt) => prompt.name).sort()).toEqual(['audit', 'explain']);
  });

  it('the explain prompt asks for a per-flag walkthrough', async () => {
    const prompt = await client.getPrompt({ name: 'explain', arguments: {} });
    const text = prompt.messages.map((message) => (message.content as { text?: string }).text ?? '').join('\n');
    expect(text).toContain('explain every flag');
    expect(text).toContain('Do not run anything new');
  });

  it('the explain prompt can be pointed at one topic', async () => {
    const prompt = await client.getPrompt({ name: 'explain', arguments: { focus: 'journalctl' } });
    const text = prompt.messages.map((message) => (message.content as { text?: string }).text ?? '').join('\n');
    expect(text).toContain('Focus on journalctl');
  });

  it('the audit prompt points at the real log path', async () => {
    const prompt = await client.getPrompt({ name: 'audit', arguments: {} });
    const text = prompt.messages.map((message) => (message.content as { text?: string }).text ?? '').join('\n');
    expect(text).toContain('audit.jsonl');
    expect(text).toContain('sudo-policy.txt');
  });
});

describe('confirm-every-command', () => {
  it('is off by default', async () => {
    const { tools } = await client.listTools();
    const run = tools.find((tool) => tool.name === 'ssh_run')!;
    expect(run._meta?.['anthropic/requiresUserInteraction']).toBeUndefined();
  });

  it('marks ssh_run as always needing the permission dialog when switched on', async () => {
    // Amend the existing [approval] table rather than adding a second one,
    // which TOML rejects.
    const strict = await start(CONFIG.replace('open-browser = false', 'open-browser = false\nconfirm-every-command = true'));
    try {
      const { tools } = await strict.listTools();
      const run = tools.find((tool) => tool.name === 'ssh_run')!;
      expect(run._meta?.['anthropic/requiresUserInteraction']).toBe(true);
      // Only that tool: listing hosts should not need a dialog.
      const hosts = tools.find((tool) => tool.name === 'ssh_hosts')!;
      expect(hosts._meta?.['anthropic/requiresUserInteraction']).toBeUndefined();
    } finally {
      await strict.close();
    }
  });
});

describe('a client that cannot show a native URL prompt', () => {
  let formOnly: Client;

  beforeEach(async () => {
    pageBodies = [];
    // Declares form mode and not URL mode — the one case this server refuses
    // to downgrade, because a form answer would carry the passphrase back
    // through the client.
    formOnly = await start(CONFIG, { form: {} });
  });

  afterEach(async () => {
    await formOnly.close();
  });

  it('hands over the link in the tool result instead of dead-ending', async () => {
    const result = textOf(await formOnly.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } }));

    expect(elicitations).toHaveLength(0);
    expect(result).toContain('ssh-mcp is locked');
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(result)?.[0];
    expect(url, 'the result must carry a usable link').toBeDefined();

    // The link must actually work, and unlock the vault on submit.
    const page = await fetch(url!);
    expect(page.status).toBe(200);
    expect(await page.text()).toContain('type="password"');

    await fetch(url!, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'passphrase=test-passphrase',
    });

    expect(textOf(await formOnly.callTool({ name: 'ssh_status', arguments: {} }))).toContain('unlocked');
  });

  it('reuses the same link while it is still live, rather than opening one per attempt', async () => {
    const first = textOf(await formOnly.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } }));
    const second = textOf(await formOnly.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } }));

    const link = (text: string) => /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(text)?.[0];
    expect(link(first)).toBeDefined();
    expect(link(second)).toBe(link(first));
  });

  // A wrong passphrase is reported where the user is looking — in the browser,
  // with the form still there — rather than coming back as "Done" and surfacing
  // as a puzzling failure on the next command.
  it('rejects a wrong passphrase on the page itself and stays open for a retry', async () => {
    const first = textOf(await formOnly.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } }));
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(first)![0];

    const post = (passphrase: string) =>
      fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ passphrase }).toString(),
      });

    const rejected = await post('wrong');
    const body = await rejected.text();
    expect(rejected.status).toBe(200);
    expect(body).toContain('did not decrypt');
    // The form is still there to try again with.
    expect(body).toContain('type="password"');
    expect(textOf(await formOnly.callTool({ name: 'ssh_status', arguments: {} }))).toContain('locked');

    // And the retry on the same still-live page works.
    expect(await (await post('test-passphrase')).text()).toContain('Done');
    expect(textOf(await formOnly.callTool({ name: 'ssh_status', arguments: {} }))).toContain('unlocked');
  });

  it('reports a missing field without consuming the page', async () => {
    const first = textOf(await formOnly.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } }));
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(first)![0];

    const empty = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'passphrase=',
    });
    expect(await empty.text()).toContain('is required');
    expect((await fetch(url)).status).toBe(200);
  });
});

describe('the sudo gate refuses before it connects', () => {
  beforeEach(async () => {
    pageBodies = [];
    answer = submitting({ passphrase: 'test-passphrase' });
    // Unlock first, so what these tests observe is the sudo gate and not the
    // lock. Every refusal below must happen before any connection is attempted.
    await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } });
    elicitations = [];
  });

  it('refuses sudo outright on a host configured with sudo = off', async () => {
    const result = await client.callTool({
      name: 'ssh_run',
      arguments: { host: 'locked-down', cmd: 'sudo systemctl restart nginx' },
    });
    expect(textOf(result)).toContain('switched off');
    expect(elicitations).toHaveLength(0);
  });

  it('refuses a root shell without offering a dialog', async () => {
    const result = await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'sudo -s' } });
    expect(textOf(result)).toContain('never permitted');
    expect(elicitations).toHaveLength(0);
  });

  /**
   * The consent model that replaced form-mode elicitation: `ssh_run` runs sudo
   * only from a stored rule, and `ssh_sudo` carries the client's own permission
   * prompt. No elicitation is involved in either, which is the point — the
   * previous design asked through a channel this client silently discards.
   */
  it('will not run sudo from ssh_run at all, and says which tool will', async () => {
    const result = textOf(
      await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'sudo systemctl restart nginx' } }),
    );

    expect(elicitations).toHaveLength(0);
    expect(result).toContain('never runs sudo');
    expect(result).toContain('ssh_sudo');
    expect(result).toContain('Nothing was run');
  });

  /**
   * The gap `ssh_edit` would otherwise leave wide open: this line needs no sudo
   * at all, so nothing in the sudo gate ever looked at it, and `/etc/foo` would
   * change with nobody seeing what it changed to.
   */
  it('refuses a file write through ssh_run, which needs no sudo to be dangerous', async () => {
    const result = textOf(
      await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'echo x > /etc/foo' } }),
    );

    expect(result).toContain('ssh_edit');
    expect(result).toContain('/etc/foo');
    expect(result).toContain('Nothing was run');
    // The refusal happened at the gate, so nothing was even attempted.
    expect(result).not.toMatch(/cannot connect/i);
  });

  it('refuses an in-place edit through ssh_sudo without offering a page', async () => {
    const result = textOf(
      await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo tee /etc/hosts' } }),
    );

    expect(result).toContain('ssh_edit');
    expect(result).not.toContain('approval page is waiting');
    expect(result).not.toMatch(/http:\/\/127\.0\.0\.1:\d+\/unlock\//);
  });

  it('leaves the everyday redirections alone', async () => {
    // A scratch path is not a config file; this must reach the host (and fail
    // to connect) rather than be refused at the gate.
    const result = textOf(
      await client.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'dmesg > /tmp/out 2>&1' } }),
    );

    expect(result).not.toContain('ssh_edit');
    expect(result).toMatch(/cannot connect/i);
  });

  // Approving on the page grants the exact command, so the *next* ssh_sudo runs
  // it without asking. The grant lives in ssh_sudo; ssh_run stays sudo-free.
  it('stops asking once the command is approved for the session', async () => {
    const first = textOf(await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update' } }));
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(first)![0];
    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'decision=session',
    });

    // Second time: no page, straight past the gate to the (unreachable) host.
    const second = textOf(await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update' } }));
    expect(second).not.toContain('approval page is waiting');
    expect(second).toMatch(/cannot connect/i);

    // And the grant is that command alone.
    const other = textOf(await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt upgrade' } }));
    expect(other).toContain('approval page is waiting');
  });

  it('asks on a page that shows the command verbatim', async () => {
    const result = textOf(await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update' } }));

    // No browser in the test config, so the link is relayed instead of waited on.
    expect(result).toContain('approval page is waiting');
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(result)![0];

    const page = await (await fetch(url)).text();
    // The point of the whole exercise: the command is on the page.
    expect(page).toContain('sudo apt update');
    expect(page).toContain('Run this with sudo on lab?');
    expect(page).toContain('value="deny"');
    expect(page).toContain('value="once"');
    expect(page).toContain('value="session"');
    // A decision page must not ask for a secret.
    expect(page).not.toContain('type="password"');
  });

  it('shows the shell extras that stop a command being remembered', async () => {
    const result = textOf(
      await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update; whoami' } }),
    );
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(result)![0];

    const page = await (await fetch(url)).text();
    expect(page).toContain('sudo apt update; whoami');
    expect(page).toContain('shell extras: ;');
    expect(page).toContain('cannot be remembered');
    // With nothing safe to store, "for this session" is not offered at all.
    expect(page).not.toContain('value="session"');
  });

  it('refuses to run when the user denies on the page', async () => {
    const result = textOf(await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update' } }));
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(result)![0];

    await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'decision=deny',
    });

    const after = textOf(await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update' } }));
    expect(after).toContain('denied');
  });

  it('ignores a decision that was never offered', async () => {
    const result = textOf(
      await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update; whoami' } }),
    );
    const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(result)![0];

    // "session" was withheld for this command; a hand-crafted POST must not
    // conjure it back.
    const rejected = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'decision=session',
    });
    expect(await rejected.text()).toContain('is required');
  });

  it('refuses a root shell through ssh_sudo too, whatever the client approved', async () => {
    const result = textOf(await client.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo -s' } }));
    // The client prompt granted the *call*; the denylist still governs the command.
    expect(result).toContain('never permitted');
  });

  it('refuses sudo through ssh_sudo on a host with sudo = off', async () => {
    const result = textOf(
      await client.callTool({ name: 'ssh_sudo', arguments: { host: 'locked-down', cmd: 'sudo apt update' } }),
    );
    expect(result).toContain('switched off');
  });

  /**
   * Seen in the wild: `ssh_sudo` reached the host, `sudo -n` refused for want of
   * a password, and the password request threw
   * `Cannot request input 'sudo-password' … did not declare the required
   * capability`. Every secret request must degrade to a relayed link, not an
   * error, on a client without URL-mode elicitation.
   */
  it('never throws a protocol error when it needs a sudo password', async () => {
    const formOnly = await start(CONFIG, { form: {} });
    try {
      pageBodies = [];
      // Unlock through the relayed link, since this client has no URL mode.
      const locked = textOf(await formOnly.callTool({ name: 'ssh_run', arguments: { host: 'lab', cmd: 'true' } }));
      const url = /http:\/\/127\.0\.0\.1:\d+\/unlock\/[\w-]+/.exec(locked)![0];
      await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'passphrase=test-passphrase',
      });

      // Nothing listens on port 1, so this cannot reach the sudo-password branch
      // for real — but it must not throw on the way, and the tool must answer
      // with content rather than an exception.
      const result = await formOnly.callTool({ name: 'ssh_sudo', arguments: { host: 'lab', cmd: 'sudo apt update' } });
      expect(Array.isArray((result as { content: unknown }).content)).toBe(true);
      expect(textOf(result)).not.toContain('did not declare the required capability');
    } finally {
      await formOnly.close();
    }
  }, 30_000);

  it('does not offer to remember a command a rule could not pin down', async () => {
    const result = textOf(
      await client.callTool({
        name: 'ssh_sudo',
        arguments: { host: 'lab', cmd: 'sudo systemctl restart nginx; whoami' },
      }),
    );
    // It may run, having been approved at the prompt, but nothing is stored.
    expect(result).not.toContain('allowed for this session');
    expect(result).not.toContain('make it permanent');
  });
});
