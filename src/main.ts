#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { ConfigError } from './config/config.js';
import { registerHostTools } from './hosts/hosts.tool.js';
import { HostError } from './hosts/registry.js';
import { createRuntime, type Runtime } from './runtime.js';
import { registerEditTool } from './session/edit.tool.js';
import { registerFileTools } from './session/files.tool.js';
import { registerLearnPrompts } from './session/learn.prompt.js';
import { registerRunTool } from './session/run.tool.js';
import { closeAllPages } from './vault/gate.js';
import { registerVaultTools } from './vault/vault.tool.js';

const VERSION = '0.1.0';

/**
 * Nothing may ever be written to stdout except the transport's own frames — a
 * stray `console.log` corrupts the protocol. Diagnostics go to stderr.
 */
function log(message: string): void {
  process.stderr.write(`ssh-mcp: ${message}\n`);
}

function buildServer(runtime: Runtime): McpServer {
  const server = new McpServer(
    { name: 'ssh-mcp', version: VERSION },
    {
      capabilities: { tools: {}, resources: {}, prompts: {} },
      // Multi-round-trip state comes back from the client as untrusted input;
      // this rejects anything not minted by this process.
      requestState: { verify: runtime.requestStateCodec.verify },
    },
  );

  registerHostTools(server, runtime);
  registerVaultTools(server, runtime);
  registerRunTool(server, runtime);
  registerFileTools(server, runtime);
  registerEditTool(server, runtime);
  registerLearnPrompts(server, runtime);

  return server;
}

async function main(): Promise<void> {
  let runtime: Runtime;
  try {
    runtime = await createRuntime();
  } catch (cause) {
    if (cause instanceof ConfigError || cause instanceof HostError) {
      log(cause.message);
      process.exit(1);
    }
    throw cause;
  }

  log(
    `started locked — ${runtime.hosts.aliases().length} host(s): ${runtime.hosts.aliases().join(', ')}. ` +
      `Config ${runtime.config.configPath}.`,
  );

  const handle = serveStdio(() => buildServer(runtime), {
    onerror: (error) => log(`transport error: ${error.message}`),
  });

  let shuttingDown = false;
  const shutdown = (reason: string): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    // Locking on the way out means a crashed or closed session never leaves
    // decrypted key material behind in a lingering process.
    runtime.vault.lock(reason);
    closeAllPages();
    void runtime.audit.flush().finally(() => void handle.close().finally(() => process.exit(0)));
  };

  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.stdin.once('close', () => shutdown('stdin closed'));
}

await main();
