import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { createRequestStateCodec, type RequestStateCodec, type ServerContext } from '@modelcontextprotocol/server';
import { AuditLog } from './audit/audit.js';
import { loadConfig, type Config } from './config/config.js';
import { HostRegistry } from './hosts/registry.js';
import { ConnectionPool } from './session/pool.js';
import { SudoGrants } from './sudo/grants.js';
import { closeAllPages, type RoundState } from './vault/gate.js';
import { setPagePort } from './vault/unlock-page.js';
import { Vault } from './vault/vault.js';

/**
 * Process-wide state, built once at startup and shared by every connection.
 *
 * The vault in particular must not be per-connection: "locked on every start"
 * means the process start, so that reconnecting a client cannot be a way to
 * shake off a lock or a sudo grant.
 */

export interface Runtime {
  readonly config: Config;
  readonly hosts: HostRegistry;
  readonly vault: Vault;
  readonly pool: ConnectionPool;
  readonly grants: SudoGrants;
  readonly audit: AuditLog;
  /** Seals multi-round-trip state so the copy the client echoes back cannot be forged. */
  mintState(payload: RoundState, ctx: ServerContext): Promise<string>;
  readonly requestStateCodec: RequestStateCodec<RoundState>;
}

export async function createRuntime(configPath?: string): Promise<Runtime> {
  const config = await loadConfig(configPath);
  const hosts = await HostRegistry.load(config);

  // Before anything can open a page: the first one to open binds the port, and
  // from then on this has no say.
  setPagePort(config.pagePort);

  const vault = new Vault(
    hosts.all().map((host) => host.keyPath),
    config.idleTimeoutMs,
  );
  const pool = new ConnectionPool(vault);
  const grants = new SudoGrants(join(config.configDir, 'sudo-policy.txt'));
  const audit = new AuditLog(join(config.configDir, 'audit.jsonl'));

  const { rules, problems } = await grants.load();
  for (const problem of problems) {
    process.stderr.write(`ssh-mcp: ${grants.policyPath}: ${problem}\n`);
  }

  // Relocking revokes approvals too: walking away for the idle timeout undoes
  // every "allow for this session".
  vault.onRelock((reason) => {
    grants.clearSession();
    closeAllPages();
    audit.write({ event: 'lock', outcome: reason });
  });

  // A per-process key is sufficient: this process serves every round of every
  // flow it starts, and a restart should invalidate anything in flight anyway.
  const requestStateCodec = createRequestStateCodec<RoundState>({
    key: randomBytes(32),
    ttlSeconds: 300,
    bind: (ctx) => ctx.mcpReq.method,
  });

  audit.write({ event: 'start', outcome: 'locked', detail: `${hosts.aliases().length} hosts, ${rules} sudo rules` });

  return {
    config,
    hosts,
    vault,
    pool,
    grants,
    audit,
    requestStateCodec,
    mintState: (payload, ctx) => requestStateCodec.mint(payload, ctx),
  };
}
