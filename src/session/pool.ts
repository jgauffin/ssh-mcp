// ssh2 is CommonJS: the class has to come off the default export, even though
// its type declarations advertise a named one.
import ssh2, { type Client, type PublicKeyAuthMethod } from 'ssh2';
import type { ResolvedHost } from '../hosts/registry.js';
import type { Vault } from '../vault/vault.js';

const { Client: SshClient } = ssh2;

/**
 * One live connection per host, reused across calls so a conversation does not
 * pay a handshake per command. The pool holds no credentials of its own — it
 * asks the vault for a key at connect time, and every connection is torn down
 * the moment the vault relocks.
 */

const READY_TIMEOUT_MS = 20_000;
const KEEPALIVE_MS = 15_000;

export class ConnectionPool {
  readonly #vault: Vault;
  readonly #clients = new Map<string, Client>();
  readonly #connecting = new Map<string, Promise<Client>>();

  constructor(vault: Vault) {
    this.#vault = vault;
    vault.onRelock(() => this.closeAll());
  }

  async get(host: ResolvedHost): Promise<Client> {
    const existing = this.#clients.get(host.alias);
    if (existing) return existing;

    const pending = this.#connecting.get(host.alias);
    if (pending) return pending;

    const attempt = this.#connect(host).finally(() => this.#connecting.delete(host.alias));
    this.#connecting.set(host.alias, attempt);
    return attempt;
  }

  async #connect(host: ResolvedHost): Promise<Client> {
    const key = this.#vault.keyFor(host.keyPath);
    const client = new SshClient();
    // Annotated so the `AuthMethod[]` overload does not swallow `key`.
    const auth: PublicKeyAuthMethod[] = [{ type: 'publickey', username: host.user, key: key.key }];

    await new Promise<void>((resolve, reject) => {
      const onError = (cause: Error): void => {
        client.removeAllListeners();
        client.end();
        reject(new Error(`cannot connect to ${host.alias} (${host.user}@${host.host}:${host.port}): ${cause.message}`));
      };

      client.once('ready', () => {
        client.removeListener('error', onError);
        resolve();
      });
      client.once('error', onError);

      client.connect({
        host: host.host,
        port: host.port,
        username: host.user,
        // The parsed key is handed over as-is rather than re-serialised: there
        // is no traditional PEM form for Ed25519, so a round trip through
        // `getPrivatePEM()` would quietly produce an unusable key.
        authHandler: auth,
        readyTimeout: READY_TIMEOUT_MS,
        keepaliveInterval: KEEPALIVE_MS,
      });
    });

    // A dropped connection must not be handed out again.
    client.on('error', () => this.#drop(host.alias, client));
    client.on('close', () => this.#drop(host.alias, client));

    this.#clients.set(host.alias, client);
    return client;
  }

  #drop(alias: string, client: Client): void {
    if (this.#clients.get(alias) === client) this.#clients.delete(alias);
  }

  closeAll(): void {
    for (const client of this.#clients.values()) {
      client.removeAllListeners();
      client.end();
    }
    this.#clients.clear();
  }
}
