import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';
import type { Client, SFTPWrapper } from 'ssh2';
import { decodeUtf8Strict, deniedByPermissions, looksBinary, missing, sftp } from './sftp.js';

/**
 * The channel budget, held to without a host.
 *
 * OpenSSH allows ten sessions per connection. Opening one SFTP channel per file
 * operation and never closing any of them therefore worked perfectly for ten
 * calls and then broke everything — `Channel open failure: open failed`, on
 * file reads *and* on every command after them, until the vault relocked and
 * took the connection with it. That is the kind of failure that looks like the
 * network and is not.
 */

class FakeWrapper extends EventEmitter {}

/** A client that counts channel opens, which is the whole assertion. */
function fakeClient(): { client: Client; opened: () => number; wrappers: FakeWrapper[] } {
  const wrappers: FakeWrapper[] = [];
  const client = {
    sftp(callback: (error: Error | undefined, wrapper: SFTPWrapper) => void) {
      const wrapper = new FakeWrapper();
      wrappers.push(wrapper);
      // Asynchronous, as the real one is: a synchronous callback would hide
      // ordering bugs that only appear against a server.
      setImmediate(() => callback(undefined, wrapper as unknown as SFTPWrapper));
    },
  } as unknown as Client;

  return { client, opened: () => wrappers.length, wrappers };
}

describe('the SFTP channel', () => {
  it('is opened once per connection, however many files are read', async () => {
    const { client, opened } = fakeClient();

    const first = await sftp(client);
    for (let call = 0; call < 20; call += 1) {
      expect(await sftp(client)).toBe(first);
    }

    expect(opened()).toBe(1);
  });

  it('is not opened twice by two calls racing for it', async () => {
    const { client, opened } = fakeClient();

    const [a, b, c] = await Promise.all([sftp(client), sftp(client), sftp(client)]);

    expect(opened()).toBe(1);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  it('is replaced once the far end closes it', async () => {
    const { client, opened, wrappers } = fakeClient();

    const first = await sftp(client);
    wrappers[0]!.emit('close');
    const second = await sftp(client);

    expect(opened()).toBe(2);
    expect(second).not.toBe(first);
  });

  it('is replaced after a channel fault rather than handed out dead', async () => {
    const { client, wrappers } = fakeClient();

    await sftp(client);
    // Nothing else listens for this, so without a handler here ssh2 would throw
    // it at the process.
    expect(() => wrappers[0]!.emit('error', new Error('channel fault'))).not.toThrow();

    expect(await sftp(client)).not.toBe(wrappers[0]);
  });

  it('gives each connection its own channel', async () => {
    const one = fakeClient();
    const two = fakeClient();

    expect(await sftp(one.client)).not.toBe(await sftp(two.client));
    expect(one.opened()).toBe(1);
    expect(two.opened()).toBe(1);
  });

  it('does not cache a failure', async () => {
    let attempts = 0;
    const client = {
      sftp(callback: (error: Error | undefined, wrapper: SFTPWrapper) => void) {
        attempts += 1;
        const failing = attempts === 1;
        setImmediate(() =>
          failing
            ? callback(new Error('no channel'), undefined as unknown as SFTPWrapper)
            : callback(undefined, new FakeWrapper() as unknown as SFTPWrapper),
        );
      },
    } as unknown as Client;

    await expect(sftp(client)).rejects.toThrow('no channel');
    // A transient refusal must not make every later file operation fail with
    // an error that happened once, minutes ago.
    await expect(sftp(client)).resolves.toBeDefined();
  });
});

describe('reading what came back', () => {
  it('tells a missing file from a refused one', () => {
    expect(missing({ code: 2 })).toBe(true);
    expect(deniedByPermissions({ code: 3 })).toBe(true);
    // Servers that do not distinguish say FAILURE; treating it as a refusal
    // only costs a sudo read that fails with a clearer message.
    expect(deniedByPermissions({ code: 4 })).toBe(true);
    expect(deniedByPermissions({ code: 2 })).toBe(false);
  });

  it('refuses to decode bytes that are not really UTF-8', () => {
    expect(decodeUtf8Strict(Buffer.from('hello', 'utf8'))).toBe('hello');
    expect(decodeUtf8Strict(Buffer.from('lösen', 'utf8'))).toBe('lösen');
    // Latin-1. `toString('utf8')` would substitute U+FFFD and the file would go
    // back corrupted with the diff showing nothing.
    expect(decodeUtf8Strict(Buffer.from([0x6c, 0xf6, 0x73]))).toBeUndefined();
  });

  it('calls a file with a NUL in it binary', () => {
    expect(looksBinary(Buffer.from([0x7f, 0x45, 0x4c, 0x00]))).toBe(true);
    expect(looksBinary(Buffer.from('shared_buffers = 128MB', 'utf8'))).toBe(false);
  });
});
