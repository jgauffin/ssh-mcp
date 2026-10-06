import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { readLocalFile, refusedAsCredential, refusedAsExecutable } from './local-file.js';
import { MAX_WRITE_BYTES } from './write.js';

/**
 * `ssh_put` is the only tool here that reads this machine's disk, so these are
 * the checks that stand between a model naming a path and that path's bytes
 * being on a remote host. Both are deliberately crude: the approval page is the
 * real control, and these only have to stop the cases a person would answer
 * "yes" to while thinking about something else.
 */

describe('a local path that looks like a credential', () => {
  const refused = (path: string, allowed: readonly string[] = []) => refusedAsCredential(path, allowed);

  it('a_private_key_is_refused_before_the_file_is_opened', () => {
    expect(refused('/home/me/.ssh/id_ed25519')).toBeDefined();
  });

  /**
   * The public half is in the same list on purpose: landing it in
   * `authorized_keys` grants access just as surely as the private one would.
   */
  it('a_public_key_is_refused_as_well_as_a_private_one', () => {
    expect(refused('/home/me/.ssh/id_ed25519.pub')).toBeDefined();
  });

  it.each([
    '/home/me/certs/service.key',
    '/home/me/certs/service.pem',
    '/home/me/keys/windows.ppk',
    '/home/me/keys/bundle.p12',
    '/srv/app/.env',
    '/srv/app/production.env',
    '/srv/app/.env.production',
    '/home/me/.netrc',
    '/home/me/.npmrc',
    '/home/me/.aws/credentials',
    '/home/me/.kube/config',
    '/home/me/.gnupg/secring.gpg',
    '/home/me/.docker/config.json',
    '/home/me/service-account-prod.json',
  ])('%s is refused', (path) => {
    expect(refused(path)).toBeDefined();
  });

  it.each([
    '/home/me/certs/service.crt',
    '/home/me/certs/ca-bundle.pem.txt',
    '/etc/myssh/notes.txt',
    '/home/me/app/appsettings.json',
    '/home/me/licence.lic',
    '/home/me/trust/cacerts',
  ])('%s is an ordinary file and is allowed through to the page', (path) => {
    expect(refused(path)).toBeUndefined();
  });

  /**
   * The shape list matches a `.ssh` path *segment*, not the substring: a
   * directory called `myssh` is not a credential store.
   */
  it('a_directory_that_merely_contains_ssh_in_its_name_is_not_a_credential_store', () => {
    expect(refused('/etc/myssh/config')).toBeUndefined();
  });

  it('an_allowlisted_path_lifts_the_refusal', () => {
    expect(refused('/home/me/certs/service.pem', ['/home/me/certs/service.pem'])).toBeUndefined();
  });

  it('an_allowlist_entry_may_be_a_glob', () => {
    expect(refused('/home/me/certs/service.pem', ['/home/me/certs/*.pem'])).toBeUndefined();
    // The glob still has to reach it: `*` stops at a separator.
    expect(refused('/home/me/certs/inner/service.pem', ['/home/me/certs/*.pem'])).toBeDefined();
  });

  it('an_allowlist_for_one_file_does_not_open_the_whole_directory', () => {
    expect(refused('/home/me/certs/other.pem', ['/home/me/certs/service.pem'])).toBeDefined();
  });

  /**
   * This server runs on the user's own machine, which is often Windows, and
   * `matchesPath` splits on `/` to find the last segment. Without normalising,
   * every bare pattern misses a backslash path and the whole guard is off.
   */
  it('a_windows_path_is_matched_the_same_as_a_posix_one', () => {
    expect(refused(String.raw`C:\Users\me\.ssh\id_rsa`)).toBeDefined();
    expect(refused(String.raw`C:\Users\me\certs\service.pem`)).toBeDefined();
    expect(refused(String.raw`C:\Users\me\certs\service.crt`)).toBeUndefined();
  });

  it('the_refusal_names_the_shape_that_matched_and_not_the_way_to_lift_it', () => {
    const reason = refused('/home/me/.ssh/id_rsa');
    expect(reason).toBeDefined();
    // A lever for whoever edits the config, never a hint the model can act on.
    expect(reason).not.toContain('[put]');
    expect(reason).not.toContain('allow');
  });
});

describe('a file that would be executable', () => {
  const text = Buffer.from('server.crt contents\n', 'utf8');

  it('any_execute_bit_in_the_mode_is_refused_however_harmless_the_content', () => {
    for (const mode of [0o700, 0o755, 0o711, 0o644 | 0o010, 0o001]) {
      expect(refusedAsExecutable(text, mode)).toBeDefined();
    }
  });

  it('setuid_and_setgid_are_refused_for_the_same_reason', () => {
    expect(refusedAsExecutable(text, 0o4600)).toBeDefined();
    expect(refusedAsExecutable(text, 0o2600)).toBeDefined();
  });

  /**
   * The mode check alone would not be enough: a file with no execute bit still
   * runs under an interpreter, and the bit can be added by anything with a
   * shell afterwards.
   */
  it.each([
    ['an ELF binary', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01])],
    ['a shell script', Buffer.from('#!/bin/sh\necho hi\n', 'utf8')],
    ['a Windows executable', Buffer.from('MZ\u0090\u0000', 'binary')],
    ['a WebAssembly module', Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01])],
    ['a Mach-O binary', Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0x07])],
    ['a Java class file', Buffer.from([0xca, 0xfe, 0xba, 0xbe, 0x00])],
  ])('%s is refused even with no execute bit asked for', (_what, content) => {
    expect(refusedAsExecutable(content, 0o600)).toBeDefined();
  });

  it('an_ordinary_file_at_a_mode_that_cannot_run_is_allowed', () => {
    expect(refusedAsExecutable(text, 0o600)).toBeUndefined();
    expect(refusedAsExecutable(text, 0o644)).toBeUndefined();
    expect(refusedAsExecutable(text, 0o640)).toBeUndefined();
  });

  it('a_certificate_is_not_mistaken_for_a_program', () => {
    const pem = Buffer.from('-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n', 'utf8');
    expect(refusedAsExecutable(pem, 0o644)).toBeUndefined();
  });

  it('an_empty_file_has_no_magic_bytes_and_is_not_refused_for_them', () => {
    expect(refusedAsExecutable(Buffer.alloc(0), 0o600)).toBeUndefined();
  });
});

describe('reading the local file', () => {
  const scratch = async (): Promise<string> => mkdtemp(join(tmpdir(), 'ssh-mcp-put-'));

  it('hands back the bytes exactly, including ones that are not text', async () => {
    const dir = await scratch();
    const path = join(dir, 'blob.bin');
    const bytes = Buffer.from([0x00, 0xff, 0x10, 0x80, 0x00]);
    await writeFile(path, bytes);

    const read = await readLocalFile(path);
    expect(read.ok && read.content.equals(bytes)).toBe(true);
  });

  it('says plainly when there is no such file', async () => {
    const dir = await scratch();
    const read = await readLocalFile(join(dir, 'nothing-here'));
    expect(read).toMatchObject({ ok: false });
    expect(read.ok === false && read.reason).toContain('no file at');
  });

  /** A directory read fails with a message that reads like a permission problem. */
  it('tells_a_directory_apart_from_a_file', async () => {
    const dir = await scratch();
    const read = await readLocalFile(dir);
    expect(read).toMatchObject({ ok: false });
    expect(read.ok === false && read.reason).toContain('directory');
  });

  it('refuses_a_file_over_the_cap_rather_than_sending_a_prefix_of_it', async () => {
    const dir = await scratch();
    const path = join(dir, 'big.bin');
    await writeFile(path, Buffer.alloc(MAX_WRITE_BYTES + 1));

    const read = await readLocalFile(path);
    expect(read).toMatchObject({ ok: false });
    expect(read.ok === false && read.reason).toContain('scp');
  });

  it('accepts a file exactly at the cap', async () => {
    const dir = await scratch();
    const path = join(dir, 'exact.bin');
    await writeFile(path, Buffer.alloc(MAX_WRITE_BYTES));

    expect((await readLocalFile(path)).ok).toBe(true);
  });
});
