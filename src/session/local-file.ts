import { readFile, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { matchesPath } from '../secrets/patterns.js';
import { MAX_WRITE_BYTES } from './write.js';

/**
 * What may be taken off this machine and sent to a host.
 *
 * `ssh_put` is the only tool here that reads the user's own disk, and that
 * makes it the only one the model can aim at a file nobody mentioned. The
 * approval page is the control — it names the local path, so a request to send
 * `~/.ssh/id_ed25519` is visible as exactly that — but a page is a thing a
 * person answers while thinking about something else, so the shapes that are
 * almost never a legitimate upload are refused before a page is ever drawn, and
 * only an explicit allowlist in the config lifts the refusal.
 *
 * The refusals deliberately do not mention the allowlist. It is a lever for the
 * person reading the config file, not a hint for the model to route around.
 */

/**
 * Local paths refused unless the config names them.
 *
 * Public keys are in here with private ones on purpose: a public key that lands
 * in `authorized_keys` grants access just as surely, so "it is the public half"
 * is not a reason to send it unasked.
 */
const CREDENTIAL_SHAPES: readonly string[] = [
  '**/.ssh/**',
  'id_*',
  '*.pem',
  '*.key',
  '*.ppk',
  '*.p12',
  '*.pfx',
  '*.jks',
  '*.keystore',
  '*.kdbx',
  '.env',
  '*.env',
  '.env.*',
  '.netrc',
  '_netrc',
  '.npmrc',
  '.pypirc',
  '.htpasswd',
  'credentials',
  'credentials.json',
  'service-account*.json',
  '**/.aws/**',
  '**/.kube/**',
  '**/.gnupg/**',
  '**/.docker/config.json',
  '**/.config/gcloud/**',
];

/**
 * One form for matching: forward slashes, and a leading `~` expanded.
 *
 * `matchesPath` splits on `/` to find the last segment, so a Windows path has
 * to be normalised or `C:\Users\me\.ssh\id_rsa` has no last segment at all and
 * every bare pattern misses it.
 */
function forMatching(path: string): string {
  const slashes = path.replace(/\\/g, '/');
  if (slashes === '~') return homedir().replace(/\\/g, '/');
  if (slashes.startsWith('~/')) return `${homedir().replace(/\\/g, '/')}/${slashes.slice(2)}`;
  return slashes;
}

/** The shape that refuses this path, or `undefined` if none does. */
export function refusedAsCredential(path: string, allowed: readonly string[]): string | undefined {
  const subject = forMatching(path);
  // The allowlist is consulted first: naming a path there is the whole way a
  // user says "yes, this one, I know what it is".
  if (allowed.some((pattern) => matchesPath(forMatching(pattern), subject))) return undefined;
  return CREDENTIAL_SHAPES.find((pattern) => matchesPath(pattern, subject));
}

/**
 * The magic bytes of things that run.
 *
 * Not exhaustive, and it cannot be: a shell script with no `#!` line is just
 * text, and no sniff will ever say otherwise. That is what the mode check is
 * for — between them, sending something that runs takes two mistakes rather
 * than none.
 */
const EXECUTABLE_MAGIC: readonly { readonly what: string; readonly magic: Buffer }[] = [
  { what: 'an ELF binary or shared library', magic: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
  { what: 'a script with a #! line', magic: Buffer.from('#!', 'ascii') },
  { what: 'a DOS or Windows executable', magic: Buffer.from('MZ', 'ascii') },
  { what: 'a WebAssembly module', magic: Buffer.from([0x00, 0x61, 0x73, 0x6d]) },
  { what: 'a Mach-O binary', magic: Buffer.from([0xfe, 0xed, 0xfa, 0xce]) },
  { what: 'a Mach-O binary', magic: Buffer.from([0xfe, 0xed, 0xfa, 0xcf]) },
  { what: 'a Mach-O binary', magic: Buffer.from([0xce, 0xfa, 0xed, 0xfe]) },
  { what: 'a Mach-O binary', magic: Buffer.from([0xcf, 0xfa, 0xed, 0xfe]) },
  { what: 'a Java class or Mach-O fat binary', magic: Buffer.from([0xca, 0xfe, 0xba, 0xbe]) },
];

/** Every bit that would let the file be run, or let it run as somebody else. */
export const EXECUTABLE_BITS = 0o7111;

/** Why this content and mode would be an executable, or `undefined`. */
export function refusedAsExecutable(content: Buffer, mode: number): string | undefined {
  if ((mode & EXECUTABLE_BITS) !== 0) {
    return `mode ${mode.toString(8).padStart(4, '0')} would make it executable (or setuid)`;
  }
  const magic = EXECUTABLE_MAGIC.find((candidate) => content.subarray(0, candidate.magic.length).equals(candidate.magic));
  // Refused whatever the mode says. A file with no execute bit still runs under
  // an interpreter — `sh it`, `ld.so it` — and the bit can be added later by
  // anything with a shell.
  return magic ? `it starts with the magic bytes of ${magic.what}` : undefined;
}

export type LocalContent =
  | { readonly ok: true; readonly content: Buffer }
  | { readonly ok: false; readonly reason: string };

/**
 * The bytes of a local file, or why there are none.
 *
 * The `isFile` check is not pedantry: a FIFO opens and then blocks forever, and
 * a directory read fails with a message that reads like a permission problem.
 */
export async function readLocalFile(path: string): Promise<LocalContent> {
  let size: number;
  try {
    const stats = await stat(path);
    if (stats.isDirectory()) return { ok: false, reason: `${path} is a directory, not a file.` };
    if (!stats.isFile()) return { ok: false, reason: `${path} is not a regular file.` };
    size = stats.size;
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { ok: false, reason: `There is no file at ${path} on this machine.` };
    if (code === 'EACCES' || code === 'EPERM') return { ok: false, reason: `${path} cannot be read on this machine.` };
    return { ok: false, reason: `${path} cannot be read: ${(cause as Error).message}` };
  }

  if (size > MAX_WRITE_BYTES) {
    return {
      ok: false,
      reason:
        `${path} is ${size} bytes, over the ${MAX_WRITE_BYTES / 1024} KiB limit for this tool. ` +
        `Something that size is a job for scp, run by the user.`,
    };
  }

  try {
    return { ok: true, content: await readFile(path) };
  } catch (cause) {
    return { ok: false, reason: `${path} cannot be read: ${(cause as Error).message}` };
  }
}
