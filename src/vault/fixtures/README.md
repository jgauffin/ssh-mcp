# Test key fixtures

Throwaway keys used only by the unit tests. They protect nothing and are safe
to commit — they exist so the OpenSSH decoding path is exercised against keys a
real `ssh-keygen` produced rather than something hand-rolled.

Passphrase for the encrypted ones: `test-passphrase`

| File                | Format          | Encrypted |
| ------------------- | --------------- | --------- |
| `id_ed25519`        | OpenSSH, Ed25519 | yes      |
| `id_rsa`            | OpenSSH, RSA 2048 | yes     |
| `id_ed25519_plain`  | OpenSSH, Ed25519 | no       |

Regenerate with:

```sh
ssh-keygen -t ed25519 -N 'test-passphrase' -C 'ssh-mcp test' -f id_ed25519 -q
ssh-keygen -t rsa -b 2048 -N 'test-passphrase' -C 'ssh-mcp test' -f id_rsa -q
ssh-keygen -t ed25519 -N '' -C 'ssh-mcp test plain' -f id_ed25519_plain -q
```

## No PPK fixture

There is deliberately no `.ppk` here, because the Windows PuTTYgen cannot
produce one without a human.

Its command line (PuTTY manual §8.2.16) accepts only `-t`, `-b`, `--primes`,
`--strong-rsa`, `--ppk-param` and `-E` — options that *preset the GUI*. The
conversion options `-O`, `-o` and `--old-passphrase` exist only in the Unix
build, so `puttygen key -O private -o key.ppk` cannot work here. It is also a
GUI-subsystem binary, so it reports that error in a message box and writes
nothing to the console.

To make one by hand: open PuTTYgen, Conversions → Import key, pick
`id_ed25519`, enter `test-passphrase`, then Save private key. Use
`--ppk-param version=2` on the command line first if you want a v2 file.

What that leaves untested is `ppk-to-openssh`'s decoding, which is that
library's own responsibility and is covered by its test suite. What *is* tested
here is the part this project owns: that a file beginning `PuTTY-User-Key-File-`
is routed to the PPK parser and everything else to `ssh2`. See
`keys.test.ts`. Verify the end-to-end PuTTY path once against a real key of
your own — `ssh_status` after unlocking reports the type and fingerprint of
every key it decoded.
