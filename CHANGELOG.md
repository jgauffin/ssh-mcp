# Changelog

## 0.2.0 (2026-10-06)

### Added

- `ssh_put` sends a local file to a host. The model names a path and never sees the
  bytes; the user approves destination, size, mode and SHA-256 on a page. An existing
  file keeps its owner, group and mode.
- `ssh_put` refuses executables: no execute or setuid bit, no ELF, Mach-O, PE,
  WebAssembly or `#!` content, and no overwriting a destination that already runs.
- `ssh_put` refuses credential-shaped local paths (`~/.ssh`, `*.pem`, `*.key`, `.env`,
  `~/.aws`) before opening the file. `[put].paths` names exceptions.
- The sudo approval page colours the command's syntax, and on a line of several commands
  marks each root command "needs approval" or "already allowed".

### Fixed

- Two calls needing the same sudo password or passphrase each opened a page, so a second
  window appeared as the first was submitted. The later call now waits on the open page.
- A `sudo` hidden inside `$(…)`, `sh -c "…"`, `env`/`xargs`/`timeout` arguments or
  `find -exec` bypassed the gate entirely: no denylist check, no page, nothing in the
  audit log. Both tools now refuse such a line and say where the sudo is.
- The sudo password page looped forever on those lines, because the password preamble
  was conditional on a sudo the parser had seen.
- A sudo-password prompt the client dismissed without showing was reported as the user
  refusing, leaving no way to supply one. Its link is now relayed instead.
