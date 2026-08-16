# ssh-mcp

An MCP server that gives Claude a shell on your servers, and cannot use it
without your explicit consent.

It starts locked on every launch. It asks for your key passphrase in a browser,
never through the model. It checks every `sudo` against a policy you control,
and remembers only what you tell it to remember. PuTTY `.ppk` keys work, so the
passphrase you already type is the only thing you need.

---

## Why build this

An agent with SSH access is useful and can also `rm -rf` your production box.
Both usual answers are bad. **Ask every time** and you click through the
twelfth dialog without reading it; a prompt you always accept is a habit, not a
control. **Just allow it** and one prompt-injected log line costs you the fleet.

So the question is *where* consent belongs:

- **To the session, not the command.** One passphrase entry opens the door. It
  closes again after an idle period. You are not asked about `uptime`.
- **To a decision you can read.** A `sudo` approval names the host and the exact
  command, and covers that command for the session, nothing more. Widening it to
  `apt *` means editing a plain-text file yourself. Nothing here writes a
  permanent grant of root; it prints the line and stops.
- **Not everything is consentable.** `sudo -s`, `sudo su`, `sudo bash` and
  anything touching `/etc/sudoers` get no dialog. Approving a root shell once
  approves everything after it, which makes "approve once" a lie.
- **The model never holds the secret.** The passphrase is entered on a one-shot
  page on `127.0.0.1`, behind a 256-bit single-use nonce, that dies on submit.
  It never enters the MCP protocol, the transcript or the model's context. The
  model sees "locked", then "unlocked".

---

## How this differs from other SSH MCP servers

Most are a thin wrapper: one tool taking `host`, `username`, `password` or
`privateKey`, and `command`, handed straight to an SSH library. Every row below
is a deliberate departure from that shape.

| | Typical SSH MCP server | ssh-mcp |
| --- | --- | --- |
| **Credentials** | In the config file, in an env var, or passed as a tool argument by the model | Nowhere at rest in usable form. Keys stay encrypted on disk; a human unlocks them per process start, out of band |
| **Target selection** | Model supplies `host`/`user`/`port`/`key` | No such parameter exists. `host` is an `enum` of aliases you listed, so an unlisted machine is *unrepresentable*, not merely rejected |
| **sudo** | Runs it, or blocks it, or asks every time | Denylist → stored rules → a separate always-prompting tool |
| **Approval scope** | Per tool call, or none | Per (host, argv); a session grant dies when the vault relocks, and only you can make one permanent |
| **Command analysis** | Substring or regex over the command string | Shell-aware: the line is split into segments, and a stored rule can only ever match a single plain command |
| **Output** | JSON envelope | Plain text, as a terminal would show it |
| **File secrets** | Returned in full, so editing a config puts its passwords in the transcript | Withheld as markers the model can anchor on but not read, put back server-side for the write. A new password can be generated or typed rather than authored by the model |
| **Audit** | — | Append-only JSONL of every command, decision and grant |

### The model cannot name a machine you did not

Every tool's `host` parameter is a JSON Schema `enum` built from your config at
startup. No `hostname`, no `port`, no `key`, no `password`. A closed set in the
schema is stronger than validation: the model has nothing to pass. Tools declare
`openWorldHint: false`.

### A wildcard grant can only match a command whose meaning is pinned

You approve `systemctl restart *` on `prod-1`. The model then runs
`sudo systemctl restart nginx; sudo rm -rf /var`. String matching on the prefix
would hand the second command root as well, so instead:

1. The line is split as a shell would split it, tracking quotes. Every separator
   (`;` `&&` `||` `|` `&`), expansion (`$(…)`, backticks, `${…}`, `$`) and
   redirection (`<` `>`) **outside** quotes is recorded.
2. Rules are matched **per sudo segment**, the way `sudoers` matches. A shell
   resolves `;` and `|` before anything runs, so that line is two commands and
   each `sudo` on it must find its own rule. `systemctl restart *` covers the
   first and nothing covers `rm -rf /var`, so the line is put to you. Note what
   this does *not* claim: appending a command that needs no sudo —
   `sudo systemctl restart nginx; rm -rf ~/scratch` — is covered, because the
   second half is an ordinary unprivileged command that `ssh_run` would have run
   without asking anyway.
3. An expansion or a redirection stops matching outright, for a different
   reason: the argv a rule was matched against is then not the argv that runs.
   `sudo systemctl restart $(cat /tmp/service)` is approve-once whatever the
   policy says. So is `&` — output nobody sees is approval nobody can check.
4. A **new** rule is only ever written from a plain single command: one segment,
   one sudo, no separators at all. Matching a pipeline is fine; storing one is
   not, because a rule is read back by a human months later.
5. Matching is per argument, not per substring. `*` is exactly one argument;
   `**` is the remaining arguments, last position only. So
   `systemctl restart *` matches `systemctl restart nginx` and refuses
   `systemctl restart nginx --now`.
6. `sudo`'s own flags are parsed. Anything not understood (a bundled `-nS`, an
   unknown `--flag`) makes the invocation ungrantable rather than guessed at.

`grep "a;b" /etc/hosts` is still a plain command; the `;` is quoted.

---

## Why run SSH through MCP at all

**Versus pasting terminal output into chat.** You are the transport. Nothing is
audited and nothing is bounded.

**Versus the agent driving your local `ssh` through a shell tool.** The common
setup, and the weakest. Your agent host already has `ssh-agent` loaded and
`~/.ssh/config` populated, so a shell tool is ambient authority over every
machine you have ever logged into: no host allowlist, no sudo policy, and an
approval prompt showing a command string that means whatever the remote shell
decides it means.

**Versus an agent inside the server.** Credentials, agent and blast radius all
land on the machine you were protecting.

An MCP server is a separate process with its own config, its own audit log, and
no ability to widen its own permissions. The model gets a capability, never the
credential.

### A note on where the trust actually is

Scope, stated plainly:

- **No defence against local malware.** A process running as you reads your key
  files directly. What the loopback page buys is that your passphrase never
  enters the model's context.
- **The denylist is not exhaustive.** `sudo find`, `sudo vim`, `sudo docker` and
  friends can be talked into a shell, so they are approve-once and never
  wildcardable. But no such list is complete. The closed host world and the
  once-only default carry the real weight.
- **Claude Code's `Elicitation` hook can auto-answer dialogs.** Configuring one
  bypasses the sudo gate. Legitimate client feature, worth knowing about.
- **The unlock link reaches the model's context** on the relayed-link fallback.
  A deliberate trade: a single-use nonce for a loopback listener with a
  two-minute life, granting only the ability to *submit* a passphrase the holder
  does not know. The passphrase never goes near that context on either path.
- **Withholding secrets is hygiene, not containment.** It removes what the
  ordinary read-then-edit workflow forces into your transcript. It does nothing
  against `base64`, `xxd` or `rev`, and the marker itself says where to aim. The
  control that actually holds is the connecting user's own permissions; see
  [Where this stops](#where-this-stops).
- **A marker can be moved.** The model can put a value it never saw somewhere
  else in the file, or into another file on the same host, or into an `ssh_sudo`
  command line. Every one of those is a page you answer with the real value in
  front of you, and none of them can be remembered.
- **`ssh_ls` and `ssh_get` run as the connecting user**, no sudo path at all.
  `ssh_edit` does escalate; the page you answer says so and shows the diff
  first.
- **The file-write guard reads paths, not intent.** `cd /etc && sed -i s/a/b/
  nginx.conf` gets through: catching it would mean tracking the working
  directory across shell segments, and the next line would just be
  `cd /etc; cd .; sed -i …`. So do wrappers (`env`, `xargs`, `nice` in front of `sed -i`), `rsync`,
  `tar -x`, `git apply` and `systemctl edit`. This is the well-known cases; the
  weight is carried by `ssh_edit` being pleasant enough to not route around.
- **`ssh_edit` reads a root-owned file before you approve anything**, via
  `sudo base64`, so it has something to diff against. That content never reaches
  the model. It draws the page and checks the file has not moved, and the reply
  carries only line counts. The model can cause a root-readable file to be read;
  it cannot see it.
- **Editing an existing file changes nothing about its owner, group, mode, ACLs
  or labels.** Both routes go through the existing inode: unprivileged truncates
  over SFTP and sends no attributes, privileged is `sudo cp`, which truncates
  rather than unlinks. `mv`, `install` and `cp --remove-destination` would
  replace the file, and the replacement would arrive owned by root: a change
  your approved diff says nothing about, and one that stops sshd and sudo
  starting.
- **A file `ssh_edit` creates is made as you if the directory allows it.**
  Otherwise it lands as `root:root` mode 0644, there being no basis for guessing
  an owner. The reply says which happened.
- **Two edits to one file are queued, a third party is not.** The file is read
  once more immediately before the write and the write is abandoned if it moved
  since you saw the diff, so the loser of a race is told rather than silently
  overwritten. That check is only authoritative for this process, which is why
  writes to the same file are serialised here. Someone typing into the same
  config over their own SSH session in the same second can still lose an update:
  closing that needs a compare-and-swap neither SFTP nor `cp` offers.
- **`ssh_edit` takes no backup.** A `.bak` beside a config file is a hazard:
  `nginx`, `logrotate.d`, `sudoers.d`, `sysctl.d`, `cron.d` and
  `sources.list.d` all glob their directories, and it copies whatever secret the
  file held to a second path. The re-read before the write and the audit trail
  replace it.
- **The remote sudo shim assumes a POSIX-ish login shell.** Hosts with
  `requiretty` in sudoers need a PTY and are not supported.

---

## Install

Requires **Node 22 or newer**, and Claude Code **2.1.199 or later** for the
`requiresUserInteraction` annotation that the sudo prompt depends on.

```sh
git clone <this repo> ssh-mcp
cd ssh-mcp
npm install
npm run build
npm test          # no network or server needed
```

With Docker running, there is a second suite that does the same work against a
real host:

```sh
npm run test:integration
```

It builds `docker/Dockerfile` — Debian, sshd, sudo, and a few config files with
passwords in them — starts a container, and drives the built server through a
real MCP client, answering the loopback pages over HTTP the way you would in a
browser. Then it reads the files back with `docker exec` and asserts on what the
*host* holds: that a password survived an edit byte for byte, that a root-owned
file kept its owner and mode, and that no secret from the container appears
anywhere in what the model was told. It skips itself when Docker is not running.

Register it with Claude Code:

```sh
claude mcp add ssh -- node /absolute/path/to/ssh-mcp/dist/main.js
```

To keep the config somewhere other than `~/.ssh-mcp/ssh-mcp.toml`:

```sh
claude mcp add ssh --env SSH_MCP_CONFIG=D:/keys/ssh-mcp.toml -- node /absolute/path/to/ssh-mcp/dist/main.js
```

The first command needing SSH opens an unlock page in your browser and prints
the link in the chat as a fallback. Type your passphrase there, then tell the
assistant to carry on. There is no form-mode fallback: a form answer travels
back through the client and into the model's context, which is the one thing a
passphrase must not do. Set `open-browser = false` under `[approval]` to get
only the link (headless boxes, remote sessions).

Every page in a run is served from one port, `8765` by default. That is for your
browser's benefit: it identifies a site by scheme, host *and* port, so a page
that moved would be a new site each time — and each new site is asked afresh
whether to save the passphrase it just watched you type. One fixed port makes
"Never" mean never. A second ssh-mcp on the same machine steps up to `8766` and
stays there. `page-port = 0` brings the old per-run random port back.

**Known limit: protocol era.** Claude Code negotiates the 2025 protocol era
over stdio, not `2026-07-28`, and does not declare URL-mode elicitation. No flag
changes this; the client has to opt in. So multi-round-trip elicitation never
engages and the consent surface is the loopback page this server opens itself.
Both eras are supported and both are tested.

---

## Configure

Create `~/.ssh-mcp/ssh-mcp.toml`. **This file is the entire attack surface**:
nothing reaches SSH that is not named in it.

```toml
[vault]
idle-timeout = "60m"          # relock, and drop session sudo grants, after this idle

[approval]
# Open the unlock page in your browser, rather than only printing its link.
open-browser = true
# Also show your client's permission dialog before every *non*-sudo run. Off by
# default; useful while you are learning what the assistant does. (Sudo always
# prompts, via ssh_sudo, and is not affected by this.)
confirm-every-command = false
# The loopback port every unlock and approval page is served on. Change it only
# if something else on this machine wants 8765; see below for why it is fixed.
page-port = 8765

[secrets]
# Withhold passwords and keys from ssh_get and command output, so editing a
# config file does not copy its credentials into the transcript. On by default.
redact = true

# Import connection details from an entry you already have.
[hosts.prod-1]
from = "ssh-config:prod-1"    # HostName / User / Port / IdentityFile from ~/.ssh/config
sudo = "ask"

[hosts.build]
from = "putty:Build Server"   # HostName / UserName / PortNumber / PublicKeyFile from a saved PuTTY session
sudo = "ask"

# Or spell it out.
[hosts.lab]
host = "192.168.1.9"
user = "root"
key  = "~/.ssh/id_ed25519"    # OpenSSH or .ppk
sudo = "off"                  # sudo refused outright on this host
description = "scratch box"
```

Entries in `~/.ssh/config` or PuTTY **not named here do not exist** to this
server. `from` opts one in, by name. Importing your whole SSH config would
defeat the point.

### Host keys

| Key | Meaning |
| --- | --- |
| `from` | `ssh-config:<name>` or `putty:<name>`, which imports connection details |
| `host`, `user`, `port`, `key` | Set or override individually; inline always wins over imported. `port` defaults to 22 |
| `sudo` | `"ask"` (default) runs sudo through the gate; `"off"` refuses it outright |
| `file-writes` | `"guard"` (default) makes `ssh_run` and `ssh_sudo` refuse in-place edits and point at `ssh_edit`; `"off"` lets them through. There is no tool parameter for this and the refusals never mention it: it is a lever you pull, not one the model can ask for. A host with it off says `writes:unguarded` in the listing |
| `description` | Shown in the host listing instead of the source |

### Secret keys

| Key | Meaning |
| --- | --- |
| `redact` | `true` (default) withholds secret-looking values from `ssh_get` and command output, and puts them back for an `ssh_edit` write. `false` returns everything verbatim |
| `patterns` | Extra patterns, on top of the built-in set. Group 1 is the value to withhold; a leading `(?i)` makes the pattern case-insensitive. One that will not compile, or has no capture group, is reported on stderr and dropped on its own |
| `paths` | Files whose contents are never returned at all, not even redacted. `*` stops at a `/`, `**` crosses one, and a pattern with no `/` matches the file name wherever it lives |

See [Editing a file that has a password in it](#editing-a-file-that-has-a-password-in-it)
for what the model sees, and for what this does not protect you from.

Authentication is **keys only**. No password option, deliberately: a password
must live somewhere, and every somewhere is worse than an encrypted key file.

Point `key` at a PuTTY `.ppk` and it works: PPK v2 and v3 (Argon2id), RSA, DSA,
ECDSA and Ed25519. After unlocking, `ssh_status` reports the type and
fingerprint of every key it decoded.

### Files it creates, next to your config

| File | Contents |
| --- | --- |
| `sudo-policy.txt` | Your persistent sudo rules. Plain text, one per line, yours to edit |
| `audit.jsonl` | Append-only record of every command, decision and grant |

The policy file is yours alone to write. `ssh_sudo` prints the line; you put it
there:

```
# ssh-mcp sudo policy. One rule per line: <host-alias-or-*>  <command pattern>
#   *  matches exactly one argument      **  matches the remaining arguments (last token only)
prod-1  systemctl restart *
prod-1  journalctl **
*       tail *
```

Wildcards stand for **whole arguments only**. A rule like `tail /var/log/*` is
rejected at load time with an explanation rather than silently never matching.
Substring globbing is left out on purpose: `/var/log/*` would otherwise match
`/var/log/../../etc/shadow`.

See [Adding standing rules](#adding-standing-rules) for where rules go, when
they take effect, and which commands no rule ever covers.

---

## Using it

The first command of each session unlocks:

```
You:    check nginx on prod-1
Claude: [ssh_run prod-1 "systemctl status nginx"]

        ssh-mcp wants you to open:
          http://127.0.0.1:8765/unlock/9nQ2…
          [open] [decline]
```

Open it, type your passphrase, and the page closes itself. A wrong passphrase is
reported on the page with the form still there to retry. The browser waits for
the vault to actually open before saying "Done", so a mistake never surfaces
later as a puzzling failure. The command then runs, and nothing asks again until
the idle timeout.

Any `sudo` forces the assistant to `ssh_sudo`, which opens a page showing
exactly what it wants to run:

```
┌ Run this with sudo on prod-1? ──────────────┐
│                                             │
│  sudo systemctl restart nginx               │
│                                             │
│ • host: prod-1 (deploy@10.0.4.12)           │
│ • shell extras: none                        │
│                                             │
│ ( ) Deny                  run nothing       │
│ (•) Allow once            this command, now │
│ ( ) Allow for this session                  │
│         this exact command, until relock    │
│                                             │
│              [ Confirm ]                    │
└─────────────────────────────────────────────┘
```

The call waits while you answer, then runs. One tool call, no "ask me again".
"For this session" means the same command goes through next time without a page.
The result tells you how to make it permanent, narrowest first:

```
— allowed for this session. To make it permanent, add a line to
  C:\Users\you\.ssh-mcp\sudo-policy.txt:
    prod-1	systemctl restart nginx
  or wider:
    prod-1	systemctl restart *
    prod-1	systemctl **
```

You type that line. Nothing here appends to that file. A permanent grant of root
should take a human deciding to give it.

### Adding standing rules

`sudo-policy.txt` sits next to your config: `~/.ssh-mcp/sudo-policy.txt`, or
`%USERPROFILE%\.ssh-mcp\sudo-policy.txt` on Windows. Nothing creates it. Make
the file yourself when you want a first rule. A line is a host, whitespace, and
a pattern; blank lines and `#` comments are ignored, so the file can explain
itself:

```
# read-only, asked constantly, never destructive
vps  systemctl status **
vps  journalctl **

# runtime lifecycle; enable/disable stay manual on purpose
vps  systemctl restart *
vps  systemctl daemon-reload
```

The host is an alias from your config, or `*` for every host. Prefer the alias.
`*  apt-get install **` across a staging box and a production box is a much
larger grant than it looks like on the page.

**The file is read once, at startup.** Editing it changes nothing until the
server restarts. Restart your MCP client, then run `ssh_status`: it lists every
loaded rule as `always  <host>  <pattern>`, which is how you confirm a rule
took. An unparseable line goes to stderr with its line number and is dropped on
its own, so a typo costs one rule and not the policy. Silently, from the tool's
point of view.

Two things catch people out, both from matching arguments rather than strings:

- **Flags are arguments, and order matters.** `apt-get install **` covers
  `apt-get install -y nginx` and does *not* cover `apt-get -y install nginx`.
- **A redirection or a `$(…)` makes the line approve-once**, whatever the policy
  says, because what would run is not what the rule was matched against. Pipes
  and `;` are fine — each sudo segment is matched on its own, so
  `journalctl -u api | tail -50` runs on a `journalctl **` rule (see
  [A wildcard grant can only match a command whose meaning is
  pinned](#a-wildcard-grant-can-only-match-a-command-whose-meaning-is-pinned)).
  A rule is still only ever *written* from a plain single command, so the "allow
  for the session" button does not appear on a pipeline.

#### Rules that can never fire

No rule covers these, so writing one leaves a dead line in your file. Two
groups, for two reasons:

| | |
| --- | --- |
| Refused outright, no dialog | shells (`sh`, `bash`, `zsh`, …), `su`, `visudo`, `sudoedit`, anything naming `/etc/sudoers`, and the flags `-s` `-i` `-E` `-b` `-A` |
| Approve-once only, never by rule | `docker`, `podman`, `lxc`, `chroot`, `env`, `chown`, `chmod`, `useradd`/`usermod`/`passwd`, `find`, `xargs`, interpreters (`python`, `perl`, `node`, `awk`, …), editors and pagers (`vi`, `nano`, `less`, `man`, …), `cp`/`mv`/`ln`/`dd`/`tee`/`tar`/`rsync`, `curl`, `wget`, `sed`, `mount`, `crontab`, `at`, `systemd-run`, `modprobe` |

The second group is not a judgement about those commands. Each can be talked
into spawning a shell or writing a file of your choosing, so a `*` over any of
them is a `*` over root. They still run; they just ask every time. Current text:
`src/sudo/denylist.ts`.

### Changing a config file

Ask for a change to `postgresql.conf` and the assistant reads it, works out the
anchor, and calls `ssh_edit`. You get a page:

```
Apply this change on prod-1?

  /etc/postgresql/16/main/postgresql.conf

  --- a/etc/postgresql/16/main/postgresql.conf
  +++ b/etc/postgresql/16/main/postgresql.conf
  @@ -112,7 +112,7 @@
    # - Memory -
   
  -shared_buffers = 128MB
  +shared_buffers = 4GB
   #huge_pages = try
   work_mem = 4MB

  • host: prod-1 (deploy@10.0.0.4)
  • written as root with sudo (deploy cannot write it)
  • 1 edit(s), +1 −1 lines

  ( ) Deny    change nothing
  ( ) Apply   write this change now
```

The file is root-owned and `deploy` cannot write it, so the write goes through
sudo. That is a line on the page, not a decision you make blind. If someone
edits the file between the diff and your answer, nothing is written and you are
shown the real diff instead. There is no *allow for this session* here: only
this diff was ever approved.

`ssh_run` and `ssh_sudo` will not do this for you. `sed -i`, `tee`, `dd of=`,
`cp` onto a config, and `>` onto any absolute path outside `/tmp` are refused
with a pointer back here. The sudo approval page can show you a command line and
nothing about what the file would end up containing.

### Editing a file that has a password in it

The file you most want the assistant to edit is the one you least want it to
read. An anchored edit needs an anchor, so "read it, then change the line above
the password" put the password in the transcript, in your client's session log
and in the model provider's request. Every time.

So the value is withheld and the position is not:

```
you:    add a connection pool setting to /etc/app/appsettings.json on prod-1
claude: [ssh_get prod-1 /etc/app/appsettings.json]

        "ConnectionStrings": {
          "Db": "Host=db;Username=app;Password={{ssh-mcp:secret:7a2fb1c4}}"
        },
        "Pool": { "Max": 20 }

        — 1 value(s) in this file are withheld and shown as {{ssh-mcp:secret:…}}
          markers. They are still in the file.
```

The model anchors on the marker like any other text, `ssh_edit` puts the real
value back before it matches, and the diff on your approval page shows the
password in full, because a diff you cannot read is not a decision. The reply is
line counts, as it always was.

Withheld by default: `password`, `passwd`, `pwd`, `secret`, `token`, `api_key`,
`access_key`, `client_secret`, `credentials`, `auth_token` and `private_key`
assignments in any of the usual shapes, the password half of a `scheme://user:pw@host`
URL, and any `-----BEGIN … PRIVATE KEY-----` block. A key whose value is `true`,
a number, or `$SOMETHING` is left alone: there is no secret on that line, and
hiding it costs the model what it needs to be useful.

Markers are per host, live in memory, and die when the vault relocks. They are
HMACs under a per-process key, so a marker in an old transcript is not a digest
anyone can attack, and after a relock it names nothing at all.

#### Setting a password nobody has to see

Rotation runs the other way: `new_string` is authored by the model, so a new
password would be in the transcript by construction. Two markers avoid that:

| In `new_string` | What happens |
| --- | --- |
| `{{ssh-mcp:generate:32}}` | ssh-mcp invents the value, from an alphabet with no shell or quoting metacharacters in it. Repeat the same request in one call and you get one value, so a password and the connection string beside it match |
| `{{ssh-mcp:ask:db-password}}` | A loopback page asks *you* to type it, exactly as the key passphrase is asked for. The name is remembered until relock |

Either way the approval diff shows what the file will really contain, and the
reply hands back a marker for the value so the rest of the session can refer to
it. That is what makes the second half of a rotation possible:

```
claude: [ssh_edit  prod-1 /etc/app/appsettings.json  → {{ssh-mcp:generate:32}}]
        Applied 1 edit(s) … The value(s) written are held as
        {{ssh-mcp:secret:c81d0f22}} until the vault relocks.

claude: [ssh_sudo prod-1 "sudo -u postgres psql -c \"ALTER USER app PASSWORD
                          '{{ssh-mcp:secret:c81d0f22}}'\""]
```

`ssh_sudo` expands markers; `ssh_run` refuses them outright, because it is the
tool with no page in front of it and an expanded marker there would be a
password retrieved with `echo`. A line carrying a marker **always** opens the
approval page, even one with no `sudo` in it, and can never be remembered for
the session or written into your policy file. The page shows the expanded line,
which is also the line that gets parsed, denylisted and write-checked: analysing
the marker form and running the expanded one is the `sudo $(…)` mistake.

`audit.jsonl` and the echo in the transcript keep the marker form. The value
went from your browser, or the server's random generator, to the file.

#### Where this stops

Once a value is known for a host it is masked wherever it turns up, not only
where a pattern finds it, so `echo … > /tmp/x` and then `cat /tmp/x` gives back
the marker. But redaction is hygiene, not containment. It removes the exposure
the ordinary read-then-edit workflow *forces* on you, and a model that means to
have the value still has a shell: `base64`, `xxd`, `rev`, `cut -c20-`,
`openssl enc`. None of those produce anything a pattern or a string comparison
will recognise. The marker is also a map: it says exactly which line to aim at.

What contains that case is the operating system, and it is already how this
server is built. `ssh_get` and `ssh_run` run as the connecting user with **no
sudo path at all**, so a root-owned `0600` file is beyond both of them today.
Only `ssh_edit` can read it, through `sudo base64`, and that content has never
reached the model. If a secret genuinely must not be readable by an assistant,
the answer is the file's mode, not a regex.

The pattern set is not exhaustive either. `[secrets].patterns` adds your own,
group 1 being the value, and `[secrets].paths` withholds whole files:

```toml
[secrets]
redact = true                                    # default
patterns = ['(?i)^\s*ldap_bind_pw\s*=\s*(.+)$']
paths = ["/etc/app/*.env", "id_rsa"]             # contents never returned at all
```

A path listed there is refused by `ssh_get` outright rather than redacted: for a
file that is nothing but secret, the honest answer is that the model does not
read it. `ssh_status` says whether redaction is on, which is how you confirm the
config took.

### Tools

| Tool | What it does |
| --- | --- |
| `ssh_run` | Runs a command line. Pipelines work; writing a file does not. Output comes back as plain text, capped at 300 lines / 64 KiB with the middle elided, with secrets withheld. **Never runs sudo, never expands a marker** |
| `ssh_sudo` | Runs a privileged command, after showing you the exact command on a page and waiting for your answer. Expands markers, and a line carrying one is always shown and never remembered. **Never writes a file** |
| `ssh_ls` | Lists a directory over SFTP, in `ls -l` form |
| `ssh_get` | Reads a text file over SFTP (≤ 256 KiB; binary refused), with passwords and keys replaced by markers |
| `ssh_edit` | Replaces exact snippets of a remote file. Shows you the unified diff on a page and waits for your answer before writing anything, including files owned by root, which it writes through sudo. Puts withheld values back, and can generate or ask for a new one |
| `ssh_hosts` | Lists the aliases you configured. Also published as the `ssh://hosts` resource |
| `ssh_status` | Locked or unlocked, which sudo grants are live, whether secrets are withheld, where the policy and audit files are |
| `ssh_lock` | Locks immediately: forgets the keys, closes the connections, revokes session grants |

Every `ssh_run` result opens with the command as a shell prompt line, so the
conversation is the record of what happened rather than a row of opaque
`ssh_run` calls:

```
deploy@prod-1$ systemctl status nginx --no-pager
● nginx.service - A high performance web server and a reverse proxy server
     Active: active (running) since Tue 2026-08-04 09:12:44 UTC; 1 day 4h ago
```

`#` for root, `$` for everyone else. The echo is on failures too. A command that
could not even connect is exactly when you want to see what it was.

To see *non*-privileged commands before they run, set
`confirm-every-command = true` under `[approval]`. That marks `ssh_run` with
`requiresUserInteraction`, so your client prompts on every call. Noisier, and
the prompt shows the tool rather than the command, but nothing runs unseen.

### Slash commands

Claude Code exposes MCP prompts as `/mcp__<server>__<name>`:

| Command | What it asks for |
| --- | --- |
| `/mcp__ssh__explain` | A walkthrough of the commands run in this conversation: every flag individually, where the files live, what a seasoned admin would reach for instead. Takes an optional `focus`, e.g. `journalctl` |
| `/mcp__ssh__audit` | A read of the audit log and policy file: what ran where, which sudo decisions were made, and which standing rules look wider than they need to be |

Prompts rather than tool descriptions, on purpose. A tool description telling
the model to explain itself would steer the assistant on every call, asked for
or not.

---

## Layout

Vertical slices. Each folder owns one concern end to end (its logic, its config,
and the tools it registers) rather than splitting across `services/`, `tools/`
and `lib/`.

```
src/
  main.ts       stdio transport, slice registration, lock on shutdown
  runtime.ts    process-wide state, built once
  config/       ssh-mcp.toml
  hosts/        WHO we may talk to    — registry, ~/.ssh/config, PuTTY registry
  vault/        WHETHER we may act    — lock state, unlock page, MRTR gate, key decoding
  sudo/         WHAT we may do        — parser, matcher, denylist, write guard, grants, the two gates
  secrets/      WHAT may be said      — secret patterns, the withheld-value store
  session/      HOW we talk           — connection pool, exec, SFTP, anchored edits, diff
  audit/        what happened
  integration/  the same, against a container (npm run test:integration)
docker/         the throwaway host those tests build
```
