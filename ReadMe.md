# ssh-mcp

An MCP server that gives Claude a shell on your servers, and cannot use it
without your explicit consent.

It starts locked on every launch. It asks for your key passphrase in a browser,
never through the model. It checks every `sudo` against a policy you control,
and remembers only what you tell it to remember. It supports PuTTY `.ppk` keys,
so the passphrase you already type is the only thing you need.

---

## Why build this

The useful thing and the dangerous thing are the same thing.

Real work on a server is a conversation: read the log, notice the OOM kill, check
the unit file, bump the memory limit, restart, watch it come back. Doing that
through an agent is genuinely better than doing it by hand: it reads two
hundred lines of `journalctl` faster than you do, it remembers which unit you
were looking at, and it does not fat-finger a hostname at 2am. Doing it by
copy-pasting terminal output into a chat window is worse than both.

But an agent with SSH access is an agent that can `rm -rf` your production box.
And the usual answers are both bad:

- **Ask every time.** Twelve dialogs into a debugging session you stop reading
  them. A prompt you always click through is not a control; it is a habit.
- **Just allow it.** One prompt-injected log line, one confidently wrong
  inference, and the blast radius is your infrastructure.

The interesting question is not "how do we get consent" but **where consent
belongs**. The answers this server picks:

**Consent belongs to the session, not the command.** One passphrase entry opens
the door; it closes again on its own after an idle period. You are not asked
about `uptime`.

**Consent belongs to a decision you can read.** A `sudo` approval names the host
and the exact command, one at a time. Approving it covers that command for the
session and nothing more; widening it to `apt *` or `apt **` means editing a
plain-text file yourself. Nothing widens on its own, and nothing in this server
writes a permanent grant of root. It prints the line and stops.

**Some things are not consentable.** `sudo -s` has no dialog. Neither does
`sudo su`, `sudo bash`, or anything touching `/etc/sudoers`. Approving a root
shell once approves everything afterwards, which makes "approve once" a lie. So
it is refused instead of asked about.

**And the model is never the one holding the secret.** This is the load-bearing
one, and it is the reason for the browser page below.

---

## The one idea worth stealing

The MCP specification has a rule that most servers can ignore and this one
cannot:

> Servers **must not** use form mode to request sensitive information such as
> passwords, API keys, access tokens, or payment credentials. Those interactions
> belong in URL mode, which keeps the data out of band so it never passes
> through the client or the LLM context.
>
> — MCP specification, revision 2026-07-28

Elicitation, a server asking the user something mid-task, is not one feature but
two, and the difference is exactly a trust boundary:

|              | Where the answer goes                     | Fit for                |
| ------------ | ----------------------------------------- | ---------------------- |
| **Form mode** | Back through the client, into the transcript, into the model's context | A yes/no. A choice. |
| **URL mode**  | Browser → server directly. The client only learns *whether* you consented. | A secret. |

That boundary is why the passphrase is collected on a one-shot page on
`127.0.0.1`, behind a 256-bit single-use nonce, that dies the moment you submit
it. The passphrase never enters the MCP protocol, the transcript, or the model's
context. The model observes only "locked", then "unlocked". Asking for it in a
form would work, and would be wrong: anything the model can read is a secret
that has leaked, into the transcript, into context compaction, into whatever
logs that transcript touches.

### What actually happened when this met a real client

The design above was half right, and the half that was wrong is worth recording,
because it is the part a spec cannot tell you.

**Claude Code negotiates the 2025 protocol era over stdio**, not `2026-07-28`.
So the entire multi-round-trip mechanism (`inputRequired`, `inputResponses`, the
signed `requestState`) never engages with the real client. Three independent
confirmations, since this one is worth being sure about:

- The SDK's own error text: *"the client on this **2025-era** connection did not
  declare the required capability"*.
- Anthropic's [announcement](https://claude.com/blog/bringing-mcp-2026-07-28-to-claude):
  *"Support is being rolled out across Claude products **soon**."*
- The [Claude Code changelog](https://code.claude.com/docs/en/changelog) across
  2.1.186 – 2.1.222: no mention of `2026-07-28`, protocol negotiation, MRTR,
  `inputRequired`, or elicitation.

It is not a misconfiguration and there is no flag to force it. Per the SDK,
*"nothing in v2 puts a 2026-07-28 byte on the wire by default… serving or
speaking 2026-07-28 is always an explicit opt-in"*, and the client is the side
that has to opt in.

This server supports both eras, and **the tests exercise both**, which they did
not at first: the end-to-end suite pinned `2026-07-28`, so it validated the era
Claude Code does not use. That single fact is why it stayed green through all
three production failures below. If you are designing around MRTR, check which
era your client actually opens with before you rely on it.

**Claude Code does not declare `elicitation.url` at all.** So it never renders
the unlock page itself. The server therefore opens the page in your browser and
also prints the link in the tool result: a local address, served by this
process, for you. That is not the client auto-fetching a URL, which the spec
forbids; nothing is fetched, a browser is pointed at a page that then talks
directly to us.

**And Claude Code declares `elicitation.form` but answers `decline` in 7–14 ms
without rendering anything.** Measured, repeatedly, in the audit log. A sudo
approval asked that way is a refusal the user never saw. Form-mode elicitation
was removed from this server entirely.

The replacement was the client's own permission prompt, via
`_meta["anthropic/requiresUserInteraction"]`, which does arrive. That lasted
until the obvious question: *"when approving sudo commands I would like to see
the command I am approving."* The prompt gates the **call** and shows the tool
name; it does not put the command in front of you. Approving `ssh_sudo` is not
approving `sudo apt update`, and a consent step that hides what it is consenting
to is theatre.

So the sudo approval moved onto the same loopback page as the passphrase, the
one surface here that is known to render and is entirely under this server's
control:

- **`ssh_run` never runs sudo.** Not "unless a rule covers it". Never. A tool
  that is sometimes privileged is a tool you cannot reason about at a glance.
- **`ssh_sudo`** opens a page showing the command verbatim, the host, the shell
  metacharacters found in it, and whether it can be remembered at all. You choose
  deny / once / for-this-session. Answering "for this session" means the same
  command does not ask again until the vault relocks.

The page is a stronger gate than the prompt it replaced, not a weaker one:
nothing but a person with a browser can answer it, the submitted value is
checked against the options actually offered, and the command is unmissable. The
denylist and shell-segment analysis still run server-side afterwards. Approving
`sudo -s` on the page does not make it allowed.

**And every secret request degrades to a relayed link rather than an error.**
The sudo-password path originally threw a protocol error when the host asked for
a password, because it reached for URL elicitation unconditionally. A consent
mechanism that throws is worse than one that is merely inconvenient.

The general lesson: **build the consent path on a channel you have watched
arrive.** Elicitation is in the spec, is documented as supported, and still did
not work here. All three failures were only visible from the audit log and from
calling the server as a client, never from the tests, which passed throughout
because the test client implements the spec faithfully.

---

## How this differs from other SSH MCP servers

Most of them are a thin wrapper: a tool that takes `host`, `username`,
`password` or `privateKey`, and `command`, and hands the lot to an SSH library.
That shape has three problems, and each one is a design decision here rather
than a missing feature.

| | Typical SSH MCP server | ssh-mcp |
| --- | --- | --- |
| **Credentials** | In the config file, in an env var, or passed as a tool argument by the model | Nowhere at rest in usable form. Keys stay encrypted on disk; a human unlocks them per process start, out of band |
| **Target selection** | Model supplies `host`/`user`/`port`/`key` | No such parameter exists. `host` is an `enum` of aliases you listed, so an unlisted machine is *unrepresentable*, not merely rejected |
| **sudo** | Runs it, or blocks it, or asks every time | Denylist → stored rules → a separate always-prompting tool |
| **Approval scope** | Per tool call, or none | Per (host, argv); a session grant dies when the vault relocks, and only you can make one permanent |
| **Command analysis** | Substring or regex over the command string | Shell-aware: the line is split into segments, and a stored rule can only ever match a single plain command |
| **Output** | JSON envelope | Plain text, as a terminal would show it |
| **Audit** | — | Append-only JSONL of every command, decision and grant |

Two of those deserve elaboration, because they are the ones that are easy to get
subtly wrong.

### The model cannot name a machine you did not

Every tool's `host` parameter is a JSON Schema `enum` built from your config at
startup. There is no `hostname` parameter, no `port`, no `key`, no `password`.
This is stronger than validating an argument: a closed set in the schema means
the model has nothing to pass. Tools declare `openWorldHint: false` to say so.

### A wildcard grant can only match a command whose meaning is pinned

This is the subtle one. Suppose you approve `systemctl restart *` on `prod-1`.
Later the model runs:

```
sudo systemctl restart nginx; rm -rf /var
```

A server that pattern-matched the command string could match the prefix and let
the whole line through. So instead:

1. The line is split the way a shell would split it, tracking quotes, and every
   separator (`;` `&&` `||` `|` `&`), expansion (`$(…)`, backticks, `${…}`, `$`)
   and redirection (`<` `>`) found **outside** quotes is recorded.
2. A stored rule may only ever match a line that has none of those. Anything
   else is approve-once, every time, with the extras shown to you.
3. Matching is per argument, not per substring. `*` is exactly one argument;
   `**` is the remaining arguments and only in last position. So
   `systemctl restart *` matches `systemctl restart nginx` and refuses
   `systemctl restart nginx --now`, because an extra argument is a miss.
4. `sudo`'s own flags are parsed, and anything not understood (a bundled `-nS`,
   an unknown `--flag`) makes the invocation ungrantable rather than guessed at.

`grep "a;b" /etc/hosts` is still a plain command, because the `;` is quoted.

---

## Why run SSH through MCP at all

If you are going to let an agent touch a server, an MCP server is a better place
for the controls than the alternatives.

**Versus pasting terminal output into chat.** You are the transport, which is
slow, and you paste whole files because trimming is work. Nothing is audited and
nothing is bounded.

**Versus letting the agent drive your local `ssh` through a shell tool.** This is
the common setup and it is the weakest one. Your agent host already has your
`ssh-agent` loaded and your `~/.ssh/config` populated, so a shell tool is
ambient authority over every machine you have ever logged into, with no host
allowlist, no sudo policy, and an approval prompt showing a command string that
means whatever the remote shell decides it means. Every control described above
is absent by construction.

**Versus an agent inside the server.** Now the credentials, the agent and the
blast radius are all on the machine you were trying to protect.

An MCP server puts a policy boundary in the one place both sides must cross,
running as a separate process with its own configuration, its own audit log and
its own idea of what it is allowed to do, and no ability to widen that on its
own. The model gets a capability; it never gets the credential.

What you also get, once that boundary exists, is that the interesting parts are
cheap: bounded output, a real audit trail, an idle lock, host aliases the model
can discover but not invent.

### A note on where the trust actually is

To be straight about scope, because a security README that oversells is worse
than none:

- **This is not a defence against local malware.** A process running as you can
  read your key files directly. What the loopback page buys, completely, is
  that your passphrase never enters the model's context.
- **The denylist is not exhaustive.** `sudo find`, `sudo vim`, `sudo docker` and
  friends can all be talked into a shell, so they are approve-once and never
  wildcardable, but no list of this kind is complete. The closed host world and
  the once-only default carry the real weight.
- **Claude Code's `Elicitation` hook can auto-answer dialogs.** Anyone who
  configures one has bypassed the sudo gate. That is a legitimate feature of the
  client and worth knowing about.
- **The unlock link does reach the model's context** on the relayed-link
  fallback. That is a deliberate trade: it is a single-use nonce for a loopback
  listener with a two-minute life, and all it grants is the ability to *submit* a
  passphrase the holder still does not know. The passphrase itself never goes
  near that context on either path.
- **`ssh_ls` and `ssh_get` run as the connecting user**, with no sudo path at
  all. `ssh_edit` does escalate, and when it does, the page you answer says so
  and shows you the diff first.
- **The file-write guard reads paths, not intent.** `cd /etc && sed -i s/a/b/
  nginx.conf` gets through, because catching it would mean tracking the working
  directory across shell segments and the next line would just be
  `cd /etc; cd .; sed -i …`. So do command wrappers (`env`, `xargs`, `nice` in
  front of `sed -i`), `rsync`, `tar -x`, `git apply` and `systemctl edit`. Same
  honesty as the denylist above: this is the well-known cases, and the weight is
  carried by `ssh_edit` being pleasant enough that nobody has to route around it.
- **`ssh_edit` reads a root-owned file before you have approved anything**, with
  `sudo base64`, so it has something to diff against. That content never reaches
  the model. It is used to draw the page and to check the file has not moved,
  and the reply carries only line counts. The honest cost is that the model can
  cause a root-readable file to be read; what it cannot do is see it.
- **Editing an existing file changes nothing about its owner, group, mode, ACLs
  or labels.** Both routes go through the inode that is already there: the
  unprivileged one truncates it over SFTP and sends no attributes at all, and
  the privileged one is `sudo cp`, which opens and truncates rather than
  unlinking. `mv`, `install` and `cp --remove-destination` would each replace
  the file, and the replacement would arrive owned by root: a change the diff
  you approved says nothing about, and one that stops sshd and sudo starting.
- **A file `ssh_edit` creates is made as you if the directory allows it.** Only
  when it does not does the file land as `root:root` mode 0644, because there is
  no basis for guessing an owner. The reply says which of the two happened.
- **`ssh_edit` takes no backup.** A `.bak` beside a config file is an active
  hazard: `nginx`, `logrotate.d`, `sudoers.d`, `sysctl.d`, `cron.d` and
  `sources.list.d` all glob their directories, and it duplicates whatever secret
  the file held to a second path. What replaces it is the re-read before the
  write and the audit trail.
- **The remote sudo shim assumes a POSIX-ish login shell.** Hosts with
  `requiretty` in sudoers need a PTY and are not supported.

---

## Install

Requires **Node 22 or newer**, and Claude Code **2.1.199 or later** for the
`requiresUserInteraction` annotation that the sudo prompt depends on.

Unlocking works like this in Claude Code: the first command that needs SSH opens
an unlock page in your browser and prints the link in the chat as a fallback. You
type your passphrase there and tell the assistant to carry on. Claude Code does
not declare URL-mode elicitation, so it will not show a native prompt for this,
and the server will *not* fall back to a form-mode prompt instead, since a form
answer travels back through the client and into the model's context, which is the
one thing a passphrase must not do.

Set `open-browser = false` under `[approval]` if you would rather just get the
link (headless boxes, remote sessions).

```sh
git clone <this repo> ssh-mcp
cd ssh-mcp
npm install
npm run build
npm test          # 330 tests, no network or server needed
```

Register it with Claude Code:

```sh
claude mcp add ssh -- node /absolute/path/to/ssh-mcp/dist/main.js
```

To keep the config somewhere other than `~/.ssh-mcp/ssh-mcp.toml`:

```sh
claude mcp add ssh --env SSH_MCP_CONFIG=D:/keys/ssh-mcp.toml -- node /absolute/path/to/ssh-mcp/dist/main.js
```

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

Entries in `~/.ssh/config` or PuTTY that are **not named here do not exist** to
this server. `from` is how you opt one in, by name. Importing your whole SSH
config would defeat the point.

### Host keys

| Key | Meaning |
| --- | --- |
| `from` | `ssh-config:<name>` or `putty:<name>`, which imports connection details |
| `host`, `user`, `port`, `key` | Set or override individually; inline always wins over imported. `port` defaults to 22 |
| `sudo` | `"ask"` (default) runs sudo through the gate; `"off"` refuses it outright |
| `file-writes` | `"guard"` (default) makes `ssh_run` and `ssh_sudo` refuse in-place edits and point at `ssh_edit`; `"off"` lets them through. There is no tool parameter for this and the refusals never mention it: it is a lever you pull, not one the model can ask for. A host with it off says `writes:unguarded` in the listing |
| `description` | Shown in the host listing instead of the source |

Authentication is **keys only**. There is no password option, deliberately: a
password would have to live somewhere, and every somewhere is worse than an
encrypted key file.

### Files it creates, next to your config

| File | Contents |
| --- | --- |
| `sudo-policy.txt` | Your persistent sudo rules. Plain text, one per line, yours to edit |
| `audit.jsonl` | Append-only record of every command, decision and grant |

The policy file is yours alone to write. `ssh_sudo` prints the line to add; only
you put it there:

```
# ssh-mcp sudo policy. One rule per line: <host-alias-or-*>  <command pattern>
#   *  matches exactly one argument      **  matches the remaining arguments (last token only)
prod-1  systemctl restart *
prod-1  journalctl **
*       tail *
```

Wildcards stand for **whole arguments only**. A rule like `tail /var/log/*` is
rejected at load time with an explanation, rather than silently never matching.
Substring globbing is left out on purpose, since `/var/log/*` would otherwise
also match `/var/log/../../etc/shadow`.

[Adding standing rules](#adding-standing-rules) covers writing rules of your
own: where to put them, when they take effect, and which commands no rule will
ever cover.

---

## Using it

The first command of each session unlocks:

```
You:    check nginx on prod-1
Claude: [ssh_run prod-1 "systemctl status nginx"]

        ssh-mcp wants you to open:
          http://127.0.0.1:49821/unlock/9nQ2…
          [open] [decline]
```

Open it, type your passphrase, and the page closes itself. A wrong passphrase is
reported on the page, with the form still there to retry. The browser waits for
the vault to actually open before saying "Done", so a mistake never surfaces
later as a puzzling failure. The command then runs, and nothing asks again until
the idle timeout.

When a `sudo` comes up the assistant has to reach for `ssh_sudo`, which opens a
page in your browser showing exactly what it wants to run:

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

The call waits while you answer, then runs: one tool call, no "ask me again".
"For this session" means the same command goes through next time without a page.
The result then tells you how to make it permanent, narrowest first:

```
— allowed for this session. To make it permanent, add a line to
  C:\Users\you\.ssh-mcp\sudo-policy.txt:
    prod-1	systemctl restart nginx
  or wider:
    prod-1	systemctl restart *
    prod-1	systemctl **
```

You type that line. Nothing in this server appends to that file. A permanent
grant of root should take a human deciding to give it.

### Adding standing rules

`sudo-policy.txt` sits next to your config: `~/.ssh-mcp/sudo-policy.txt`, or
`%USERPROFILE%\.ssh-mcp\sudo-policy.txt` on Windows. There is no command that
creates it: make the file yourself when you want a first rule. A missing file
means no persistent rules, which is a perfectly good state to stay in.

A line is a host, whitespace, and a pattern. Blank lines and `#` comments are
ignored, so the file can explain itself:

```
# read-only, asked constantly, never destructive
vps  systemctl status **
vps  journalctl **

# runtime lifecycle; enable/disable stay manual on purpose
vps  systemctl restart *
vps  systemctl daemon-reload
```

The host is an alias from your config, or `*` for every host. Prefer the alias:
`*  apt-get install **` on a config with a staging box and a production box is a
much larger grant than it looks like on the page.

**The file is read once, at startup.** Editing it changes nothing until the
server restarts. Restart your MCP client, then run `ssh_status`, which lists
every loaded rule as `always  <host>  <pattern>`. That listing is how you
confirm a rule took, and it is worth reading once after any edit: a rule you
believe exists but that never loaded is the failure mode this design most wants
to avoid.

A line that cannot be parsed is reported on stderr with its line number, that
one rule is dropped, and the rest of the file still loads. So a typo costs you
one rule rather than the whole policy, but it costs it silently from the tool's
point of view, which is the other reason to check `ssh_status` after editing.

#### Getting a rule right

Start from what `ssh_sudo` printed after you approved something. It offers the
exact command first and the wider forms after, narrowest at the top, and copying
the first line you are actually comfortable with is a better habit than writing
a pattern from imagination.

Two things catch people out, both of them consequences of matching arguments
rather than strings:

- **Flags are arguments, and order matters.** `apt-get install **` covers
  `apt-get install -y nginx` and does *not* cover `apt-get -y install nginx`.
  Pick one form and stay with it.
- **A rule only matches a simple command line.** A pipe, a redirection, a `&&`
  or a `$(…)` makes the line approve-once no matter what the policy says. See
  [A wildcard grant can only match a command whose meaning is
  pinned](#a-wildcard-grant-can-only-match-a-command-whose-meaning-is-pinned).
  In practice this means reaching for a flag instead of a pipe:
  `journalctl -u api -n 50 --no-pager` matches a rule, `journalctl -u api |
  tail -50` asks every time.

#### Rules that can never fire

Some commands are not covered by any rule, so writing one for them only leaves a
dead line in your file. Two groups, for two different reasons:

| | |
| --- | --- |
| Refused outright, no dialog | shells (`sh`, `bash`, `zsh`, …), `su`, `visudo`, `sudoedit`, anything naming `/etc/sudoers`, and the flags `-s` `-i` `-E` `-b` `-A` |
| Approve-once only, never by rule | `docker`, `podman`, `lxc`, `chroot`, `env`, `chown`, `chmod`, `useradd`/`usermod`/`passwd`, `find`, `xargs`, interpreters (`python`, `perl`, `node`, `awk`, …), editors and pagers (`vi`, `nano`, `less`, `man`, …), `cp`/`mv`/`ln`/`dd`/`tee`/`tar`/`rsync`, `curl`, `wget`, `sed`, `mount`, `crontab`, `at`, `systemd-run`, `modprobe` |

The second group is not a judgement about those commands. It is that each of
them can be talked into spawning a shell or writing a file of your choosing, so
a `*` over any of them is a `*` over root. They still run; they just ask each
time. The lists live in `src/sudo/denylist.ts` if you want the current text.

### Tools

Every `ssh_run` result opens with the command as a shell prompt line, so the
conversation itself is the record of what happened rather than a row of opaque
`ssh_run` calls:

```
deploy@prod-1$ systemctl status nginx --no-pager
● nginx.service - A high performance web server and a reverse proxy server
     Active: active (running) since Tue 2026-08-04 09:12:44 UTC; 1 day 4h ago
```

`#` for root and `$` for everyone else, as every Linux tutorial writes it. The
echo is on the failures too. A command that could not even connect is exactly
when you want to see what it was.

Anything using sudo goes through `ssh_sudo`, which shows you the command first.
To see the *non*-privileged commands before they run as well, set
`confirm-every-command = true` under `[approval]`; that marks `ssh_run` with
`requiresUserInteraction`, so your client prompts on every call. Noisier, and
that prompt shows the tool rather than the command, but then nothing runs
entirely unseen.

### Changing a config file

Ask for a change to `postgresql.conf` and the assistant reads it, works out the
anchor, and calls `ssh_edit`. What you get is a page:

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
sudo, but that is a line on the page, not a decision you are making blind. If
someone else edits the file between the diff and your answer, nothing is
written and you are shown the real diff instead.

`ssh_run` and `ssh_sudo` will not do this for you. `sed -i`, `tee`, `dd of=`,
`cp` onto a config, and `>` onto any absolute path outside `/tmp` are all
refused with a pointer back here, because the sudo approval page can show you
a command line and nothing at all about what the file would end up containing.

Two slash commands help with the learning side. Claude Code exposes MCP prompts
as `/mcp__<server>__<name>`:

| Command | What it asks for |
| --- | --- |
| `/mcp__ssh__explain` | A walkthrough of the commands run in this conversation: every flag individually, where the files live, what a seasoned admin would reach for instead. Takes an optional `focus`, e.g. `journalctl` |
| `/mcp__ssh__audit` | A read of the audit log and policy file: what ran where, which sudo decisions were made, and which standing rules look wider than they need to be |

These are prompts rather than tool descriptions on purpose. A tool description
that told the model to explain itself would be this server steering the
assistant on every call, whether or not anyone asked.

### Tools

| Tool | What it does |
| --- | --- |
| `ssh_run` | Runs a command line. Pipelines work; writing a file does not. Output comes back as plain text, capped at 300 lines / 64 KiB with the middle elided. **Never runs sudo** |
| `ssh_sudo` | Runs a privileged command, after showing you the exact command on a page and waiting for your answer. **Never writes a file** |
| `ssh_ls` | Lists a directory over SFTP, in `ls -l` form |
| `ssh_get` | Reads a text file over SFTP (≤ 256 KiB; binary refused) |
| `ssh_edit` | Replaces exact snippets of a remote file. Shows you the unified diff on a page and waits for your answer before writing anything, including files owned by root, which it writes through sudo |
| `ssh_hosts` | Lists the aliases you configured. Also published as the `ssh://hosts` resource |
| `ssh_status` | Locked or unlocked, which sudo grants are live, where the policy and audit files are |
| `ssh_lock` | Locks immediately: forgets the keys, closes the connections, revokes session grants |

### PuTTY keys

Point `key` at a `.ppk` and it works. Both PPK v2 and v3 (Argon2id) are
supported, as are RSA, DSA, ECDSA and Ed25519.

This goes through the pure-JavaScript `ppk-to-openssh` rather than shelling out
to `puttygen`, for two reasons: `puttygen` would write a **decrypted key to
disk**, and `ssh2`'s own PPK support is not enough: its parser only recognises
`PuTTY-User-Key-File-2` with RSA/DSA, so the v3 files modern PuTTY writes by
default would fail.

After unlocking, `ssh_status` reports the type and fingerprint of every key it
decoded, which is the quickest way to confirm your `.ppk` was read correctly.

---

## Design notes

### Why editing is a diff and not a write

The tool this replaced took a path and a whole file and wrote it. That asked the
model for everything and the user for nothing. The model had to reproduce every
line it did not care about, and the failure mode when it did not was silent
deletion of the parts it forgot; the user, meanwhile, saw a tool name in a
permission dialog and no indication of what was in it.

`ssh_edit` inverts both halves.

The model sends **anchors**, not content: the exact text to replace and what to
replace it with. It cannot drop a line it never read, because it only ever names
the lines it means. That is also what keeps the diff short enough to be read by
a human who is in the middle of doing something else.

The user sees the **change**, verbatim, on the same loopback page the sudo
approval uses: `+` and `-` lines, the path, whether it will be written as them
or as root, and two buttons. If the diff is too long to render in full, the tool
refuses rather than eliding it: a consent dialog nobody reads is not consent,
and that applies to this server's own page.

There is no *allow for this session*. The reasoning that keeps `tee`, `cp`, `dd`
and `mv` off every wildcard applies with more force here. Remembering a file
write would be remembering permission over contents the model chooses, and only
this diff was ever approved. The approval is keyed by the hashes of both the old
and the new content, so it cannot be replayed against a different change, and a
file that moved under it opens a fresh page showing the truth instead.

**And it escalates**, because the files worth diffing are mostly not yours.
`/etc/postgresql/16/main/postgresql.conf` is world-readable and root-owned: the
old route was `sudo sed -i` through `ssh_sudo`, where the page could show you
the command and nothing whatsoever about its effect. So `ssh_edit` reads through
`sudo base64` when it has to, and writes through `sudo cp` from a `0600` temp
file, which truncates the destination in place and leaves mode, owner, group and
labels on the inode that was already there. It never puts the new content on a
command line, where `ARG_MAX` and a world-readable process table are waiting.

That last property is load-bearing and invisible: neither the diff nor the
success message would show an edit that had quietly rewritten a config's
ownership, and the service that reads it would just stop starting. So the
commands are built in one place and `session/edit.tool.test.ts` pins them:
that they say `sudo` at all, and that the write is a `cp` onto the destination
and not any of the forms that unlink it first. Both of those were wrong in the
first cut of this tool, and neither was visible from the outside.

That guarantee only means something if it cannot be routed around, which is why
`ssh_run` and `ssh_sudo` now refuse in-place editors and redirection onto an
absolute path outside `/tmp`. `echo x > /etc/foo` needed no sudo and so passed
no gate at all; that was the widest hole in the consent model.

### Plain text, not JSON

Tool results are `text` content blocks that look like terminal output. There is
no `outputSchema` and no `structuredContent` on any exec tool, because SSH output
*is already text*: wrapping it escapes every newline to `\n` and every quote,
which costs tokens for something the model reads as text either way. The host
listing and the sudo policy file are plain text for the same reason, plus a
second one: a rule you cannot read at a glance is a rule you cannot audit.

The one exception is the audit log, which is JSONL. It is written for you and
your tools and never sent to the model, and being able to `jq` a year of sudo
decisions is worth more than being able to skim it.

### One password, many sudos

A command line may contain several sudos, and the password reaches the host as a
single line on the exec channel's stdin. Piping that stdin into `sudo -S`, the
obvious thing and what this did at first, feeds exactly one of them: the first
sudo that actually has to authenticate consumes the line, and the rest read EOF
and fail with `sudo: no password was provided`. It looked intermittent, because
whether a later sudo needed to authenticate at all depended on whether sudo's
timestamp cache was still warm from a previous run.

`sudo -S` cannot be made safe by feeding it more copies, either. Sudo consumes
the line only when it decides to prompt, so under a `NOPASSWD` rule the password
would stay in the pipe and become the *privileged command's* stdin: `sudo tee
/etc/whatever` would write the password into the file.

So the line is moved off stdin into a file only its owner can read, and sudo is
pointed at a one-line helper that prints it. `-A` consults that helper afresh
for every invocation and never touches the command's own stdin. The helper has
to be executable, which a `noexec` `/tmp` forbids, so the arrangement is probed
with `sudo -A -v` rather than assumed. If the probe fails, the password is spent
on a single `sudo -v`, which runs no command and so leaves nothing able to read
what it consumed, and the rest of the line runs `sudo -n` off the cache that
validated. That fallback gives up only on sudos the cache does not reach: it is keyed by
tty or by parent process, and these channels have no tty, so a sudo nested in a
pipeline may still be asked to authenticate. It then fails loudly and asks you
for the password again, which is the point: the failure that started all this
was one nobody was told about.

The password is never in argv (`ps` is world-readable) and never in the
environment (every child would inherit it, and one `env` would print it into the
conversation).

### Layout

Vertical slices. Each folder owns one concern end to end (its logic, its config,
and the tools it registers) rather than being split across `services/`, `tools/`
and `lib/` layers.

```
src/
  main.ts       stdio transport, slice registration, lock on shutdown
  runtime.ts    process-wide state, built once
  config/       ssh-mcp.toml
  hosts/        WHO we may talk to    — registry, ~/.ssh/config, PuTTY registry
  vault/        WHETHER we may act    — lock state, unlock page, MRTR gate, key decoding
  sudo/         WHAT we may do        — parser, matcher, denylist, write guard, grants, the two gates
  session/      HOW we talk           — connection pool, exec, SFTP, anchored edits, diff
  audit/        what happened
```

### Protocol details worth knowing if you are writing one of these

Verified against `@modelcontextprotocol/server` 2.0.0 rather than assumed, since
several of these are recent changes:

- The v2 package is `@modelcontextprotocol/server`; schemas use **Standard
  Schema**, so Zod v4 goes straight into `registerTool`.
- **`ctx.mcpReq.elicitInput()` is deprecated and throws** on the 2026-07-28 era.
  The current mechanism is to *return* `inputRequired({ inputRequests: … })` and
  read the answer back with `acceptedContent(ctx.mcpReq.inputResponses, key)` when
  the client re-calls your tool. Handlers must tolerate re-entry.
- `requestState` round-trips through the client and comes back
  attacker-controlled. `createRequestStateCodec` (HMAC-SHA256, with context
  binding) is the supplied answer; this server binds to the request method and
  mints a fresh per-process key.
- On the modern era, client capabilities arrive **per request** in
  `ctx.mcpReq.envelope`, and `Server.getClientCapabilities()` returns
  `undefined`. Read the envelope first and treat the accessor as the 2025-era
  fallback.
- The elicitation capability is split into `form` and `url` sub-capabilities. A
  client declaring a bare `elicitation: {}` has declared **neither**.
- **Set `mode: 'form'` explicitly.** It is optional on `ElicitRequestFormParams`
  and the SDK omits it, but a client that dispatches on `mode` then has nothing
  to render and answers `decline`, which reaches the user as a refusal they were
  never asked about. URL mode never shows this, because its `mode` is mandatory.
- Keep elicitation schemas free of combinators. The spec's titled-enum form uses
  `oneOf`, and a client that cannot render one may decline the whole dialog. Plain
  `enum` with the labels in `description` is the safe shape.
- Assume any dialog can fail to appear, and make the refusal actionable. When
  form mode is unavailable this server prints the exact `sudo-policy.txt` line to
  add, instead of just saying no.
- **A client can answer `decline` without rendering anything**, even having
  declared form support. Observed in the wild at 7–14 ms between the request and
  the refusal. Reporting that as "the user declined" blames someone for a choice
  they were never shown, so this server stamps a signed timestamp into
  `requestState` and treats an answer under 400 ms as *no dialog reached the
  user*, which routes to the actionable advice instead of a bare refusal.
- `ssh2` is CommonJS: `import { utils } from 'ssh2'` fails at load despite the
  typings, and its parsed keys must be handed to `authHandler` rather than
  re-serialised: `getPrivatePEM()` produces something unusable for Ed25519.
- Nothing may write to stdout except the transport. Diagnostics go to stderr;
  `ctx.mcpReq.log` is deprecated too.

### Tests

330 tests, none needing a network or a server. The ones that matter most:

- `sudo/approval.test.ts`: the assertions the whole design rests on. If one of
  these starts failing, an approval has become wider than the user agreed to.
  Includes the one that says `gatePrivileged` never even offers a page for a
  file write.
- `sudo/parse.test.ts`: quoting, separators, expansions, sudo flag parsing, and
  redirection targets. Half of it pins what did *not* change: `argv`,
  `expansions` and `simple` still mean exactly what they meant before the
  redirection work, because a stored rule is matched against `argv`.
- `sudo/writes.test.ts`: the file-write guard. The **must keep working** list
  comes first and is deliberately mundane (`> /dev/null 2>&1`, `> /tmp/out`,
  `make 2>&1 | tee build.log`, `echo hi > out.txt`), because a guard that
  refuses ordinary commands gets switched off, and then it guards nothing.
- `session/diff.test.ts`, including a property test over random edits: every
  hunk must be a faithful window on both files, or the page is showing someone a
  change that is not the change about to be written. That assertion is what makes
  hand-rolling the diff defensible instead of taking a dependency.
- `session/edit.tool.test.ts`: the privileged command lines, held to their
  invariants without a host: that they invoke sudo, and that the write cannot
  become a form that unlinks the destination and takes its ownership with it.
  The end-to-end version of that assertion, owner and mode unchanged after
  editing a root-owned file, needs a live host and is a manual check.
- `vault/approval-page.test.ts`: the consent surface itself, driven over real
  HTTP: that a diff renders with `+`/`-` apart, that a `<script>` in a config
  file comes back escaped, that `value="session"` is absent, and that approving
  one change never stands for a different change to the same file.
- `main.test.ts`: end-to-end over real stdio, pinned to protocol 2026-07-28. A
  full unlock driven through the loopback page, `ssh_run` refusing un-approved
  sudo before it connects, `ssh_sudo` being the only tool carrying
  `requiresUserInteraction`, and a session grant covering the exact command
  approved and nothing adjacent to it.

- `vault/gate.test.ts`: the secret-request fallback, driven directly. The
  end-to-end suite cannot reach that branch: it needs a live host whose sudo
  demands a password, and the test hosts point at a closed port on purpose.

Two caveats these tests earned the hard way.

**The suite ran against the wrong protocol era for most of its life.** It pinned
`2026-07-28`; Claude Code opens 2025. There is now a
`describe('on a 2025-era connection…')` block walking the same ground over a
default connection declaring form-only elicitation, the configuration Claude
Code actually presents, because that is what ships.

**And a green suite still cannot tell you the consent path works.** The test
client implements elicitation faithfully, so it renders everything the real one
discards. Every failure in this project's history surfaced from the audit log or
from calling the server as a client. None of them from a red test.

`src/vault/fixtures/` holds throwaway `ssh-keygen` keys with a public
passphrase. There is no `.ppk` fixture there; see that folder's README for why
the Windows PuTTYgen cannot produce one without a human.
