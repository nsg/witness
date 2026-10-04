<div align="center">
  <h1>witness</h1>
  <p>Wrap your shell, tag every command, and collaborate through an observational REST API with human-approved suggestions.</p>

  [![AI usage: vibe](https://nsg.github.io/aibadge/vibe.svg)](https://nsg.github.io/aibadge/#vibe)
  [![CI](https://github.com/nsg/witness/actions/workflows/ci.yml/badge.svg)](https://github.com/nsg/witness/actions/workflows/ci.yml)
</div>

## About

`witness` wraps an interactive shell inside a PTY and records every command you run —
assigning each an incrementing id, timestamps, exit code, and captured output. It exposes
that record through a small, token-authenticated REST API designed for observation and
human-approved suggestions.

The point is collaborative troubleshooting: start `witness`, hand the printed URL to an
external agent, and it can "look at your screen" — observing the commands you run and their
output to help you debug — without ever being able to execute anything. An agent may queue inert
command text, but only your local Ctrl-G can insert it and only your Enter can run it
(unless you opt in to [auto-approve](#auto-approve)).

Your shell behaves exactly as normal. Full-screen apps (`vim`, `less`, `htop`, `fzf`) work
untouched, and their alternate-screen output is intentionally left out of the record.

## Features

- Transparent PTY wrapper — your shell, prompt, and TUIs work as usual.
- Per-command records: id, start/finish time (RFC3339), exit code, captured output.
- Observational REST API with bearer-token auth (header **or** `?token=` query param).
- Agent can *suggest* commands (`POST /suggest`) — you review them at your prompt with Ctrl-G
  and decide; nothing ever executes without your Enter. Works over SSH and sudo too.
- Opt-in `--auto-approve` runs suggestions without the Ctrl-G step, and a JSON Lines audit log
  records every command and suggestion.
- Auto-selected free port and `0.0.0.0` bind, so multiple sessions run side by side.
- Self-documenting: `GET /docs.md?token=…` returns a dynamic guide for the agent.
- `strip_ansi=true` for clean, plain-text output.
- `witness ssh <host>` extends tagging to a remote shell — remote commands appear in the
  same timeline. Only a small marker-printing hook is injected; nothing is installed remotely.
- End-to-end encrypted relay mode connects session and agent hosts that cannot reach each other
  directly, without trusting the relay with API traffic.
- A colored `(witness)` prompt prefix so you always know a session is being recorded.
- Tagging survives privilege changes — `sudo -i`, `sudo -s`, `su`, and nested shells stay
  recorded (witness transparently re-installs the hook in the new shell).

## Quick Start

Build from source (Rust stable):

```bash
cargo build --release
```

Or install the latest prebuilt Linux binary:

```bash
curl -fsSL https://raw.githubusercontent.com/nsg/witness/master/install.sh | bash
```

The script picks the build that matches this system's glibc. Run it again to
update: a `witness` already in `PATH` is replaced in place, otherwise it goes to
`~/.local/bin` or `~/bin`. Set `WITNESS_INSTALL_DIR` to install somewhere else.

Start a session:

```bash
witness run
```

`witness` prints a ready-to-paste line — give it to your agent and say *"read this"*:

```
witness: session ready — observational shell view with human-approved suggestions
witness: api    http://your-host:38121
witness: token  4f3c…
witness:
witness: give your agent this URL and say "read this":
witness:   http://your-host:38121/docs.md?token=4f3c…
```

Now use your shell normally. Everything you run is queryable through the API.

## API

All endpoints return JSON (except `/docs.md`, which returns Markdown). Every endpoint except
`/health` requires the token, supplied as `Authorization: Bearer <token>` **or** `?token=<token>`.

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /health` | none | Liveness check. |
| `GET /docs.md?token=…` | yes | Dynamic, self-contained guide for an agent, with live host/port/token. |
| `GET /commands?since=<id>` | yes | Command records with `id > since` (default `0`). Includes the running command. |
| `GET /commands/<id>` | yes | A single record, or `404`. |
| `GET /tail?n=<count>` | yes | The last `n` completed records (default `20`), newest last. |
| `GET /status` | yes | Tiny polling payload: newest command id, its time, `age_seconds`, `running`, `count`, `pending_suggestions`. |
| `POST /suggest` | yes | Queue inert command text for human review; at most 10 may be pending. |
| `GET /suggestions` | yes | All session suggestions, oldest first, with `pending`/`inserted`/`auto_approved` status. |

By default, suggestions never execute automatically. After an agent posts one, witness displays a local
notification; at your prompt, Ctrl-G inserts its sanitized text without a newline. You can edit
it, press Enter to run it, discard it, or ignore it. Because insertion happens in the local PTY
input path, the same flow works in shells reached through `witness ssh`, `sudo`, or `su`.

Add `&strip_ansi=true` to `/commands` and `/tail` for plain-text output.

```bash
curl "http://your-host:38121/tail?n=20&strip_ansi=true&token=4f3c…"
```

A record looks like:

```json
{
  "id": 2,
  "command": "ls -la",
  "started_at": "2026-09-03T09:01:59Z",
  "finished_at": "2026-09-03T09:02:00Z",
  "exit_code": 0,
  "output": "total 8\n…",
  "truncated": false,
  "running": false
}
```

## Auto-approve

`witness run --auto-approve` (or `witness ssh --auto-approve <host>`) drops the Ctrl-G step: witness types each suggestion into your
shell, followed by Enter, on its own. It is off by default.

> [!WARNING]
> With `--auto-approve`, anyone holding the session token can run commands as you. The API is
> plain HTTP and binds to `0.0.0.0` by default, so keep it on a network you trust or bind it
> with `--addr 127.0.0.1:0`.

Suggestions run one at a time, in the order posted, and only at a fresh prompt you have not
typed at. One that arrives while a command is running, or while you are typing, waits for the
next prompt — press Enter on an empty line to release it, or Ctrl-G to insert it yourself.
Wherever your prompt is, that is where the command runs, including shells reached through
`witness ssh`, `sudo`, or `su`.

## Audit log

With `--auto-approve`, or whenever `--audit-log <path>` is given, witness appends one JSON
object per line to an audit log (created with mode `0600`):

| Event | Meaning |
|-------|---------|
| `session_started` | A session opened; records whether auto-approve is on. |
| `suggested` | An agent posted a suggestion. |
| `suggestion_rejected` | A suggestion was refused (invalid, or the queue was full). |
| `inserted` | You inserted a suggestion with Ctrl-G. |
| `auto_approved` | Witness sent a suggestion to the shell on its own. |
| `command_started` | The shell started a command, whoever typed it. |
| `command_finished` | That command ended, with its exit code. |

The `suggested` and `suggestion_rejected` events include `"via":"direct"` or
`"via":"relay"`.

```json
{"at":"2026-10-04T07:29:14.760795147Z","session":37914,"event":"auto_approved","suggestion_id":1,"command":"systemctl status nginx","reason":"check if it is running"}
```

Every entry carries a timestamp and the witness process id as `session`, so sessions can share
one file. The default location is `$XDG_STATE_HOME/witness/audit.log`, falling back to
`~/.local/state/witness/audit.log`. An auto-approved command is logged before it is sent; if
that write fails, the command is not run.

## SSH

To let the agent see commands you run on a remote host, connect with:

```bash
witness ssh user@remote-host
```

This works two ways:

- **Standalone** — run directly, it starts its own session (prints a banner) wrapping the SSH
  connection. Remote commands are tagged and served through the API.
- **Nested** — run from inside an existing `witness run` session, it folds remote commands into
  the same timeline as your local ones, with no second server.

A standalone `witness ssh` also accepts `--auto-approve`, `--audit-log <path>`,
`--relay <url>`, and `--relay-key-file <path>`; put them before the host, since everything from
the first ssh argument on is passed to ssh. Nested, the outer `witness run` session decides and
the flags are ignored.

Only a small hook that prints marker escape sequences is injected into the remote shell; those
markers ride back over the SSH connection and are parsed locally. Nothing is installed on the
remote. The remote host needs `bash`, `mktemp`, and `base64`.

## Relay

Relay mode connects hosts that cannot reach each other directly. It has three pieces:

- The **session host** runs `witness run` or `witness ssh`; this is where the observed shell runs.
- The **agent host** runs `witness connect`, which exposes the normal witness API on a local
  `127.0.0.1` port. The agent continues to use ordinary HTTP and `curl` exactly as it does for a
  direct session.
- The **relay** runs `witness serve` on a third machine that both hosts can reach outbound over
  HTTPS. It pairs their WebSocket connections and forwards encrypted messages without inspecting
  them.

The relay is untrusted. It sees the channel id, source IP addresses, connection timing, and
encrypted message sizes, and it can drop or delay traffic. It cannot read or forge traffic, and
replayed traffic is rejected. Encryption and authentication are end to end between the session
host and agent host using a pre-shared key known only to those two hosts.

Run the relay behind a TLS-terminating reverse proxy. `witness serve` itself provides plain HTTP
and WebSocket service; the examples assume the proxy exposes it as `https://relay.example`.

On the relay:

```bash
witness serve --addr 127.0.0.1:8080
```

On the session host:

```bash
witness run --relay https://relay.example
```

With no supplied key, the session host generates one and prints it in the startup banner. Copy
that key securely to the agent host.

On the agent host, connect and enter the key at the hidden prompt:

```bash
witness connect https://relay.example
```

The connect banner prints a local `/docs.md?token=...` URL to give to the agent. Keep
`witness connect` running while the agent uses that URL.

Relay keys have the form `wk1_<32 lowercase hex chars>_<64 lowercase hex chars>`. Generate one
ahead of time with `witness key`. On both the session host and agent host, key sources are checked
in this order:
`--relay-key-file <path>` (trimmed file contents), then `WITNESS_RELAY_KEY`. There is deliberately
no command-line key flag because command arguments are visible in the process list. When neither
source is present, the session host generates and prints a key; `witness connect` prompts with
echo disabled, or fails on non-interactive stdin with instructions to use one of the two sources.

For example, to use the same key file on both hosts:

```bash
witness key > relay.key
witness run --relay https://relay.example --relay-key-file relay.key
```

```bash
witness connect https://relay.example --relay-key-file relay.key
```

### Approving agents on the relay

Start the relay with `--require-approval` to put a human in the loop:

```bash
witness serve --addr 127.0.0.1:8080 --require-approval
```

An agent that connects to a channel nobody has approved is turned away, and its requests through
`witness connect` fail with `503` until someone opens `https://relay.example/admin` and presses
Approve. The page lists each waiting channel (the middle part of the relay key) and the address
the agent connected from. The address comes from
`X-Forwarded-For` when the proxy sets it, so make sure your proxy overwrites that header.

An approval lasts as long as the agent keeps talking: every request pushes it forward, and after
two hours of silence (`--approval-idle-minutes`) the channel closes again until it is approved
once more. Revoke closes an approved channel at once, including streams already open.

> [!WARNING]
> `witness serve` does not authenticate `/admin`. Protect that path in the reverse proxy (basic
> auth, SSO, or an allow-list) and leave `/relay/` open; anyone who can reach `/admin` can approve.

This is a check on who uses the relay, enforced by the relay. It stops an agent, or someone with
a copied key, from connecting unnoticed. It is not part of the end-to-end protection: a
compromised relay could skip it, though it still could not read or forge traffic.

## Configuration

`witness run` options:

| Option | Default | Description |
|--------|---------|-------------|
| `--shell <path>` | `/bin/bash` | Shell to wrap (bash hooks). |
| `--addr <host:port>` | `0.0.0.0:0` | API bind address; port `0` picks a free port. Defaults to `127.0.0.1:0` when `--relay` is used. |
| `--public-host <host>` | machine FQDN/IP | Hostname advertised in the banner and docs. |
| `--token <token>` | `$WITNESS_TOKEN` or random | Bearer token for this session. |
| `--max-commands <n>` | `10000` | Retained command records (ring buffer). |
| `--max-output-bytes <n>` | `1048576` | Captured output cap per command; extra is truncated. |
| `--auto-approve` | off | Run agent suggestions without waiting for Ctrl-G. |
| `--audit-log <path>` | off, or the default path with `--auto-approve` | Append every command and suggestion to this file. |
| `--relay <url>` | off | Connect the session host outbound to this relay URL. |
| `--relay-key-file <path>` | `$WITNESS_RELAY_KEY`, otherwise generated | Read the relay key from this file. Takes precedence over the environment. |

`witness ssh` accepts `--auto-approve`, `--audit-log`, `--relay`, and `--relay-key-file` before
the SSH host. In a nested witness session, the outer `witness run` configuration applies and
these flags are ignored.

`witness connect <relay-url>` options:

| Option | Default | Description |
|--------|---------|-------------|
| `--addr <host:port>` | `127.0.0.1:0` | Local API bind address; port `0` picks a free port. |
| `--token <token>` | `$WITNESS_TOKEN` or random | Bearer token checked by the local API. |
| `--relay-key-file <path>` | `$WITNESS_RELAY_KEY`, otherwise prompt | Read the relay key from this file. Takes precedence over the environment. |

`witness serve` options:

| Option | Default | Description |
|--------|---------|-------------|
| `--addr <host:port>` | `0.0.0.0:8080` | Relay bind address. |
| `--require-approval` | off | Hold each agent until a human approves its channel at `/admin`. |
| `--approval-idle-minutes <n>` | `120` | Agent silence after which an approval lapses. |

`witness key` prints a fresh relay key.

The token is valid only for the running session; each session picks its own port. `witness
token` prints a fresh random token.

## License

MIT — see [LICENSE.md](LICENSE.md).
