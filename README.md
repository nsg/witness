<div align="center">
  <h1>witness</h1>
  <p>Wrap your shell, tag every command, and let an agent read your terminal over a read-only REST API.</p>

  [![AI usage: vibe](https://nsg.github.io/aibadge/vibe.svg)](https://nsg.github.io/aibadge/#vibe)
  [![CI](https://github.com/nsg/witness/actions/workflows/ci.yml/badge.svg)](https://github.com/nsg/witness/actions/workflows/ci.yml)
</div>

## About

`witness` wraps an interactive shell inside a PTY and records every command you run —
assigning each an incrementing id, timestamps, exit code, and captured output. It exposes
that record through a small **read-only**, token-authenticated REST API.

The point is collaborative troubleshooting: start `witness`, hand the printed URL to an
external agent, and it can "look at your screen" — observing the commands you run and their
output to help you debug — without ever being able to execute anything. Input only ever flows
from you to your shell; the API is strictly observational.

Your shell behaves exactly as normal. Full-screen apps (`vim`, `less`, `htop`, `fzf`) work
untouched, and their alternate-screen output is intentionally left out of the record.

## Features

- Transparent PTY wrapper — your shell, prompt, and TUIs work as usual.
- Per-command records: id, start/finish time (RFC3339), exit code, captured output.
- Read-only REST API with bearer-token auth (header **or** `?token=` query param).
- Auto-selected free port and `0.0.0.0` bind, so multiple sessions run side by side.
- Self-documenting: `GET /docs.md?token=…` returns a dynamic guide for the agent.
- `strip_ansi=true` for clean, plain-text output.
- `witness ssh <host>` extends tagging to a remote shell — remote commands appear in the
  same timeline. Only a small marker-printing hook is injected; nothing is installed remotely.
- A colored `(witness)` prompt prefix so you always know a session is being recorded.
- Tagging survives privilege changes — `sudo -i`, `sudo -s`, `su`, and nested shells stay
  recorded (witness transparently re-installs the hook in the new shell).

## Quick Start

Build from source (Rust stable):

```bash
cargo build --release
```

Or grab the latest prebuilt Linux binary:

```bash
curl -fsSL https://github.com/nsg/witness/releases/latest/download/witness-linux-glibc -o ~/bin/witness
chmod +x ~/bin/witness
```

Start a session:

```bash
witness run
```

`witness` prints a ready-to-paste line — give it to your agent and say *"read this"*:

```
witness: session ready — read-only shell view for an external agent
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
| `GET /status` | yes | Tiny polling payload: newest command id, its time, `age_seconds`, `running`, `count`. |

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

Only a small hook that prints marker escape sequences is injected into the remote shell; those
markers ride back over the SSH connection and are parsed locally. Nothing is installed on the
remote. The remote host needs `bash`, `mktemp`, and `base64`.

## Configuration

`witness run` options:

| Option | Default | Description |
|--------|---------|-------------|
| `--shell <path>` | `/bin/bash` | Shell to wrap (bash hooks). |
| `--addr <host:port>` | `0.0.0.0:0` | API bind address; port `0` picks a free port. |
| `--public-host <host>` | machine FQDN/IP | Hostname advertised in the banner and docs. |
| `--token <token>` | `$WITNESS_TOKEN` or random | Bearer token for this session. |
| `--max-commands <n>` | `10000` | Retained command records (ring buffer). |
| `--max-output-bytes <n>` | `1048576` | Captured output cap per command; extra is truncated. |

The token is valid only for the running session; each session picks its own port. `witness
token` prints a fresh random token.

## License

MIT — see [LICENSE.md](LICENSE.md).
