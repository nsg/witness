use std::{
    fmt::Write as _,
    io::{self, Write as _},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{
        HeaderMap, StatusCode, Uri,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::store::{CommandRecord, Store, SuggestError, Suggestion, validate_suggestion};

#[derive(Clone, Default)]
pub struct Notifier {
    output_lock: Arc<Mutex<()>>,
}

impl Notifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let _guard = self.output_lock.lock().unwrap();
        let mut stdout = io::stdout().lock();
        stdout.write_all(bytes)?;
        stdout.flush()
    }
}

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<Store>>,
    notifier: Notifier,
    public_host: Arc<str>,
    port: u16,
    token: Arc<str>,
}

#[derive(Deserialize)]
struct AuthQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct CommandsQuery {
    #[serde(default)]
    since: u64,
    #[serde(default)]
    strip_ansi: bool,
}

#[derive(Deserialize)]
struct TailQuery {
    #[serde(default = "default_tail_count")]
    n: usize,
    #[serde(default)]
    strip_ansi: bool,
}

#[derive(Deserialize)]
struct SuggestBody {
    command: String,
    reason: Option<String>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub fn router(
    store: Arc<Mutex<Store>>,
    notifier: Notifier,
    token: String,
    public_host: String,
    port: u16,
) -> Router {
    let token: Arc<str> = Arc::from(token);
    let protected = Router::new()
        .route("/commands", get(commands))
        .route("/commands/{id}", get(command))
        .route("/tail", get(tail))
        .route("/status", get(status))
        .route("/suggest", post(suggest))
        .route("/suggestions", get(suggestions))
        .route("/docs.md", get(docs))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&token),
            require_auth,
        ));
    Router::new()
        .route("/health", get(health))
        .merge(protected)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(AppState {
            store,
            notifier,
            public_host: Arc::from(public_host),
            port,
            token,
        })
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn commands(State(state): State<AppState>, uri: Uri) -> impl IntoResponse {
    let Query(query) = match Query::<CommandsQuery>::try_from_uri(&uri) {
        Ok(query) => query,
        Err(_) => return bad_request("invalid query").into_response(),
    };
    let mut records = state.store.lock().unwrap().commands_since(query.since);
    maybe_strip_outputs(&mut records, query.strip_ansi);
    Json(records).into_response()
}

async fn command(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    let Ok(id) = id.parse::<u64>() else {
        return bad_request("invalid command id").into_response();
    };
    match state.store.lock().unwrap().command(id) {
        Some(record) => Json(record).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody { error: "not found" }),
        )
            .into_response(),
    }
}

async fn tail(State(state): State<AppState>, uri: Uri) -> impl IntoResponse {
    let Query(query) = match Query::<TailQuery>::try_from_uri(&uri) {
        Ok(query) => query,
        Err(_) => return bad_request("invalid query").into_response(),
    };
    let mut records = state.store.lock().unwrap().tail(query.n);
    maybe_strip_outputs(&mut records, query.strip_ansi);
    Json(records).into_response()
}

async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let status = state.store.lock().unwrap().status();
    Json(status).into_response()
}

async fn suggest(State(state): State<AppState>, Json(body): Json<SuggestBody>) -> Response {
    if let Err(error) = validate_suggestion(&body.command) {
        return bad_request(error).into_response();
    }
    if body
        .reason
        .as_deref()
        .is_some_and(|reason| reason.chars().any(char::is_control))
    {
        return bad_request("control characters not allowed").into_response();
    }

    let (suggestion, immediate_notice) = {
        let mut store = state.store.lock().unwrap();
        let suggestion = match store.add_suggestion(body.command, body.reason) {
            Ok(suggestion) => suggestion,
            Err(SuggestError::QueueFull) => {
                return (
                    StatusCode::CONFLICT,
                    Json(ErrorBody {
                        error: "queue full",
                    }),
                )
                    .into_response();
            }
        };
        let notice = render_suggestion_notice(&suggestion);
        let immediate_notice = if store.command_is_open() {
            store.push_pending_notice(notice);
            None
        } else {
            Some(notice)
        };
        (suggestion, immediate_notice)
    };

    if let Some(notice) = immediate_notice {
        let _ = state.notifier.write(notice.as_bytes());
    }
    (StatusCode::CREATED, Json(suggestion)).into_response()
}

async fn suggestions(State(state): State<AppState>) -> Json<Vec<Suggestion>> {
    Json(state.store.lock().unwrap().suggestions())
}

async fn docs(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/markdown; charset=utf-8")],
        generate_docs(&state.public_host, state.port, &state.token),
    )
}

fn authorized(headers: &HeaderMap, query_token: Option<&str>, expected: &str) -> bool {
    let header_authorized = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|provided| provided.as_bytes().ct_eq(expected.as_bytes()).into());
    let query_authorized =
        query_token.is_some_and(|provided| provided.as_bytes().ct_eq(expected.as_bytes()).into());
    header_authorized | query_authorized
}

fn unauthorized() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorBody {
            error: "unauthorized",
        }),
    )
}

fn bad_request(error: &'static str) -> (StatusCode, Json<ErrorBody>) {
    (StatusCode::BAD_REQUEST, Json(ErrorBody { error }))
}

fn render_suggestion_notice(suggestion: &Suggestion) -> String {
    let reason = suggestion
        .reason
        .as_deref()
        .map(|reason| format!("  — {reason}"))
        .unwrap_or_default();
    format!(
        "\r\n\x1b[1;36m(witness) suggestion #{} — press Ctrl-G to insert:\x1b[0m {}\x1b[2m{}\x1b[0m\r\n",
        suggestion.id, suggestion.command, reason
    )
}

async fn not_found() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorBody { error: "not found" }),
    )
}

async fn method_not_allowed() -> (StatusCode, Json<ErrorBody>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(ErrorBody {
            error: "method not allowed",
        }),
    )
}

async fn require_auth(State(expected): State<Arc<str>>, request: Request, next: Next) -> Response {
    let query_token = Query::<AuthQuery>::try_from_uri(request.uri())
        .ok()
        .and_then(|Query(query)| query.token);
    if authorized(request.headers(), query_token.as_deref(), &expected) {
        next.run(request).await
    } else {
        unauthorized().into_response()
    }
}

fn maybe_strip_outputs(records: &mut [CommandRecord], strip: bool) {
    if strip {
        for record in records {
            record.output = strip_ansi(&record.output);
        }
    }
}

fn default_tail_count() -> usize {
    20
}

fn generate_docs(host: &str, port: u16, token: &str) -> String {
    let base_url = format!("http://{host}:{port}");
    let mut docs = String::new();
    writeln!(docs, "# Witness human-controlled shell session API").unwrap();
    writeln!(docs).unwrap();
    writeln!(
        docs,
        "This API is observational: you can inspect the commands the human runs, including each command's id, time, exit code, and captured output, but the API **CANNOT** execute anything. `POST /suggest` only queues inert proposal text; the human must physically insert it at their prompt with Ctrl-G, review it, and press Enter themselves."
    )
    .unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "## Connection details").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "- Base URL: `{base_url}`").unwrap();
    writeln!(docs, "- Session token: `{token}`").unwrap();
    writeln!(docs, "- This document: `{base_url}/docs.md?token={token}`").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "The token is valid only for **THIS** session, and port `{port}` is unique to this witness instance.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "## SSH sessions").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "When the human uses `witness ssh <host>`, commands run in the remote shell are also tagged and appear as normal command records, flat and interleaved with local commands. You can watch remote troubleshooting through this same API workflow.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "## Endpoints").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `GET /health`").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Open health check; no token is required.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(docs, "curl \"{base_url}/health\"").unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `GET /commands?since=<id>&token=<token>`").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Returns command records whose `id` is greater than `since`. Start with `since=0`, then poll by passing the last id you saw.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(
        docs,
        "curl \"{base_url}/commands?since=0&strip_ansi=true&token={token}\""
    )
    .unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `GET /commands/<id>?token=<token>`").unwrap();
    writeln!(docs).unwrap();
    writeln!(
        docs,
        "Returns one command record by id. Replace `1` with the id you need."
    )
    .unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(docs, "curl \"{base_url}/commands/1?token={token}\"").unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `GET /tail?n=<count>&token=<token>`").unwrap();
    writeln!(docs).unwrap();
    writeln!(
        docs,
        "Returns the most recent completed commands, newest last. `n` defaults to 20."
    )
    .unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(
        docs,
        "curl \"{base_url}/tail?n=20&strip_ansi=true&token={token}\""
    )
    .unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `GET /status?token=<token>`").unwrap();
    writeln!(docs).unwrap();
    writeln!(
        docs,
        "Tiny polling endpoint. Returns only `last_id` (the newest command id), `last_command_at`, `age_seconds` (how long ago it was), `running`, `count`, and `pending_suggestions`. Poll this cheaply; when `last_id` grows, fetch the new records from `/commands?since=<lastId>`."
    )
    .unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(docs, "curl \"{base_url}/status?token={token}\"").unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `POST /suggest`").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Queues one inert, single-line command proposal. A suggestion never executes automatically: the human sees a terminal notification and may press Ctrl-G at their prompt to insert the text, then edit and run it with Enter, discard it, or ignore it. Watch `/commands` (or `/status` `last_id`) to learn whether and how it ran. Keep suggestions non-interactive, include a short reason, and remember that at most 10 suggestions may be pending.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(
        docs,
        "curl -X POST \"{base_url}/suggest?token={token}\" -H 'Content-Type: application/json' -d '{{\"command\":\"systemctl status nginx\",\"reason\":\"check if it is running\"}}'"
    )
    .unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `GET /suggestions`").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Returns every suggestion from this session, oldest first, including whether each is `pending` or `inserted`.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(docs, "curl \"{base_url}/suggestions?token={token}\"").unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "### `GET /docs.md?token=<token>`").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Returns this session-specific guide.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "```sh").unwrap();
    writeln!(docs, "curl \"{base_url}/docs.md?token={token}\"").unwrap();
    writeln!(docs, "```").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Authenticated endpoints also accept `Authorization: Bearer {token}` instead of the query token. For `/commands` and `/tail`, append `&strip_ansi=true` for clean plain-text output; using this option is recommended.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "## JSON command record schema").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Each returned command record contains:").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "- `id` — session-local numeric command id.").unwrap();
    writeln!(docs, "- `command` — command text reported by Bash.").unwrap();
    writeln!(docs, "- `started_at` — RFC 3339 start timestamp.").unwrap();
    writeln!(
        docs,
        "- `finished_at` — RFC 3339 finish timestamp, or `null` while running."
    )
    .unwrap();
    writeln!(
        docs,
        "- `exit_code` — numeric shell exit code, or `null` while running or if unavailable."
    )
    .unwrap();
    writeln!(
        docs,
        "- `output` — captured terminal output for the command."
    )
    .unwrap();
    writeln!(
        docs,
        "- `truncated` — whether output exceeded this session's per-command byte limit."
    )
    .unwrap();
    writeln!(docs, "- `running` — whether the command is still running.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "## Typical workflow").unwrap();
    writeln!(docs).unwrap();
    writeln!(
        docs,
        "1. Call `{base_url}/tail?n=20&strip_ansi=true&token={token}` to inspect recent activity."
    )
    .unwrap();
    writeln!(docs, "2. Remember the greatest returned `id` as `lastId`.").unwrap();
    writeln!(docs, "3. Poll `{base_url}/status?token={token}` cheaply; when its `last_id` exceeds `lastId`, fetch `{base_url}/commands?since=<lastId>&strip_ansi=true&token={token}` and update `lastId`.").unwrap();
    writeln!(docs).unwrap();
    writeln!(docs, "Alternate-screen/TUI application output, such as vim, less, or htop, is intentionally **not captured**.").unwrap();
    docs
}

pub fn strip_ansi(input: &str) -> String {
    #[derive(Clone, Copy)]
    enum State {
        Ground,
        Escape,
        EscapeIntermediate,
        Csi,
        Osc,
        OscEscape,
        ControlString,
        ControlStringEscape,
    }

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut state = State::Ground;
    for &byte in bytes {
        state = match state {
            State::Ground if byte == 0x1b => State::Escape,
            State::Ground => {
                if byte == b'\n' || byte == b'\t' || (byte >= 0x20 && byte != 0x7f) {
                    output.push(byte);
                }
                State::Ground
            }
            State::Escape => match byte {
                b'[' => State::Csi,
                b']' => State::Osc,
                b'P' | b'X' | b'^' | b'_' => State::ControlString,
                0x20..=0x2f => State::EscapeIntermediate,
                0x1b => State::Escape,
                _ => State::Ground,
            },
            State::EscapeIntermediate => match byte {
                0x20..=0x2f => State::EscapeIntermediate,
                0x1b => State::Escape,
                _ => State::Ground,
            },
            State::Csi => {
                if byte == 0x1b {
                    State::Escape
                } else if (0x40..=0x7e).contains(&byte) {
                    State::Ground
                } else {
                    State::Csi
                }
            }
            State::Osc => match byte {
                0x07 => State::Ground,
                0x1b => State::OscEscape,
                _ => State::Osc,
            },
            State::OscEscape => match byte {
                b'\\' | 0x07 => State::Ground,
                0x1b => State::OscEscape,
                _ => State::Osc,
            },
            State::ControlString => {
                if byte == 0x1b {
                    State::ControlStringEscape
                } else {
                    State::ControlString
                }
            }
            State::ControlStringEscape => match byte {
                b'\\' => State::Ground,
                0x1b => State::ControlStringEscape,
                _ => State::ControlString,
            },
        };
    }
    String::from_utf8_lossy(&output)
        .chars()
        .filter(|character| *character == '\n' || *character == '\t' || !character.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};

    use super::{authorized, generate_docs, strip_ansi};

    #[test]
    fn strips_color_and_control_sequences() {
        let input = concat!(
            "\x1b[31mred\x1b[0m\r\n",
            "\x1b]0;title\x07plain\ttext",
            "\x1b(B\x1bPprivate\x1b\\",
            "\u{0085}done"
        );
        assert_eq!(strip_ansi(input), "red\nplain\ttextdone");
    }

    #[test]
    fn docs_include_runtime_values_and_endpoints() {
        let docs = generate_docs("shell.example.test", 43210, "fixed-session-token");
        for expected in [
            "fixed-session-token",
            "shell.example.test",
            "43210",
            "witness ssh <host>",
            "/commands",
            "/tail",
            "/status",
            "/suggest",
            "/health",
            "/docs.md",
        ] {
            assert!(docs.contains(expected), "docs missing {expected:?}");
        }
    }

    #[test]
    fn token_check_accepts_header_or_query_and_rejects_invalid_tokens() {
        let expected = "correct-token";
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer correct-token"),
        );
        assert!(authorized(&headers, None, expected));

        let empty_headers = HeaderMap::new();
        assert!(authorized(&empty_headers, Some("correct-token"), expected));

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong-token"),
        );
        assert!(!authorized(&headers, None, expected));
        assert!(authorized(&headers, Some("correct-token"), expected));
        assert!(!authorized(&empty_headers, Some("wrong-token"), expected));
        assert!(!authorized(&empty_headers, None, expected));
    }
}
