use std::{
    collections::HashMap,
    fmt::Write as _,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{
        ConnectInfo, Form, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{Extensions, HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use chrono::{SecondsFormat, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::Instant;

const MAX_MESSAGE_SIZE: usize = 128 * 1024;
const WAIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const MAX_WAITING_CHANNELS: usize = 10_000;
const MAX_CONNECTIONS: usize = 20_000;
const SEND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_APPROVAL_ENTRIES: usize = 1000;
/// Sent to an agent socket before closing it, so `witness connect` can tell
/// a missing approval from a missing session. Only a hint: the relay is
/// untrusted and the text is not authenticated.
pub const APPROVAL_HINT: &str = "approval-required";

#[derive(Clone, Copy)]
enum Role {
    Session,
    Agent,
}

#[derive(Clone)]
struct RelayState {
    inner: Arc<Mutex<RelayInner>>,
    connections: Arc<Semaphore>,
    approval_required: bool,
    /// Proves an approve or revoke was submitted from the admin page itself.
    csrf: Arc<str>,
}

impl RelayState {
    fn new(approval_idle: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RelayInner {
                approvals: approval_idle.map(Approvals::new),
                ..RelayInner::default()
            })),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            approval_required: approval_idle.is_some(),
            csrf: Arc::from(crate::generate_token()),
        }
    }
}

#[derive(Default)]
struct RelayInner {
    channels: HashMap<[u8; 16], WaitingChannel>,
    next_id: u64,
    approvals: Option<Approvals>,
}

/// Channels a human has let through, and those waiting for one. An approval
/// lasts until the agent has been silent for `idle`.
struct Approvals {
    idle: Duration,
    entries: HashMap<[u8; 16], Approval>,
}

struct Approval {
    agent: String,
    requested_at: String,
    seen: Instant,
    approved: bool,
}

struct ApprovalRow {
    channel: [u8; 16],
    agent: String,
    requested_at: String,
    approved_for: Option<Duration>,
}

impl Approvals {
    fn new(idle: Duration) -> Self {
        Self {
            idle,
            entries: HashMap::new(),
        }
    }

    fn approved(&self, channel: [u8; 16], now: Instant) -> bool {
        self.entries
            .get(&channel)
            .is_some_and(|entry| entry.approved && now.duration_since(entry.seen) < self.idle)
    }

    /// An agent message on an approved channel pushes the expiry forward.
    fn record_activity(&mut self, channel: [u8; 16], now: Instant) -> bool {
        if !self.approved(channel, now) {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(&channel) {
            entry.seen = now;
        }
        true
    }

    /// Lists a refused agent for a human to decide on.
    fn request(&mut self, channel: [u8; 16], agent: &str, now: Instant) {
        self.prune(now);
        if let Some(entry) = self.entries.get_mut(&channel) {
            if entry.approved {
                entry.requested_at = timestamp();
            }
            entry.approved = false;
            entry.seen = now;
            entry.agent = agent.to_owned();
            return;
        }
        // Anyone can ask, so a full list drops its oldest request, never an
        // approval, to keep a real agent from being crowded out for good.
        if self.entries.len() >= MAX_APPROVAL_ENTRIES {
            let oldest = self
                .entries
                .iter()
                .filter(|(_, entry)| !entry.approved)
                .min_by_key(|(_, entry)| entry.seen)
                .map(|(channel, _)| *channel);
            match oldest {
                Some(oldest) => self.entries.remove(&oldest),
                None => return,
            };
        }
        self.entries.insert(
            channel,
            Approval {
                agent: agent.to_owned(),
                requested_at: timestamp(),
                seen: now,
                approved: false,
            },
        );
    }

    fn approve(&mut self, channel: [u8; 16], now: Instant) {
        if let Some(entry) = self.entries.get_mut(&channel) {
            entry.approved = true;
            entry.seen = now;
        }
    }

    fn revoke(&mut self, channel: [u8; 16]) {
        self.entries.remove(&channel);
    }

    fn prune(&mut self, now: Instant) {
        let idle = self.idle;
        self.entries
            .retain(|_, entry| now.duration_since(entry.seen) < idle);
    }

    fn rows(&mut self, now: Instant) -> Vec<ApprovalRow> {
        self.prune(now);
        let mut rows: Vec<_> = self
            .entries
            .iter()
            .map(|(channel, entry)| ApprovalRow {
                channel: *channel,
                agent: entry.agent.clone(),
                requested_at: entry.requested_at.clone(),
                approved_for: entry
                    .approved
                    .then(|| self.idle.saturating_sub(now.duration_since(entry.seen))),
            })
            .collect();
        rows.sort_by(|a, b| {
            (a.approved_for.is_some(), &a.requested_at)
                .cmp(&(b.approved_for.is_some(), &b.requested_at))
        });
        rows
    }
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Enforces the approval on one socket of a channel. Both sockets of a pair
/// carry one, so a revoked channel stops in both directions.
struct Gate {
    state: RelayState,
    channel: [u8; 16],
    agent: String,
}

impl Gate {
    fn open(&self) -> bool {
        let inner = self.state.inner.lock().unwrap();
        inner
            .approvals
            .as_ref()
            .is_none_or(|approvals| approvals.approved(self.channel, Instant::now()))
    }

    /// Counts an agent message, or lists the agent as waiting if the
    /// approval is gone, so it shows up again without a reconnect.
    fn record_activity(&self) -> bool {
        let mut inner = self.state.inner.lock().unwrap();
        let Some(approvals) = inner.approvals.as_mut() else {
            return true;
        };
        let now = Instant::now();
        if approvals.record_activity(self.channel, now) {
            return true;
        }
        approvals.request(self.channel, &self.agent, now);
        false
    }

    fn request(&self) {
        if let Some(approvals) = self.state.inner.lock().unwrap().approvals.as_mut() {
            approvals.request(self.channel, &self.agent, Instant::now());
        }
    }
}

#[derive(Default)]
struct WaitingChannel {
    session: Option<Waiting>,
    agent: Option<Waiting>,
    upgrading: usize,
}

struct Waiting {
    id: u64,
    ready: oneshot::Sender<WaitResult>,
}

enum WaitResult {
    Paired(Peer),
    Replaced,
}

struct Peer {
    to_peer: mpsc::Sender<Vec<u8>>,
    from_peer: mpsc::Receiver<Vec<u8>>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub async fn serve(addr: SocketAddr, approval_idle: Option<Duration>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    eprintln!("witness: relay listening on {bound}");
    if approval_idle.is_some() {
        eprintln!("witness: agents need approval at /admin — restrict that path in your proxy");
    }
    axum::serve(
        listener,
        router(approval_idle).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

pub fn router(approval_idle: Option<Duration>) -> Router {
    let state = RelayState::new(approval_idle);
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/relay/{channel}/session", get(session))
        .route("/relay/{channel}/agent", get(agent));
    if approval_idle.is_some() {
        router = router
            .route("/admin", get(admin))
            .route("/admin/approve/{channel}", post(approve))
            .route("/admin/revoke/{channel}", post(revoke));
    }
    router.with_state(state)
}

async fn admin(State(state): State<RelayState>) -> Html<String> {
    let rows = match state.inner.lock().unwrap().approvals.as_mut() {
        Some(approvals) => approvals.rows(Instant::now()),
        None => Vec::new(),
    };
    Html(render_admin(&rows, &state.csrf))
}

fn render_admin(rows: &[ApprovalRow], csrf: &str) -> String {
    let mut page = String::from(concat!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta http-equiv=\"refresh\" content=\"5\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
        "<title>witness relay approvals</title><style>",
        "body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}",
        "table{border-collapse:collapse}th,td{text-align:left;padding:.4rem .9rem;",
        "border-bottom:1px solid #ddd}code{font-size:.9em}button{padding:.3rem .8rem}",
        "form{display:inline}</style></head><body><h1>witness relay approvals</h1>",
        "<p>The channel is the middle part of the relay key. ",
        "Traffic is end-to-end encrypted, so nothing else about a request is visible here.</p>",
    ));
    if rows.is_empty() {
        page.push_str("<p>No agent is waiting and nothing is approved.</p>");
    } else {
        page.push_str(
            "<table><tr><th>Channel</th><th>Agent address</th><th>Asked</th>\
             <th>Status</th><th></th></tr>",
        );
        for row in rows {
            let channel = channel_hex(&row.channel);
            let button = |action: &str, label: &str| {
                format!(
                    "<form method=\"post\" action=\"admin/{action}/{channel}\">\
                     <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
                     <button>{label}</button></form> "
                )
            };
            let (status, buttons) = match row.approved_for {
                Some(left) => (
                    format!(
                        "approved, {} min of silence left",
                        left.as_secs().div_ceil(60)
                    ),
                    button("revoke", "Revoke"),
                ),
                None => (
                    "waiting for approval".to_owned(),
                    button("approve", "Approve") + &button("revoke", "Dismiss"),
                ),
            };
            let _ = write!(
                page,
                "<tr><td><code>{channel}</code></td><td>{}</td><td>{}</td>\
                 <td>{status}</td><td>{buttons}</td></tr>",
                escape_html(&row.agent),
                escape_html(&row.requested_at),
            );
        }
        page.push_str("</table>");
    }
    page.push_str("</body></html>");
    page
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

#[derive(Deserialize)]
struct Decision {
    csrf: String,
}

async fn approve(
    State(state): State<RelayState>,
    Path(channel): Path<String>,
    Form(decision): Form<Decision>,
) -> Response {
    decide(state, &channel, &decision, true)
}

async fn revoke(
    State(state): State<RelayState>,
    Path(channel): Path<String>,
    Form(decision): Form<Decision>,
) -> Response {
    decide(state, &channel, &decision, false)
}

fn decide(state: RelayState, channel: &str, decision: &Decision, approve: bool) -> Response {
    // The proxy's login is typically a cookie or cached credential, which a
    // browser would also attach to a form posted from another site. Only the
    // admin page itself can know the token.
    let from_admin_page: bool = decision.csrf.as_bytes().ct_eq(state.csrf.as_bytes()).into();
    if !from_admin_page {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(channel) = parse_channel(channel) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if let Some(approvals) = state.inner.lock().unwrap().approvals.as_mut() {
        if approve {
            approvals.approve(channel, Instant::now());
        } else {
            approvals.revoke(channel);
        }
    }
    // Relative, so the page also works under a path prefix in the proxy.
    (StatusCode::SEE_OTHER, [(header::LOCATION, "../../admin")]).into_response()
}

/// The agent's address as best the relay knows it, for the human to judge.
fn agent_label(headers: &HeaderMap, extensions: &Extensions) -> String {
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match forwarded {
        Some(address) => address.chars().take(64).collect(),
        None => extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| "unknown".to_owned(), |info| info.0.ip().to_string()),
    }
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn session(
    State(state): State<RelayState>,
    Path(channel): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    upgrade(state, channel, Role::Session, String::new(), ws).await
}

async fn agent(
    State(state): State<RelayState>,
    Path(channel): Path<String>,
    headers: HeaderMap,
    extensions: Extensions,
    ws: WebSocketUpgrade,
) -> Response {
    let label = agent_label(&headers, &extensions);
    upgrade(state, channel, Role::Agent, label, ws).await
}

async fn upgrade(
    state: RelayState,
    channel: String,
    role: Role,
    agent: String,
    ws: WebSocketUpgrade,
) -> Response {
    let Some(channel) = parse_channel(&channel) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "channel must be exactly 32 lowercase hex characters",
            }),
        )
            .into_response();
    };
    let capacity_reached = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: "relay capacity reached",
            }),
        )
            .into_response()
    };
    // Held for the socket's whole life, paired or not.
    let Ok(permit) = Arc::clone(&state.connections).try_acquire_owned() else {
        return capacity_reached();
    };
    {
        let mut inner = state.inner.lock().unwrap();
        if !inner.channels.contains_key(&channel) && inner.channels.len() >= MAX_WAITING_CHANNELS {
            return capacity_reached();
        }
        inner.channels.entry(channel).or_default().upgrading += 1;
    }
    let failed_state = state.clone();
    ws.max_message_size(MAX_MESSAGE_SIZE)
        .max_frame_size(MAX_MESSAGE_SIZE)
        .on_failed_upgrade(move |_| finish_upgrade(&failed_state, channel))
        .on_upgrade(move |socket| handle_socket(state, channel, role, agent, socket, permit))
}

async fn handle_socket(
    state: RelayState,
    channel: [u8; 16],
    role: Role,
    agent: String,
    mut socket: WebSocket,
    _permit: OwnedSemaphorePermit,
) {
    let gate = state.approval_required.then(|| Gate {
        state: state.clone(),
        channel,
        agent,
    });
    let is_agent = matches!(role, Role::Agent);
    if let Some(gate) = &gate
        && is_agent
        && !gate.open()
    {
        // Connecting alone must not extend an approval, so only look.
        gate.request();
        finish_upgrade(&state, channel);
        refuse(&mut socket).await;
        return;
    }
    let (ready_tx, ready_rx) = oneshot::channel();
    let (id, paired) = {
        let mut inner = state.inner.lock().unwrap();
        inner.next_id = inner.next_id.wrapping_add(1);
        let id = inner.next_id;
        let entry = inner.channels.entry(channel).or_default();
        entry.upgrading = entry.upgrading.saturating_sub(1);
        let (same, opposite) = match role {
            Role::Session => (&mut entry.session, &mut entry.agent),
            Role::Agent => (&mut entry.agent, &mut entry.session),
        };
        if let Some(older) = same.take() {
            let _ = older.ready.send(WaitResult::Replaced);
        }
        if let Some(other) = opposite.take() {
            let (to_old, from_new) = mpsc::channel(16);
            let (to_new, from_old) = mpsc::channel(16);
            let _ = other.ready.send(WaitResult::Paired(Peer {
                to_peer: to_new,
                from_peer: from_new,
            }));
            (
                id,
                Some(Peer {
                    to_peer: to_old,
                    from_peer: from_old,
                }),
            )
        } else {
            *same = Some(Waiting {
                id,
                ready: ready_tx,
            });
            (id, None)
        }
    };

    if paired.is_some() {
        let mut inner = state.inner.lock().unwrap();
        if inner.channels.get(&channel).is_some_and(|entry| {
            entry.session.is_none() && entry.agent.is_none() && entry.upgrading == 0
        }) {
            inner.channels.remove(&channel);
        }
    }

    if let Some(peer) = paired {
        splice(&mut socket, peer, None, gate, is_agent).await;
        return;
    }

    let mut ready_rx = ready_rx;
    let mut buffered = None;
    let timeout = tokio::time::sleep(WAIT_TIMEOUT);
    tokio::pin!(timeout);
    let mut ping = tokio::time::interval_at(Instant::now() + PING_INTERVAL, PING_INTERVAL);
    loop {
        tokio::select! {
            result = &mut ready_rx => {
                match result {
                    Ok(WaitResult::Paired(peer)) => {
                        splice(&mut socket, peer, buffered, gate, is_agent).await;
                    }
                    Ok(WaitResult::Replaced) | Err(_) => {
                        let _ = socket.send(Message::Close(None)).await;
                    }
                }
                return;
            }
            message = socket.next() => match message {
                Some(Ok(Message::Binary(bytes))) if buffered.is_none() => {
                    buffered = Some(bytes.to_vec());
                }
                Some(Ok(Message::Binary(_))) => break,
                Some(Ok(Message::Ping(bytes))) => {
                    if socket.send(Message::Pong(bytes)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Text(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            },
            _ = ping.tick() => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            () = &mut timeout => break,
        }
    }
    remove_waiting(&state, channel, role, id);
    let _ = socket.send(Message::Close(None)).await;
}

/// A peer that stops reading must not hold the pair open forever.
async fn within_deadline<T, E>(send: impl Future<Output = Result<T, E>>) -> bool {
    matches!(tokio::time::timeout(SEND_TIMEOUT, send).await, Ok(Ok(_)))
}

async fn refuse(socket: &mut WebSocket) {
    within_deadline(socket.send(Message::Text(APPROVAL_HINT.into()))).await;
    within_deadline(socket.send(Message::Close(None))).await;
}

async fn splice(
    socket: &mut WebSocket,
    mut peer: Peer,
    buffered: Option<Vec<u8>>,
    gate: Option<Gate>,
    is_agent: bool,
) {
    // Agent messages count as activity; everything else only needs the
    // channel to still be approved. Checked for every message in both
    // directions, so a lapsed or revoked approval stops an open stream and
    // whatever is still queued in it.
    let allowed = |from_agent: bool| match &gate {
        Some(gate) if from_agent => gate.record_activity(),
        Some(gate) => gate.open(),
        None => true,
    };
    if let Some(message) = buffered {
        if !allowed(is_agent) {
            refuse(socket).await;
            return;
        }
        if !within_deadline(peer.to_peer.send(message)).await {
            return;
        }
    }
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            incoming = socket.next() => match incoming {
                Some(Ok(Message::Binary(bytes))) => {
                    if !allowed(is_agent) {
                        refuse(socket).await;
                        return;
                    }
                    idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                    if !within_deadline(peer.to_peer.send(bytes.to_vec())).await {
                        break;
                    }
                }
                Some(Ok(Message::Ping(bytes))) => {
                    if !within_deadline(socket.send(Message::Pong(bytes))).await {
                        break;
                    }
                }
                Some(Ok(Message::Text(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            },
            outgoing = peer.from_peer.recv() => match outgoing {
                Some(bytes) => {
                    if !allowed(false) {
                        refuse(socket).await;
                        return;
                    }
                    idle.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
                    if !within_deadline(socket.send(Message::Binary(bytes.into()))).await {
                        break;
                    }
                }
                None => break,
            },
            () = &mut idle => break,
        }
    }
    within_deadline(socket.send(Message::Close(None))).await;
}

fn remove_waiting(state: &RelayState, channel: [u8; 16], role: Role, id: u64) {
    let mut inner = state.inner.lock().unwrap();
    let Some(entry) = inner.channels.get_mut(&channel) else {
        return;
    };
    let slot = match role {
        Role::Session => &mut entry.session,
        Role::Agent => &mut entry.agent,
    };
    if slot.as_ref().is_some_and(|waiting| waiting.id == id) {
        *slot = None;
    }
    if entry.session.is_none() && entry.agent.is_none() && entry.upgrading == 0 {
        inner.channels.remove(&channel);
    }
}

fn finish_upgrade(state: &RelayState, channel: [u8; 16]) {
    let mut inner = state.inner.lock().unwrap();
    let Some(entry) = inner.channels.get_mut(&channel) else {
        return;
    };
    entry.upgrading = entry.upgrading.saturating_sub(1);
    if entry.upgrading == 0 && entry.session.is_none() && entry.agent.is_none() {
        inner.channels.remove(&channel);
    }
}

fn channel_hex(channel: &[u8; 16]) -> String {
    let mut value = String::with_capacity(32);
    for byte in channel {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn parse_channel(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut channel = [0; 16];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        channel[index] = (hex(pair[0])? << 4) | hex(pair[1])?;
    }
    Some(channel)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANNEL: [u8; 16] = [7; 16];
    const IDLE: Duration = Duration::from_secs(7200);

    #[test]
    fn agent_is_listed_until_approved() {
        let mut approvals = Approvals::new(IDLE);
        let now = Instant::now();
        assert!(!approvals.approved(CHANNEL, now));
        approvals.request(CHANNEL, "203.0.113.9", now);
        let rows = approvals.rows(now);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent, "203.0.113.9");
        assert!(rows[0].approved_for.is_none());

        approvals.approve(CHANNEL, now);
        assert!(approvals.approved(CHANNEL, now));
    }

    #[test]
    fn only_agent_messages_extend_an_approval() {
        let mut approvals = Approvals::new(IDLE);
        let start = Instant::now();
        approvals.request(CHANNEL, "agent", start);
        approvals.approve(CHANNEL, start);

        let almost = IDLE - Duration::from_secs(1);
        assert!(approvals.record_activity(CHANNEL, start + almost));
        assert!(approvals.approved(CHANNEL, start + almost * 2));
        assert!(
            !approvals.approved(CHANNEL, start + almost + IDLE),
            "checking does not extend"
        );
    }

    #[test]
    fn silence_ends_an_approval_and_the_agent_must_ask_again() {
        let mut approvals = Approvals::new(IDLE);
        let start = Instant::now();
        approvals.request(CHANNEL, "agent", start);
        approvals.approve(CHANNEL, start);

        let later = start + IDLE;
        assert!(!approvals.record_activity(CHANNEL, later));
        approvals.request(CHANNEL, "agent", later);
        assert!(approvals.rows(later)[0].approved_for.is_none());
        assert!(!approvals.approved(CHANNEL, later));
    }

    #[test]
    fn approving_an_unknown_channel_does_nothing() {
        let mut approvals = Approvals::new(IDLE);
        let now = Instant::now();
        approvals.approve(CHANNEL, now);
        assert!(!approvals.approved(CHANNEL, now));
    }

    #[test]
    fn revoke_stops_an_approved_channel() {
        let mut approvals = Approvals::new(IDLE);
        let now = Instant::now();
        approvals.request(CHANNEL, "agent", now);
        approvals.approve(CHANNEL, now);
        approvals.revoke(CHANNEL);
        assert!(!approvals.approved(CHANNEL, now));
    }

    #[test]
    fn a_full_list_drops_the_oldest_request_but_never_an_approval() {
        let mut approvals = Approvals::new(IDLE);
        let start = Instant::now();
        approvals.request(CHANNEL, "trusted", start);
        approvals.approve(CHANNEL, start);
        for index in 0..MAX_APPROVAL_ENTRIES as u32 {
            let mut channel = [0; 16];
            channel[..4].copy_from_slice(&index.to_be_bytes());
            let at = start + Duration::from_secs(1 + u64::from(index));
            approvals.request(channel, "flood", at);
        }
        let now = start + Duration::from_secs(3600);
        assert!(approvals.approved(CHANNEL, now));
        approvals.request([9; 16], "late", now);
        let rows = approvals.rows(now);
        assert_eq!(rows.len(), MAX_APPROVAL_ENTRIES);
        assert!(rows.iter().any(|row| row.agent == "late"));
        assert!(
            !rows.iter().any(|row| row.channel == [0; 16]),
            "oldest went"
        );
    }

    #[test]
    fn admin_page_escapes_the_reported_agent_address() {
        let rows = [ApprovalRow {
            channel: CHANNEL,
            agent: "<script>alert(1)</script>".into(),
            requested_at: "2026-10-04T09:00:00Z".into(),
            approved_for: None,
        }];
        let page = render_admin(&rows, "token");
        assert!(!page.contains("<script>"));
        assert!(page.contains("&lt;script&gt;"));
    }
}
