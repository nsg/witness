use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use futures_util::StreamExt;
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};

const MAX_MESSAGE_SIZE: usize = 128 * 1024;
const WAIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const MAX_WAITING_CHANNELS: usize = 10_000;
const MAX_CONNECTIONS: usize = 20_000;
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum Role {
    Session,
    Agent,
}

#[derive(Clone)]
struct RelayState {
    inner: Arc<Mutex<RelayInner>>,
    connections: Arc<Semaphore>,
}

impl Default for RelayState {
    fn default() -> Self {
        Self {
            inner: Arc::default(),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }
}

#[derive(Default)]
struct RelayInner {
    channels: HashMap<[u8; 16], WaitingChannel>,
    next_id: u64,
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

pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    eprintln!("witness: relay listening on {bound}");
    axum::serve(listener, router()).await?;
    Ok(())
}

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/relay/{channel}/session", get(session))
        .route("/relay/{channel}/agent", get(agent))
        .with_state(RelayState::default())
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn session(
    State(state): State<RelayState>,
    Path(channel): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    upgrade(state, channel, Role::Session, ws).await
}

async fn agent(
    State(state): State<RelayState>,
    Path(channel): Path<String>,
    ws: WebSocketUpgrade,
) -> Response {
    upgrade(state, channel, Role::Agent, ws).await
}

async fn upgrade(state: RelayState, channel: String, role: Role, ws: WebSocketUpgrade) -> Response {
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
        .on_upgrade(move |socket| handle_socket(state, channel, role, socket, permit))
}

async fn handle_socket(
    state: RelayState,
    channel: [u8; 16],
    role: Role,
    mut socket: WebSocket,
    _permit: OwnedSemaphorePermit,
) {
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
        splice(&mut socket, peer, None).await;
        return;
    }

    let mut ready_rx = ready_rx;
    let mut buffered = None;
    let timeout = tokio::time::sleep(WAIT_TIMEOUT);
    tokio::pin!(timeout);
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    loop {
        tokio::select! {
            result = &mut ready_rx => {
                match result {
                    Ok(WaitResult::Paired(peer)) => splice(&mut socket, peer, buffered).await,
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

async fn splice(socket: &mut WebSocket, mut peer: Peer, buffered: Option<Vec<u8>>) {
    if let Some(message) = buffered
        && !within_deadline(peer.to_peer.send(message)).await
    {
        return;
    }
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            incoming = socket.next() => match incoming {
                Some(Ok(Message::Binary(bytes))) => {
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
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
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
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
