use std::{fmt, path::Path, str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, Uri, header},
};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use tokio::{
    net::TcpStream,
    sync::{Mutex, Semaphore},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use tower::ServiceExt;

const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"witness-relay-v1";
const CHUNK_SIZE: usize = 65_000;
const MAX_LOGICAL_SIZE: usize = 64 * 1024 * 1024;
const MAX_WS_MESSAGE_SIZE: usize = 128 * 1024;
const PING_INTERVAL: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_SESSION_STREAMS: usize = 8;

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Clone, PartialEq, Eq)]
pub struct RelayKey {
    pub channel: [u8; 16],
    pub psk: [u8; 32],
}

impl RelayKey {
    pub fn generate() -> Self {
        let mut channel = [0; 16];
        let mut psk = [0; 32];
        rand::rng().fill_bytes(&mut channel);
        rand::rng().fill_bytes(&mut psk);
        Self { channel, psk }
    }
}

impl fmt::Debug for RelayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayKey")
            .field("channel", &channel_hex(&self.channel))
            .field("psk", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for RelayKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "wk1_{}_{}",
            channel_hex(&self.channel),
            bytes_hex(&self.psk)
        )
    }
}

impl FromStr for RelayKey {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let Some(rest) = value.strip_prefix("wk1_") else {
            bail!("invalid relay key: expected wk1_<32 lowercase hex>_<64 lowercase hex>");
        };
        let Some((channel, psk)) = rest.split_once('_') else {
            bail!("invalid relay key: expected wk1_<32 lowercase hex>_<64 lowercase hex>");
        };
        if channel.len() != 32 || psk.len() != 64 || rest.matches('_').count() != 1 {
            bail!("invalid relay key: expected wk1_<32 lowercase hex>_<64 lowercase hex>");
        }
        Ok(Self {
            channel: decode_hex::<16>(channel).context("invalid relay key channel")?,
            psk: decode_hex::<32>(psk).context("invalid relay key PSK")?,
        })
    }
}

#[derive(Clone, Copy)]
pub enum Role {
    Session,
    Agent,
}

impl Role {
    fn path(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Agent => "agent",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestHeaders {
    pub host: Option<String>,
    pub content_type: Option<String>,
    pub authorization: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelRequest {
    pub method: String,
    pub uri: String,
    pub headers: RequestHeaders,
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TunnelResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFailure {
    Unavailable,
    Timeout,
    WrongKey,
    ApprovalRequired,
}

/// The relay refused the agent because no human has approved the channel.
#[derive(Debug)]
struct ApprovalRequired;

impl fmt::Display for ApprovalRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("waiting for approval on the relay")
    }
}

impl std::error::Error for ApprovalRequired {}

fn stream_failure(error: &anyhow::Error, otherwise: ClientFailure) -> ClientFailure {
    if error.is::<ApprovalRequired>() {
        ClientFailure::ApprovalRequired
    } else {
        otherwise
    }
}

impl fmt::Display for ClientFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("relay unavailable"),
            Self::Timeout => formatter.write_str("relay timeout"),
            Self::WrongKey => {
                formatter.write_str("relay handshake failed; the relay key is probably wrong")
            }
            Self::ApprovalRequired => formatter.write_str("waiting for approval on the relay"),
        }
    }
}

impl std::error::Error for ClientFailure {}

pub fn session_key(path: Option<&Path>) -> Result<(RelayKey, bool)> {
    match supplied_key(path)? {
        Some(key) => Ok((key, true)),
        None => Ok((RelayKey::generate(), false)),
    }
}

pub fn agent_key(path: Option<&Path>) -> Result<RelayKey> {
    if let Some(key) = supplied_key(path)? {
        return Ok(key);
    }
    prompt_key()
}

fn supplied_key(path: Option<&Path>) -> Result<Option<RelayKey>> {
    let value = if let Some(path) = path {
        Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read relay key file {}", path.display()))?,
        )
    } else {
        std::env::var("WITNESS_RELAY_KEY").ok()
    };
    value.map(|value| value.trim().parse()).transpose()
}

fn prompt_key() -> Result<RelayKey> {
    use std::io::Write as _;

    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        bail!("stdin is not a terminal; provide --relay-key-file or WITNESS_RELAY_KEY");
    }
    let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut original) } == -1 {
        return Err(std::io::Error::last_os_error()).context("failed to read terminal mode");
    }
    let mut hidden = original;
    hidden.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &hidden) } == -1 {
        return Err(std::io::Error::last_os_error()).context("failed to disable terminal echo");
    }
    struct Restore(libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.0);
            }
        }
    }
    let restore = Restore(original);
    eprint!("relay key: ");
    std::io::stderr().flush()?;
    let mut value = String::new();
    let read = std::io::stdin().read_line(&mut value);
    drop(restore);
    eprintln!();
    read.context("failed to read relay key")?;
    value.trim().parse()
}

pub fn relay_url(base: &str, key: &RelayKey, role: Role) -> Result<String> {
    let uri: Uri = base.parse().context("invalid relay URL")?;
    let scheme = match uri.scheme_str() {
        Some("https") => "wss",
        Some("http") => "ws",
        Some(other) => bail!("unsupported relay URL scheme {other:?}; expected http or https"),
        None => bail!("relay URL must start with http:// or https://"),
    };
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("relay URL is missing a host"))?;
    if uri.query().is_some() {
        bail!("relay URL must not contain a query string");
    }
    let path = uri.path().trim_end_matches('/');
    Ok(format!(
        "{scheme}://{authority}{path}/relay/{}/{}",
        channel_hex(&key.channel),
        role.path()
    ))
}

pub fn spawn_session(relay: String, key: RelayKey, router: Router) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(url) = relay_url(&relay, &key, Role::Session) else {
            return;
        };
        // The relay can replay an old handshake opener to open streams that
        // never carry a request, so bound how many are held at once.
        let streams = Arc::new(Semaphore::new(MAX_SESSION_STREAMS));
        let mut backoff = Duration::from_secs(1);
        loop {
            let Ok(permit) = Arc::clone(&streams).acquire_owned().await else {
                return;
            };
            if let Ok(socket) = connect_websocket(&url).await {
                backoff = Duration::from_secs(1);
                if let Ok(stream) = responder_handshake(socket, &key).await {
                    let router = router.clone();
                    tokio::spawn(async move {
                        let _ = serve_stream(stream, router).await;
                        drop(permit);
                    });
                    continue;
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    })
}

async fn serve_stream(mut stream: NoiseSocket, router: Router) -> Result<()> {
    loop {
        let bytes = tokio::time::timeout(STREAM_IDLE_TIMEOUT, stream.receive()).await??;
        let request: TunnelRequest = serde_json::from_slice(&bytes)?;
        let response = dispatch(&router, request).await?;
        stream.send(&serde_json::to_vec(&response)?).await?;
    }
}

async fn dispatch(router: &Router, request: TunnelRequest) -> Result<TunnelResponse> {
    let method = Method::from_bytes(request.method.as_bytes()).context("invalid request method")?;
    let uri: Uri = request.uri.parse().context("invalid request URI")?;
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in [
        (header::HOST, request.headers.host),
        (header::CONTENT_TYPE, request.headers.content_type),
        (header::AUTHORIZATION, request.headers.authorization),
    ] {
        if let Some(value) = value {
            builder = builder.header(name, HeaderValue::from_str(&value)?);
        }
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::from(request.body))?)
        .await?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(response.into_body(), MAX_LOGICAL_SIZE).await?;
    Ok(TunnelResponse {
        status,
        content_type,
        body: String::from_utf8(body.to_vec()).context("API response was not UTF-8")?,
    })
}

#[derive(Clone)]
pub struct TunnelClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    url: String,
    key: RelayKey,
    stream: Mutex<Option<NoiseSocket>>,
}

impl TunnelClient {
    pub fn new(relay: &str, key: RelayKey) -> Result<Self> {
        let client = Self {
            inner: Arc::new(ClientInner {
                url: relay_url(relay, &key, Role::Agent)?,
                key,
                stream: Mutex::new(None),
            }),
        };
        let maintenance = client.clone();
        tokio::spawn(async move { maintenance.keepalive().await });
        Ok(client)
    }

    pub async fn probe(&self) -> std::result::Result<(), ClientFailure> {
        let mut stream = self.inner.stream.lock().await;
        if stream.is_some() {
            return Ok(());
        }
        match tokio::time::timeout(CONNECT_TIMEOUT, self.establish()).await {
            Ok(Ok(connected)) => {
                *stream = Some(connected);
                Ok(())
            }
            Ok(Err(failure)) => Err(failure),
            Err(_) => Err(ClientFailure::Timeout),
        }
    }

    pub async fn request(
        &self,
        request: TunnelRequest,
    ) -> std::result::Result<TunnelResponse, ClientFailure> {
        let retry = request.method == "GET";
        if !retry {
            // A stream that died while idle only shows it on use. Find out
            // with a request that is safe to repeat, so the one that must be
            // sent exactly once goes out on a stream known to be alive.
            Box::pin(self.request(TunnelRequest {
                method: "GET".into(),
                uri: "/health".into(),
                headers: RequestHeaders {
                    host: None,
                    content_type: None,
                    authorization: None,
                },
                body: String::new(),
            }))
            .await?;
        }
        let mut attempts = if retry { 2 } else { 1 };
        loop {
            attempts -= 1;
            match self.request_once(&request).await {
                Ok(response) => return Ok(response),
                Err(ClientFailure::Unavailable | ClientFailure::Timeout) if attempts > 0 => {}
                Err(error) => return Err(error),
            }
        }
    }

    async fn request_once(
        &self,
        request: &TunnelRequest,
    ) -> std::result::Result<TunnelResponse, ClientFailure> {
        let mut slot = self.inner.stream.lock().await;
        // The stream leaves the slot for the exchange and returns only after
        // a complete response. If this future is dropped midway, the stream
        // goes with it, so a late response can never answer the next request.
        let mut stream = match slot.take() {
            Some(stream) => stream,
            None => match tokio::time::timeout(CONNECT_TIMEOUT, self.establish()).await {
                Ok(result) => result?,
                Err(_) => return Err(ClientFailure::Timeout),
            },
        };
        let exchange = async {
            stream
                .send(&serde_json::to_vec(request).map_err(|_| ClientFailure::Unavailable)?)
                .await
                .map_err(|_| ClientFailure::Unavailable)?;
            // Once a request that must not repeat is out, an approval notice
            // is not believed: it is unauthenticated and reads as "safe to
            // retry", while the request may already have been carried out.
            let bytes = stream.receive().await.map_err(|error| {
                if request.method == "GET" {
                    stream_failure(&error, ClientFailure::Unavailable)
                } else {
                    ClientFailure::Unavailable
                }
            })?;
            serde_json::from_slice(&bytes).map_err(|_| ClientFailure::Unavailable)
        };
        match tokio::time::timeout(REQUEST_TIMEOUT, exchange).await {
            Ok(Ok(response)) => {
                *slot = Some(stream);
                Ok(response)
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(ClientFailure::Timeout),
        }
    }

    async fn establish(&self) -> std::result::Result<NoiseSocket, ClientFailure> {
        let socket = connect_websocket(&self.inner.url)
            .await
            .map_err(|_| ClientFailure::Unavailable)?;
        initiator_handshake(socket, &self.inner.key).await
    }

    async fn keepalive(self) {
        let mut interval = tokio::time::interval(PING_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Ok(mut slot) = self.inner.stream.try_lock()
                && let Some(mut stream) = slot.take()
                && matches!(
                    tokio::time::timeout(CONNECT_TIMEOUT, stream.ping()).await,
                    Ok(Ok(()))
                )
            {
                *slot = Some(stream);
            }
        }
    }
}

struct NoiseSocket {
    socket: WebSocket,
    noise: TransportState,
}

impl NoiseSocket {
    async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        for encrypted in encrypt_chunks(&mut self.noise, plaintext)? {
            self.socket.send(Message::Binary(encrypted.into())).await?;
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut plaintext = Vec::new();
        loop {
            let encrypted = receive_binary(&mut self.socket).await?;
            if decrypt_chunk(&mut self.noise, &encrypted, &mut plaintext)? {
                return Ok(plaintext);
            }
        }
    }

    async fn ping(&mut self) -> Result<()> {
        self.socket.send(Message::Ping(Vec::new().into())).await?;
        Ok(())
    }
}

async fn connect_websocket(url: &str) -> Result<WebSocket> {
    // Fails only when a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_WS_MESSAGE_SIZE);
    config.max_frame_size = Some(MAX_WS_MESSAGE_SIZE);
    let (socket, _) = connect_async_with_config(url, Some(config), false).await?;
    Ok(socket)
}

async fn initiator_handshake(
    mut socket: WebSocket,
    key: &RelayKey,
) -> std::result::Result<NoiseSocket, ClientFailure> {
    let mut handshake = handshake_state(key, true).map_err(|_| ClientFailure::Unavailable)?;
    let mut output = vec![0; 65_535];
    // Handshake payloads stay empty: accepting application data here would enable 0-RTT replay.
    let written = handshake
        .write_message(&[], &mut output)
        .map_err(|_| ClientFailure::WrongKey)?;
    socket
        .send(Message::Binary(output[..written].to_vec().into()))
        .await
        .map_err(|_| ClientFailure::Unavailable)?;
    let incoming = receive_binary(&mut socket)
        .await
        .map_err(|error| stream_failure(&error, ClientFailure::WrongKey))?;
    let read = handshake
        .read_message(&incoming, &mut output)
        .map_err(|_| ClientFailure::WrongKey)?;
    if read != 0 {
        return Err(ClientFailure::WrongKey);
    }
    let noise = handshake
        .into_transport_mode()
        .map_err(|_| ClientFailure::WrongKey)?;
    Ok(NoiseSocket { socket, noise })
}

async fn responder_handshake(mut socket: WebSocket, key: &RelayKey) -> Result<NoiseSocket> {
    let mut handshake = handshake_state(key, false)?;
    let incoming = receive_binary(&mut socket).await?;
    let mut output = vec![0; 65_535];
    let read = handshake.read_message(&incoming, &mut output)?;
    if read != 0 {
        bail!("Noise handshake contained an application payload");
    }
    let written = handshake.write_message(&[], &mut output)?;
    socket
        .send(Message::Binary(output[..written].to_vec().into()))
        .await?;
    let noise = handshake.into_transport_mode()?;
    Ok(NoiseSocket { socket, noise })
}

fn handshake_state(key: &RelayKey, initiator: bool) -> Result<HandshakeState> {
    let params: NoiseParams = NOISE_PARAMS.parse()?;
    let mut prologue = Vec::with_capacity(PROLOGUE.len() + key.channel.len());
    prologue.extend_from_slice(PROLOGUE);
    prologue.extend_from_slice(&key.channel);
    let builder = Builder::new(params).prologue(&prologue)?.psk(0, &key.psk)?;
    Ok(if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

async fn receive_binary(socket: &mut WebSocket) -> Result<Vec<u8>> {
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    loop {
        tokio::select! {
            message = socket.next() => match message {
                Some(Ok(Message::Binary(bytes))) => return Ok(bytes.to_vec()),
                Some(Ok(Message::Ping(bytes))) => socket.send(Message::Pong(bytes)).await?,
                Some(Ok(Message::Text(text))) if text.as_str() == crate::relay::APPROVAL_HINT => {
                    return Err(ApprovalRequired.into());
                }
                Some(Ok(Message::Text(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => bail!("WebSocket closed"),
            },
            _ = ping.tick() => socket.send(Message::Ping(Vec::new().into())).await?,
        }
    }
}

fn encrypt_chunks(noise: &mut TransportState, plaintext: &[u8]) -> Result<Vec<Vec<u8>>> {
    let chunks: Vec<&[u8]> = if plaintext.is_empty() {
        vec![&[]]
    } else {
        plaintext.chunks(CHUNK_SIZE).collect()
    };
    let mut encrypted = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.iter().enumerate() {
        let mut framed = Vec::with_capacity(chunk.len() + 1);
        framed.push(u8::from(index + 1 == chunks.len()));
        framed.extend_from_slice(chunk);
        let mut output = vec![0; framed.len() + 16];
        let written = noise.write_message(&framed, &mut output)?;
        output.truncate(written);
        encrypted.push(output);
    }
    Ok(encrypted)
}

fn decrypt_chunk(
    noise: &mut TransportState,
    encrypted: &[u8],
    plaintext: &mut Vec<u8>,
) -> Result<bool> {
    let mut output = vec![0; encrypted.len()];
    let read = noise.read_message(encrypted, &mut output)?;
    let (&final_chunk, chunk) = output[..read]
        .split_first()
        .ok_or_else(|| anyhow!("empty tunnel frame"))?;
    if final_chunk > 1 {
        bail!("invalid tunnel frame marker");
    }
    if chunk.len() > CHUNK_SIZE {
        bail!("tunnel frame exceeds 65000 bytes");
    }
    if plaintext.len().saturating_add(chunk.len()) > MAX_LOGICAL_SIZE {
        bail!("tunnel message exceeds 64 MiB");
    }
    plaintext.extend_from_slice(chunk);
    Ok(final_chunk == 1)
}

fn channel_hex(channel: &[u8; 16]) -> String {
    bytes_hex(channel)
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(value, "{byte:02x}").unwrap();
    }
    value
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("expected {} lowercase hex characters", N * 2);
    }
    let mut output = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (hex(pair[0]) << 4) | hex(pair[1]);
    }
    Ok(output)
}

fn hex(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex as StdMutex};

    use super::*;
    use crate::{api, relay, store::Store};

    fn transport_pair(key: &RelayKey) -> (TransportState, TransportState) {
        let mut initiator = handshake_state(key, true).unwrap();
        let mut responder = handshake_state(key, false).unwrap();
        let mut first = [0; 65_535];
        let mut second = [0; 65_535];
        let first_len = initiator.write_message(&[], &mut first).unwrap();
        assert_eq!(
            responder
                .read_message(&first[..first_len], &mut second)
                .unwrap(),
            0
        );
        let second_len = responder.write_message(&[], &mut second).unwrap();
        assert_eq!(
            initiator
                .read_message(&second[..second_len], &mut first)
                .unwrap(),
            0
        );
        (
            initiator.into_transport_mode().unwrap(),
            responder.into_transport_mode().unwrap(),
        )
    }

    #[test]
    fn relay_key_round_trip_and_rejects_malformed_values() {
        let key = RelayKey::generate();
        assert_eq!(key.to_string().parse::<RelayKey>().unwrap(), key);
        assert!(!format!("{key:?}").contains(&bytes_hex(&key.psk)));
        for value in [
            "",
            "wk1_00_00",
            "wk2_00000000000000000000000000000000_0000000000000000000000000000000000000000000000000000000000000000",
            "wk1_0000000000000000000000000000000A_0000000000000000000000000000000000000000000000000000000000000000",
            "wk1_00000000000000000000000000000000_000000000000000000000000000000000000000000000000000000000000000g",
        ] {
            assert!(value.parse::<RelayKey>().is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn maps_relay_urls_and_rejects_bad_schemes() {
        let key: RelayKey = "wk1_00112233445566778899aabbccddeeff_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".parse().unwrap();
        assert_eq!(
            relay_url("https://relay.test/base/", &key, Role::Agent).unwrap(),
            "wss://relay.test/base/relay/00112233445566778899aabbccddeeff/agent"
        );
        assert_eq!(
            relay_url("http://relay.test", &key, Role::Session).unwrap(),
            "ws://relay.test/relay/00112233445566778899aabbccddeeff/session"
        );
        assert!(relay_url("ftp://relay.test", &key, Role::Agent).is_err());
    }

    #[test]
    fn noise_framing_round_trips_large_messages_and_rejects_replay() {
        let key = RelayKey::generate();
        let (mut sender, mut receiver) = transport_pair(&key);
        let message = vec![0x5a; CHUNK_SIZE + 1234];
        let frames = encrypt_chunks(&mut sender, &message).unwrap();
        assert_eq!(frames.len(), 2);
        let mut decoded = Vec::new();
        assert!(!decrypt_chunk(&mut receiver, &frames[0], &mut decoded).unwrap());
        assert!(decrypt_chunk(&mut receiver, &frames[1], &mut decoded).unwrap());
        assert_eq!(decoded, message);

        let (mut sender, mut receiver) = transport_pair(&key);
        let frame = encrypt_chunks(&mut sender, b"once").unwrap().remove(0);
        let mut decoded = Vec::new();
        assert!(decrypt_chunk(&mut receiver, &frame, &mut decoded).unwrap());
        assert!(decrypt_chunk(&mut receiver, &frame, &mut Vec::new()).is_err());

        let (mut other_sender, _) = transport_pair(&key);
        let (_, mut other_receiver) = transport_pair(&key);
        let frame = encrypt_chunks(&mut other_sender, b"replayed")
            .unwrap()
            .remove(0);
        assert!(decrypt_chunk(&mut other_receiver, &frame, &mut Vec::new()).is_err());
    }

    #[test]
    fn wrong_psk_fails_handshake() {
        let first_key = RelayKey::generate();
        let mut second_key = first_key.clone();
        second_key.psk[0] ^= 1;
        let mut initiator = handshake_state(&first_key, true).unwrap();
        let mut responder = handshake_state(&second_key, false).unwrap();
        let mut message = [0; 65_535];
        let length = initiator.write_message(&[], &mut message).unwrap();
        assert!(
            responder
                .read_message(&message[..length], &mut [0; 65_535])
                .is_err()
        );
    }

    #[tokio::test]
    async fn relay_round_trips_api_requests_in_process() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            axum::serve(listener, relay::router(None)).await.unwrap();
        });

        let store = Arc::new(StdMutex::new(Store::new(10, 1024)));
        let router = api::tunnel_router(Arc::clone(&store), api::Notifier::new(), None, None);
        let key = RelayKey::generate();
        let base = format!("http://{addr}");
        let session_task = spawn_session(base.clone(), key.clone(), router);
        let client = TunnelClient::new(&base, key).unwrap();
        client.probe().await.unwrap();

        let response = client
            .request(TunnelRequest {
                method: "GET".into(),
                uri: "/status".into(),
                headers: RequestHeaders {
                    host: Some("127.0.0.1:43210".into()),
                    content_type: None,
                    authorization: Some("Bearer local-token".into()),
                },
                body: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response.body).unwrap()["count"],
            0
        );

        let response = client
            .request(TunnelRequest {
                method: "POST".into(),
                uri: "/suggest".into(),
                headers: RequestHeaders {
                    host: Some("127.0.0.1:43210".into()),
                    content_type: Some("application/json".into()),
                    authorization: Some("Bearer local-token".into()),
                },
                body: r#"{"command":"echo relayed","reason":"test"}"#.into(),
            })
            .await
            .unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(store.lock().unwrap().pending_suggestions(), 1);

        let response = client
            .request(TunnelRequest {
                method: "GET".into(),
                uri: "/docs.md".into(),
                headers: RequestHeaders {
                    host: Some("127.0.0.1:43210".into()),
                    content_type: None,
                    authorization: Some("Bearer local-token".into()),
                },
                body: String::new(),
            })
            .await
            .unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("http://127.0.0.1:43210"));
        assert!(response.body.contains("local-token"));

        session_task.abort();
        relay_task.abort();
    }
}
