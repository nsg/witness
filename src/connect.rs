use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tokio::sync::Semaphore;

use crate::{
    api,
    tunnel::{ClientFailure, RequestHeaders, TunnelClient, TunnelRequest},
};

const MAX_REQUEST_SIZE: usize = 1024 * 1024;
const MAX_QUEUED_REQUESTS: usize = 32;
// Covers waiting for the shared stream as well as the exchange itself.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone)]
struct ConnectState {
    client: TunnelClient,
    token: Arc<str>,
    queue: Arc<Semaphore>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub async fn run(
    relay_url: String,
    addr: SocketAddr,
    token: Option<String>,
    relay_key_file: Option<PathBuf>,
) -> Result<()> {
    let key = crate::tunnel::agent_key(relay_key_file.as_deref())?;
    let client = TunnelClient::new(&relay_url, key)?;
    let token = token
        .or_else(|| std::env::var("WITNESS_TOKEN").ok())
        .unwrap_or_else(crate::generate_token);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;

    match client.probe().await {
        Ok(()) => {}
        Err(ClientFailure::WrongKey) => {
            bail!("relay handshake failed; the relay key is probably wrong")
        }
        Err(ClientFailure::ApprovalRequired) => {
            eprintln!(
                "witness: the relay is waiting for a human to approve this channel — requests will retry"
            );
        }
        Err(ClientFailure::Unavailable | ClientFailure::Timeout) => {
            eprintln!("witness: no session is waiting on the relay yet — requests will retry");
        }
    }

    let base_url = format!("http://{bound}");
    eprintln!("witness: connected through relay {relay_url} — end-to-end encrypted");
    eprintln!("witness: api    {base_url}");
    eprintln!("witness: token  {token}");
    eprintln!("witness:");
    eprintln!("witness: give your agent this URL and say \"read this\":");
    eprintln!("witness:   {base_url}/docs.md?token={token}");

    let state = ConnectState {
        client,
        token: Arc::from(token),
        queue: Arc::new(Semaphore::new(MAX_QUEUED_REQUESTS)),
    };
    let app = Router::new()
        .route("/health", get(health))
        .fallback(forward)
        .with_state(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn forward(State(state): State<ConnectState>, request: Request) -> Response {
    if !api::request_authorized(request.headers(), request.uri(), &state.token) {
        return api::unauthorized();
    }
    // A stalled relay must not let requests and their bodies pile up.
    let Ok(_queued) = state.queue.try_acquire() else {
        return relay_error(StatusCode::SERVICE_UNAVAILABLE, "too many pending requests");
    };

    let method = request.method().to_string();
    let uri = request.uri().to_string();
    let headers = RequestHeaders {
        host: header_value(request.headers(), header::HOST),
        content_type: header_value(request.headers(), header::CONTENT_TYPE),
        authorization: header_value(request.headers(), header::AUTHORIZATION),
    };
    let body = match to_bytes(request.into_body(), MAX_REQUEST_SIZE).await {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ErrorBody {
                    error: "request body too large",
                }),
            )
                .into_response();
        }
    };
    let Ok(body) = String::from_utf8(body.to_vec()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "request body must be UTF-8",
            }),
        )
            .into_response();
    };

    let request = TunnelRequest {
        method,
        uri,
        headers,
        body,
    };
    let result = tokio::time::timeout(FORWARD_TIMEOUT, state.client.request(request))
        .await
        .unwrap_or(Err(ClientFailure::Timeout));
    match result {
        Ok(response) => {
            let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut builder = Response::builder().status(status);
            if let Some(content_type) = response.content_type
                && let Ok(value) = HeaderValue::from_str(&content_type)
            {
                builder = builder.header(header::CONTENT_TYPE, value);
            }
            builder
                .body(Body::from(response.body))
                .unwrap_or_else(|_| relay_error(StatusCode::BAD_GATEWAY, "relay unavailable"))
        }
        Err(ClientFailure::Timeout) => relay_error(StatusCode::GATEWAY_TIMEOUT, "relay timeout"),
        Err(ClientFailure::WrongKey) => relay_error(
            StatusCode::BAD_GATEWAY,
            "relay handshake failed; the relay key is probably wrong",
        ),
        Err(ClientFailure::ApprovalRequired) => relay_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "waiting for a human to approve this channel on the relay; retry later",
        ),
        Err(ClientFailure::Unavailable) => {
            relay_error(StatusCode::BAD_GATEWAY, "relay unavailable")
        }
    }
}

fn relay_error(status: StatusCode, error: &'static str) -> Response {
    (status, Json(ErrorBody { error })).into_response()
}

fn header_value(headers: &axum::http::HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
