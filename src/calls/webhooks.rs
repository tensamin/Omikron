//! LiveKit events are authenticated hints to inspect current media, never authority writes.
//!
//! Set LIVEKIT_WEBHOOK_BIND to a socket address to opt in. POST raw LiveKit events to
//! /livekit/webhook. Terminate TLS at the reverse proxy when exposing this listener.
use std::{convert::Infallible, io, net::SocketAddr, sync::Arc, time::Duration};

use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use livekit_api::{access_token::TokenVerifier, webhooks::WebhookReceiver};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
};
use uuid::Uuid;

use crate::{calls::call_manager::CallManager, config::LiveKitConfig};

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 32;
const MAX_AUTH_BYTES: usize = 4096;
const MAX_CONNECTIONS: usize = 32;
const HEADER_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_EVENT_AGE_MS: i64 = 5 * 60 * 1000;
const MAX_EVENT_ID_BYTES: usize = 128;
const WEBHOOK_PATH: &str = "/livekit/webhook";

struct State {
    manager: Arc<CallManager>,
    receiver: WebhookReceiver,
}

/// Binds before returning so invalid configuration and occupied ports fail startup.
/// An absent bind variable disables ingestion. Dropping the shutdown sender also stops it.
pub async fn start(
    manager: Arc<CallManager>,
    config: LiveKitConfig,
    shutdown: watch::Receiver<bool>,
) -> io::Result<Option<JoinHandle<io::Result<()>>>> {
    let bind = match std::env::var("LIVEKIT_WEBHOOK_BIND") {
        Ok(value) => value.parse::<SocketAddr>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid LIVEKIT_WEBHOOK_BIND socket address",
            )
        })?,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid LIVEKIT_WEBHOOK_BIND",
            ));
        }
    };
    if config.api_key.is_empty() || config.api_secret.is_empty() || manager.repository.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "webhooks require LiveKit credentials and call repository",
        ));
    }
    let listener = TcpListener::bind(bind).await?;
    let state = Arc::new(State {
        manager,
        receiver: WebhookReceiver::new(TokenVerifier::with_api_key(
            &config.api_key,
            &config.api_secret,
        )),
    });
    Ok(Some(tokio::spawn(serve(listener, state, shutdown))))
}

async fn serve(
    listener: TcpListener,
    state: Arc<State>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            changed = shutdown.changed() => { if changed.is_err() { break; } },
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                // Reject overload immediately rather than accumulate sockets or waiting tasks.
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new())
                        .header_read_timeout(HEADER_TIMEOUT)
                        .max_buf_size(MAX_HEADER_BYTES)
                        .max_headers(MAX_HEADERS)
                        .keep_alive(false);
                    let connection = builder.serve_connection(TokioIo::new(stream), service_fn(move |request| {
                        let state = state.clone();
                        async move { Ok::<_, Infallible>(handle(request, &state).await) }
                    }));
                    // Includes body upload, repository work, and response write time.
                    let _ = tokio::time::timeout(CONNECTION_TIMEOUT, connection).await;
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

fn response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

async fn handle(request: Request<Incoming>, state: &State) -> Response<Full<Bytes>> {
    if request.uri().path() != WEBHOOK_PATH {
        return response(StatusCode::NOT_FOUND);
    }
    if request.method() != Method::POST {
        return response(StatusCode::METHOD_NOT_ALLOWED);
    }
    let mut headers = request.headers().get_all(header::AUTHORIZATION).iter();
    let Some(auth) = headers.next() else {
        return response(StatusCode::UNAUTHORIZED);
    };
    if headers.next().is_some() || auth.len() > MAX_AUTH_BYTES {
        return response(StatusCode::UNAUTHORIZED);
    }
    let Ok(auth) = auth.to_str() else {
        return response(StatusCode::UNAUTHORIZED);
    };
    // LiveKit sends the JWT directly. Also accept the standard Bearer form.
    let auth = auth.strip_prefix("Bearer ").unwrap_or(auth).to_owned();
    if request.headers().contains_key(header::CONTENT_ENCODING) {
        return response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|size| size > MAX_BODY_BYTES as u64)
    {
        return response(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let body = match Limited::new(request.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(error) if error.is::<http_body_util::LengthLimitError>() => {
            return response(StatusCode::PAYLOAD_TOO_LARGE);
        }
        Err(_) => return response(StatusCode::BAD_REQUEST),
    };
    let Ok(body) = std::str::from_utf8(&body) else {
        return response(StatusCode::BAD_REQUEST);
    };
    let hint = match verified_hint(&state.receiver, body, &auth, CallManager::timestamp()) {
        Ok(Some(hint)) => hint,
        Ok(None) => return response(StatusCode::NO_CONTENT),
        Err(status) => return response(status),
    };
    let Ok(call) = state.manager.call_id(hint.room) else {
        return response(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(repository) = &state.manager.repository else {
        return response(StatusCode::SERVICE_UNAVAILABLE);
    };
    // Atomic deduplication and durable enqueue happen together in the repository.
    match repository
        .queue_media_inspection(
            call,
            hint.event_id,
            hint.created_at_ms,
            CallManager::timestamp(),
            MAX_EVENT_AGE_MS,
        )
        .await
    {
        Ok(_) | Err(tau::calls::CallError::NotFound) => response(StatusCode::NO_CONTENT),
        Err(_) => response(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[derive(Debug, PartialEq)]
struct Hint {
    room: Uuid,
    event_id: String,
    created_at_ms: i64,
}

fn verified_hint(
    receiver: &WebhookReceiver,
    body: &str,
    auth: &str,
    now_ms: i64,
) -> Result<Option<Hint>, StatusCode> {
    // receive checks HS256, issuer, token validity and SHA-256 over every raw body byte.
    let event = receiver
        .receive(body, auth)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let created_at_ms = event
        .created_at
        .checked_mul(1000)
        .ok_or(StatusCode::BAD_REQUEST)?;
    if event.id.is_empty() || event.id.len() > MAX_EVENT_ID_BYTES || created_at_ms <= 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Future events are rejected too. No event timestamp becomes observed presence time.
    if created_at_ms > now_ms || now_ms.saturating_sub(created_at_ms) > MAX_EVENT_AGE_MS {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !matches!(
        event.event.as_str(),
        "participant_joined" | "participant_left" | "track_published" | "room_finished"
    ) {
        return Ok(None);
    }
    let room = event.room.ok_or(StatusCode::BAD_REQUEST)?;
    let room = Uuid::parse_str(&room.name).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Some(Hint {
        room,
        event_id: event.id,
        created_at_ms,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use livekit_api::access_token::AccessToken;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const KEY: &str = "webhook-test-key";
    const SECRET: &str = "webhook-test-secret";

    fn receiver() -> WebhookReceiver {
        WebhookReceiver::new(TokenVerifier::with_api_key(KEY, SECRET))
    }

    fn sign(body: &str, key: &str, secret: &str) -> String {
        AccessToken::with_api_key(key, secret)
            .with_sha256(&base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body)))
            .to_jwt()
            .unwrap()
    }

    fn event(kind: &str, id: &str, created_at: i64) -> String {
        serde_json::json!({ "event": kind, "id": id, "createdAt": created_at.to_string(),
            "room": {"name": "1cdd09b5-625d-4fe9-923c-4fdce576c1da"} })
        .to_string()
    }

    #[test]
    fn signatures_bind_issuer_secret_and_every_raw_body_byte() {
        let body = event("participant_joined", "evt-1", 1_000_000);
        let token = sign(&body, KEY, SECRET);
        assert!(
            verified_hint(&receiver(), &body, &token, 1_000_000_000)
                .unwrap()
                .is_some()
        );
        for invalid in [
            sign(&body, "other-key", SECRET),
            sign(&body, KEY, "other-secret"),
        ] {
            assert_eq!(
                verified_hint(&receiver(), &body, &invalid, 1_000_000_000),
                Err(StatusCode::UNAUTHORIZED)
            );
        }
        assert_eq!(
            verified_hint(&receiver(), &(body.clone() + " "), &token, 1_000_000_000),
            Err(StatusCode::UNAUTHORIZED)
        );
        let tampered = body.replace("participant_joined", "participant_left");
        assert_eq!(
            verified_hint(&receiver(), &tampered, &token, 1_000_000_000),
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn only_reconciliation_hints_are_selected_and_time_is_bounded() {
        for kind in [
            "participant_joined",
            "participant_left",
            "track_published",
            "room_finished",
            "egress_ended",
        ] {
            let body = event(kind, "evt-2", 1_000_000);
            let token = sign(&body, KEY, SECRET);
            let result = verified_hint(&receiver(), &body, &token, 1_000_001_000).unwrap();
            assert_eq!(result.is_some(), kind != "egress_ended");
            if let Some(hint) = result {
                assert_eq!(hint.created_at_ms, 1_000_000_000);
                assert_eq!(hint.event_id, "evt-2");
            }
        }
        for (id, time) in [
            ("", 1_000_000),
            ("evt", 0),
            ("evt", 999_699),
            ("evt", 1_000_001),
            ("evt", i64::MAX),
        ] {
            let body = event("participant_joined", id, time);
            assert_eq!(
                verified_hint(&receiver(), &body, &sign(&body, KEY, SECRET), 1_000_000_000),
                Err(StatusCode::BAD_REQUEST)
            );
        }
        let body = event("room_finished", "evt", 1_000_000)
            .replace("1cdd09b5-625d-4fe9-923c-4fdce576c1da", "not-a-call");
        assert_eq!(
            verified_hint(&receiver(), &body, &sign(&body, KEY, SECRET), 1_000_000_000),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    async fn test_server() -> (SocketAddr, watch::Sender<bool>, JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, rx) = watch::channel(false);
        let state = Arc::new(State {
            manager: Arc::new(CallManager::default()),
            receiver: receiver(),
        });
        (address, shutdown, tokio::spawn(serve(listener, state, rx)))
    }

    async fn request(address: SocketAddr, headers: &str, body: &[u8]) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(CONNECTION_TIMEOUT, stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        String::from_utf8(response).unwrap()
    }

    #[tokio::test]
    async fn real_http_rejects_unauthenticated_oversized_and_duplicate_auth_requests() {
        let (address, shutdown, task) = test_server().await;
        let response = request(
            address,
            "POST /livekit/webhook HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
            b"",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
        let response = request(address, &format!("POST /livekit/webhook HTTP/1.1\r\nHost: localhost\r\nAuthorization: invalid\r\nContent-Length: {}\r\n\r\n", MAX_BODY_BYTES + 1), b"").await;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        let response = request(address, "POST /livekit/webhook HTTP/1.1\r\nHost: localhost\r\nAuthorization: a\r\nAuthorization: b\r\nContent-Length: 0\r\n\r\n", b"").await;
        assert!(response.starts_with("HTTP/1.1 401"), "{response}");
        // Chunked uploads have no Content-Length. They still hit the same hard body limit.
        let chunked = format!(
            "{:x}\r\n{}\r\n0\r\n\r\n",
            MAX_BODY_BYTES + 1,
            "x".repeat(MAX_BODY_BYTES + 1)
        );
        let response = request(address, "POST /livekit/webhook HTTP/1.1\r\nHost: localhost\r\nAuthorization: invalid\r\nTransfer-Encoding: chunked\r\n\r\n", chunked.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 413"), "{response}");
        shutdown.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_parser_bounds_headers_and_expires_incomplete_headers() {
        let (address, shutdown, task) = test_server().await;
        let oversized = format!(
            "POST /livekit/webhook HTTP/1.1\r\nHost: localhost\r\nX-Large: {}\r\n\r\n",
            "x".repeat(MAX_HEADER_BYTES)
        );
        let response = request(address, &oversized, b"").await;
        assert!(response.starts_with("HTTP/1.1 431"), "{response}");
        let many = format!(
            "POST /livekit/webhook HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
            "X-Header: x\r\n".repeat(MAX_HEADERS)
        );
        let response = request(address, &many, b"").await;
        assert!(response.starts_with("HTTP/1.1 431"), "{response}");
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST /livekit/webhook HTTP/1.1\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(
            HEADER_TIMEOUT + Duration::from_secs(2),
            stream.read_to_end(&mut response),
        )
        .await
        .expect("incomplete headers must time out")
        .unwrap();
        shutdown.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn signed_delivery_durably_deduplicates_and_only_queues_inspection() {
        use crate::calls::{
            call_util::LiveKitService, repository::SqliteCallRepository, runtime::CallRuntime,
        };
        use tau::calls::{self as domain, CallRepository};

        let repository =
            Arc::new(SqliteCallRepository::open(std::path::Path::new(":memory:")).unwrap());
        let authority =
            domain::CallAuthority::new(format!("omega-key:{}", "1".repeat(64))).unwrap();
        let owner = domain::CallAuthority::new(format!("omikron-key:{}", "2".repeat(64))).unwrap();
        let livekit = Arc::new(LiveKitService::new(None));
        let runtime = Arc::new(CallRuntime {
            repository: repository.clone(),
            rho: Arc::new(crate::rho::rho_manager::RhoManager::new()),
            principal_authority: authority.clone(),
        });
        let engine = Arc::new(domain::CallEngine::new(
            repository.clone(),
            livekit.clone(),
            runtime.clone(),
            runtime,
            Arc::new(domain::SystemCallClock),
        ));
        let manager = Arc::new(CallManager::new_with_owner(livekit, 1).with_runtime(
            repository.clone(),
            engine,
            owner,
            authority,
        ));
        let room = manager.reserve(1).await.unwrap();
        let id = manager.call_id(room).unwrap();
        let before = repository.read(id.clone()).await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, rx) = watch::channel(false);
        let task = tokio::spawn(serve(
            listener,
            Arc::new(State {
                manager,
                receiver: receiver(),
            }),
            rx,
        ));
        let body = event(
            "participant_joined",
            "durable-event",
            CallManager::timestamp() / 1000,
        )
        .replace("1cdd09b5-625d-4fe9-923c-4fdce576c1da", &room.to_string());
        let headers = format!(
            "POST /livekit/webhook HTTP/1.1\r\nHost: localhost\r\nAuthorization: {}\r\nContent-Length: {}\r\n\r\n",
            sign(&body, KEY, SECRET),
            body.len()
        );
        assert!(
            request(address, &headers, body.as_bytes())
                .await
                .starts_with("HTTP/1.1 204")
        );
        let mut effects = repository
            .claim_effects(CallManager::timestamp(), 10)
            .await
            .unwrap();
        assert_eq!(effects.len(), 1);
        let effect = effects.pop().unwrap();
        assert_eq!(effect.effect, domain::CallEffect::InspectRoom);
        repository
            .finish_effect(effect, Ok(()), CallManager::timestamp())
            .await
            .unwrap();
        // Retrying after the first effect completed must not create another effect.
        assert!(
            request(address, &headers, body.as_bytes())
                .await
                .starts_with("HTTP/1.1 204")
        );
        assert!(
            repository
                .claim_effects(CallManager::timestamp(), 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(repository.read(id).await.unwrap(), before);
        shutdown.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_incomplete_connections() {
        let (address, shutdown, task) = test_server().await;
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"POST /livekit/webhook HTTP/1.1\r\n")
            .await
            .unwrap();
        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        let result =
            tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut bytes)).await;
        assert!(result.is_ok());
    }
}
