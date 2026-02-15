mod anonymous_clients;
mod calls;
mod data;
mod omega;
mod rho;
mod util;

use async_tungstenite::accept_hdr_async;
use dotenv::dotenv;
use futures::StreamExt;
use once_cell::sync::Lazy;
use std::{env, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tungstenite::handshake::server::{Request, Response};

use crate::{
    anonymous_clients::{
        anonymous_client_connection::AnonymousClientConnection, anonymous_manager,
    },
    calls::call_util::garbage_collect_calls,
    rho::{client_connection::ClientConnection, iota_connection::IotaConnection},
    util::{
        crypto_helper::{load_public_key, load_secret_key},
        logger::{PrintType, startup},
    },
};

static PRIVATE_KEY: Lazy<String> = Lazy::new(|| env::var("PRIVATE_KEY").unwrap());
pub fn get_private_key() -> x448::Secret {
    load_secret_key(&*PRIVATE_KEY).unwrap()
}
static PUBLIC_KEY: Lazy<String> = Lazy::new(|| env::var("PUBLIC_KEY").unwrap());
pub fn get_public_key() -> x448::PublicKey {
    load_public_key(&*PUBLIC_KEY).unwrap()
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    startup();
    let address = format!(
        "{}:{}",
        env::var("IP").unwrap_or("0.0.0.0".to_string()),
        env::var("PORT").unwrap_or("959".to_string())
    );
    let listener = TcpListener::bind(&address).await.unwrap();

    log!(
        0,
        PrintType::General,
        "WebSocket server listening on {}",
        address,
    );

    garbage_collect_calls();

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut path: String = "/".to_string();

            let callback = |req: &Request, response: Response| {
                path = req.uri().path().to_string();
                Ok(response)
            };
            let ws_stream = match accept_hdr_async(stream.compat(), callback).await {
                Ok(ws) => ws,
                Err(e) => {
                    log!(0, PrintType::General, "WebSocket upgrade failed: {}", e,);
                    return;
                }
            };
            let (sender, receiver) = ws_stream.split();
            if path.starts_with("/ws/client") {
                log_in!(0, PrintType::Client, "New Client connection");
                let client_conn: Arc<ClientConnection> =
                    Arc::from(ClientConnection::new(sender, receiver));
                loop {
                    let msg_result = {
                        let mut session_lock = client_conn.receiver.write().await;
                        session_lock.next().await
                    };

                    match msg_result {
                        Some(Ok(msg)) => {
                            if msg.is_text() {
                                let text = msg.into_text().unwrap();
                                client_conn.clone().handle_message(text).await;
                            } else if msg.is_close() {
                                log_in!(
                                    client_conn.get_user_id().await,
                                    PrintType::Client,
                                    "Client disconnected"
                                );
                                client_conn.handle_close().await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            log_err!(
                                client_conn.get_user_id().await,
                                PrintType::Client,
                                "WebSocket error: {}",
                                e
                            );
                            client_conn.handle_close().await;
                            return;
                        }
                        _ => {
                            log_in!(
                                client_conn.get_user_id().await,
                                PrintType::Client,
                                "Client stream ended"
                            );
                            client_conn.handle_close().await;
                            return;
                        }
                    }
                }
            } else if path.starts_with("/ws/anonymous_client") {
                log_in!(0, PrintType::Client, "New Anonymous Client connection");
                let client_conn: Arc<AnonymousClientConnection> =
                    Arc::from(AnonymousClientConnection::new(sender, receiver));
                anonymous_manager::add_anonymous_user(client_conn.clone()).await;
                loop {
                    let msg_result = {
                        let mut session_lock = client_conn.receiver.write().await;
                        session_lock.next().await
                    };

                    match msg_result {
                        Some(Ok(msg)) => {
                            if msg.is_text() {
                                let text = msg.into_text().unwrap();
                                client_conn.clone().handle_message(text).await;
                            } else if msg.is_close() {
                                log_in!(
                                    client_conn.get_user_id().await,
                                    PrintType::Client,
                                    "Anonymous Client disconnected"
                                );
                                anonymous_manager::remove_anonymous_user(
                                    client_conn.get_user_id().await,
                                )
                                .await;
                                client_conn.handle_close().await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            log_err!(
                                client_conn.get_user_id().await,
                                PrintType::Client,
                                "WebSocket error: {}",
                                e
                            );
                            anonymous_manager::remove_anonymous_user(
                                client_conn.get_user_id().await,
                            )
                            .await;
                            client_conn.handle_close().await;
                            return;
                        }
                        _ => {
                            log_in!(
                                client_conn.get_user_id().await,
                                PrintType::Client,
                                "Anonymous Client stream ended"
                            );
                            anonymous_manager::remove_anonymous_user(
                                client_conn.get_user_id().await,
                            )
                            .await;
                            client_conn.handle_close().await;
                            return;
                        }
                    }
                }
            } else if path.starts_with("/ws/iota") {
                log_in!(0, PrintType::Iota, "New Iota connection");
                let iota_conn: Arc<IotaConnection> =
                    Arc::from(IotaConnection::new(sender, receiver));
                loop {
                    let msg_result = {
                        let mut session_lock = iota_conn.receiver.write().await;
                        session_lock.next().await
                    };

                    match msg_result {
                        Some(Ok(msg)) => {
                            if msg.is_text() {
                                let text = msg.into_text().unwrap();
                                iota_conn.clone().handle_message(text).await;
                            } else if msg.is_close() {
                                log_in!(
                                    iota_conn.get_iota_id().await,
                                    PrintType::Iota,
                                    "Iota disconnected"
                                );
                                iota_conn.handle_close().await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            log_err!(
                                iota_conn.get_iota_id().await,
                                PrintType::Iota,
                                "WebSocket error: {}",
                                e
                            );
                            iota_conn.handle_close().await;
                            return;
                        }
                        _ => {
                            // Stream ended
                            log_in!(
                                iota_conn.get_iota_id().await,
                                PrintType::Iota,
                                "Iota stream ended"
                            );
                            iota_conn.handle_close().await;
                            return;
                        }
                    }
                }
            }
        });
    }
}
