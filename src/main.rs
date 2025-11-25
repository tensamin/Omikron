mod auth;
mod calls;
mod data;
mod omega;
mod rho;
mod util;

use async_tungstenite::accept_hdr_async;
use dotenv::dotenv;
use futures::StreamExt;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tungstenite::handshake::server::{Request, Response};

use crate::{
    omega::omega_connection::OmegaConnection,
    rho::{client_connection::ClientConnection, iota_connection::IotaConnection},
    util::{
        config_util::CONFIG,
        print::{PrintType, line, line_err},
    },
};

#[tokio::main]
async fn main() {
    dotenv().ok();
    tokio::spawn(async move {
        OmegaConnection::new().connect().await;
    });
    let address = format!("{}:{}", &CONFIG.read().await.ip, &CONFIG.read().await.port);
    let listener = TcpListener::bind(&address).await.unwrap();

    line(
        PrintType::General,
        &format!("WebSocket server listening on {}", &address),
    );

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut path: String = "/".to_string();

            let callback = |req: &Request, response: Response| {
                path = req.uri().path().to_string(); // Extract URI path
                Ok(response)
            };
            let ws_stream = match accept_hdr_async(stream.compat(), callback).await {
                Ok(ws) => ws,
                Err(e) => {
                    line_err(
                        PrintType::General,
                        &format!("WebSocket upgrade failed: {}", e),
                    );
                    return;
                }
            };
            let (sender, receiver) = ws_stream.split();
            if path == "/ws/client/" {
                line(PrintType::ClientIn, "New Client connection");
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
                                line(PrintType::ClientIn, "Client disconnected");
                                client_conn.handle_close().await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            line_err(PrintType::ClientIn, &format!("WebSocket error: {}", e));
                            client_conn.handle_close().await;
                            return;
                        }
                        None => {
                            line(PrintType::ClientIn, "Client stream ended");
                            client_conn.handle_close().await;
                            return;
                        }
                    }
                }
            } else if path == "/ws/iota/" {
                line(PrintType::IotaIn, "New Iota connection");
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
                                line(PrintType::IotaIn, "Iota disconnected");
                                iota_conn.handle_close().await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            line_err(PrintType::IotaIn, &format!("WebSocket error: {}", e));
                            iota_conn.handle_close().await;
                            return;
                        }
                        None => {
                            // Stream ended
                            line(PrintType::IotaIn, "Iota stream ended");
                            iota_conn.handle_close().await;
                            return;
                        }
                    }
                }
            }
        });
    }
}
