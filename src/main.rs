mod auth;
mod calls;
mod data;
mod omega;
mod rho;
mod util;

use futures::StreamExt;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_hdr_async;
use tungstenite::handshake::server::{Request, Response};

use crate::{
    omega::omega_connection::OmegaConnection,
    rho::{client_connection::ClientConnection, iota_connection::IotaConnection},
};
#[tokio::main]
async fn main() {
    OmegaConnection::new().connect().await;

    let listener = TcpListener::bind("0.0.0.0:959").await.unwrap();
    println!("WebSocket server listening on 0.0.0.0:959");

    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let mut path: String = "/".to_string();
            let callback = |req: &Request, response: Response| {
                path = format!("{}", &req.uri().path());
                Ok(response)
            };
            let ws_stream = match accept_hdr_async(stream, callback).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("WebSocket upgrade failed: {}", e);
                    return;
                }
            };
            println!("New {} connection", path);
            if path == "/ws/client/" {
                let client_conn: Arc<ClientConnection> =
                    Arc::from(ClientConnection::new(ws_stream));
                loop {
                    let msg_result = {
                        let mut session_lock = client_conn.session.lock().await;
                        session_lock.next().await
                    };

                    match msg_result {
                        Some(Ok(msg)) => {
                            if msg.is_text() {
                                let text = msg.into_text().unwrap();
                                client_conn.clone().handle_message(text).await;
                            } else if msg.is_close() {
                                println!("Client disconnected");
                                client_conn.handle_close().await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            eprintln!("WebSocket error: {}", e);
                            client_conn.handle_close().await;
                            return;
                        }
                        None => {
                            println!("Client stream ended");
                            client_conn.handle_close().await;
                            return;
                        }
                    }
                }
            } else if path == "/ws/iota/" {
                let iota_conn: Arc<IotaConnection> = Arc::from(IotaConnection::new(ws_stream));
                loop {
                    let msg_result = {
                        let mut session_lock = iota_conn.session.lock().await;
                        session_lock.next().await
                    };

                    match msg_result {
                        Some(Ok(msg)) => {
                            if msg.is_text() {
                                let text = msg.into_text().unwrap();
                                iota_conn.clone().handle_message(text).await;
                            } else if msg.is_close() {
                                println!("Iota disconnected");
                                iota_conn.handle_close().await;
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            eprintln!("WebSocket error: {}", e);
                            iota_conn.handle_close().await;
                            return;
                        }
                        None => {
                            // Stream ended
                            println!("Iota stream ended");
                            iota_conn.handle_close().await;
                            return;
                        }
                    }
                }
            }
        });
    }
}
