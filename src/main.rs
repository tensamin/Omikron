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
    util::print::PrintType,
    util::print::line,
    util::print::line_err,
    util::print::print_start_message,
};

#[tokio::main(flavor = "multi_thread", worker_threads = 32)]
#[allow(unused_must_uscae, dead_code)]
async fn main() {
    print_start_message();
    tokio::spawn(async move {
        OmegaConnection::new().connect().await;
    });
    let listener = TcpListener::bind("0.0.0.0:959").await.unwrap();
    line(
        PrintType::OmegaIn,
        "WebSocket server listening on 0.0.0.0:959",
    );

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
                    line_err(
                        PrintType::General,
                        &format!("WebSocket upgrade failed: {}", e),
                    );
                    return;
                }
            };
            if path == "/ws/client/" {
                line(PrintType::ClientIn, "New Client connection");
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
                                let text = msg.into_text();
                                let cc = client_conn.clone();
                                cc.handle_message(text.unwrap()).await;
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
                                let ic = iota_conn.clone();
                                ic.handle_message(text).await;
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
