mod auth;
mod calls;
mod data;
mod omega;
mod rho;
mod util;

use crate::rho::client_connection;
use crate::rho::iota_connection;
use crate::util::config_util::Config;
use crate::util::file_util;
use tokio_websocket_server::socket::{WebSocketMessage, WebsocketServer};
use tracing::info;
use tracing_subscriber::fmt;

#[tokio::main]
async fn main() {
    fmt::init();

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
