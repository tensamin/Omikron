use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::{
    log,
    rho::connection::GeneralConnection,
    util::{file_util::load_file_vec, logger::PrintType},
};
use mtp::transport::{Host, Policy, SendMode, host};

pub async fn start(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = load_file_vec("certs", "cert.pem").expect("Error loading Pemfile");

    let key_pem = load_file_vec("certs", "key.pem").expect("Error loading Keyfile");

    let mut host: Host = host(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        cert_pem,
        key_pem,
        Policy {
            send_mode: SendMode::SingleStreamPerMessage,
            max_message_size: 1_000_000_000,
            close_frame_len: u32::MAX,
            application_close_code: 0,
            open_stream_timeout: Duration::from_millis(2_000),
            write_timeout: Duration::from_millis(2_000),
            accept_stream_timeout: Duration::from_millis(10_000),
            read_timeout: Duration::from_millis(30_000),
            keep_alive_interval: Some(Duration::from_secs(6)),
            max_idle_timeout: Some(Duration::from_secs(30)),
            force_close_delay: Duration::from_millis(300),
            max_transient_recv_errors: 20,
            transient_recv_backoff: Duration::from_millis(100),
            receiver_queue_capacity: 1000,
        },
    )
    .await?;
    log!(0, PrintType::General, "Server listening on port {}", port);

    while let Some((sender, receiver)) = host.next().await {
        tokio::spawn(async move {
            let conn = GeneralConnection::new(sender, receiver);
            conn.handle().await;
        });
    }
    log!(0, PrintType::General, "Server stopped");

    Ok(())
}
