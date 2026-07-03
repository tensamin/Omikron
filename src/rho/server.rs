use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::load_keyring;
use crate::{
    log,
    rho::connection::GeneralConnection,
    util::{file_util::load_file_vec, logger::PrintType},
};
use mtp::crypto::PublicKeyBundle;
use mtp::host::{AuthenticationPolicy, Host, HostConfig, Policy, SendMode};

pub async fn get_by_connector_id(
    _client_id: u64,
    description: Option<String>,
) -> Option<PublicKeyBundle> {
    if let Some(description) = description {
        if description == "iota" {
            todo!()
        } else if description == "client" {
            todo!()
        } else if description == "anonymous" {
            todo!()
        } else if description == "app" {
            todo!()
        }
    }
    None
}
pub async fn complete_register(_pub_key: PublicKeyBundle, description: Option<String>) -> u64 {
    if let Some(description) = description {
        if description == "iota" {
            todo!()
        }
    }
    0
}

pub async fn start(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = load_file_vec("certs", "cert.pem").expect("Error loading Pemfile");

    let key_pem = load_file_vec("certs", "key.pem").expect("Error loading Keyfile");

    let host_config = HostConfig::new(
        IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)),
        port,
        cert_pem,
        key_pem,
    )
    .with_policy(Policy {
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
    })
    .with_authentication(
        load_keyring(),
        Box::new(|user_id, description| Box::pin(get_by_connector_id(user_id, description))),
        Box::new(|pub_key, description| Box::pin(complete_register(pub_key, description))),
    )
    .with_authentication_policy(AuthenticationPolicy::AllowAuthentication);

    let mut host: Host = Host::new(host_config).await?;
    log!(0, PrintType::General, "Server listening on port {}", port);

    while let Ok(Some(conn)) = host.accept().await {
        tokio::spawn(async move {
            let conn = GeneralConnection::new(conn.sender, conn.receiver);
            conn.handle().await;
        });
    }
    log!(0, PrintType::General, "Server stopped");

    Ok(())
}
