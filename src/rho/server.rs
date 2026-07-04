use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;

use crate::load_keyring;
use crate::{
    log, log_err,
    omega::omega_connection::get_omega_connection,
    rho::connection::GeneralConnection,
    util::{file_util::load_file_vec, logger::PrintType},
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::PublicKeyBundle;
use mtp::host::{AuthenticationPolicy, Host, HostConfig, Policy, SendMode};

/*
 * Resolves the PublicKeyBundle mtp needs to verify a login's signed
 * challenge response. "iota"/"client" ids are looked up through Omega, the
 * source of truth for both kinds of registered keys. Any other description
 * (including "anonymous") never resolves, which routes the connection
 * through mtp's unauthenticated fallback instead of rejecting it outright.
 */
pub async fn get_by_connector_id(
    client_id: u64,
    description: Option<String>,
) -> Option<PublicKeyBundle> {
    let request = match description.as_deref() {
        Some("iota") => {
            println!("Iota connection request for client_id: {}", client_id);
            CommunicationValue::new(CommunicationType::GetIotaData)
                .add_typed_default(DataType::IotaId, DataValue::SignedNumber(client_id as i128))
        }
        Some("client") => CommunicationValue::new(CommunicationType::GetUserData)
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(client_id as i128)),
        _ => return None,
    };

    let response = match get_omega_connection()
        .await_response(&request, Some(Duration::from_secs(20)))
        .await
    {
        Ok(response) => response,
        Err(e) => {
            log_err!(
                client_id as i64,
                PrintType::General,
                "Failed to look up public key for connector (description={:?}): {}",
                description,
                e
            );
            return None;
        }
    };

    let bytes = BASE64_STD
        .decode(response.get_data(DataType::PublicKey).as_str()?)
        .ok()?;
    PublicKeyBundle::from_bytes(&bytes).ok()
}

/* Only Iota registration goes through mtp's Register flow; users are registered out of band. */
pub async fn complete_register(pub_key: PublicKeyBundle, description: Option<String>) -> u64 {
    println!("Iota register start");
    if description.as_deref() != Some("iota") {
        return 0;
    }
    println!("Iota connection request");

    let request = CommunicationValue::new(CommunicationType::CompleteRegisterIota)
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(BASE64_STD.encode(pub_key.as_bytes())),
        );

    let response = match get_omega_connection()
        .await_response(&request, Some(Duration::from_secs(20)))
        .await
    {
        Ok(response) => response,
        Err(e) => {
            log_err!(
                0,
                PrintType::General,
                "Failed to complete Iota registration: {}",
                e
            );
            return 0;
        }
    };

    match response.get_data(DataType::IotaId) {
        DataValue::SignedNumber(id) => *id as u64,
        _ => 0,
    }
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
    log!(0, PrintType::General, "Server listening on port {}.", port);

    loop {
        let conn = match host.accept().await {
            Ok(Some(conn)) => {
                println!("Accepted connection");
                conn
            }
            Ok(None) => break,
            Err(e) => {
                /*
                 * A single client's failed/aborted handshake (bad auth, a
                 * probe, a mid-handshake disconnect) must not take down the
                 * whole listener, only that connection attempt is lost.
                 */
                log_err!(0, PrintType::General, "Rejected connection: {}", e);
                continue;
            }
        };

        tokio::spawn(async move {
            let Some(conn) = GeneralConnection::new(conn) else {
                log_err!(
                    0,
                    PrintType::General,
                    "Rejected connection: unrecognized or unauthenticated description"
                );
                return;
            };
            conn.handle().await;
        });
    }
    log!(0, PrintType::General, "Server stopped");

    Ok(())
}
