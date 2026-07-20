use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;

use crate::{
    app_state::AppState,
    log, log_err,
    omega::omega_connection::OmegaConnection,
    rho::connection::GeneralConnection,
    util::{file_util::load_file_vec, logger::PrintType},
};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::PublicKeyBundle;
use mtp::host::{AuthenticationPolicy, HostConfig, Policy, SendMode};
use mtp::webserver::{MTPWebServer, WebServerConfig};

/*
 * Resolves the PublicKeyBundle mtp needs to verify a login's signed
 * challenge response. "iota"/"client" ids are looked up through Omega, the
 * source of truth for both kinds of registered keys. Any other description
 * (including "anonymous") never resolves, which routes the connection
 * through mtp's unauthenticated fallback instead of rejecting it outright.
 */
pub async fn get_by_connector_id(
    omega: Arc<OmegaConnection>,
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

    let response = match omega
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
pub async fn complete_register(
    omega: Arc<OmegaConnection>,
    pub_key: PublicKeyBundle,
    description: Option<String>,
) -> u64 {
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

    let response = match omega
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

pub async fn start(state: Arc<AppState>) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = load_file_vec("certs", "cert.pem").expect("Error loading Pemfile");

    let key_pem = load_file_vec("certs", "key.pem").expect("Error loading Keyfile");

    let host_config = HostConfig::new(
        IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)),
        state.config.rho_port,
        cert_pem,
        key_pem,
    )
    .with_policy(
        Policy::default()
            .with_send_mode(SendMode::SingleStreamPerMessage)
            .with_max_message_size(1_000_000_000)
            .with_timeouts(
                Duration::from_millis(2_000),
                Duration::from_millis(2_000),
                Duration::from_millis(30_000),
            )
            .with_keep_alive(Some(Duration::from_secs(6)))
            .with_max_idle_timeout(Some(Duration::from_secs(30)))
            .with_receiver_queue_capacity(1000)
            .with_max_concurrent_stream_tasks(10)
            .with_persistent_stream_retries(5, Duration::from_secs(5)),
    )
    .with_authentication(
        state
            .keyring_for_host()
            .map_err(|error| format!("Unable to copy keyring for host: {error}"))?,
        Box::new({
            let omega = state.omega.clone();
            move |user_id, description| {
                Box::pin(get_by_connector_id(omega.clone(), user_id, description))
            }
        }),
        Box::new({
            let omega = state.omega.clone();
            move |pub_key, description| {
                Box::pin(complete_register(omega.clone(), pub_key, description))
            }
        }),
    )
    .with_authentication_policy(AuthenticationPolicy::AllowAuthentication);

    let web_config = WebServerConfig::new()
        .route("/", |_request, response| async move { response.body("OK") })?;
    let mut host = MTPWebServer::new(host_config, web_config).await?;
    log!(
        0,
        PrintType::General,
        "Server listening on port {}.",
        state.config.rho_port
    );

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

        let state = state.clone();
        tokio::spawn(async move {
            let Some(conn) = GeneralConnection::new(conn, state) else {
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
