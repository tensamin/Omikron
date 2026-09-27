use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;

use crate::{
    app_state::AppState,
    log, log_err,
    omega::{AuthIdentity, AuthIdentityKind, omega_connection::OmegaConnection},
    rho::connection::{ConnectionKind, GeneralConnection, OptionalDataValueCompat},
    util::{file_util::load_file_vec, logger::PrintType},
};
use http::{Method, StatusCode};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::crypto::PublicKeyBundle;
use mtp::host::{AuthenticationPolicy, HostConfig, Policy, SendMode};
use mtp::webserver::{HttpResponse, MTPWebServer, WebServerConfig};
use tokio::sync::watch;

fn with_cors(response: HttpResponse) -> HttpResponse {
    response
        .header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "*")
        .header("access-control-allow-private-network", "true")
}

fn web_config(max_connections: usize) -> Result<WebServerConfig, mtp::webserver::RouterError> {
    WebServerConfig::new()
        .max_connections(max_connections)
        .route("/", |request, response| async move {
            let response = if request.method == Method::OPTIONS {
                response.status(StatusCode::NO_CONTENT)
            } else {
                response.body("OK")
            };
            with_cors(response)
        })?
        .fallback(|request, response| async move {
            let status = if request.method == Method::OPTIONS {
                StatusCode::NO_CONTENT
            } else {
                StatusCode::NOT_FOUND
            };
            with_cors(response.status(status))
        })
}

fn rho_policy() -> Policy {
    Policy::default()
        .with_send_mode(SendMode::SingleStreamPerMessage)
        .with_timeouts(
            Duration::from_millis(2_000),
            Duration::from_millis(2_000),
            Duration::from_millis(30_000),
        )
        .with_keep_alive(Some(Duration::from_secs(6)))
        .with_max_idle_timeout(Some(Duration::from_secs(30)))
        .with_receiver_queue_capacity(1000)
        .with_max_concurrent_stream_tasks(10)
        .with_persistent_stream_retries(5, Duration::from_secs(5))
}

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
    let identity = authentication_identity(client_id, description.as_deref())?;
    if omega.recently_missing_key(identity) {
        return None;
    }
    let request = public_key_lookup_request(omega.omikron_id(), identity);

    if !omega.is_ready().await {
        return omega.cached_authenticated_key(identity);
    }

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
            return omega.cached_authenticated_key(identity);
        }
    };

    if response.is_type(CommunicationType::ErrorNotFound) {
        omega.invalidate_authenticated_key(identity);
        omega.cache_missing_key(identity);
        return None;
    }

    let bytes = BASE64_STD
        .decode(authenticated_key_response(&response, identity)?)
        .ok()?;
    let public_key = PublicKeyBundle::from_bytes(&bytes).ok()?;
    omega.cache_authenticated_key(identity, public_key.clone());
    Some(public_key)
}

fn authenticated_key_response(
    response: &CommunicationValue,
    identity: AuthIdentity,
) -> Option<&str> {
    let (expected_type, expected_field) = match identity.kind {
        AuthIdentityKind::Iota => (CommunicationType::GetIotaData, DataType::IotaId),
        AuthIdentityKind::Client => (CommunicationType::GetUserData, DataType::UserId),
    };
    if !response.is_type(expected_type)
        || response
            .get_data(expected_field)
            .as_number()
            .and_then(|id| u64::try_from(id).ok())
            != Some(identity.id)
    {
        return None;
    }
    response
        .get_data(DataType::PublicKey)
        .and_then(DataValue::as_str)
}

fn authentication_identity(client_id: u64, description: Option<&str>) -> Option<AuthIdentity> {
    let kind = match description {
        Some("client") => AuthIdentityKind::Client,
        Some("iota") => AuthIdentityKind::Iota,
        _ => return None,
    };

    Some(AuthIdentity {
        kind,
        id: client_id,
    })
}

fn public_key_lookup_request(omikron_id: u64, identity: AuthIdentity) -> CommunicationValue {
    match identity.kind {
        AuthIdentityKind::Iota => {
            println!("Iota connection request for client_id: {}", identity.id);
            CommunicationValue::new(CommunicationType::GetIotaData)
                .with_sender(omikron_id)
                .add_typed_default(
                    DataType::IotaId,
                    DataValue::SignedNumber(identity.id as i128),
                )
        }
        AuthIdentityKind::Client => CommunicationValue::new(CommunicationType::GetUserData)
            .with_sender(omikron_id)
            .add_typed_default(
                DataType::UserId,
                DataValue::SignedNumber(identity.id as i128),
            ),
    }
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

    let pub_key_bytes = match pub_key.try_as_bytes() {
        Ok(bytes) => bytes,
        Err(error) => {
            log_err!(
                0,
                PrintType::General,
                "Failed to serialize Iota public key: {}",
                error
            );
            return 0;
        }
    };

    let request = CommunicationValue::new(CommunicationType::CompleteRegisterIota)
        .add_typed_default(
            DataType::PublicKey,
            DataValue::Str(BASE64_STD.encode(pub_key_bytes)),
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
        Some(DataValue::SignedNumber(id)) => *id as u64,
        _ => 0,
    }
}

pub async fn start(
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = load_file_vec("certs", "cert.pem")
        .map_err(|error| format!("load certs/cert.pem: {error}"))?;

    let key_pem = load_file_vec("certs", "key.pem")
        .map_err(|error| format!("load certs/key.pem: {error}"))?;

    let host_config = HostConfig::new(
        state.config.bind_address,
        state.config.rho_port,
        cert_pem,
        key_pem,
    )
    .with_policy(rho_policy())
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

    let web_config = web_config(state.config.rho_max_connections)?;
    let mut host = MTPWebServer::new(host_config, web_config).await?;
    let mut provisioning_cleanup = tokio::time::interval(Duration::from_secs(30));
    log!(
        0,
        PrintType::General,
        "Server listening on {}:{}.",
        state.config.bind_address,
        state.config.rho_port
    );

    loop {
        let accepted = tokio::select! {
            _ = shutdown.wait_for(|shutting_down| *shutting_down) => break,
            _ = provisioning_cleanup.tick() => {
                state.provisioning.prune_expired();
                continue;
            }
            accepted = host.accept() => accepted,
        };
        let conn = match accepted {
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

        let global_permit = match state.rho_connection_limits.all.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                log_err!(
                    0,
                    PrintType::General,
                    "Rejected connection: global Rho connection limit reached"
                );
                continue;
            }
        };
        let peer_ip = conn.remote_addr.map(|address| address.ip());
        let state = state.clone();
        tokio::spawn(async move {
            let Some(conn) = GeneralConnection::new(conn, state.clone()) else {
                log_err!(
                    0,
                    PrintType::General,
                    "Rejected connection: unrecognized or unauthenticated description"
                );
                return;
            };

            let anonymous_permit = if matches!(
                conn.connection_kind(),
                ConnectionKind::AnonymousClient
                    | ConnectionKind::RegisteringClient
                    | ConnectionKind::ProvisioningClient
                    | ConnectionKind::TAuth
            ) {
                match state
                    .rho_connection_limits
                    .anonymous
                    .clone()
                    .try_acquire_owned()
                {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        log_err!(
                            0,
                            PrintType::General,
                            "Rejected anonymous connection: anonymous limit reached"
                        );
                        return;
                    }
                }
            } else {
                None
            };

            let anonymous_ip_permit = if matches!(
                conn.connection_kind(),
                ConnectionKind::AnonymousClient
                    | ConnectionKind::RegisteringClient
                    | ConnectionKind::ProvisioningClient
                    | ConnectionKind::TAuth
            ) {
                let Some(peer_ip) = peer_ip else {
                    log_err!(
                        0,
                        PrintType::General,
                        "Rejected anonymous connection: peer address unavailable"
                    );
                    return;
                };
                match state
                    .rho_connection_limits
                    .try_acquire_anonymous_per_ip(peer_ip)
                {
                    Some(permit) => Some(permit),
                    None => {
                        log_err!(
                            0,
                            PrintType::General,
                            "Rejected anonymous connection: per-IP limit reached"
                        );
                        return;
                    }
                }
            } else {
                None
            };

            let _global_permit = global_permit;
            let _anonymous_permit = anonymous_permit;
            let _anonymous_ip_permit = anonymous_ip_permit;
            conn.handle().await;
        });
    }
    host.shutdown().await;
    log!(0, PrintType::General, "Server stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AuthIdentity, AuthIdentityKind, HttpResponse, authenticated_key_response,
        authentication_identity, public_key_lookup_request, rho_policy, web_config, with_cors,
    };
    use mtp::codec::{CommunicationType, DataType, DataValue};
    use std::time::Duration;

    #[test]
    fn rho_connection_budget_configures_mtp_admission() {
        let config = web_config(7).expect("health route is valid");
        assert_eq!(config.max_connections, 7);
    }

    #[test]
    fn web_responses_allow_all_origins() {
        let response = with_cors(HttpResponse::default());
        assert_eq!(response.headers["access-control-allow-origin"], "*");
        assert_eq!(
            response.headers["access-control-allow-methods"],
            "GET, POST, OPTIONS"
        );
        assert_eq!(response.headers["access-control-allow-headers"], "*");
        assert_eq!(
            response.headers["access-control-allow-private-network"],
            "true"
        );
    }

    #[test]
    fn public_key_lookup_identifies_the_omikron() {
        let request = public_key_lookup_request(
            17,
            AuthIdentity {
                kind: AuthIdentityKind::Client,
                id: 42,
            },
        );

        assert!(request.is_type(CommunicationType::GetUserData));
        assert_eq!(request.sender(), Some(17));
        assert_eq!(
            request.get_data(DataType::UserId),
            Some(&DataValue::SignedNumber(42))
        );
    }

    #[test]
    fn authentication_identity_separates_clients_and_iotas_with_the_same_id() {
        assert_ne!(
            authentication_identity(42, Some("client")),
            authentication_identity(42, Some("iota"))
        );
        assert_eq!(authentication_identity(42, Some("anonymous")), None);
    }

    #[test]
    fn authentication_caches_only_matching_omega_identity_responses() {
        for kind in [AuthIdentityKind::Iota, AuthIdentityKind::Client] {
            let identity = AuthIdentity { kind, id: 42 };
            let (expected_type, expected_field, wrong_type) = match kind {
                AuthIdentityKind::Iota => (
                    CommunicationType::GetIotaData,
                    DataType::IotaId,
                    CommunicationType::GetUserData,
                ),
                AuthIdentityKind::Client => (
                    CommunicationType::GetUserData,
                    DataType::UserId,
                    CommunicationType::GetIotaData,
                ),
            };
            let frame = |ty, id| {
                mtp::codec::CommunicationValue::new(ty)
                    .add_typed_default(expected_field, DataValue::SignedNumber(id))
                    .add_typed_default(DataType::PublicKey, DataValue::Str("key".into()))
            };
            assert_eq!(
                authenticated_key_response(&frame(expected_type, 42), identity),
                Some("key")
            );
            assert_eq!(
                authenticated_key_response(&frame(wrong_type, 42), identity),
                None
            );
            assert_eq!(
                authenticated_key_response(&frame(expected_type, 43), identity),
                None
            );
        }
    }

    #[test]
    fn rho_policy_keeps_idle_peers_alive_and_detects_dead_peers() {
        let policy = rho_policy();
        assert_eq!(policy.keep_alive_interval, Some(Duration::from_secs(6)));
        assert_eq!(policy.max_idle_timeout, Some(Duration::from_secs(30)));
    }
}
