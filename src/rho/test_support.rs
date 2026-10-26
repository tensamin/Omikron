use super::{rho_manager::RhoManager, server::rho_policy};
use crate::{
    app_state::AppState,
    calls::call_manager::CallManager,
    config::{CallLimits, Config, OfflineAuthPolicy, TransportConfig},
    omega::omega_connection::OmegaConnection,
};
use mtp::{
    client::{ClientConfig, MTPClient},
    crypto::Keyring,
    host::{AuthenticationPolicy, HostConfig},
    webserver::{MTPWebServer, WebMTPConnection, WebServerConfig},
};
use std::{sync::Arc, time::Duration};

pub fn state() -> Arc<AppState> {
    let config = Config {
        password_upstream_timeout: Duration::from_secs(18),
        message_drain: Duration::from_secs(2),
        cleanup_timeout: Duration::from_secs(25),
        wait_on_incomplete_shutdown: false,
        rho_port: 0,
        bind_address: "127.0.0.1".parse().unwrap(),
        omega_host: "127.0.0.1".into(),
        omega_port: 0,
        omikron_id: 1,
        omega_sync_timeout: Duration::from_millis(100),
        omega_sync_retries: 1,
        omega_transport: TransportConfig {
            max_message_size: 1024 * 1024,
            handshake_max_message_size: 64 * 1024,
        },
        offline_auth: OfflineAuthPolicy {
            client_max_age: Duration::ZERO,
            iota_max_age: Some(Duration::ZERO),
        },
        call_limits: CallLimits::default(),
        rho_max_connections: 2,
        rho_max_anonymous_connections: 1,
        rho_max_anonymous_connections_per_ip: 1,
        provisioning_session_ttl: Duration::from_secs(60),
        provisioning_max_sessions: 2,
        logger_queue_capacity: 10,
        livekit: None,
    };
    let rho = Arc::new(RhoManager::new());
    let omega = Arc::new(OmegaConnection::from_config(
        &config,
        Keyring::generate(),
        rho.clone(),
    ));
    AppState::new(
        config,
        Keyring::generate(),
        omega,
        rho,
        Arc::new(CallManager::default()),
    )
}

pub async fn guest(role: &str) -> (MTPWebServer, mtp::client::MTPConnection, WebMTPConnection) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .pem()
        .into_bytes();
    let config = HostConfig::new(
        "127.0.0.1".parse().unwrap(),
        0,
        cert.clone(),
        key.serialize_pem().into_bytes(),
    )
    .with_policy(rho_policy())
    .with_authentication_policy(AuthenticationPolicy::Unauthenticated);
    let mut host = MTPWebServer::new(config, WebServerConfig::new().serve_tcp_https(false))
        .await
        .unwrap();
    let config = ClientConfig::new(format!("https://127.0.0.1:{}/", host.local_addr().port()))
        .with_pinned_pem(cert)
        .with_description(role)
        // Legacy native clients finish their opening stream after each message.
        // Rho's outbound persistent stream independently orders its responses.
        .with_policy(rho_policy().with_send_mode(mtp::host::SendMode::SingleStreamPerMessage));
    let (client, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(MTPClient::connect(config), host.accept())
    })
    .await
    .unwrap();
    (host, client.unwrap(), accepted.unwrap().unwrap())
}

pub async fn authenticated(
    role: &str,
) -> (MTPWebServer, mtp::client::MTPConnection, WebMTPConnection) {
    authenticated_with_key(role, &Keyring::generate()).await
}

pub async fn authenticated_with_key(
    role: &str,
    client_keys: &Keyring,
) -> (MTPWebServer, mtp::client::MTPConnection, WebMTPConnection) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .pem()
        .into_bytes();
    let host_keys = Keyring::generate();
    let host_public = host_keys.public_key_bundle();
    let client_public = client_keys.public_key_bundle();
    let expected_role = role.to_string();
    let config = HostConfig::new(
        "127.0.0.1".parse().unwrap(),
        0,
        cert.clone(),
        key.serialize_pem().into_bytes(),
    )
    .with_policy(rho_policy())
    .with_authentication(
        host_keys,
        Box::new(move |id, role| {
            let public = (id == 42 && role.as_deref() == Some(expected_role.as_str()))
                .then(|| client_public.clone());
            Box::pin(async move { public })
        }),
        Box::new(|_, _| Box::pin(async { 0 })),
    )
    .with_authentication_policy(AuthenticationPolicy::ForceAuthentication);
    let mut host = MTPWebServer::new(config, WebServerConfig::new().serve_tcp_https(false))
        .await
        .unwrap();
    let config = ClientConfig::new(format!("https://127.0.0.1:{}/", host.local_addr().port()))
        .with_pinned_pem(cert)
        .with_description(role)
        .with_client_id(42)
        .with_policy(rho_policy().with_send_mode(mtp::host::SendMode::SingleStreamPerMessage));
    let (client, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            MTPClient::auth_connect(config, client_keys, &host_public),
            host.accept()
        )
    })
    .await
    .unwrap();
    (host, client.unwrap(), accepted.unwrap().unwrap())
}
