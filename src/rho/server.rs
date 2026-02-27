use crate::{rho::connection::GeneralConnection, util::file_util::load_file_buf};
use epsilon_native::Host;
use quinn::ServerConfig;
use rustls::pki_types::PrivateKeyDer;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

pub async fn start(port: u16) {
    let tls_cfg = load_tls().expect("TLS config failed");

    let server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg)
        .expect("Failed to convert to QuicServerConfig");

    let server_cfg = ServerConfig::with_crypto(Arc::new(server_crypto));

    let mut host: Host = epsilon_native::host(port, server_cfg).await.unwrap();
    tokio::spawn(async move {
        while let Some((sender, receiver)) = host.next().await {
            tokio::spawn(async move {
                GeneralConnection::new(sender, receiver).handle().await;
            });
        }
    });
}

fn load_tls() -> Option<rustls::ServerConfig> {
    let mut cert_file_buf = load_file_buf("certs", "cert.pem").ok()?;
    let mut key_file_buf = load_file_buf("certs", "cert.key").ok()?;

    let cert_chain = rustls_pemfile::certs(&mut cert_file_buf)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;

    let mut keys: Vec<PrivateKeyDer> = rustls_pemfile::pkcs8_private_keys(&mut key_file_buf)
        .map(|k| k.map(Into::into))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;

    if keys.is_empty() {
        let mut key_file_buf = load_file_buf("certs", "cert.key").ok()?;
        keys = rustls_pemfile::rsa_private_keys(&mut key_file_buf)
            .map(|k| k.map(Into::into))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
    }

    if keys.is_empty() {
        return None;
    }

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .ok()?;

    Some(cfg)
}
