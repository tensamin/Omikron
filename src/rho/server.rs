use crate::{
    log,
    rho::connection::GeneralConnection,
    util::file_util::{load_file_buf, load_file_vec},
};
use epsilon_native::Host;
use quinn::ServerConfig;
use rustls::{
    ServerConfig as CryptoConfig,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{
        CertificateDer, PrivateKeyDer,
        pem::{PemObject, SectionKind},
    },
};
use std::sync::Arc;

pub async fn start(port: u16) {
    let _ = aws_lc_rs::default_provider().install_default();

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

fn load_tls() -> Option<CryptoConfig> {
    let _ = aws_lc_rs::default_provider().install_default();

    let mut cert_pem = load_file_buf("certs", "cert.pem").ok()?;
    let cert_chain = rustls_pemfile::certs(&mut cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;

    let key_pem = load_file_vec("certs", "key.pem").ok()?;
    let key_der = rustls_pemfile::private_key(&mut &*key_pem).ok()??;

    let cfg = CryptoConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .ok()?;

    Some(cfg)
}
