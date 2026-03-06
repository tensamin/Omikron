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

    let key_pem = load_file_vec("certs", "key.pem").unwrap();
    let cert_pem = load_file_vec("certs", "cert.pem").unwrap();

    let mut host: Host = epsilon_native::host(port, cert_pem, key_pem).await.unwrap();
    tokio::spawn(async move {
        while let Some((sender, receiver)) = host.next().await {
            tokio::spawn(async move {
                GeneralConnection::new(sender, receiver).handle().await;
            });
        }
    });
}
