use crate::{
    log,
    rho::connection::GeneralConnection,
    util::{file_util::load_file_vec, logger::PrintType},
};
use epsilon_native::Host;

pub async fn start(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = load_file_vec("certs", "cert.pem").expect("Error loading Pemfile");

    let key_pem = load_file_vec("certs", "key.pem").expect("Error loading Keyfile");

    let mut host: Host = epsilon_native::host(port, cert_pem, key_pem).await?;
    log!(0, PrintType::General, "Server listening on port {}", port);

    while let Some((sender, receiver)) = host.next().await {
        tokio::spawn(async move {
            let conn = GeneralConnection::new(sender, receiver);
            conn.handle().await;
        });
    }

    Ok(())
}
