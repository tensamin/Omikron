use crate::{log, rho::connection::GeneralConnection, util::file_util::load_file_vec};
use epsilon_native::Host;

pub async fn start(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let cert_pem = load_file_vec("certs", "cert.pem")
        .map_err(|e| format!("Failed to load certificate: {}", e))?;
    let key_pem = load_file_vec("certs", "key.pem")
        .map_err(|e| format!("Failed to load private key: {}", e))?;

<<<<<<< HEAD
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
=======
    let mut host: Host = epsilon_native::host(port, cert_pem, key_pem).await?;
    log!(
        0,
        crate::util::logger::PrintType::Omikron,
        "Webtransport Server listening on port {}",
        port
    );

    while let Some((sender, receiver)) = host.next().await {
        tokio::spawn(async move {
            let conn = GeneralConnection::new(sender, receiver);
            conn.handle().await;
        });
    }

    Ok(())
>>>>>>> b2e6e903f789a81dd3629c21c08f03bbb430280b
}
