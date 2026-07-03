mod anonymous_clients;
mod calls;
mod data;
mod omega;
mod rho;
mod util;

use std::env;
use std::path::PathBuf;

use dotenv::dotenv;
use once_cell::sync::Lazy;

pub static WORKING_DIR: Lazy<PathBuf> =
    Lazy::new(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
use rustls::crypto::aws_lc_rs::default_provider;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use mtp::crypto::Keyring;

use crate::{
    calls::call_util::garbage_collect_calls,
    omega::omega_connection::get_omega_connection,
    rho::server::start,
    util::logger::startup,
};

static KEYRING: Lazy<Keyring> = Lazy::new(|| {
    if let Ok(encoded) = env::var("KEYRING") {
        let bytes = BASE64_STD.decode(&encoded).expect("Invalid KEYRING base64");
        Keyring::from_bytes(&bytes).expect("Invalid KEYRING data")
    } else {
        let kr = Keyring::generate();
        eprintln!(
            "Generated KEYRING (save to env): {}",
            BASE64_STD.encode(&kr.to_bytes())
        );
        kr
    }
});

pub fn get_keyring() -> &'static Keyring {
    &KEYRING
}

#[tokio::main]
async fn main() {
    if let Err(_) = default_provider().install_default() {
        println!("Error loading Provider");
        return;
    }
    dotenv().ok();
    startup();

    let rho_port = env::var("RHO_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(959);

    get_omega_connection();
    tokio::spawn(async move {
        if let Err(e) = start(rho_port).await {
            log_err!(0, util::logger::PrintType::General, "{}", e);
        }
    });
    garbage_collect_calls();

    tokio::signal::ctrl_c().await.unwrap();
}
