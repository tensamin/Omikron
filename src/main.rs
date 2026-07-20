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

use mtp::crypto::Keyring;
use mtp::files::{load_keyring_raw, save_keyring_raw, save_public_key_bundle};

use crate::{
    calls::call_util::garbage_collect_calls, omega::omega_connection::get_omega_connection,
    rho::server::start, util::logger::startup,
};

const KEYRING_PATH: &str = "./omikron.mk";
const PUBLIC_KEY_PATH: &str = "./omikron.mpkb";

static KEYRING: Lazy<Keyring> = Lazy::new(|| {
    load_keyring_raw(KEYRING_PATH).unwrap_or_else(|_| {
        let kr = Keyring::generate();
        save_keyring_raw(&kr, KEYRING_PATH).expect("Failed to save generated keyring");
        save_public_key_bundle(&kr.public_key_bundle(), PUBLIC_KEY_PATH)
            .expect("Failed to save generated public key bundle");
        eprintln!("Generated new keyring at {}", KEYRING_PATH);
        kr
    })
});

pub fn get_keyring() -> &'static Keyring {
    &KEYRING
}
pub fn load_keyring() -> Keyring {
    Keyring::from_bytes(&KEYRING.to_bytes()).unwrap()
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
        .unwrap_or(443);

    get_omega_connection();
    tokio::spawn(async move {
        if let Err(e) = start(rho_port).await {
            log_err!(0, util::logger::PrintType::General, "{}", e);
        }
    });
    garbage_collect_calls();

    tokio::signal::ctrl_c().await.unwrap();
}
