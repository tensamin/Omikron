mod anonymous_clients;
mod app_state;
mod calls;
mod config;
mod data;
mod identity;
mod omega;
mod rho;
mod services;
mod util;

use std::path::PathBuf;

use dotenv::dotenv;
use once_cell::sync::Lazy;

pub static WORKING_DIR: Lazy<PathBuf> =
    Lazy::new(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
use rustls::crypto::aws_lc_rs::default_provider;

use mtp::crypto::Keyring;

use crate::{
    app_state::AppState,
    calls::{call_manager::CallManager, call_util::LiveKitService},
    config::Config,
    identity::{
        KEYRING_PATH, PUBLIC_KEY_PATH, identity_secret_from_environment, load_or_create_keyring,
    },
    omega::omega_connection::{OmegaConnection, start_task_cleanup_loop},
    rho::rho_manager::RhoManager,
    rho::server::start,
    util::logger::startup,
};

#[tokio::main]
async fn main() {
    if let Err(_) = default_provider().install_default() {
        println!("Error loading Provider");
        return;
    }
    dotenv().ok();
    startup();

    let config = match Config::from_environment() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Invalid configuration: {error}");
            return;
        }
    };

    let identity_secret = match identity_secret_from_environment() {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("Unable to load Omikron identity secret: {error}");
            return;
        }
    };
    let keyring =
        match load_or_create_keyring(identity_secret.as_slice(), KEYRING_PATH, PUBLIC_KEY_PATH) {
            Ok(keyring) => keyring,
            Err(error) => {
                eprintln!("Unable to load Omikron identity: {error}");
                return;
            }
        };
    drop(identity_secret);

    let omega_keyring = match keyring_for_omega(&keyring) {
        Ok(keyring) => keyring,
        Err(error) => {
            eprintln!("Unable to copy keyring for Omega: {error}");
            return;
        }
    };
    let rho = std::sync::Arc::new(RhoManager::new());
    let omega = std::sync::Arc::new(OmegaConnection::from_config(
        &config,
        omega_keyring,
        rho.clone(),
    ));
    omega.clone().start().await;
    start_task_cleanup_loop(omega.clone());
    let livekit = std::sync::Arc::new(LiveKitService::new(config.livekit.clone()));
    let call_manager = std::sync::Arc::new(CallManager::new(livekit.clone()));
    let state = AppState::new(config.clone(), keyring, omega, rho, call_manager, livekit);
    tokio::spawn(async move {
        if let Err(e) = start(state).await {
            log_err!(0, util::logger::PrintType::General, "{}", e);
        }
    });

    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("Unable to wait for shutdown signal: {error}");
    }
}

fn keyring_for_omega(keyring: &Keyring) -> Result<Keyring, String> {
    let bytes = keyring.try_to_bytes().map_err(|error| error.to_string())?;
    Keyring::from_bytes(&bytes).map_err(|error| error.to_string())
}
