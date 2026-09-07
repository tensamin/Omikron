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

use std::{fmt::Write, path::PathBuf};

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
    identity::{KEYRING_PATH, PUBLIC_KEY_PATH, load_or_create_keyring},
    omega::omega_connection::{OmegaConnection, start_task_cleanup_loop},
    rho::rho_manager::RhoManager,
    rho::server::start,
    util::logger::{PrintType, startup},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(_) = default_provider().install_default() {
        return Err("Error loading Provider".into());
    }
    dotenv().ok();
    startup();

    let config = match Config::from_environment() {
        Ok(config) => config,
        Err(error) => {
            return Err(format!("Invalid configuration: {error}").into());
        }
    };

    let keyring = match load_or_create_keyring(KEYRING_PATH, PUBLIC_KEY_PATH) {
        Ok(keyring) => keyring,
        Err(error) => {
            return Err(format!("Unable to load Omikron keyring: {error}").into());
        }
    };
    let public_key = match omega_database_public_key(&keyring) {
        Ok(public_key) => public_key,
        Err(error) => {
            return Err(format!("Unable to serialize public key for Omega: {error}").into());
        }
    };
    log!(
        0,
        PrintType::Omikron,
        "Omikron public_key for Omega enrollment: {public_key}"
    );

    let omega_keyring = match keyring_for_omega(&keyring) {
        Ok(keyring) => keyring,
        Err(error) => {
            return Err(format!("Unable to copy keyring for Omega: {error}").into());
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
    tokio::select! {
        _ = omega.await_ready() => {}
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| format!("Unable to wait for shutdown signal: {error}"))?;
            omega.stop().await;
            return Ok(());
        }
    }
    let livekit = std::sync::Arc::new(LiveKitService::new(config.livekit.clone()));
    let call_manager = std::sync::Arc::new(CallManager::new_with_owner(
        livekit.clone(),
        config.omikron_id,
    ));
    livekit.clone().garbage_collect_calls(call_manager.clone());
    let state = AppState::new(config.clone(), keyring, omega, rho, call_manager, livekit);
    tokio::select! {
        result = start(state) => {
            result.map_err(|error| format!("Rho listener terminated: {error}"))?;
            return Err("Rho listener stopped unexpectedly".into());
        }
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| format!("Unable to wait for shutdown signal: {error}"))?;
        }
    }
    Ok(())
}

fn keyring_for_omega(keyring: &Keyring) -> Result<Keyring, String> {
    let bytes = keyring.try_to_bytes().map_err(|error| error.to_string())?;
    Keyring::from_bytes(&bytes).map_err(|error| error.to_string())
}

fn omega_database_public_key(keyring: &Keyring) -> Result<String, String> {
    let public_key = keyring
        .public_key_bundle()
        .try_as_bytes()
        .map_err(|error| error.to_string())?;
    omega_database_blob_literal(&public_key)
}

fn omega_database_blob_literal(public_key: &[u8]) -> Result<String, String> {
    let mut literal = String::with_capacity(3 + public_key.len() * 2);
    literal.push_str("X'");
    for byte in public_key {
        write!(&mut literal, "{byte:02X}").map_err(|error| error.to_string())?;
    }
    literal.push('\'');
    Ok(literal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_blob_literal_is_valid_mysql_hex_syntax() {
        assert_eq!(
            omega_database_blob_literal(&[0x00, 0x1A, 0xFF]),
            Ok("X'001AFF'".to_string())
        );
    }
}
