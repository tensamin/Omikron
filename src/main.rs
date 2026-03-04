mod anonymous_clients;
mod calls;
mod data;
mod omega;
mod rho;
mod util;

use std::env;

use dotenv::dotenv;
use once_cell::sync::Lazy;
use rustls::crypto::aws_lc_rs::default_provider;

use crate::{
    calls::call_util::garbage_collect_calls,
    omega::omega_connection::get_omega_connection,
    rho::server::start,
    util::{
        crypto_helper::{load_public_key, load_secret_key},
        logger::startup,
    },
};

static PRIVATE_KEY: Lazy<String> = Lazy::new(|| env::var("PRIVATE_KEY").unwrap());
pub fn get_private_key() -> x448::Secret {
    load_secret_key(&*PRIVATE_KEY).unwrap()
}
static PUBLIC_KEY: Lazy<String> = Lazy::new(|| env::var("PUBLIC_KEY").unwrap());
pub fn get_public_key() -> x448::PublicKey {
    load_public_key(&*PUBLIC_KEY).unwrap()
}

#[tokio::main]
async fn main() {
    if let Err(_) = default_provider().install_default() {
        println!("Error loading Provider");
        return;
    }
    dotenv().ok();
    startup();

    get_omega_connection();
    tokio::spawn(async move {
        let _ = start(959).await;
    });
    garbage_collect_calls();

    tokio::signal::ctrl_c().await.unwrap();
}
