#[path = "../identity.rs"]
mod identity;

use identity::{
    KEYRING_PATH, PUBLIC_KEY_PATH, identity_secret_from_environment, migrate_raw_keyring,
};

fn main() {
    let secret = match identity_secret_from_environment() {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("Unable to load Omikron identity secret: {error}");
            std::process::exit(1);
        }
    };

    if let Err(error) = migrate_raw_keyring(secret.as_slice(), KEYRING_PATH, PUBLIC_KEY_PATH) {
        eprintln!("Unable to migrate Omikron identity: {error}");
        std::process::exit(1);
    }

    println!("Migrated {KEYRING_PATH} to protected keyring storage");
}
