use std::{env, io::ErrorKind, path::Path};

use mtp::crypto::Keyring;
use mtp::files::{FileError, load_keyring, save_keyring, save_public_key_bundle};
use zeroize::Zeroizing;

pub const KEYRING_PATH: &str = "./omikron.mk";
pub const PUBLIC_KEY_PATH: &str = "./omikron.mpkb";
const IDENTITY_SECRET_ENV: &str = "OMIKRON_IDENTITY_SECRET";

pub fn identity_secret_from_environment() -> Result<Zeroizing<Vec<u8>>, String> {
    let secret = env::var(IDENTITY_SECRET_ENV).map_err(|_| {
        format!("{IDENTITY_SECRET_ENV} must be set before Omikron networking starts")
    })?;
    if secret.trim().is_empty() {
        return Err(format!("{IDENTITY_SECRET_ENV} must not be empty"));
    }
    Ok(Zeroizing::new(secret.into_bytes()))
}

#[allow(dead_code)]
pub fn load_or_create_keyring(
    passphrase: &[u8],
    keyring_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
) -> Result<Keyring, String> {
    let keyring_path = keyring_path.as_ref();
    let public_key_path = public_key_path.as_ref();

    match load_keyring(keyring_path, passphrase) {
        Ok(keyring) => Ok(keyring),
        Err(FileError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            let keyring = Keyring::generate();
            save_keyring(&keyring, keyring_path, passphrase).map_err(|error| {
                format!("unable to persist Omikron keyring at {keyring_path:?}: {error}")
            })?;
            save_public_key_bundle(&keyring.public_key_bundle(), public_key_path).map_err(
                |error| {
                    format!(
                        "unable to persist Omikron public key bundle at {public_key_path:?}: {error}"
                    )
                },
            )?;
            eprintln!(
                "Generated new protected keyring at {}",
                keyring_path.display()
            );
            Ok(keyring)
        }
        Err(error) => Err(format!(
            "unable to load existing Omikron identity from {}: {error}",
            keyring_path.display()
        )),
    }
}

#[cfg(feature = "raw-migration")]
#[allow(dead_code)]
pub fn migrate_raw_keyring(
    passphrase: &[u8],
    keyring_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
) -> Result<Keyring, String> {
    use mtp::files::load_keyring_raw;

    let keyring = load_keyring_raw(keyring_path.as_ref())
        .map_err(|error| format!("raw keyring migration failed: {error}"))?;
    save_keyring(&keyring, keyring_path.as_ref(), passphrase)
        .map_err(|error| format!("protected keyring write failed: {error}"))?;
    save_public_key_bundle(&keyring.public_key_bundle(), public_key_path.as_ref())
        .map_err(|error| format!("public key bundle write failed: {error}"))?;
    Ok(keyring)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TestPaths {
        directory: std::path::PathBuf,
        keyring: std::path::PathBuf,
        public_key: std::path::PathBuf,
    }

    impl TestPaths {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = env::temp_dir().join(format!("omikron-identity-{suffix}"));
            fs::create_dir_all(&directory).unwrap();
            Self {
                keyring: directory.join("omikron.mk"),
                public_key: directory.join("omikron.mpkb"),
                directory,
            }
        }
    }

    impl Drop for TestPaths {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn missing_identity_is_created_and_can_be_loaded_again() {
        let paths = TestPaths::new();
        let passphrase = b"test identity secret";
        let first = load_or_create_keyring(passphrase, &paths.keyring, &paths.public_key).unwrap();
        let first_public = first.public_key_bundle().try_as_bytes().unwrap();
        let second = load_or_create_keyring(passphrase, &paths.keyring, &paths.public_key).unwrap();

        assert_eq!(
            second.public_key_bundle().try_as_bytes().unwrap(),
            first_public
        );
    }

    #[test]
    fn corrupt_identity_fails_closed() {
        let paths = TestPaths::new();
        fs::write(&paths.keyring, b"not a keyring").unwrap();

        let error =
            load_or_create_keyring(b"test identity secret", &paths.keyring, &paths.public_key)
                .unwrap_err();
        assert!(error.contains("unable to load existing Omikron identity"));
    }

    #[test]
    fn unreadable_identity_fails_closed() {
        let paths = TestPaths::new();
        fs::create_dir(&paths.keyring).unwrap();

        let error =
            load_or_create_keyring(b"test identity secret", &paths.keyring, &paths.public_key)
                .unwrap_err();
        assert!(error.contains("unable to load existing Omikron identity"));
    }

    #[test]
    fn public_key_persistence_failure_fails_closed() {
        let paths = TestPaths::new();
        fs::create_dir(&paths.public_key).unwrap();

        let error =
            load_or_create_keyring(b"test identity secret", &paths.keyring, &paths.public_key)
                .unwrap_err();
        assert!(error.contains("unable to persist Omikron public key bundle"));
    }

    #[cfg(feature = "raw-migration")]
    #[test]
    fn raw_identity_migration_rewrites_protected_storage() {
        use mtp::files::{load_keyring, save_keyring_raw};

        let paths = TestPaths::new();
        let original = Keyring::generate();
        save_keyring_raw(&original, &paths.keyring).unwrap();

        let migrated =
            migrate_raw_keyring(b"test identity secret", &paths.keyring, &paths.public_key)
                .unwrap();
        let loaded = load_keyring(&paths.keyring, b"test identity secret").unwrap();

        assert_eq!(
            migrated.public_key_bundle().try_as_bytes().unwrap(),
            original.public_key_bundle().try_as_bytes().unwrap()
        );
        assert_eq!(
            loaded.public_key_bundle().try_as_bytes().unwrap(),
            original.public_key_bundle().try_as_bytes().unwrap()
        );
    }
}
