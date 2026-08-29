use std::{io::ErrorKind, path::Path};

use mtp::crypto::Keyring;
use mtp::files::{FileError, load_keyring_raw, save_keyring_raw, save_public_key_bundle};

pub const KEYRING_PATH: &str = "./omikron.mk";
pub const PUBLIC_KEY_PATH: &str = "./omikron.mpkb";

pub fn load_or_create_keyring(
    keyring_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
) -> Result<Keyring, String> {
    let keyring_path = keyring_path.as_ref();
    let public_key_path = public_key_path.as_ref();

    match load_keyring_raw(keyring_path) {
        Ok(keyring) => Ok(keyring),
        Err(FileError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            let keyring = Keyring::generate();
            save_keyring_raw(&keyring, keyring_path).map_err(|error| {
                format!("unable to persist Omikron keyring at {keyring_path:?}: {error}")
            })?;
            save_public_key_bundle(&keyring.public_key_bundle(), public_key_path).map_err(
                |error| {
                    format!(
                        "unable to persist Omikron public key bundle at {public_key_path:?}: {error}"
                    )
                },
            )?;
            eprintln!("Generated new keyring at {}", keyring_path.display());
            Ok(keyring)
        }
        Err(error) => Err(format!(
            "unable to load existing Omikron identity from {}: {error}",
            keyring_path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env, fs,
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
        let first = load_or_create_keyring(&paths.keyring, &paths.public_key).unwrap();
        let first_public = first.public_key_bundle().try_as_bytes().unwrap();
        let stored = load_keyring_raw(&paths.keyring).unwrap();
        let second = load_or_create_keyring(&paths.keyring, &paths.public_key).unwrap();

        assert_eq!(
            stored.public_key_bundle().try_as_bytes().unwrap(),
            first_public
        );
        assert_eq!(
            second.public_key_bundle().try_as_bytes().unwrap(),
            first_public
        );
    }

    #[test]
    fn corrupt_identity_fails_closed() {
        let paths = TestPaths::new();
        fs::write(&paths.keyring, b"not a keyring").unwrap();

        let error = load_or_create_keyring(&paths.keyring, &paths.public_key).unwrap_err();
        assert!(error.contains("unable to load existing Omikron identity"));
    }

    #[test]
    fn unreadable_identity_fails_closed() {
        let paths = TestPaths::new();
        fs::create_dir(&paths.keyring).unwrap();

        let error = load_or_create_keyring(&paths.keyring, &paths.public_key).unwrap_err();
        assert!(error.contains("unable to load existing Omikron identity"));
    }

    #[test]
    fn public_key_persistence_failure_fails_closed() {
        let paths = TestPaths::new();
        fs::create_dir(&paths.public_key).unwrap();

        let error = load_or_create_keyring(&paths.keyring, &paths.public_key).unwrap_err();
        assert!(error.contains("unable to persist Omikron public key bundle"));
    }
}
