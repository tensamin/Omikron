use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use mtp::crypto::{Keyring, PublicKeyBundle};
use mtp::files::{
    FileError, load_keyring_raw, load_public_key_bundle, save_keyring_raw, save_public_key_bundle,
};

#[cfg(unix)]
fn verify_private_keyring(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "keyring must be a regular owner-only file owned by the service user",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_keyring(_: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "keyring permissions cannot be verified on this platform",
    ))
}

pub const KEYRING_PATH: &str = "./omikron.mk";
pub const PUBLIC_KEY_PATH: &str = "./omikron.mpkb";

static PUBLIC_BUNDLE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn load_or_create_keyring(
    keyring_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
) -> Result<Keyring, String> {
    let keyring_path = keyring_path.as_ref();
    let public_key_path = public_key_path.as_ref();

    verify_private_keyring(keyring_path).map_err(|error| {
        format!(
            "unable to load existing Omikron identity from {}: {error}",
            keyring_path.display()
        )
    })?;
    let keyring = match load_keyring_raw(keyring_path) {
        Ok(keyring) => keyring,
        Err(FileError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            let keyring = Keyring::generate();
            save_keyring_raw(&keyring, keyring_path).map_err(|error| {
                format!("unable to persist Omikron keyring at {keyring_path:?}: {error}")
            })?;
            persist_public_bundle(&keyring.public_key_bundle(), public_key_path)?;
            eprintln!("Generated new keyring at {}", keyring_path.display());
            return Ok(keyring);
        }
        Err(error) => {
            return Err(format!(
                "unable to load existing Omikron identity from {}: {error}",
                keyring_path.display()
            ));
        }
    };

    let expected_bundle = keyring.public_key_bundle();
    match load_public_key_bundle(public_key_path) {
        Ok(persisted_bundle) => {
            let expected = expected_bundle
                .try_as_bytes()
                .map_err(|error| format!("unable to encode Omikron public key bundle: {error}"))?;
            let actual = persisted_bundle.try_as_bytes().map_err(|error| {
                format!(
                    "unable to encode persisted Omikron public key bundle at {public_key_path:?}: {error}"
                )
            })?;
            if expected != actual {
                return Err(format!(
                    "Omikron public key bundle at {public_key_path:?} does not match the private keyring"
                ));
            }
        }
        Err(FileError::Io(error)) if error.kind() == ErrorKind::NotFound => {
            persist_public_bundle(&expected_bundle, public_key_path)?;
        }
        Err(error) => {
            return Err(format!(
                "unable to load Omikron public key bundle from {}: {error}",
                public_key_path.display()
            ));
        }
    }

    Ok(keyring)
}

fn persist_public_bundle(bundle: &PublicKeyBundle, path: &Path) -> Result<(), String> {
    let temporary_path = temporary_path(path)?;
    if let Err(error) = save_public_key_bundle(bundle, &temporary_path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!(
            "unable to persist Omikron public key bundle at {path:?}: {error}"
        ));
    }
    if let Err(error) = fs::File::open(&temporary_path).and_then(|file| file.sync_all()) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!(
            "unable to persist Omikron public key bundle at {path:?}: {error}"
        ));
    }
    if let Err(error) = fs::rename(&temporary_path, path) {
        let _ = fs::remove_file(&temporary_path);
        return Err(format!(
            "unable to persist Omikron public key bundle at {path:?}: {error}"
        ));
    }
    Ok(())
}

fn temporary_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("Omikron public key bundle path has no file name: {path:?}"))?;
    let mut temporary_name = file_name.to_os_string();
    temporary_name.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        PUBLIC_BUNDLE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    Ok(parent.join(temporary_name))
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

    #[test]
    fn restart_after_keyring_write_repairs_missing_public_bundle() {
        let paths = TestPaths::new();
        let keyring = Keyring::generate();
        save_keyring_raw(&keyring, &paths.keyring).unwrap();
        let original_keyring = fs::read(&paths.keyring).unwrap();

        let restarted = load_or_create_keyring(&paths.keyring, &paths.public_key).unwrap();

        assert_eq!(fs::read(&paths.keyring).unwrap(), original_keyring);
        assert_eq!(
            load_public_key_bundle(&paths.public_key)
                .unwrap()
                .try_as_bytes()
                .unwrap(),
            restarted.public_key_bundle().try_as_bytes().unwrap()
        );
    }

    #[test]
    fn mismatched_public_bundle_fails_closed() {
        let paths = TestPaths::new();
        let keyring = Keyring::generate();
        let other_keyring = Keyring::generate();
        save_keyring_raw(&keyring, &paths.keyring).unwrap();
        save_public_key_bundle(&other_keyring.public_key_bundle(), &paths.public_key).unwrap();

        let error = load_or_create_keyring(&paths.keyring, &paths.public_key).unwrap_err();

        assert!(error.contains("does not match the private keyring"));
    }
}
