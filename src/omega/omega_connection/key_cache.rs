use super::*;

#[cfg(unix)]
pub(super) fn authenticated_cache_file_trusted(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && metadata.mode() & 0o077 == 0
            && metadata.uid() == unsafe { libc::geteuid() }
    })
}

#[cfg(not(unix))]
pub(super) fn authenticated_cache_file_trusted(_: &std::path::Path) -> bool {
    false
}

pub(super) fn authenticated_key_path(identity: AuthIdentity) -> std::path::PathBuf {
    let kind = match identity.kind {
        AuthIdentityKind::Client => "client",
        AuthIdentityKind::Iota => "iota",
    };

    crate::WORKING_DIR
        .join("authenticated-public-keys")
        .join(kind)
        .join(format!("{}.mpkb", identity.id))
}

pub(super) fn authenticated_key_timestamp_path(identity: AuthIdentity) -> std::path::PathBuf {
    authenticated_key_path(identity).with_extension("mpkb.cached-at")
}

pub(super) fn cached_at_is_fresh(
    now: SystemTime,
    cached_at: SystemTime,
    max_age: Duration,
) -> bool {
    now.duration_since(cached_at)
        .is_ok_and(|age| age <= max_age)
}

impl OmegaConnection {
    pub fn recently_missing_key(&self, identity: AuthIdentity) -> bool {
        if self
            .missing_key_cache
            .get(&identity)
            .is_some_and(|timestamp| timestamp.elapsed() < Duration::from_secs(5))
        {
            return true;
        }
        self.missing_key_cache.remove(&identity);
        false
    }

    pub fn cache_missing_key(&self, identity: AuthIdentity) {
        if self.missing_key_cache.len() >= 1024 {
            self.missing_key_cache
                .retain(|_, timestamp| timestamp.elapsed() < Duration::from_secs(5));
            if self.missing_key_cache.len() >= 1024 {
                self.missing_key_cache.clear();
            }
        }
        self.missing_key_cache.insert(identity, Instant::now());
    }

    pub fn cached_authenticated_key(
        &self,
        identity: AuthIdentity,
    ) -> Option<mtp::crypto::PublicKeyBundle> {
        let max_age = match identity.kind {
            AuthIdentityKind::Client => Some(self.offline_auth.client_max_age),
            AuthIdentityKind::Iota => self.offline_auth.iota_max_age,
        }?;
        if let Some(key) = self.authenticated_key_cache.get(&identity)
            && cached_at_is_fresh(SystemTime::now(), key.cached_at, max_age)
        {
            return Some(key.public_key.clone());
        }
        self.authenticated_key_cache.remove(&identity);

        if !authenticated_cache_file_trusted(&authenticated_key_path(identity))
            || !authenticated_cache_file_trusted(&authenticated_key_timestamp_path(identity))
        {
            return None;
        }
        let cached_at = std::fs::read_to_string(authenticated_key_timestamp_path(identity))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
            .map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds))?;
        if !cached_at_is_fresh(SystemTime::now(), cached_at, max_age) {
            self.invalidate_authenticated_key(identity);
            return None;
        }
        let key = load_public_key_bundle(authenticated_key_path(identity)).ok()?;
        self.authenticated_key_cache.insert(
            identity,
            CachedAuthenticatedKey {
                public_key: key.clone(),
                cached_at,
            },
        );
        Some(key)
    }

    pub fn cache_authenticated_key(
        &self,
        identity: AuthIdentity,
        public_key: mtp::crypto::PublicKeyBundle,
    ) {
        self.missing_key_cache.remove(&identity);
        let path = authenticated_key_path(identity);
        if let Some(parent) = path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            log_err!(
                identity.id as i64,
                PrintType::General,
                "Create authenticated key cache directory failed: {}",
                error
            );
            return;
        }
        if let Err(error) = save_public_key_bundle(&public_key, &path) {
            log_err!(
                identity.id as i64,
                PrintType::General,
                "Persist authenticated key cache failed: {}",
                error
            );
            return;
        }
        #[cfg(unix)]
        if std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .is_err()
        {
            self.invalidate_authenticated_key(identity);
            return;
        }
        let cached_at = SystemTime::now();
        let timestamp = match cached_at.duration_since(UNIX_EPOCH) {
            Ok(timestamp) => timestamp.as_secs().to_string(),
            Err(error) => {
                log_err!(
                    identity.id as i64,
                    PrintType::General,
                    "Create authenticated key cache timestamp failed: {}",
                    error
                );
                self.invalidate_authenticated_key(identity);
                return;
            }
        };
        if let Err(error) = std::fs::write(authenticated_key_timestamp_path(identity), timestamp) {
            log_err!(
                identity.id as i64,
                PrintType::General,
                "Persist authenticated key cache timestamp failed: {}",
                error
            );
            self.invalidate_authenticated_key(identity);
            return;
        }
        #[cfg(unix)]
        if std::fs::set_permissions(
            authenticated_key_timestamp_path(identity),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .is_err()
        {
            self.invalidate_authenticated_key(identity);
            return;
        }
        self.authenticated_key_cache.insert(
            identity,
            CachedAuthenticatedKey {
                public_key,
                cached_at,
            },
        );
    }

    pub fn invalidate_authenticated_key(&self, identity: AuthIdentity) {
        self.authenticated_key_cache.remove(&identity);
        for path in [
            authenticated_key_path(identity),
            authenticated_key_timestamp_path(identity),
        ] {
            if let Err(error) = std::fs::remove_file(&path)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                log_err!(
                    identity.id as i64,
                    PrintType::General,
                    "Remove authenticated key cache {} failed: {}",
                    path.display(),
                    error
                );
            }
        }
    }
}
