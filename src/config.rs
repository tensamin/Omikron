use std::{env, net::IpAddr, time::Duration};

use thiserror::Error;

const DEFAULT_RHO_PORT: u16 = 443;
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0";
const DEFAULT_OMEGA_HOST: &str = "tensamin.net";
const DEFAULT_OMEGA_PORT: u16 = 9187;
const DEFAULT_OMEGA_SYNC_TIMEOUT_SECONDS: u64 = 20;
const DEFAULT_OMEGA_SYNC_RETRIES: u32 = 3;
const DEFAULT_RHO_MAX_CONNECTIONS: usize = 256;
const DEFAULT_RHO_MAX_ANONYMOUS_CONNECTIONS: usize = 128;
const DEFAULT_RHO_MAX_ANONYMOUS_CONNECTIONS_PER_IP: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveKitConfig {
    pub hostname: String,
    pub client_url: String,
    pub api_key: String,
    pub api_secret: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub rho_port: u16,
    pub bind_address: IpAddr,
    pub omega_host: String,
    pub omega_port: u16,
    pub omikron_id: u64,
    /// Maximum duration of one route or subscription synchronization request.
    pub omega_sync_timeout: Duration,
    /// Number of synchronization requests before the transport is closed and
    /// the normal reconnect loop starts.
    pub omega_sync_retries: u32,
    /// Maximum number of application sessions accepted by the Rho listener.
    pub rho_max_connections: usize,
    /// Maximum number of anonymous application sessions.
    pub rho_max_anonymous_connections: usize,
    /// Maximum number of anonymous sessions from one peer IP address.
    pub rho_max_anonymous_connections_per_ip: usize,
    pub livekit: Option<LiveKitConfig>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("{name} must be a valid {kind}")]
    InvalidValue {
        name: &'static str,
        kind: &'static str,
    },
    #[error(
        "LIVEKIT_HOSTNAME, LIVEKIT_CLIENT_URL, LIVEKIT_API_KEY, and LIVEKIT_API_SECRET must be set together"
    )]
    IncompleteLiveKitCredentials,
}

impl Config {
    pub fn from_environment() -> Result<Self, ConfigError> {
        let rho_port = parse_or_default("RHO_PORT", DEFAULT_RHO_PORT)?;
        let bind_address = parse_bind_address(env::var("BIND_ADDRESS").ok())?;
        let omega_port = parse_or_default("OMEGA_PORT", DEFAULT_OMEGA_PORT)?;
        let omikron_id = parse_or_default("ID", 0_u64)?;
        // Each synchronization request is bounded by this timeout. After
        // omega_sync_retries attempts, Omikron closes the authenticated
        // transport so the normal reconnect loop can establish a clean state.
        let omega_sync_timeout = Duration::from_secs(parse_or_default(
            "OMEGA_SYNC_TIMEOUT_SECONDS",
            DEFAULT_OMEGA_SYNC_TIMEOUT_SECONDS,
        )?);
        let omega_sync_retries =
            parse_or_default("OMEGA_SYNC_RETRIES", DEFAULT_OMEGA_SYNC_RETRIES)?.max(1);
        let rho_max_connections =
            parse_positive_or_default("RHO_MAX_CONNECTIONS", DEFAULT_RHO_MAX_CONNECTIONS)?;
        let rho_max_anonymous_connections = parse_positive_or_default(
            "RHO_MAX_ANONYMOUS_CONNECTIONS",
            DEFAULT_RHO_MAX_ANONYMOUS_CONNECTIONS,
        )?;
        let rho_max_anonymous_connections_per_ip = parse_positive_or_default(
            "RHO_MAX_ANONYMOUS_CONNECTIONS_PER_IP",
            DEFAULT_RHO_MAX_ANONYMOUS_CONNECTIONS_PER_IP,
        )?;
        let omega_host = env::var("OMEGA_HOST")
            .unwrap_or_else(|_| DEFAULT_OMEGA_HOST.to_string())
            .trim()
            .to_string();

        if omega_host.is_empty() {
            return Err(ConfigError::InvalidValue {
                name: "OMEGA_HOST",
                kind: "non-empty host name",
            });
        }

        Ok(Self {
            rho_port,
            bind_address,
            omega_host,
            omega_port,
            omikron_id,
            omega_sync_timeout,
            omega_sync_retries,
            rho_max_connections,
            rho_max_anonymous_connections,
            rho_max_anonymous_connections_per_ip,
            livekit: livekit_from_environment()?,
        })
    }
}

fn parse_bind_address(value: Option<String>) -> Result<IpAddr, ConfigError> {
    value
        .as_deref()
        .unwrap_or(DEFAULT_BIND_ADDRESS)
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidValue {
            name: "BIND_ADDRESS",
            kind: "IP address",
        })
}

fn parse_or_default<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    match env::var(name) {
        Ok(value) => value.trim().parse().map_err(|_| ConfigError::InvalidValue {
            name,
            kind: "number",
        }),
        Err(_) => Ok(default),
    }
}

fn parse_positive_or_default<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr + PartialEq + Default,
{
    let value = parse_or_default(name, default)?;
    if value == T::default() {
        return Err(ConfigError::InvalidValue {
            name,
            kind: "positive number",
        });
    }
    Ok(value)
}

fn livekit_from_environment() -> Result<Option<LiveKitConfig>, ConfigError> {
    livekit_from_values(
        env::var("LIVEKIT_HOSTNAME").ok(),
        env::var("LIVEKIT_CLIENT_URL").ok(),
        env::var("LIVEKIT_API_KEY").ok(),
        env::var("LIVEKIT_API_SECRET").ok(),
    )
}

fn livekit_from_values(
    hostname: Option<String>,
    client_url: Option<String>,
    api_key: Option<String>,
    api_secret: Option<String>,
) -> Result<Option<LiveKitConfig>, ConfigError> {
    match (hostname, client_url, api_key, api_secret) {
        (None, None, None, None) => Ok(None),
        (Some(hostname), Some(client_url), Some(api_key), Some(api_secret))
            if !hostname.trim().is_empty()
                && !client_url.trim().is_empty()
                && !api_key.trim().is_empty()
                && !api_secret.trim().is_empty() =>
        {
            Ok(Some(LiveKitConfig {
                hostname,
                client_url,
                api_key,
                api_secret,
            }))
        }
        _ => Err(ConfigError::IncompleteLiveKitCredentials),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn livekit_credentials_must_be_complete() {
        assert_eq!(
            livekit_from_values(
                Some("host".to_string()),
                Some("url".to_string()),
                Some("key".to_string()),
                None
            ),
            Err(ConfigError::IncompleteLiveKitCredentials)
        );
    }

    #[test]
    fn complete_livekit_credentials_are_loaded() {
        assert_eq!(
            livekit_from_values(
                Some("https://livekit.example".to_string()),
                Some("wss://livekit.example".to_string()),
                Some("key".to_string()),
                Some("secret".to_string()),
            ),
            Ok(Some(LiveKitConfig {
                hostname: "https://livekit.example".to_string(),
                client_url: "wss://livekit.example".to_string(),
                api_key: "key".to_string(),
                api_secret: "secret".to_string(),
            }))
        );
    }

    #[test]
    fn parses_configured_bind_address() {
        assert_eq!(
            parse_bind_address(Some("10.200.2.0".to_string())),
            Ok(IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 2, 0)))
        );
    }

    #[test]
    fn rejects_invalid_bind_address() {
        assert_eq!(
            parse_bind_address(Some("not-an-address".to_string())),
            Err(ConfigError::InvalidValue {
                name: "BIND_ADDRESS",
                kind: "IP address",
            })
        );
    }
}
