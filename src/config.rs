use std::{env, net::IpAddr, time::Duration};

use thiserror::Error;

const DEFAULT_RHO_PORT: u16 = 443;
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0";
const DEFAULT_OMEGA_HOST: &str = "tensamin.net";
const DEFAULT_OMEGA_PORT: u16 = 9187;
const DEFAULT_OMEGA_SYNC_TIMEOUT_SECONDS: u64 = 20;
const DEFAULT_OMEGA_SYNC_RETRIES: u32 = 3;
const DEFAULT_OMEGA_TRANSPORT_MAX_MESSAGE_SIZE: u64 = 16 * 1024 * 1024;
const DEFAULT_OMEGA_TRANSPORT_HANDSHAKE_MAX_MESSAGE_SIZE: u64 = 64 * 1024;
const DEFAULT_RHO_MAX_CONNECTIONS: usize = 256;
const DEFAULT_RHO_MAX_ANONYMOUS_CONNECTIONS: usize = 128;
const DEFAULT_RHO_MAX_ANONYMOUS_CONNECTIONS_PER_IP: usize = 16;
const DEFAULT_LOGGER_QUEUE_CAPACITY: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveKitConfig {
    pub hostname: String,
    pub client_url: String,
    pub api_key: String,
    pub api_secret: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    pub max_message_size: u64,
    pub handshake_max_message_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallLimits {
    pub max_members_per_call: usize,
    pub max_pending_invites_per_call: usize,
    pub max_calls_per_user: usize,
    pub invite_ttl: Duration,
    pub reservation_ttl: Duration,
    pub empty_grace: Duration,
    pub max_call_age: Duration,
}

impl Default for CallLimits {
    fn default() -> Self {
        Self {
            max_members_per_call: 64,
            max_pending_invites_per_call: 64,
            max_calls_per_user: 16,
            invite_ttl: Duration::from_secs(3 * 24 * 60 * 60),
            reservation_ttl: Duration::from_secs(30),
            empty_grace: Duration::from_secs(5 * 60),
            max_call_age: Duration::from_secs(3 * 24 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfflineAuthPolicy {
    pub client_max_age: Duration,
    pub iota_max_age: Option<Duration>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub password_upstream_timeout: Duration,
    pub message_drain: Duration,
    pub cleanup_timeout: Duration,
    pub wait_on_incomplete_shutdown: bool,
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
    pub omega_transport: TransportConfig,
    pub offline_auth: OfflineAuthPolicy,
    pub call_limits: CallLimits,
    /// Maximum number of application sessions accepted by the Rho listener.
    pub rho_max_connections: usize,
    /// Maximum number of anonymous application sessions.
    pub rho_max_anonymous_connections: usize,
    /// Maximum number of anonymous sessions from one peer IP address.
    pub rho_max_anonymous_connections_per_ip: usize,
    pub provisioning_session_ttl: Duration,
    pub provisioning_max_sessions: usize,
    /// Maximum number of log entries waiting for the logger thread.
    pub logger_queue_capacity: usize,
    pub livekit: Option<LiveKitConfig>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("{name} is required")]
    MissingValue { name: &'static str },
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
        let omikron_id = require_positive(
            "ID",
            parse_required("ID", "positive integer")?,
            "positive integer",
        )?;
        // Each synchronization request is bounded by this timeout. After
        // omega_sync_retries attempts, Omikron closes the authenticated
        // transport so the normal reconnect loop can establish a clean state.
        let omega_sync_timeout = Duration::from_secs(parse_or_default(
            "OMEGA_SYNC_TIMEOUT_SECONDS",
            DEFAULT_OMEGA_SYNC_TIMEOUT_SECONDS,
        )?);
        let omega_sync_retries =
            parse_or_default("OMEGA_SYNC_RETRIES", DEFAULT_OMEGA_SYNC_RETRIES)?.max(1);
        let omega_transport = TransportConfig {
            max_message_size: parse_positive_or_default(
                "OMEGA_TRANSPORT_MAX_MESSAGE_SIZE",
                DEFAULT_OMEGA_TRANSPORT_MAX_MESSAGE_SIZE,
            )?,
            handshake_max_message_size: parse_positive_or_default(
                "OMEGA_TRANSPORT_HANDSHAKE_MAX_MESSAGE_SIZE",
                DEFAULT_OMEGA_TRANSPORT_HANDSHAKE_MAX_MESSAGE_SIZE,
            )?,
        };
        let offline_auth = OfflineAuthPolicy {
            client_max_age: Duration::from_secs(parse_positive_or_default(
                "CLIENT_OFFLINE_AUTH_MAX_AGE_SECONDS",
                24 * 60 * 60,
            )?),
            iota_max_age: env::var("IOTA_OFFLINE_AUTH_MAX_AGE_SECONDS")
                .ok()
                .map(|value| {
                    value.parse::<u64>().ok().filter(|age| *age > 0).ok_or(
                        ConfigError::InvalidValue {
                            name: "IOTA_OFFLINE_AUTH_MAX_AGE_SECONDS",
                            kind: "positive number of seconds",
                        },
                    )
                })
                .transpose()?
                .map(Duration::from_secs),
        };
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
        let logger_queue_capacity =
            parse_positive_or_default("LOGGER_QUEUE_CAPACITY", DEFAULT_LOGGER_QUEUE_CAPACITY)?;
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
            password_upstream_timeout: {
                let seconds =
                    parse_positive_or_default("PASSWORD_UPSTREAM_TIMEOUT_SECONDS", 18_u64)?;
                if seconds > 20 {
                    return Err(ConfigError::InvalidValue {
                        name: "PASSWORD_UPSTREAM_TIMEOUT_SECONDS",
                        kind: "integer between 1 and 20",
                    });
                }
                Duration::from_secs(seconds)
            },
            message_drain: Duration::from_secs(parse_positive_or_default(
                "MESSAGE_DRAIN_SECONDS",
                2,
            )?),
            cleanup_timeout: Duration::from_secs(parse_positive_or_default(
                "CLEANUP_TIMEOUT_SECONDS",
                25,
            )?),
            wait_on_incomplete_shutdown: env::var("WAIT_ON_INCOMPLETE_SHUTDOWN")
                .ok()
                .map(|value| {
                    value.trim().parse().map_err(|_| ConfigError::InvalidValue {
                        name: "WAIT_ON_INCOMPLETE_SHUTDOWN",
                        kind: "boolean, true or false",
                    })
                })
                .transpose()?
                .unwrap_or(false),
            rho_port,
            bind_address,
            omega_host,
            omega_port,
            omikron_id,
            omega_sync_timeout,
            omega_sync_retries,
            omega_transport,
            offline_auth,
            call_limits: CallLimits {
                max_members_per_call: parse_positive_or_default("CALL_MAX_MEMBERS", 64)?,
                max_pending_invites_per_call: parse_positive_or_default(
                    "CALL_MAX_PENDING_INVITES",
                    64,
                )?,
                max_calls_per_user: parse_positive_or_default("CALL_MAX_CALLS_PER_USER", 16)?,
                invite_ttl: Duration::from_secs(parse_positive_or_default(
                    "CALL_INVITE_TTL_SECONDS",
                    3 * 24 * 60 * 60,
                )?),
                reservation_ttl: Duration::from_secs(parse_positive_or_default(
                    "CALL_RESERVATION_TTL_SECONDS",
                    30,
                )?),
                empty_grace: Duration::from_secs(parse_positive_or_default(
                    "CALL_EMPTY_GRACE_SECONDS",
                    5 * 60,
                )?),
                max_call_age: Duration::from_secs(parse_positive_or_default(
                    "CALL_MAX_AGE_SECONDS",
                    3 * 24 * 60 * 60,
                )?),
            },
            rho_max_connections,
            rho_max_anonymous_connections,
            rho_max_anonymous_connections_per_ip,
            provisioning_session_ttl: Duration::from_secs(parse_positive_or_default(
                "PROVISIONING_SESSION_TTL_SECONDS",
                3 * 60,
            )?),
            provisioning_max_sessions: parse_positive_or_default(
                "PROVISIONING_MAX_SESSIONS",
                1024,
            )?,
            logger_queue_capacity,
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

fn parse_required<T>(name: &'static str, kind: &'static str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
{
    let value = match env::var(name) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Err(ConfigError::MissingValue { name }),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(ConfigError::InvalidValue { name, kind });
        }
    };

    value
        .trim()
        .parse()
        .map_err(|_| ConfigError::InvalidValue { name, kind })
}

fn parse_positive_or_default<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr + PartialEq + Default,
{
    require_positive(name, parse_or_default(name, default)?, "positive number")
}

fn require_positive<T>(name: &'static str, value: T, kind: &'static str) -> Result<T, ConfigError>
where
    T: PartialEq + Default,
{
    if value == T::default() {
        return Err(ConfigError::InvalidValue { name, kind });
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

    #[test]
    fn rejects_zero_transport_limit() {
        assert_eq!(
            require_positive("OMEGA_TRANSPORT_MAX_MESSAGE_SIZE", 0_u64, "positive number",),
            Err(ConfigError::InvalidValue {
                name: "OMEGA_TRANSPORT_MAX_MESSAGE_SIZE",
                kind: "positive number",
            })
        );
    }

    #[test]
    fn rejects_zero_omikron_id() {
        assert_eq!(
            require_positive("ID", 0_u64, "positive integer"),
            Err(ConfigError::InvalidValue {
                name: "ID",
                kind: "positive integer",
            })
        );
    }
}
