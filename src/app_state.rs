use std::{net::IpAddr, sync::Arc};

use dashmap::DashMap;
use mtp::crypto::Keyring;
use tokio::sync::Semaphore;

use crate::{
    calls::{call_manager::CallManager, call_util::LiveKitService},
    config::Config,
    omega::omega_connection::OmegaConnection,
    provisioning::ProvisioningManager,
    rho::rho_manager::RhoManager,
    services::call_state::CallStateAggregator,
};

pub struct RhoConnectionLimits {
    pub all: Arc<Semaphore>,
    pub anonymous: Arc<Semaphore>,
    anonymous_by_ip: Arc<DashMap<IpAddr, usize>>,
    max_anonymous_per_ip: usize,
}

impl RhoConnectionLimits {
    pub fn new(max_all: usize, max_anonymous: usize, max_anonymous_per_ip: usize) -> Self {
        Self {
            all: Arc::new(Semaphore::new(max_all)),
            anonymous: Arc::new(Semaphore::new(max_anonymous)),
            anonymous_by_ip: Arc::new(DashMap::new()),
            max_anonymous_per_ip,
        }
    }

    pub fn try_acquire_anonymous_per_ip(&self, ip: IpAddr) -> Option<RhoIpConnectionPermit> {
        let mut count = self.anonymous_by_ip.entry(ip).or_insert(0);
        if *count >= self.max_anonymous_per_ip {
            return None;
        }
        *count += 1;
        drop(count);

        Some(RhoIpConnectionPermit {
            ip,
            active_by_ip: self.anonymous_by_ip.clone(),
        })
    }

    #[cfg(test)]
    fn anonymous_count_for_ip(&self, ip: IpAddr) -> usize {
        self.anonymous_by_ip.get(&ip).map_or(0, |count| *count)
    }
}

pub struct RhoIpConnectionPermit {
    ip: IpAddr,
    active_by_ip: Arc<DashMap<IpAddr, usize>>,
}

impl Drop for RhoIpConnectionPermit {
    fn drop(&mut self) {
        if let Some(mut count) = self.active_by_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
        }
        self.active_by_ip
            .remove_if(&self.ip, |_, count| *count == 0);
    }
}

/*
 * Holds startup dependencies so listener and connection constructors can take
 * one explicit handle while the remaining manager migrations are completed.
 */
pub struct AppState {
    pub config: Config,
    pub keyring: Keyring,
    pub omega: Arc<OmegaConnection>,
    pub rho: Arc<RhoManager>,
    pub call_manager: Arc<CallManager>,
    pub call_state_aggregator: Arc<CallStateAggregator>,
    pub livekit: Arc<LiveKitService>,
    pub rho_connection_limits: Arc<RhoConnectionLimits>,
    pub provisioning: Arc<ProvisioningManager>,
}

impl AppState {
    pub fn new(
        config: Config,
        keyring: Keyring,
        omega: Arc<OmegaConnection>,
        rho: Arc<RhoManager>,
        call_manager: Arc<CallManager>,
        livekit: Arc<LiveKitService>,
    ) -> Arc<Self> {
        let rho_connection_limits = Arc::new(RhoConnectionLimits::new(
            config.rho_max_connections,
            config.rho_max_anonymous_connections,
            config.rho_max_anonymous_connections_per_ip,
        ));
        Arc::new(Self {
            provisioning: Arc::new(ProvisioningManager::new(
                config.provisioning_session_ttl,
                config.provisioning_max_sessions,
            )),
            config,
            keyring,
            omega,
            rho: rho.clone(),
            call_state_aggregator: Arc::new(
                CallStateAggregator::new(call_manager.clone()).with_rho(rho.clone()),
            ),
            call_manager,
            livekit,
            rho_connection_limits,
        })
    }

    pub fn keyring_for_host(&self) -> Result<Keyring, String> {
        let bytes = self
            .keyring
            .try_to_bytes()
            .map_err(|error| error.to_string())?;
        Keyring::from_bytes(&bytes).map_err(|error| error.to_string())
    }
}
