use std::sync::Arc;

use mtp::crypto::Keyring;

use crate::{
    calls::{call_manager::CallManager, call_util::LiveKitService},
    config::Config,
    omega::omega_connection::OmegaConnection,
    rho::rho_manager::RhoManager,
    services::call_state::CallStateAggregator,
};

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
        Arc::new(Self {
            config,
            keyring,
            omega,
            rho,
            call_state_aggregator: Arc::new(CallStateAggregator::new(call_manager.clone())),
            call_manager,
            livekit,
        })
    }

    pub fn keyring_for_host(&self) -> Result<Keyring, String> {
        Keyring::from_bytes(&self.keyring.to_bytes()).map_err(|error| error.to_string())
    }
}
