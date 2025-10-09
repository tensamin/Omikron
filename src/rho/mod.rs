//! Rho module - Connection management between Iota and Client connections
//!
//! This module implements the Rho connection management system that maps
//! single Iota connections to multiple Client connections, providing
//! bidirectional communication capabilities.

pub mod client_connection;
pub mod iota_connection;
pub mod rho_connection;
pub mod rho_manager;

// Re-export commonly used types for convenience
pub use client_connection::ClientConnection;
pub use iota_connection::IotaConnection;
pub use rho_connection::RhoConnection;

// Re-export key manager functions
pub use rho_manager::{
    add_rho, connection_count, contains_iota, get_all_connections, get_rho_by_iota,
    get_rho_con_for_user, remove_rho,
};
