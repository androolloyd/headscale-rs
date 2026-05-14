//! Configuration for headscale-rs core.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Core configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Listen address for control plane
    pub listen_addr: SocketAddr,
    /// Database path
    pub db_path: PathBuf,
    /// WireGuard interface name
    pub wg_interface: String,
    /// WireGuard listen port
    pub wg_port: u16,
    /// DERP server URL for NAT traversal
    pub derp_url: Option<String>,
    /// Enable IPv6
    pub ipv6: bool,
    /// Mesh network CIDR
    pub mesh_cidr: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap(),
            db_path: PathBuf::from("/var/lib/headscale/db.sqlite"),
            wg_interface: "wg0".to_string(),
            wg_port: 51820,
            derp_url: None,
            ipv6: true,
            mesh_cidr: "100.64.0.0/10".to_string(),
        }
    }
}
