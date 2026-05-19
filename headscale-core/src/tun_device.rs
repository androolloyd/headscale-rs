//! TUN device abstraction for userspace networking.
//!
//! Provides a cross-platform interface for virtual network devices
//! that allows reading and writing IP packets directly.

use std::io;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Configuration for creating a TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Name of the TUN device (e.g., "wg0", "utun5").
    pub name: String,
    /// IPv4 address to assign to the device.
    pub address: Ipv4Addr,
    /// Netmask (e.g., 24 for /24).
    pub netmask: u8,
    /// MTU (Maximum Transmission Unit).
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "wg0".to_string(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: 24,
            mtu: 1420, // WireGuard default MTU
        }
    }
}

/// Handle to a TUN device for async packet I/O.
pub struct TunDevice {
    #[cfg(not(target_os = "windows"))]
    device: tun::AsyncDevice,
    config: TunConfig,
}

impl TunDevice {
    /// Create a new TUN device with the given configuration.
    ///
    /// Requires appropriate permissions (root/admin or CAP_NET_ADMIN on Linux).
    #[cfg(not(target_os = "windows"))]
    pub async fn create(config: TunConfig) -> Result<Self, TunError> {
        use tun::Configuration;

        let mut tun_config = Configuration::default();
        #[allow(deprecated)]
        tun_config
            .name(&config.name)
            .address(config.address)
            .netmask(Ipv4Addr::from(netmask_to_ipv4(config.netmask)))
            .mtu(config.mtu)
            .up();

        #[cfg(target_os = "linux")]
        tun_config.platform_config(|p| {
            p.packet_information(false);
        });

        let device =
            tun::create_as_async(&tun_config).map_err(|e| TunError::Create(e.to_string()))?;

        tracing::info!(
            name = %config.name,
            address = %config.address,
            netmask = config.netmask,
            mtu = config.mtu,
            "TUN device created"
        );

        Ok(Self { device, config })
    }

    /// Windows placeholder - TUN not yet supported.
    #[cfg(target_os = "windows")]
    pub async fn create(_config: TunConfig) -> Result<Self, TunError> {
        Err(TunError::Unsupported(
            "TUN device not yet supported on Windows".to_string(),
        ))
    }

    /// Get the device configuration.
    pub fn config(&self) -> &TunConfig {
        &self.config
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Read a packet from the TUN device.
    ///
    /// Returns the number of bytes read into the buffer.
    #[cfg(not(target_os = "windows"))]
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.device.read(buf).await.map_err(TunError::Read)
    }

    /// Write a packet to the TUN device.
    ///
    /// Returns the number of bytes written.
    #[cfg(not(target_os = "windows"))]
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        self.device.write(buf).await.map_err(TunError::Write)
    }

    /// Split the device into read and write halves for concurrent I/O.
    #[cfg(not(target_os = "windows"))]
    pub fn split(self) -> (TunReader, TunWriter) {
        let (reader, writer) = tokio::io::split(self.device);
        (TunReader { inner: reader }, TunWriter { inner: writer })
    }
}

/// Read half of a TUN device.
#[cfg(not(target_os = "windows"))]
pub struct TunReader {
    inner: tokio::io::ReadHalf<tun::AsyncDevice>,
}

#[cfg(not(target_os = "windows"))]
impl TunReader {
    /// Read a packet from the TUN device.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.inner.read(buf).await.map_err(TunError::Read)
    }
}

/// Write half of a TUN device.
#[cfg(not(target_os = "windows"))]
pub struct TunWriter {
    inner: tokio::io::WriteHalf<tun::AsyncDevice>,
}

#[cfg(not(target_os = "windows"))]
impl TunWriter {
    /// Write a packet to the TUN device.
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TunError> {
        self.inner.write(buf).await.map_err(TunError::Write)
    }
}

/// Convert a netmask prefix length to an IPv4 address.
fn netmask_to_ipv4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("Failed to create TUN device: {0}")]
    Create(String),

    #[error("Failed to read from TUN device: {0}")]
    Read(io::Error),

    #[error("Failed to write to TUN device: {0}")]
    Write(io::Error),

    #[error("TUN device not supported: {0}")]
    Unsupported(String),
}

/// Parse the destination IP address from an IPv4 packet.
pub fn parse_ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    // IPv4 header: destination address is at bytes 16-19
    if packet.len() < 20 {
        return None;
    }

    // Check IP version (first 4 bits should be 4 for IPv4)
    if (packet[0] >> 4) != 4 {
        return None;
    }

    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

/// Parse the source IP address from an IPv4 packet.
pub fn parse_ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    // IPv4 header: source address is at bytes 12-15
    if packet.len() < 20 {
        return None;
    }

    // Check IP version
    if (packet[0] >> 4) != 4 {
        return None;
    }

    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netmask_conversion() {
        assert_eq!(netmask_to_ipv4(0), 0);
        assert_eq!(netmask_to_ipv4(8), 0xFF00_0000);
        assert_eq!(netmask_to_ipv4(16), 0xFFFF_0000);
        assert_eq!(netmask_to_ipv4(24), 0xFFFF_FF00);
        assert_eq!(netmask_to_ipv4(32), 0xFFFF_FFFF);
    }

    #[test]
    fn test_parse_ipv4_destination() {
        // Minimal valid IPv4 header with dst 10.0.0.1
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // IPv4, IHL=5
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;

        assert_eq!(
            parse_ipv4_destination(&packet),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_parse_ipv4_source() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // IPv4, IHL=5
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 100;

        assert_eq!(
            parse_ipv4_source(&packet),
            Some(Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn test_parse_invalid_packets() {
        // Too short
        assert_eq!(parse_ipv4_destination(&[0u8; 10]), None);

        // IPv6 packet (version 6)
        let mut ipv6 = [0u8; 20];
        ipv6[0] = 0x60; // IPv6
        assert_eq!(parse_ipv4_destination(&ipv6), None);
    }

    #[test]
    fn test_default_config() {
        let config = TunConfig::default();
        assert_eq!(config.name, "wg0");
        assert_eq!(config.mtu, 1420);
        assert_eq!(config.netmask, 24);
    }
}
