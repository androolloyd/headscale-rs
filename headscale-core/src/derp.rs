//! DERP client for relay fallback when direct connections fail.
//!
//! DERP (Designated Encrypted Relay for Packets) provides a relay service
//! for WireGuard packets when direct UDP connections aren't possible.
//! This is a simplified implementation compatible with Tailscale's DERP protocol.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{RwLock, broadcast, mpsc};

use crate::config::EmbeddedDerpConfig;
use crate::stun::StunListener;

/// Default DERP port (HTTPS).
pub const DERP_PORT: u16 = 443;

/// DERP frame types.
const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PEER_PRESENT: u8 = 0x09;

/// A DERP server entry.
#[derive(Debug, Clone)]
pub struct DerpServer {
    /// Server name/ID.
    pub name: String,
    /// Server hostname.
    pub hostname: String,
    /// Server address.
    pub addr: SocketAddr,
    /// Region code (e.g., "us-east", "eu-west").
    pub region: String,
    /// Whether STUN is available on this server.
    pub stun_enabled: bool,
}

/// DERP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerpState {
    /// Not connected.
    Disconnected,
    /// Connecting to server.
    Connecting,
    /// Connected and authenticated.
    Connected,
    /// Connection failed.
    Failed,
}

/// Events from the DERP client.
#[derive(Debug, Clone)]
pub enum DerpEvent {
    /// Connected to a DERP server.
    Connected { server: String },
    /// Disconnected from a DERP server.
    Disconnected { server: String, reason: String },
    /// Received a packet from a peer via DERP.
    PacketReceived { peer_key: [u8; 32], data: Vec<u8> },
    /// A peer is now reachable via this DERP server.
    PeerPresent { peer_key: [u8; 32] },
    /// A peer is no longer reachable via this DERP server.
    PeerGone { peer_key: [u8; 32] },
}

/// DERP client for relay connections.
pub struct DerpClient {
    /// Our WireGuard public key.
    local_key: [u8; 32],
    /// Available DERP servers.
    servers: Vec<DerpServer>,
    /// Active connections by server name.
    connections: RwLock<HashMap<String, DerpConnection>>,
    /// Event sender.
    event_tx: broadcast::Sender<DerpEvent>,
    /// Preferred server (closest/lowest latency).
    preferred_server: RwLock<Option<String>>,
}

/// An active connection to a DERP server.
struct DerpConnection {
    /// Server name.
    _server_name: String,
    /// Connection state.
    state: DerpState,
    /// Channel to send packets.
    tx: mpsc::Sender<DerpFrame>,
    /// Server's public key.
    _server_key: Option<[u8; 32]>,
    /// Last activity time.
    _last_activity: Instant,
}

/// A DERP frame to send.
#[derive(Debug)]
enum DerpFrame {
    /// Send a packet to a peer.
    Send { peer_key: [u8; 32], data: Vec<u8> },
}

impl DerpClient {
    /// Create a new DERP client.
    pub fn new(local_key: [u8; 32], servers: Vec<DerpServer>) -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            local_key,
            servers,
            connections: RwLock::new(HashMap::new()),
            event_tx,
            preferred_server: RwLock::new(None),
        }
    }

    /// Subscribe to DERP events.
    pub fn subscribe(&self) -> broadcast::Receiver<DerpEvent> {
        self.event_tx.subscribe()
    }

    /// Get available servers.
    pub fn servers(&self) -> &[DerpServer] {
        &self.servers
    }

    /// Get the preferred server.
    pub async fn preferred_server(&self) -> Option<String> {
        self.preferred_server.read().await.clone()
    }

    /// Connect to a DERP server.
    pub async fn connect(&self, server_name: &str) -> Result<(), DerpError> {
        let server = self
            .servers
            .iter()
            .find(|s| s.name == server_name)
            .ok_or_else(|| DerpError::ServerNotFound(server_name.to_string()))?
            .clone();

        // Check if already connected
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(server_name)
                && conn.state == DerpState::Connected
            {
                return Ok(());
            }
        }

        tracing::info!(server = %server_name, addr = %server.addr, "Connecting to DERP server");

        // Connect to the server
        let stream = TcpStream::connect(server.addr).await?;

        // Create channels for communication
        let (tx, rx) = mpsc::channel(256);

        // Store the connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(
                server_name.to_string(),
                DerpConnection {
                    _server_name: server_name.to_string(),
                    state: DerpState::Connecting,
                    tx,
                    _server_key: None,
                    _last_activity: Instant::now(),
                },
            );
        }

        // Spawn connection handler
        let local_key = self.local_key;
        let event_tx = self.event_tx.clone();
        let server_name_owned = server_name.to_string();

        tokio::spawn(async move {
            // Box::pin to keep the spawned future's stack footprint small —
            // `handle_derp_connection` has a 64 KiB packet buffer + per-stream
            // rustls state, so dropping it on the stack triggers
            // `clippy::large_futures` and risks stack overflow under deep tasks.
            if let Err(e) = Box::pin(handle_derp_connection(
                stream,
                local_key,
                rx,
                event_tx.clone(),
            ))
            .await
            {
                tracing::warn!(server = %server_name_owned, error = %e, "DERP connection failed");
                let _ = event_tx.send(DerpEvent::Disconnected {
                    server: server_name_owned,
                    reason: e.to_string(),
                });
            }
        });

        // Update preferred server if this is first connection
        {
            let mut preferred = self.preferred_server.write().await;
            if preferred.is_none() {
                *preferred = Some(server_name.to_string());
            }
        }

        Ok(())
    }

    /// Disconnect from a DERP server.
    pub async fn disconnect(&self, server_name: &str) -> Result<(), DerpError> {
        let mut connections = self.connections.write().await;
        if connections.remove(server_name).is_some() {
            tracing::info!(server = %server_name, "Disconnected from DERP server");
            let _ = self.event_tx.send(DerpEvent::Disconnected {
                server: server_name.to_string(),
                reason: "User requested".to_string(),
            });
        }
        Ok(())
    }

    /// Send a packet to a peer via DERP relay.
    pub async fn send_to_peer(&self, peer_key: &[u8; 32], data: &[u8]) -> Result<(), DerpError> {
        // Find a connected server
        let connections = self.connections.read().await;

        // Try preferred server first
        let preferred = self.preferred_server.read().await;
        let server_name = preferred.as_ref().and_then(|name| {
            connections
                .get(name)
                .filter(|c| c.state == DerpState::Connected)
                .map(|_| name.clone())
        });

        // Or find any connected server
        let server_name = server_name.or_else(|| {
            connections
                .iter()
                .find(|(_, c)| c.state == DerpState::Connected)
                .map(|(name, _)| name.clone())
        });

        let server_name = server_name.ok_or(DerpError::NotConnected)?;
        let conn = connections
            .get(&server_name)
            .ok_or(DerpError::NotConnected)?;

        conn.tx
            .send(DerpFrame::Send {
                peer_key: *peer_key,
                data: data.to_vec(),
            })
            .await
            .map_err(|_| DerpError::SendFailed)?;

        Ok(())
    }

    /// Get connection state for a server.
    pub async fn connection_state(&self, server_name: &str) -> DerpState {
        let connections = self.connections.read().await;
        connections
            .get(server_name)
            .map_or(DerpState::Disconnected, |c| c.state)
    }

    /// Get all connected servers.
    pub async fn connected_servers(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .filter(|(_, c)| c.state == DerpState::Connected)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// Handle a DERP connection.
async fn handle_derp_connection(
    mut stream: TcpStream,
    local_key: [u8; 32],
    mut rx: mpsc::Receiver<DerpFrame>,
    event_tx: broadcast::Sender<DerpEvent>,
) -> Result<(), DerpError> {
    // Send client info
    send_client_info(&mut stream, &local_key).await?;

    // Wait for server key
    let _server_key = recv_server_key(&mut stream).await?;

    // Connection established
    let _ = event_tx.send(DerpEvent::Connected {
        server: "unknown".to_string(),
    });

    // Main loop. 64 KiB stack buffer for one DERP frame — protocol-mandated
    // upper bound, allocated once per connection. clippy::large_stack_arrays
    // warns at 16 KiB; this lives inside an `async fn` already pinned via
    // `Box::pin` at the call site, so the stack pressure is bounded.
    #[allow(clippy::large_stack_arrays)]
    let mut buf = [0u8; 65536];
    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            // Handle incoming frames
            result = stream.read(&mut buf) => {
                let n = result?;
                if n == 0 {
                    return Err(DerpError::ConnectionClosed);
                }

                if let Some(event) = parse_derp_frame(&buf[..n]) {
                    let _ = event_tx.send(event);
                }
            }

            // Handle outgoing frames
            Some(frame) = rx.recv() => {
                match frame {
                    DerpFrame::Send { peer_key, data } => {
                        send_packet(&mut stream, &peer_key, &data).await?;
                    }
                }
            }

            // Send keepalives
            _ = keepalive_interval.tick() => {
                send_keepalive(&mut stream).await?;
            }
        }
    }
}

/// Send client info frame.
async fn send_client_info(stream: &mut TcpStream, key: &[u8; 32]) -> Result<(), DerpError> {
    let mut frame = Vec::with_capacity(37);
    frame.push(FRAME_CLIENT_INFO);
    frame.extend_from_slice(&32u32.to_be_bytes());
    frame.extend_from_slice(key);

    stream.write_all(&frame).await?;
    Ok(())
}

/// Receive server key frame.
async fn recv_server_key(stream: &mut TcpStream) -> Result<[u8; 32], DerpError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    if header[0] != FRAME_SERVER_KEY {
        return Err(DerpError::Protocol(format!(
            "Expected server key, got frame type {}",
            header[0]
        )));
    }

    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len != 32 {
        return Err(DerpError::Protocol(format!(
            "Invalid server key length: {len}"
        )));
    }

    let mut key = [0u8; 32];
    stream.read_exact(&mut key).await?;

    Ok(key)
}

/// Send a packet to a peer.
async fn send_packet(
    stream: &mut TcpStream,
    peer_key: &[u8; 32],
    data: &[u8],
) -> Result<(), DerpError> {
    let len = (32 + data.len()) as u32;
    let mut frame = Vec::with_capacity(5 + 32 + data.len());
    frame.push(FRAME_SEND_PACKET);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(peer_key);
    frame.extend_from_slice(data);

    stream.write_all(&frame).await?;
    Ok(())
}

/// Send a keepalive frame.
async fn send_keepalive(stream: &mut TcpStream) -> Result<(), DerpError> {
    let frame = [FRAME_KEEP_ALIVE, 0, 0, 0, 0];
    stream.write_all(&frame).await?;
    Ok(())
}

/// Parse a DERP frame into an event.
/// Exposed as pub for fuzzing.
pub fn parse_derp_frame(data: &[u8]) -> Option<DerpEvent> {
    if data.len() < 5 {
        return None;
    }

    let frame_type = data[0];
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

    if data.len() < 5 + len {
        return None;
    }

    let payload = &data[5..5 + len];

    match frame_type {
        FRAME_RECV_PACKET if payload.len() >= 32 => {
            let mut peer_key = [0u8; 32];
            peer_key.copy_from_slice(&payload[..32]);
            let data = payload[32..].to_vec();
            Some(DerpEvent::PacketReceived { peer_key, data })
        }
        FRAME_PEER_PRESENT if payload.len() >= 32 => {
            let mut peer_key = [0u8; 32];
            peer_key.copy_from_slice(&payload[..32]);
            Some(DerpEvent::PeerPresent { peer_key })
        }
        FRAME_PEER_GONE if payload.len() >= 32 => {
            let mut peer_key = [0u8; 32];
            peer_key.copy_from_slice(&payload[..32]);
            Some(DerpEvent::PeerGone { peer_key })
        }
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DerpError {
    #[error("Server not found: {0}")]
    ServerNotFound(String),

    #[error("Not connected to any DERP server")]
    NotConnected,

    #[error("Failed to send packet")]
    SendFailed,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Embedded DERP/STUN runtime.
///
/// The Rust runtime owns the lightweight STUN responder. DERP relay traffic is
/// delegated to the upstream `derper` binary because DERP's relay protocol has
/// no maintained Rust implementation in this repository.
pub struct EmbeddedDerpRuntime {
    cfg: EmbeddedDerpConfig,
    stun: Option<StunListener>,
    sidecar: Option<DerperSidecar>,
}

impl EmbeddedDerpRuntime {
    /// Start with a config whose `derper_config_path` is already resolved.
    pub async fn start(cfg: EmbeddedDerpConfig) -> Result<Self, EmbeddedDerpError> {
        validate_embedded_derp_config(&cfg)?;

        if !cfg.enabled {
            return Ok(Self {
                cfg,
                stun: None,
                sidecar: None,
            });
        }

        let stun = match cfg.stun_addr {
            Some(addr) => Some(StunListener::bind(addr).await?),
            None => None,
        };
        let sidecar = if cfg.relay_enabled() {
            Some(DerperSidecar::spawn(&cfg)?)
        } else {
            None
        };

        Ok(Self { cfg, stun, sidecar })
    }

    /// Resolve the `derper -c` config path under `state_dir` before starting.
    pub async fn start_with_state_dir(
        cfg: EmbeddedDerpConfig,
        state_dir: impl AsRef<Path>,
    ) -> Result<Self, EmbeddedDerpError> {
        Self::start(cfg.with_default_derper_config_path(state_dir.as_ref())).await
    }

    /// Runtime config after default path resolution.
    pub fn config(&self) -> &EmbeddedDerpConfig {
        &self.cfg
    }

    /// Local STUN bind address when the embedded STUN listener is active.
    pub fn stun_local_addr(&self) -> Option<SocketAddr> {
        self.stun.as_ref().and_then(|stun| stun.local_addr().ok())
    }

    /// Sidecar process status when a DERP relay sidecar was started.
    pub fn sidecar_status(&self) -> Option<SidecarStatus> {
        self.sidecar.as_ref().map(DerperSidecar::status)
    }
}

fn validate_embedded_derp_config(cfg: &EmbeddedDerpConfig) -> Result<(), EmbeddedDerpError> {
    if !cfg.enabled {
        return Ok(());
    }
    if cfg.host_name.trim().is_empty() {
        return Err(EmbeddedDerpError::MissingHostName);
    }
    if cfg.stun_addr.is_none() {
        return Err(EmbeddedDerpError::MissingStunAddress);
    }
    if cfg.relay_enabled() {
        if cfg.derper_binary.as_os_str().is_empty() {
            return Err(EmbeddedDerpError::MissingDerperBinary(PathBuf::new()));
        }
        if !cfg.derper_binary.is_file() {
            return Err(EmbeddedDerpError::MissingDerperBinary(
                cfg.derper_binary.clone(),
            ));
        }
        if cfg.derper_config_path.as_os_str().is_empty() {
            return Err(EmbeddedDerpError::MissingDerperConfigPath);
        }
    }
    Ok(())
}

/// Embedded DERP runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddedDerpError {
    #[error("embedded DERP host_name is required when enabled")]
    MissingHostName,

    #[error("embedded DERP stun_addr is required when enabled")]
    MissingStunAddress,

    #[error("embedded DERP derper_binary is missing or not a file: {0:?}")]
    MissingDerperBinary(PathBuf),

    #[error("embedded DERP derper_config_path is required when the relay sidecar is enabled")]
    MissingDerperConfigPath,

    #[error("embedded DERP/STUN I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Current status of the upstream `derper` sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarStatus {
    Running { pid: u32 },
    Exited { code: Option<i32> },
    NotStarted,
}

/// `derper` subprocess lifecycle.
pub struct DerperSidecar {
    child: Arc<Mutex<Option<std::process::Child>>>,
    status: Arc<Mutex<SidecarStatus>>,
}

impl DerperSidecar {
    /// Spawn the configured upstream `derper` binary.
    pub fn spawn(cfg: &EmbeddedDerpConfig) -> Result<Self, EmbeddedDerpError> {
        validate_embedded_derp_config(cfg)?;

        let mut command = Command::new(&cfg.derper_binary);
        command
            .arg("-a")
            .arg(cfg.derper_listen_addr.to_string())
            .arg("-hostname")
            .arg(&cfg.host_name)
            .arg("-stun=false")
            .arg("-http-port=-1")
            .arg("-c")
            .arg(&cfg.derper_config_path)
            .arg("-certmode")
            .arg(&cfg.derper_cert_mode)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        if let Some(cert_dir) = &cfg.derper_cert_dir {
            command.arg("-certdir").arg(cert_dir);
        }
        if cfg.verify_clients {
            command.arg("-verify-clients");
        }
        if let Some(url) = &cfg.verify_client_url {
            command
                .arg("-verify-client-url")
                .arg(url)
                .arg("-verify-client-url-fail-open=false");
        }

        let child = command.spawn()?;
        let pid = child.id();
        let child = Arc::new(Mutex::new(Some(child)));
        let status = Arc::new(Mutex::new(SidecarStatus::Running { pid }));

        watch_sidecar(Arc::clone(&child), Arc::clone(&status));

        Ok(Self { child, status })
    }

    /// Return the latest observed process status.
    pub fn status(&self) -> SidecarStatus {
        lock_or_recover(&self.status).clone()
    }

    /// Stop the sidecar process. Idempotent.
    pub fn terminate(&self) {
        let mut guard = lock_or_recover(&self.child);
        let Some(child) = guard.as_mut() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
        *guard = None;
        *lock_or_recover(&self.status) = SidecarStatus::NotStarted;
    }
}

impl Drop for DerperSidecar {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn watch_sidecar(
    child: Arc<Mutex<Option<std::process::Child>>>,
    status: Arc<Mutex<SidecarStatus>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let exit_code = {
                let mut guard = lock_or_recover(&child);
                let Some(child) = guard.as_mut() else {
                    return;
                };
                match child.try_wait() {
                    Ok(Some(exit)) => {
                        *guard = None;
                        Some(exit.code())
                    }
                    Ok(None) => None,
                    Err(err) => {
                        tracing::warn!(error = %err, "derper sidecar try_wait failed");
                        None
                    }
                }
            };

            if let Some(code) = exit_code {
                *lock_or_recover(&status) = SidecarStatus::Exited { code };
                return;
            }
        }
    });
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_recv_packet() {
        let peer_key = [42u8; 32];
        let packet_data = b"hello";

        let mut frame = Vec::new();
        frame.push(FRAME_RECV_PACKET);
        frame.extend_from_slice(&((32 + 5) as u32).to_be_bytes());
        frame.extend_from_slice(&peer_key);
        frame.extend_from_slice(packet_data);

        let event = parse_derp_frame(&frame).unwrap();
        match event {
            DerpEvent::PacketReceived { peer_key: pk, data } => {
                assert_eq!(pk, peer_key);
                assert_eq!(data, packet_data);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_parse_peer_present() {
        let peer_key = [99u8; 32];

        let mut frame = Vec::new();
        frame.push(FRAME_PEER_PRESENT);
        frame.extend_from_slice(&32u32.to_be_bytes());
        frame.extend_from_slice(&peer_key);

        let event = parse_derp_frame(&frame).unwrap();
        match event {
            DerpEvent::PeerPresent { peer_key: pk } => {
                assert_eq!(pk, peer_key);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_derp_server() {
        let server = DerpServer {
            name: "nyc1".to_string(),
            hostname: "derp1.example.com".to_string(),
            addr: "1.2.3.4:443".parse().unwrap(),
            region: "us-east".to_string(),
            stun_enabled: true,
        };

        assert_eq!(server.name, "nyc1");
        assert!(server.stun_enabled);
    }

    #[tokio::test]
    async fn embedded_runtime_disabled_starts_no_listeners() {
        let runtime = EmbeddedDerpRuntime::start(EmbeddedDerpConfig::default())
            .await
            .unwrap();

        assert!(runtime.stun_local_addr().is_none());
        assert!(runtime.sidecar_status().is_none());
    }

    #[tokio::test]
    async fn embedded_runtime_stun_only_binds_udp_listener() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            stun_addr: Some("127.0.0.1:0".parse().unwrap()),
            stun_only: true,
            ..EmbeddedDerpConfig::default()
        };

        let runtime = EmbeddedDerpRuntime::start(cfg).await.unwrap();
        let addr = runtime.stun_local_addr().unwrap();

        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
        assert!(runtime.sidecar_status().is_none());
    }

    #[tokio::test]
    async fn embedded_runtime_requires_derper_binary_for_relay() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            stun_addr: Some("127.0.0.1:0".parse().unwrap()),
            derper_config_path: "/tmp/headscale-rs-test-derper.key".into(),
            ..EmbeddedDerpConfig::default()
        };

        let result = EmbeddedDerpRuntime::start(cfg).await;

        assert!(matches!(
            result,
            Err(EmbeddedDerpError::MissingDerperBinary(_))
        ));
    }

    #[tokio::test]
    async fn embedded_runtime_requires_stun_addr_when_enabled() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            ..EmbeddedDerpConfig::default()
        };

        let result = EmbeddedDerpRuntime::start(cfg).await;

        assert!(matches!(result, Err(EmbeddedDerpError::MissingStunAddress)));
    }

    #[test]
    fn embedded_derp_config_resolves_default_sidecar_config_path() {
        let cfg = EmbeddedDerpConfig::default()
            .with_default_derper_config_path(std::path::Path::new("/var/lib/headscale"));

        assert_eq!(
            cfg.derper_config_path,
            std::path::PathBuf::from("/var/lib/headscale/derper.key")
        );
    }

    #[tokio::test]
    async fn sidecar_verify_url_is_fail_closed_for_admission_tests() {
        use std::io::Write;

        let unique = format!(
            "headscale-rs-derper-args-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        let args_file = dir.join("args.txt");
        let fake_derper = dir.join("derper-fake.sh");
        let escaped_args_file = args_file.display().to_string().replace('\'', "'\\''");
        let mut file = std::fs::File::create(&fake_derper).unwrap();
        writeln!(
            file,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nsleep 30\n",
            escaped_args_file
        )
        .unwrap();
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_derper).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_derper, perms).unwrap();
        }

        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            stun_addr: Some("127.0.0.1:0".parse().unwrap()),
            derper_binary: fake_derper,
            derper_listen_addr: "127.0.0.1:0".parse().unwrap(),
            derper_config_path: dir.join("derper.key"),
            derper_cert_mode: "manual".to_string(),
            verify_client_url: Some("http://127.0.0.1:51821/verify".to_string()),
            ..EmbeddedDerpConfig::default()
        };

        let sidecar = DerperSidecar::spawn(&cfg).unwrap();
        let mut args = String::new();
        for _ in 0..20 {
            if let Ok(raw) = std::fs::read_to_string(&args_file)
                && raw.contains("-verify-client-url-fail-open=false")
            {
                args = raw;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        sidecar.terminate();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(args.contains("-verify-client-url\n"));
        assert!(args.contains("http://127.0.0.1:51821/verify\n"));
        assert!(args.contains("-verify-client-url-fail-open=false\n"));
    }
}
