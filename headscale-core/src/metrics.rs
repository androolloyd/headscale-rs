//! Prometheus metrics for mesh coordination.

use std::sync::{Arc, LazyLock};

use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

/// Labels for node metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct NodeLabels {
    pub node_id: String,
}

/// Labels for tunnel metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TunnelLabels {
    pub local_node: String,
    pub remote_node: String,
    pub tunnel_type: String, // direct, derp
}

/// Labels for endpoint metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct EndpointLabels {
    pub endpoint_type: String, // local, stun, derp
}

/// Mesh networking metrics.
pub struct MeshMetrics {
    registry: Registry,

    // Node metrics
    pub nodes_registered: Gauge,
    pub nodes_online: Gauge,

    // Tunnel metrics
    pub tunnels_active: Gauge,
    pub tunnel_handshakes_total: Family<TunnelLabels, Counter>,
    pub tunnel_bytes_sent: Family<TunnelLabels, Counter>,
    pub tunnel_bytes_received: Family<TunnelLabels, Counter>,

    // Endpoint metrics
    pub endpoints_discovered: Family<EndpointLabels, Gauge>,
    pub stun_requests_total: Counter,
    pub stun_failures_total: Counter,

    // DERP metrics
    pub derp_connections_active: Gauge,
    pub derp_bytes_relayed: Counter,

    // Connection latency
    pub tunnel_rtt_seconds: Histogram,

    // Registration metrics
    pub registration_requests_total: Counter,
    pub registration_failures_total: Counter,
}

impl MeshMetrics {
    /// Create a new mesh metrics registry.
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // Node metrics
        let nodes_registered = Gauge::default();
        registry.register(
            "mesh_nodes_registered",
            "Total number of registered nodes",
            nodes_registered.clone(),
        );

        let nodes_online = Gauge::default();
        registry.register(
            "mesh_nodes_online",
            "Number of currently online nodes",
            nodes_online.clone(),
        );

        // Tunnel metrics
        let tunnels_active = Gauge::default();
        registry.register(
            "mesh_tunnels_active",
            "Number of active WireGuard tunnels",
            tunnels_active.clone(),
        );

        let tunnel_handshakes_total = Family::<TunnelLabels, Counter>::default();
        registry.register(
            "mesh_tunnel_handshakes_total",
            "Total WireGuard handshakes completed",
            tunnel_handshakes_total.clone(),
        );

        let tunnel_bytes_sent = Family::<TunnelLabels, Counter>::default();
        registry.register(
            "mesh_tunnel_bytes_sent_total",
            "Total bytes sent through tunnels",
            tunnel_bytes_sent.clone(),
        );

        let tunnel_bytes_received = Family::<TunnelLabels, Counter>::default();
        registry.register(
            "mesh_tunnel_bytes_received_total",
            "Total bytes received through tunnels",
            tunnel_bytes_received.clone(),
        );

        // Endpoint metrics
        let endpoints_discovered = Family::<EndpointLabels, Gauge>::default();
        registry.register(
            "mesh_endpoints_discovered",
            "Number of discovered endpoints by type",
            endpoints_discovered.clone(),
        );

        let stun_requests_total = Counter::default();
        registry.register(
            "mesh_stun_requests_total",
            "Total STUN discovery requests",
            stun_requests_total.clone(),
        );

        let stun_failures_total = Counter::default();
        registry.register(
            "mesh_stun_failures_total",
            "Total STUN discovery failures",
            stun_failures_total.clone(),
        );

        // DERP metrics
        let derp_connections_active = Gauge::default();
        registry.register(
            "mesh_derp_connections_active",
            "Number of active DERP relay connections",
            derp_connections_active.clone(),
        );

        let derp_bytes_relayed = Counter::default();
        registry.register(
            "mesh_derp_bytes_relayed_total",
            "Total bytes relayed through DERP",
            derp_bytes_relayed.clone(),
        );

        // Latency histogram
        let tunnel_rtt_seconds =
            Histogram::new([0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0].into_iter());
        registry.register(
            "mesh_tunnel_rtt_seconds",
            "Tunnel round-trip time in seconds",
            tunnel_rtt_seconds.clone(),
        );

        // Registration metrics
        let registration_requests_total = Counter::default();
        registry.register(
            "mesh_registration_requests_total",
            "Total node registration requests",
            registration_requests_total.clone(),
        );

        let registration_failures_total = Counter::default();
        registry.register(
            "mesh_registration_failures_total",
            "Total node registration failures",
            registration_failures_total.clone(),
        );

        Self {
            registry,
            nodes_registered,
            nodes_online,
            tunnels_active,
            tunnel_handshakes_total,
            tunnel_bytes_sent,
            tunnel_bytes_received,
            endpoints_discovered,
            stun_requests_total,
            stun_failures_total,
            derp_connections_active,
            derp_bytes_relayed,
            tunnel_rtt_seconds,
            registration_requests_total,
            registration_failures_total,
        }
    }

    /// Record a tunnel handshake.
    pub fn record_handshake(&self, local: &str, remote: &str, tunnel_type: &str) {
        let labels = TunnelLabels {
            local_node: local.to_string(),
            remote_node: remote.to_string(),
            tunnel_type: tunnel_type.to_string(),
        };
        self.tunnel_handshakes_total.get_or_create(&labels).inc();
    }

    /// Record bytes sent through a tunnel.
    pub fn record_bytes_sent(&self, local: &str, remote: &str, tunnel_type: &str, bytes: u64) {
        let labels = TunnelLabels {
            local_node: local.to_string(),
            remote_node: remote.to_string(),
            tunnel_type: tunnel_type.to_string(),
        };
        self.tunnel_bytes_sent.get_or_create(&labels).inc_by(bytes);
    }

    /// Record bytes received through a tunnel.
    pub fn record_bytes_received(&self, local: &str, remote: &str, tunnel_type: &str, bytes: u64) {
        let labels = TunnelLabels {
            local_node: local.to_string(),
            remote_node: remote.to_string(),
            tunnel_type: tunnel_type.to_string(),
        };
        self.tunnel_bytes_received
            .get_or_create(&labels)
            .inc_by(bytes);
    }

    /// Update endpoint count for a type.
    pub fn set_endpoints(&self, endpoint_type: &str, count: i64) {
        let labels = EndpointLabels {
            endpoint_type: endpoint_type.to_string(),
        };
        self.endpoints_discovered.get_or_create(&labels).set(count);
    }

    /// Record tunnel RTT.
    pub fn record_rtt(&self, rtt_secs: f64) {
        self.tunnel_rtt_seconds.observe(rtt_secs);
    }

    /// Encode metrics in Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry).unwrap_or_default();
        buffer
    }
}

impl Default for MeshMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global mesh metrics instance.
static MESH_METRICS: LazyLock<Arc<MeshMetrics>> = LazyLock::new(|| Arc::new(MeshMetrics::new()));

/// Get the global mesh metrics instance.
pub fn mesh_metrics() -> Arc<MeshMetrics> {
    MESH_METRICS.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_metrics_creation() {
        let metrics = MeshMetrics::new();
        assert!(!metrics.encode().is_empty());
    }

    #[test]
    fn test_node_counts() {
        let metrics = MeshMetrics::new();
        metrics.nodes_registered.set(10);
        metrics.nodes_online.set(8);

        let output = metrics.encode();
        assert!(output.contains("mesh_nodes_registered"));
        assert!(output.contains("mesh_nodes_online"));
    }

    #[test]
    fn test_tunnel_metrics() {
        let metrics = MeshMetrics::new();
        metrics.record_handshake("node-a", "node-b", "direct");
        metrics.record_bytes_sent("node-a", "node-b", "direct", 1024);
        metrics.record_bytes_received("node-a", "node-b", "direct", 512);

        let output = metrics.encode();
        assert!(output.contains("mesh_tunnel_handshakes_total"));
        assert!(output.contains("mesh_tunnel_bytes_sent_total"));
    }

    #[test]
    fn test_rtt_histogram() {
        let metrics = MeshMetrics::new();
        metrics.record_rtt(0.005);
        metrics.record_rtt(0.015);
        metrics.record_rtt(0.050);

        let output = metrics.encode();
        assert!(output.contains("mesh_tunnel_rtt_seconds"));
    }
}
