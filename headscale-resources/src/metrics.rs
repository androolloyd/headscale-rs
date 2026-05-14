//! Prometheus metrics for resource metering.

use std::sync::Arc;

use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;

/// Labels for resource metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ResourceLabels {
    pub resource_type: String,
    pub consumer: String,
    pub provider: String,
}

/// Labels for payment metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PaymentLabels {
    pub from: String,
    pub to: String,
}

/// Resource metrics registry.
pub struct ResourceMetrics {
    registry: Registry,

    // Inference metrics
    pub inference_tokens_total: Family<ResourceLabels, Counter>,

    // Storage metrics
    pub storage_bytes_used: Family<ResourceLabels, Gauge>,

    // Compute metrics
    pub compute_cpu_seconds: Family<ResourceLabels, Counter>,

    // Bandwidth metrics
    pub bandwidth_bytes_total: Family<ResourceLabels, Counter>,

    // Payment metrics
    pub payment_transactions_total: Family<PaymentLabels, Counter>,

    // Escrow metrics
    pub escrow_active_count: Gauge,

    // Session duration histogram
    pub session_duration_seconds: Histogram,
}

impl ResourceMetrics {
    /// Create a new metrics registry.
    pub fn new() -> Self {
        let mut registry = Registry::default();

        // Initialize inference metrics
        let inference_tokens_total = Family::<ResourceLabels, Counter>::default();
        registry.register(
            "inference_tokens",
            "Total number of inference tokens processed",
            inference_tokens_total.clone(),
        );

        // Initialize storage metrics
        let storage_bytes_used = Family::<ResourceLabels, Gauge>::default();
        registry.register(
            "storage_bytes_used",
            "Current storage bytes in use",
            storage_bytes_used.clone(),
        );

        // Initialize compute metrics
        let compute_cpu_seconds = Family::<ResourceLabels, Counter>::default();
        registry.register(
            "compute_cpu_seconds",
            "Total CPU seconds consumed",
            compute_cpu_seconds.clone(),
        );

        // Initialize bandwidth metrics
        let bandwidth_bytes_total = Family::<ResourceLabels, Counter>::default();
        registry.register(
            "bandwidth_bytes",
            "Total bandwidth bytes transferred",
            bandwidth_bytes_total.clone(),
        );

        // Initialize payment metrics
        let payment_transactions_total = Family::<PaymentLabels, Counter>::default();
        registry.register(
            "payment_transactions",
            "Total number of payment transactions",
            payment_transactions_total.clone(),
        );

        // Initialize escrow metrics
        let escrow_active_count = Gauge::default();
        registry.register(
            "escrow_active_count",
            "Number of active escrow contracts",
            escrow_active_count.clone(),
        );

        // Initialize session duration histogram
        let session_duration_seconds = Histogram::new(
            [0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0, 600.0].into_iter()
        );
        registry.register(
            "session_duration_seconds",
            "Distribution of session durations",
            session_duration_seconds.clone(),
        );

        Self {
            registry,
            inference_tokens_total,
            storage_bytes_used,
            compute_cpu_seconds,
            bandwidth_bytes_total,
            payment_transactions_total,
            escrow_active_count,
            session_duration_seconds,
        }
    }

    /// Record inference tokens.
    pub fn record_inference_tokens(&self, consumer: &str, provider: &str, tokens: u64) {
        let labels = ResourceLabels {
            resource_type: "inference".to_string(),
            consumer: consumer.to_string(),
            provider: provider.to_string(),
        };
        self.inference_tokens_total.get_or_create(&labels).inc_by(tokens);
    }

    /// Record storage usage.
    pub fn record_storage_bytes(&self, consumer: &str, provider: &str, bytes: i64) {
        let labels = ResourceLabels {
            resource_type: "storage".to_string(),
            consumer: consumer.to_string(),
            provider: provider.to_string(),
        };
        self.storage_bytes_used.get_or_create(&labels).set(bytes);
    }

    /// Record CPU seconds.
    pub fn record_compute_cpu_seconds(&self, consumer: &str, provider: &str, seconds: f64) {
        let labels = ResourceLabels {
            resource_type: "compute".to_string(),
            consumer: consumer.to_string(),
            provider: provider.to_string(),
        };
        // Convert to microseconds for integer counter
        self.compute_cpu_seconds.get_or_create(&labels).inc_by((seconds * 1_000_000.0) as u64);
    }

    /// Record bandwidth usage.
    pub fn record_bandwidth_bytes(&self, consumer: &str, provider: &str, bytes: u64) {
        let labels = ResourceLabels {
            resource_type: "bandwidth".to_string(),
            consumer: consumer.to_string(),
            provider: provider.to_string(),
        };
        self.bandwidth_bytes_total.get_or_create(&labels).inc_by(bytes);
    }

    /// Record a payment transaction.
    pub fn record_payment_transaction(&self, from: &str, to: &str) {
        let labels = PaymentLabels {
            from: from.to_string(),
            to: to.to_string(),
        };
        self.payment_transactions_total.get_or_create(&labels).inc();
    }

    /// Update active escrow count.
    pub fn set_escrow_active_count(&self, count: i64) {
        self.escrow_active_count.set(count);
    }

    /// Record session duration.
    pub fn record_session_duration(&self, duration_secs: f64) {
        self.session_duration_seconds.observe(duration_secs);
    }

    /// Encode metrics in Prometheus text format.
    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        encode(&mut buffer, &self.registry).unwrap_or_default();
        buffer
    }
}

impl Default for ResourceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Global metrics instance.
static METRICS: once_cell::sync::Lazy<Arc<ResourceMetrics>> =
    once_cell::sync::Lazy::new(|| Arc::new(ResourceMetrics::new()));

/// Get the global metrics instance.
pub fn global_metrics() -> Arc<ResourceMetrics> {
    METRICS.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = ResourceMetrics::new();
        assert!(!metrics.encode().is_empty());
    }

    #[test]
    fn test_record_inference_tokens() {
        let metrics = ResourceMetrics::new();
        metrics.record_inference_tokens("consumer1", "provider1", 100);
        metrics.record_inference_tokens("consumer1", "provider1", 50);

        let output = metrics.encode();
        assert!(output.contains("inference_tokens"));
    }

    #[test]
    fn test_record_storage_bytes() {
        let metrics = ResourceMetrics::new();
        metrics.record_storage_bytes("consumer1", "provider1", 1024);

        let output = metrics.encode();
        assert!(output.contains("storage_bytes_used"));
    }

    #[test]
    fn test_record_compute_cpu_seconds() {
        let metrics = ResourceMetrics::new();
        metrics.record_compute_cpu_seconds("consumer1", "provider1", 1.5);

        let output = metrics.encode();
        assert!(output.contains("compute_cpu_seconds"));
    }

    #[test]
    fn test_record_bandwidth_bytes() {
        let metrics = ResourceMetrics::new();
        metrics.record_bandwidth_bytes("consumer1", "provider1", 2048);

        let output = metrics.encode();
        assert!(output.contains("bandwidth_bytes"));
    }

    #[test]
    fn test_record_payment_transaction() {
        let metrics = ResourceMetrics::new();
        metrics.record_payment_transaction("alice", "bob");

        let output = metrics.encode();
        assert!(output.contains("payment_transactions"));
    }

    #[test]
    fn test_escrow_active_count() {
        let metrics = ResourceMetrics::new();
        metrics.set_escrow_active_count(5);

        let output = metrics.encode();
        assert!(output.contains("escrow_active_count"));
    }

    #[test]
    fn test_session_duration() {
        let metrics = ResourceMetrics::new();
        metrics.record_session_duration(10.5);
        metrics.record_session_duration(25.0);

        let output = metrics.encode();
        assert!(output.contains("session_duration_seconds"));
    }
}
