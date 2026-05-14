//! gRPC API implementation.
//!
//! Provides high-performance gRPC services for:
//! - Node registration and management
//! - Resource queries and metering
//! - Payment operations
//! - Health checks and metrics

use async_trait::async_trait;
use tonic::{Request, Response};

// Re-export generated protobuf code
pub use crate::generated::*;

// Import tonic::Status for use in trait signatures
use tonic::Status as TonicStatus;

/// Service trait implementations
pub mod services {
    use super::*;

    /// Node service implementation trait
    #[async_trait]
    pub trait NodeServiceImpl: Send + Sync + 'static {
        /// Register a new node
        async fn register(
            &self,
            request: Request<RegisterRequest>,
        ) -> Result<Response<RegisterResponse>, TonicStatus>;

        /// Update node information
        async fn update_node(
            &self,
            request: Request<UpdateNodeRequest>,
        ) -> Result<Response<Node>, TonicStatus>;

        /// Get node by ID
        async fn get_node(
            &self,
            request: Request<GetNodeRequest>,
        ) -> Result<Response<Node>, TonicStatus>;

        /// List all nodes
        async fn list_nodes(
            &self,
            request: Request<ListNodesRequest>,
        ) -> Result<Response<ListNodesResponse>, TonicStatus>;

        /// Delete a node
        async fn delete_node(
            &self,
            request: Request<DeleteNodeRequest>,
        ) -> Result<Response<Status>, TonicStatus>;

        /// Node heartbeat
        async fn heartbeat(
            &self,
            request: Request<HeartbeatRequest>,
        ) -> Result<Response<Status>, TonicStatus>;

        /// Get peers for a node
        async fn get_peers(
            &self,
            request: Request<GetPeersRequest>,
        ) -> Result<Response<GetPeersResponse>, TonicStatus>;
    }

    /// Resource service implementation trait
    #[async_trait]
    pub trait ResourceServiceImpl: Send + Sync + 'static {
        /// Register a resource capability
        async fn register_resource(
            &self,
            request: Request<RegisterResourceRequest>,
        ) -> Result<Response<Status>, TonicStatus>;

        /// Query available resources
        async fn query_resources(
            &self,
            request: Request<QueryResourcesRequest>,
        ) -> Result<Response<QueryResourcesResponse>, TonicStatus>;

        /// Get resource usage
        async fn get_usage(
            &self,
            request: Request<GetUsageRequest>,
        ) -> Result<Response<GetUsageResponse>, TonicStatus>;

        /// Record resource usage
        async fn record_usage(
            &self,
            request: Request<RecordUsageRequest>,
        ) -> Result<Response<Status>, TonicStatus>;

        /// Get resource pricing
        async fn get_pricing(
            &self,
            request: Request<GetPricingRequest>,
        ) -> Result<Response<GetPricingResponse>, TonicStatus>;
    }

    /// Payment service implementation trait
    #[async_trait]
    pub trait PaymentServiceImpl: Send + Sync + 'static {
        /// Get account balance
        async fn get_balance(
            &self,
            request: Request<GetBalanceRequest>,
        ) -> Result<Response<GetBalanceResponse>, TonicStatus>;

        /// Deposit funds
        async fn deposit(
            &self,
            request: Request<DepositRequest>,
        ) -> Result<Response<Transaction>, TonicStatus>;

        /// Transfer between accounts
        async fn transfer(
            &self,
            request: Request<TransferRequest>,
        ) -> Result<Response<Transaction>, TonicStatus>;

        /// Get transaction history
        async fn get_history(
            &self,
            request: Request<GetHistoryRequest>,
        ) -> Result<Response<GetHistoryResponse>, TonicStatus>;

        /// Set credit limit
        async fn set_credit_limit(
            &self,
            request: Request<SetCreditLimitRequest>,
        ) -> Result<Response<Status>, TonicStatus>;

        /// Create payment channel
        async fn create_channel(
            &self,
            request: Request<CreateChannelRequest>,
        ) -> Result<Response<PaymentChannel>, TonicStatus>;

        /// Update payment channel
        async fn update_channel(
            &self,
            request: Request<UpdateChannelRequest>,
        ) -> Result<Response<PaymentChannel>, TonicStatus>;

        /// Close payment channel
        async fn close_channel(
            &self,
            request: Request<CloseChannelRequest>,
        ) -> Result<Response<Status>, TonicStatus>;

        /// Get payment channels
        async fn get_channels(
            &self,
            request: Request<GetChannelsRequest>,
        ) -> Result<Response<GetChannelsResponse>, TonicStatus>;
    }

    /// Health service implementation trait
    #[async_trait]
    pub trait HealthServiceImpl: Send + Sync + 'static {
        /// Check service health
        async fn check(
            &self,
            request: Request<HealthCheckRequest>,
        ) -> Result<Response<HealthCheckResponse>, TonicStatus>;

        /// Get metrics
        async fn get_metrics(
            &self,
            request: Request<MetricsRequest>,
        ) -> Result<Response<MetricsResponse>, TonicStatus>;
    }
}

/// Main gRPC server struct
pub struct HeadscaleGrpc {
    // Services will be added here once we implement them
}

impl HeadscaleGrpc {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for HeadscaleGrpc {
    fn default() -> Self {
        Self::new()
    }
}
