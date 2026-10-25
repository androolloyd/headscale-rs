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
    use super::{
        CloseChannelRequest, CreateChannelRequest, DepositRequest, GetBalanceRequest,
        GetBalanceResponse, GetChannelsRequest, GetChannelsResponse, GetHistoryRequest,
        GetHistoryResponse, GetPricingRequest, GetPricingResponse, GetUsageRequest,
        GetUsageResponse, HealthCheckRequest, HealthCheckResponse, MetricsRequest, MetricsResponse,
        PaymentChannel, QueryResourcesRequest, QueryResourcesResponse, RecordUsageRequest,
        RegisterResourceRequest, Request, Response, SetCreditLimitRequest, Status, TonicStatus,
        Transaction, TransferRequest, UpdateChannelRequest, async_trait,
    };

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

/// Upstream `headscale.v1.HeadscaleService` implementation slices.
///
/// The upstream public service is deliberately narrow: user, pre-auth-key,
/// node/debug, auth, API-key, policy, and health RPCs. Route approval lives on
/// the node `SetApprovedRoutes` RPC, and version stays on the public HTTP
/// `/version` endpoint rather than gRPC.
#[cfg(feature = "admin")]
pub mod upstream {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::Utc;
    use parking_lot::Mutex;
    use prost::Message as _;
    use prost_types::FileDescriptorSet;
    use tonic::{Request, Response, Status, metadata::MetadataMap};

    use crate::admin::{
        ApiKeyAdmin, ApiKeyAdminError, ApiKeyAdminKey, ApiKeyMintRequest, MachineAdmin,
        MachineAdminError, MachineAdminMutation, MachineAdminRecord, MachineAdminView,
        PreauthAdmin, PreauthAdminError, PreauthAdminKey, PreauthAdminKeyView, PreauthMintRequest,
        UserAdmin, UserRecord, UserRegistry, UserRegistryError,
    };
    use crate::generated::headscale_service_server::{HeadscaleService, HeadscaleServiceServer};
    use crate::generated::{
        ApiKey, AuthApproveRequest, AuthApproveResponse, AuthRegisterRequest, AuthRegisterResponse,
        AuthRejectRequest, AuthRejectResponse, BackfillNodeIPsRequest, BackfillNodeIPsResponse,
        CheckPolicyRequest, CheckPolicyResponse, CreateApiKeyRequest, CreateApiKeyResponse,
        CreatePreAuthKeyRequest, CreatePreAuthKeyResponse, CreateUserRequest, CreateUserResponse,
        DebugCreateNodeRequest, DebugCreateNodeResponse, DeleteApiKeyRequest, DeleteApiKeyResponse,
        DeleteNodeRequest, DeleteNodeResponse, DeletePreAuthKeyRequest, DeletePreAuthKeyResponse,
        DeleteUserRequest, DeleteUserResponse, ExpireApiKeyRequest, ExpireApiKeyResponse,
        ExpireNodeRequest, ExpireNodeResponse, ExpirePreAuthKeyRequest, ExpirePreAuthKeyResponse,
        GetNodeRequest, GetNodeResponse, GetPolicyRequest, GetPolicyResponse, HealthRequest,
        HealthResponse, ListApiKeysRequest, ListApiKeysResponse, ListNodesRequest,
        ListNodesResponse, ListPreAuthKeysRequest, ListPreAuthKeysResponse, ListUsersRequest,
        ListUsersResponse, Node, PreAuthKey, RegisterMethod, RegisterNodeRequest,
        RegisterNodeResponse, RenameNodeRequest, RenameNodeResponse, RenameUserRequest,
        RenameUserResponse, SetApprovedRoutesRequest, SetApprovedRoutesResponse, SetPolicyRequest,
        SetPolicyResponse, SetTagsRequest, SetTagsResponse, User as ProtoUser,
    };
    use crate::policy::{
        PolicyCheckNodeSnapshot, PolicyDoc, PolicyParseError, PolicyStore, PolicyUser,
        check_policy_semantics_for_snapshot, compile_policy_for_snapshot,
        warn_policy_tests_at_boot_for_snapshot,
    };
    use crate::tailscale_wire::routes::{
        PrimaryRouteState, active_approved_routes, active_exit_routes, normalize_advertised_routes,
        normalize_routes,
    };
    use crate::tailscale_wire::wire::{ZERO_DISCO_KEY, stable_id_from_key};
    use crate::tailscale_wire::{IpAllocator, MachineRecord, MachineRegistry};

    const AUTH_PREFIX: &str = "Bearer ";
    const GO_ZERO_TIME_UNIX_SECONDS: i64 = -62_135_596_800;
    const PREAUTH_NEVER_EXPIRES_AT: u64 = i64::MAX as u64;
    const PUBLIC_HEADSCALE_SERVICE_NAME: &str = "headscale.v1.HeadscaleService";
    const PUBLIC_HEADSCALE_DESCRIPTOR_FILES: &[&str] = &[
        "apikey.proto",
        "auth.proto",
        "google/api/annotations.proto",
        "google/api/http.proto",
        "google/protobuf/descriptor.proto",
        "google/protobuf/timestamp.proto",
        "headscale.proto",
        "node.proto",
        "policy.proto",
        "preauthkey.proto",
        "user.proto",
    ];
    const PUBLIC_HEADSCALE_DESCRIPTOR_RENAMES: &[(&str, &str)] = &[
        ("apikey.proto", "headscale/v1/apikey.proto"),
        ("auth.proto", "headscale/v1/auth.proto"),
        ("headscale.proto", "headscale/v1/headscale.proto"),
        ("node.proto", "headscale/v1/node.proto"),
        ("policy.proto", "headscale/v1/policy.proto"),
        ("preauthkey.proto", "headscale/v1/preauthkey.proto"),
        ("user.proto", "headscale/v1/user.proto"),
    ];

    #[derive(Clone)]
    pub struct HeadscaleAdminService {
        users: Arc<dyn UserAdmin>,
        api_keys: Arc<dyn ApiKeyAdmin>,
        preauth: Arc<dyn PreauthAdmin>,
        policy: PolicyStore,
        machines: Arc<dyn MachineAdmin>,
        database_health: Option<Arc<dyn DatabaseHealthCheck>>,
        policy_persistence: Option<Arc<dyn PolicyPersistence>>,
        policy_mode: PolicyMode,
        registration_cache: Arc<crate::tailscale_wire::RegistrationCache>,
        wire_registry: Option<Arc<MachineRegistry>>,
        ip_allocator: Option<Arc<dyn IpAllocator>>,
        primary_routes: Arc<Mutex<PrimaryRouteState>>,
        require_api_key_auth: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PolicyMode {
        Memory,
        Database,
        File { path: PathBuf },
        Unsupported { mode: String },
    }

    #[async_trait]
    pub trait DatabaseHealthCheck: Send + Sync {
        async fn ping(&self) -> Result<(), String>;
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PersistedPolicy {
        pub policy: String,
        pub updated_at: i64,
    }

    #[async_trait]
    pub trait PolicyPersistence: Send + Sync {
        async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String>;
        async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String>;

        // Existing custom backends retain their whole-second contract. Native
        // pools override these methods without changing PersistedPolicy fields.
        async fn get_latest_policy_with_timestamp(
            &self,
        ) -> Result<Option<(PersistedPolicy, prost_types::Timestamp)>, String> {
            self.get_latest_policy().await.map(|policy| {
                policy.map(|policy| {
                    let updated_at = unix_to_timestamp(policy.updated_at);
                    (policy, updated_at)
                })
            })
        }

        async fn set_policy_with_timestamp(
            &self,
            policy: &str,
        ) -> Result<(PersistedPolicy, prost_types::Timestamp), String> {
            self.set_policy(policy).await.map(|policy| {
                let updated_at = unix_to_timestamp(policy.updated_at);
                (policy, updated_at)
            })
        }
    }

    fn policy_with_timestamp(
        value: headscale_db::policies::TimedPolicyRow,
    ) -> (PersistedPolicy, prost_types::Timestamp) {
        let updated_at = value.updated_at_datetime().map_or_else(
            || unix_to_timestamp(value.row.updated_at),
            datetime_to_timestamp,
        );
        (
            PersistedPolicy {
                policy: value.row.data,
                updated_at: value.row.updated_at,
            },
            updated_at,
        )
    }

    #[cfg(feature = "admin")]
    #[async_trait]
    impl DatabaseHealthCheck for sqlx::SqlitePool {
        async fn ping(&self) -> Result<(), String> {
            sqlx::query("SELECT 1")
                .execute(self)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    }

    #[cfg(all(feature = "admin", feature = "postgres-sqlx"))]
    #[async_trait]
    impl DatabaseHealthCheck for sqlx::PgPool {
        async fn ping(&self) -> Result<(), String> {
            headscale_db::check_postgres_health(self)
                .await
                .map_err(|e| e.to_string())
        }
    }

    #[cfg(feature = "admin")]
    #[async_trait]
    impl PolicyPersistence for sqlx::SqlitePool {
        async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String> {
            self.get_latest_policy_with_timestamp()
                .await
                .map(|value| value.map(|(policy, _)| policy))
        }

        async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String> {
            self.set_policy_with_timestamp(policy)
                .await
                .map(|(policy, _)| policy)
        }

        async fn get_latest_policy_with_timestamp(
            &self,
        ) -> Result<Option<(PersistedPolicy, prost_types::Timestamp)>, String> {
            headscale_db::policies::get_latest_with_timestamp(self)
                .await
                .map(|value| value.map(policy_with_timestamp))
                .map_err(|error| error.to_string())
        }

        async fn set_policy_with_timestamp(
            &self,
            policy: &str,
        ) -> Result<(PersistedPolicy, prost_types::Timestamp), String> {
            headscale_db::policies::set_with_timestamp(self, policy)
                .await
                .map(policy_with_timestamp)
                .map_err(|error| error.to_string())
        }
    }

    #[cfg(all(feature = "admin", feature = "postgres-sqlx"))]
    #[async_trait]
    impl PolicyPersistence for sqlx::PgPool {
        async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String> {
            self.get_latest_policy_with_timestamp()
                .await
                .map(|value| value.map(|(policy, _)| policy))
        }

        async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String> {
            self.set_policy_with_timestamp(policy)
                .await
                .map(|(policy, _)| policy)
        }

        async fn get_latest_policy_with_timestamp(
            &self,
        ) -> Result<Option<(PersistedPolicy, prost_types::Timestamp)>, String> {
            headscale_db::policies::get_latest_postgres_with_timestamp(self)
                .await
                .map(|value| value.map(policy_with_timestamp))
                .map_err(|error| error.to_string())
        }

        async fn set_policy_with_timestamp(
            &self,
            policy: &str,
        ) -> Result<(PersistedPolicy, prost_types::Timestamp), String> {
            headscale_db::policies::set_postgres_with_timestamp(self, policy)
                .await
                .map(policy_with_timestamp)
                .map_err(|error| error.to_string())
        }
    }

    impl HeadscaleAdminService {
        pub fn new(
            users: UserRegistry,
            api_keys: Arc<dyn ApiKeyAdmin>,
            preauth: Arc<dyn PreauthAdmin>,
            policy: PolicyStore,
            machines: Arc<dyn MachineAdmin>,
        ) -> Self {
            Self::with_user_admin(Arc::new(users), api_keys, preauth, policy, machines)
        }

        pub fn with_user_admin(
            users: Arc<dyn UserAdmin>,
            api_keys: Arc<dyn ApiKeyAdmin>,
            preauth: Arc<dyn PreauthAdmin>,
            policy: PolicyStore,
            machines: Arc<dyn MachineAdmin>,
        ) -> Self {
            Self {
                users,
                api_keys,
                preauth,
                policy,
                machines,
                database_health: None,
                policy_persistence: None,
                policy_mode: PolicyMode::Memory,
                registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
                wire_registry: None,
                ip_allocator: None,
                primary_routes: Arc::new(Mutex::new(PrimaryRouteState::new())),
                require_api_key_auth: false,
            }
        }

        pub fn with_database_health(
            mut self,
            database_health: Arc<dyn DatabaseHealthCheck>,
        ) -> Self {
            self.database_health = Some(database_health);
            self
        }

        #[cfg(feature = "admin")]
        pub fn with_database_pool(self, pool: sqlx::SqlitePool) -> Self {
            self.with_database_health(Arc::new(pool))
        }

        #[cfg(all(feature = "admin", feature = "postgres-sqlx"))]
        pub fn with_postgres_database_pool(self, pool: sqlx::PgPool) -> Self {
            self.with_database_health(Arc::new(pool))
        }

        pub fn with_policy_persistence(
            mut self,
            policy_persistence: Arc<dyn PolicyPersistence>,
        ) -> Self {
            let debug_persistence = policy_persistence.clone();
            self.policy.set_debug_source(move || {
                let persistence = debug_persistence.clone();
                async move {
                    persistence
                        .get_latest_policy()
                        .await?
                        .map(|policy| policy.policy.into_bytes())
                        .ok_or_else(|| "acl policy not found".to_owned())
                }
            });
            self.policy_persistence = Some(policy_persistence);
            self.policy_mode = PolicyMode::Database;
            self
        }

        #[cfg(feature = "admin")]
        pub fn with_policy_pool(self, pool: sqlx::SqlitePool) -> Self {
            self.with_policy_persistence(Arc::new(pool))
        }

        #[cfg(all(feature = "admin", feature = "postgres-sqlx"))]
        pub fn with_postgres_policy_pool(self, pool: sqlx::PgPool) -> Self {
            self.with_policy_persistence(Arc::new(pool))
        }

        pub fn with_policy_file(mut self, path: impl Into<PathBuf>) -> Self {
            let path = path.into();
            let debug_path = path.clone();
            self.policy.set_debug_source(move || {
                let path = debug_path.clone();
                async move {
                    if path.as_os_str().is_empty() {
                        return Ok(Vec::new());
                    }
                    tokio::fs::read(&path).await.map_err(|error| {
                        format!("reading policy from path {}: {error}", path.display())
                    })
                }
            });
            self.policy_mode = PolicyMode::File { path };
            self
        }

        pub fn with_unsupported_policy_mode(mut self, mode: impl Into<String>) -> Self {
            let mode = mode.into();
            let debug_mode = mode.clone();
            self.policy.set_debug_source(move || {
                let mode = debug_mode.clone();
                async move { Err(format!("unsupported policy mode: {mode}")) }
            });
            self.policy_mode = PolicyMode::Unsupported { mode };
            self
        }

        #[cfg(test)]
        pub(crate) fn policy_for_test(&self) -> &PolicyStore {
            &self.policy
        }

        pub async fn load_policy_from_persistence(&self) -> Result<bool, Status> {
            let guard = self.policy.lock_mutation().await;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                let _guard = guard;
                service.load_policy_from_persistence_inner().await
            })
            .await
            .map_err(|error| Status::internal(format!("finishing policy load: {error}")))?
        }

        async fn load_policy_from_persistence_inner(&self) -> Result<bool, Status> {
            let Some(policy_persistence) = &self.policy_persistence else {
                return Ok(false);
            };
            let Some(policy) = policy_persistence
                .get_latest_policy()
                .await
                .map_err(|e| Status::unknown(format!("loading policy from database: {e}")))?
            else {
                return Ok(false);
            };
            if policy.policy.is_empty() {
                return Ok(false);
            }
            // Same native decoder as set/check/file reload, so a stored policy
            // that Go accepts is never rejected by a narrower admin-path parser.
            let (mut doc, source) = crate::policy::parse_hujson_policy_bytes(
                policy.policy.as_bytes(),
            )
            .map_err(|e| {
                Status::invalid_argument(format!(
                    "loading policy from database: {}",
                    native_policy_parse_error(e)
                ))
            })?;
            self.validate_candidate_policy(&mut doc, &source, "reloading policy")
                .await?;
            self.policy
                .try_set_at_quiet(doc, policy.policy, policy.updated_at)
                .map_err(|error| Status::invalid_argument(format!("reloading policy: {error}")))?;
            Ok(true)
        }

        /// Reload the configured policy source and fan out route/policy changes.
        ///
        /// This is the production v0.29.5 SIGHUP path. The result reports
        /// whether nonempty policy bytes were loaded. A successful configured
        /// reload still invalidates SSH approvals and rechecks routes when
        /// those bytes are empty or the database has no policy row.
        pub async fn reload_policy_from_config(&self) -> Result<bool, Status> {
            let guard = self.policy.lock_mutation().await;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                let _guard = guard;
                service.reload_policy_from_config_inner().await
            })
            .await
            .map_err(|error| Status::internal(format!("finishing policy reload: {error}")))?
        }

        async fn reload_policy_from_config_inner(&self) -> Result<bool, Status> {
            let reload_requested = matches!(
                &self.policy_mode,
                PolicyMode::File { .. } | PolicyMode::Database | PolicyMode::Unsupported { .. }
            );
            let loaded = match &self.policy_mode {
                PolicyMode::File { path } => {
                    if path.as_os_str().is_empty() {
                        return Ok(false);
                    }
                    let original = tokio::fs::read(path).await.map_err(|e| {
                        Status::unknown(format!("reloading policy file {}: {e}", path.display()))
                    })?;
                    if original.is_empty() {
                        false
                    } else {
                        let (mut doc, raw) = crate::policy::parse_hujson_policy_bytes(&original)
                            .map_err(|e| {
                                Status::invalid_argument(format!(
                                    "reloading policy file {}: {e}",
                                    path.display()
                                ))
                            })?;
                        self.validate_candidate_policy(&mut doc, &raw, "reloading policy")
                            .await?;
                        self.policy
                            .try_set_bytes_quiet(doc, original, raw)
                            .map_err(|error| {
                                Status::invalid_argument(format!("reloading policy: {error}"))
                            })?;
                        true
                    }
                }
                PolicyMode::Database => self.load_policy_from_persistence_inner().await?,
                PolicyMode::Memory | PolicyMode::Unsupported { .. } => false,
            };

            if reload_requested {
                if !loaded {
                    self.policy.invalidate_ssh_auth();
                }
                self.registration_cache.clear_ssh_auth();
                crate::admin::machines::apply_policy_auto_approvals(
                    &self.policy,
                    self.machines.as_ref(),
                )
                .await
                .map_err(machine_error_to_status)?;
                self.policy.notify_change();
            }

            Ok(loaded)
        }

        pub async fn authorize_api_key_metadata(
            &self,
            metadata: &MetadataMap,
        ) -> Result<(), Status> {
            if !self.require_api_key_auth {
                return Ok(());
            }
            let token = bearer_token(metadata)?.to_string();
            match self.api_keys.validate_for_state(&token).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(Status::unauthenticated("invalid token")),
                Err(_) => Err(Status::internal("validating token")),
            }
        }

        pub fn require_api_key_auth(mut self) -> Self {
            self.require_api_key_auth = true;
            self
        }

        pub fn with_registration_cache(
            mut self,
            registration_cache: Arc<crate::tailscale_wire::RegistrationCache>,
        ) -> Self {
            self.registration_cache = registration_cache;
            self
        }

        pub fn with_wire_registry(mut self, wire_registry: Arc<MachineRegistry>) -> Self {
            wire_registry.configure_policy(&self.policy);
            if let Some(allocator) = &self.ip_allocator {
                wire_registry.configure_ip_allocator(allocator);
            }
            self.wire_registry = Some(wire_registry);
            self
        }

        async fn node_proto(
            &self,
            machine: &MachineAdminRecord,
            subnet_routes: &[String],
            for_list: bool,
        ) -> Result<Node, Status> {
            let view = self
                .machines
                .get_view(&self.machines.mutation_selector(machine))
                .await
                .map_err(machine_error_to_status)?
                .unwrap_or_else(|| MachineAdminView::from_record(machine.clone()));
            self.node_view_proto(&view, subnet_routes, for_list).await
        }

        async fn node_view_proto(
            &self,
            view: &MachineAdminView,
            subnet_routes: &[String],
            for_list: bool,
        ) -> Result<Node, Status> {
            let mut node = machine_to_node_with_routes_and_user(
                &view.record,
                &self.users,
                &self.preauth,
                subnet_routes,
                view.associations.user.clone(),
                view.associations.auth_key.clone(),
            )
            .await?;
            node.name.clone_from(&view.raw_hostname);
            if for_list && !view.record.tags.is_empty() {
                node.user = Some(tagged_devices_user_to_proto());
            }
            Ok(node)
        }

        pub fn with_ip_allocator(mut self, ip_allocator: Arc<dyn IpAllocator>) -> Self {
            if let Some(registry) = &self.wire_registry {
                registry.configure_ip_allocator(&ip_allocator);
            }
            self.ip_allocator = Some(ip_allocator);
            self
        }

        fn notify_user_removed_full_update(&self) {
            if let Some(registry) = &self.wire_registry {
                registry.wake_user_removed_full_update();
            } else if !self.machines.notify_user_removed_full_update() {
                self.policy.refresh();
            }
        }

        pub fn into_service_server(self) -> HeadscaleServiceServer<Self> {
            HeadscaleServiceServer::new(self)
        }

        pub fn into_authenticated_service_server(self) -> HeadscaleServiceServer<Self> {
            self.require_api_key_auth().into_service_server()
        }

        pub fn reflection_service() -> Result<
            tonic_reflection::server::v1::ServerReflectionServer<
                impl tonic_reflection::server::v1::ServerReflection,
            >,
            tonic_reflection::server::Error,
        > {
            tonic_reflection::server::Builder::configure()
                .register_file_descriptor_set(Self::public_file_descriptor_set()?)
                .with_service_name(PUBLIC_HEADSCALE_SERVICE_NAME)
                .build_v1()
        }

        pub fn public_file_descriptor_set()
        -> Result<FileDescriptorSet, tonic_reflection::server::Error> {
            let mut descriptors = FileDescriptorSet::decode(crate::generated::FILE_DESCRIPTOR_SET)?;
            descriptors.file.retain(|file| {
                file.name
                    .as_deref()
                    .is_some_and(|name| PUBLIC_HEADSCALE_DESCRIPTOR_FILES.contains(&name))
            });
            for file in &mut descriptors.file {
                if let Some(name) = file
                    .name
                    .as_deref()
                    .and_then(upstream_public_descriptor_name)
                {
                    file.name = Some(name.to_string());
                }
                for dependency in &mut file.dependency {
                    if let Some(name) = upstream_public_descriptor_name(dependency) {
                        *dependency = name.to_string();
                    }
                }
            }

            let has_headscale_service = descriptors.file.iter().any(|file| {
                file.package.as_deref() == Some("headscale.v1")
                    && file
                        .service
                        .iter()
                        .any(|service| service.name.as_deref() == Some("HeadscaleService"))
            });
            if !has_headscale_service {
                return Err(tonic_reflection::server::Error::InvalidFileDescriptorSet(
                    format!("{PUBLIC_HEADSCALE_SERVICE_NAME} missing from descriptor set"),
                ));
            }

            Ok(descriptors)
        }

        async fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
            self.authorize_api_key_metadata(request.metadata()).await
        }

        async fn machine_view_by_id(&self, node_id: u64) -> Result<MachineAdminView, Status> {
            if let Some(view) = self
                .machines
                .get_view(&node_id.to_string())
                .await
                .map_err(machine_error_to_status)?
                && machine_numeric_id(&view.record) == node_id
            {
                return Ok(view);
            }
            self.machines
                .list_views()
                .await
                .map_err(machine_error_to_status)?
                .into_iter()
                .find(|view| machine_numeric_id(&view.record) == node_id)
                .ok_or_else(|| Status::not_found("node not found"))
        }

        async fn node_mutation_selector(&self, node_id: u64) -> Result<String, Status> {
            if let Some(selector) = self.machines.numeric_mutation_selector(node_id) {
                return Ok(selector);
            }
            self.machine_by_id(node_id)
                .await
                .map(|record| self.machines.mutation_selector(&record))
        }

        async fn machine_by_id(&self, node_id: u64) -> Result<MachineAdminRecord, Status> {
            self.machine_view_by_id(node_id)
                .await
                .map(|view| view.record)
        }

        async fn refresh_policy_users(&self) -> Result<crate::policy::PolicyUserChange, String> {
            let identities = self
                .users
                .policy_users()
                .await
                .map_err(|error| error.to_string())?;
            self.policy.set_users_with_change_quiet(identities)
        }

        async fn validate_candidate_policy(
            &self,
            doc: &mut PolicyDoc,
            raw: &str,
            context: &str,
        ) -> Result<(), Status> {
            // Set/reload use the directory retained by the live manager.
            // CheckPolicy supplies its separately loaded sandbox directory.
            let identities = self.policy.users_snapshot();
            Self::validate_candidate_policy_users(doc, raw, context, identities)?;
            let nodes = self
                .machines
                .policy_nodes_for_check()
                .await
                .map_err(machine_error_to_status)?;
            Self::validate_candidate_policy_nodes(doc, raw, context, &nodes)
        }

        fn validate_candidate_policy_users(
            doc: &mut PolicyDoc,
            raw: &str,
            context: &str,
            mut identities: Vec<PolicyUser>,
        ) -> Result<(), Status> {
            identities.sort_by_key(|user| user.id);
            crate::policy::validate_policy_user_references_for_source(doc, raw, &identities)
                .map_err(|error| {
                    let message = format!("validating policy user references: {error}");
                    if context == "setting policy" {
                        Status::unknown(format!("{context}: {message}"))
                    } else {
                        Status::invalid_argument(message)
                    }
                })?;
            doc.users = Some(identities);
            Ok(())
        }

        fn validate_candidate_policy_nodes(
            doc: &PolicyDoc,
            raw: &str,
            context: &str,
            nodes: &[PolicyCheckNodeSnapshot],
        ) -> Result<(), Status> {
            if context == "checking policy" {
                // CheckPolicy constructs an isolated manager before its
                // SetPolicy test pass. Constructor errors take precedence
                // over failed assertions; the live store is never changed.
                compile_policy_for_snapshot(doc, raw, nodes).map_err(Status::invalid_argument)?;
                // NewPolicyManager warns after constructor compilation, even
                // when the following sandbox SetPolicy rejects its tests.
                warn_policy_tests_at_boot_for_snapshot(doc, raw, nodes);
            }
            check_policy_semantics_for_snapshot(doc, raw, nodes).map_err(|error| {
                if context == "setting policy" {
                    Status::unknown(format!("{context}: {error}"))
                } else if context == "checking policy" {
                    Status::invalid_argument(error)
                } else {
                    Status::invalid_argument(format!("{context}: {error}"))
                }
            })
        }

        async fn user_by_stored_name(&self, name: &str) -> Result<UserRecord, Status> {
            let identities = self
                .users
                .policy_users()
                .await
                .map_err(user_lookup_error_to_unknown)?;
            // Gorm ignores a zero Name field in its struct WHERE predicate.
            let mut matching = identities
                .into_iter()
                .filter(|user| name.is_empty() || user.name == name);
            let first = matching.next().ok_or_else(upstream_user_not_found_status)?;
            let count = 1 + matching.count();
            if count != 1 {
                return Err(Status::unknown(format!(
                    "expected exactly one user, found {count}"
                )));
            }
            let mut user = self
                .users
                .get_by_id(first.id)
                .await
                .map_err(user_lookup_error_to_unknown)?
                .ok_or_else(upstream_user_not_found_status)?;
            user.name = first.name;
            Ok(user)
        }

        async fn prepare_registration_addresses(
            &self,
            record: &mut MachineAdminRecord,
        ) -> Result<(), Status> {
            crate::admin::machines::prepare_auth_path_addresses(
                self.machines.as_ref(),
                self.ip_allocator.as_deref(),
                &self.policy,
                record,
            )
            .await
            .map_err(|error| match error {
                crate::admin::machines::AuthPathAddressError::Selection(error) => {
                    machine_error_to_status(error)
                }
                crate::admin::machines::AuthPathAddressError::Tags(error) => {
                    Status::invalid_argument(error)
                }
                crate::admin::machines::AuthPathAddressError::Allocation(error) => {
                    Status::internal(error)
                }
            })
        }

        async fn unique_node_key(&self) -> Result<String, Status> {
            loop {
                let node_key = random_key_hex()?;
                if self.machines.get(&node_key).await.is_none()
                    && !self.registration_cache.contains_node_key(&node_key)
                {
                    return Ok(node_key);
                }
            }
        }

        /// `State.AutoApproveRoutes` for a node registered through the CLI path.
        async fn auto_approve_registered_node(
            &self,
            node: &MachineAdminRecord,
        ) -> Result<(), MachineAdminError> {
            crate::admin::machines::auto_approve_registered_node(
                self.machines.as_ref(),
                &self.policy,
                self.wire_registry.as_deref(),
                node,
            )
            .await
        }

        async fn register_node_body(
            &self,
            body: RegisterNodeRequest,
        ) -> Result<RegisterNodeResponse, Status> {
            let registration_id = registration_cache_key_from_register_key(&body.key)?;
            let selected_user = self
                .users
                .get_for_registration_by_name(&body.user)
                .await
                .map_err(|error| {
                    let status = user_lookup_error_to_unknown(error);
                    Status::unknown(format!("looking up user: {}", status.message()))
                })?
                .ok_or_else(|| Status::unknown("looking up user: user not found"))?;
            let selected_user_id = selected_user.user.id;
            let (mut pending, hostinfo, completion) = match self
                .registration_cache
                .pending_registration_completion(&registration_id)
            {
                Some(pending) => pending,
                None if self.registration_cache.get(&registration_id).is_some() => {
                    return Err(Status::failed_precondition(
                        "auth request already completed",
                    ));
                }
                None => return Err(Status::unknown("node not found in registration cache")),
            };
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                // State.HandleNodeFromAuthPath resolves the numeric user after
                // the pending entry exists, before waiting for its machine lock.
                let captured_user = service
                    .users
                    .get_for_registration(selected_user_id)
                    .await
                    .map_err(|error| {
                        let status = user_lookup_error_to_unknown(error);
                        Status::unknown(format!("finding user: {}", status.message()))
                    })?
                    .ok_or_else(|| Status::unknown("finding user: user not found"))?;
                let user = captured_user.user.clone();
                let machine_key = pending.machine_key_hex.clone();
                let node_key = pending.node_key_hex.clone();
                let registration_lock =
                    match service.machines.registration_guard(&machine_key).await {
                        Some(guard) => Some(guard),
                        None => match &service.wire_registry {
                            Some(registry) => Some(registry.lock_registration(&machine_key).await),
                            None => None,
                        },
                    };
                let node_key_lock = match service
                    .machines
                    .node_key_registration_guard(&node_key)
                    .await
                {
                    Some(guard) => Some(guard),
                    None => match &service.wire_registry {
                        Some(registry) => {
                            Some(registry.lock_node_key_registration(&node_key).await)
                        }
                        None => None,
                    },
                };
                let publication_scope = service
                    .wire_registry
                    .as_ref()
                    .map(|registry| registry.registration_publication_scope(&pending));
                set_registration_user_identity(&mut pending, &user);
                let mut record = wire_record_to_machine_admin(pending.clone());
                record.user = user.name.clone();
                record.user_id = Some(user.id);
                record.register_method = RegisterMethod::Cli as i32;
                if let Some(registry) = &service.wire_registry {
                    registry
                        .validate_registration_node_key(&record.id, &record.machine_key_hex)
                        .map_err(Status::invalid_argument)?;
                }
                service.prepare_registration_addresses(&mut record).await?;

                let result = service
                    .machines
                    .complete_registration_with_user_snapshot(
                        record,
                        &service.policy,
                        Some(pending.clone()),
                        hostinfo,
                        captured_user,
                    )
                    .await
                    .map_err(machine_error_to_status)?;
                let node = result.record;
                let mut wire_record = service
                    .machines
                    .wire_record_for_publication(&node.id, service.wire_registry.as_deref())
                    .await
                    .map_err(machine_error_to_status)?
                    .unwrap_or_else(|| machine_admin_to_wire_record_with_pending(&node, &pending));
                let saved_user = service
                    .wire_registry
                    .as_ref()
                    .and_then(|registry| registry.cached_native_user(&wire_record))
                    .flatten();
                set_registration_user_identity(
                    &mut wire_record,
                    saved_user.as_ref().unwrap_or(&user),
                );
                if wire_record.is_tagged() {
                    wire_record.clear_user_identity();
                }
                if let Some(registry) = &service.wire_registry {
                    if let Some(old_node_key_hex) = result.replaced_node_key_hex.as_deref() {
                        registry
                            .try_replace_node_key_auth_completion(
                                old_node_key_hex,
                                wire_record.node_key_hex.clone(),
                                wire_record.clone(),
                            )
                            .map_err(Status::unknown)?;
                    } else {
                        registry
                            .try_upsert_auth_completion(
                                wire_record.node_key_hex.clone(),
                                wire_record.clone(),
                            )
                            .map_err(Status::unknown)?;
                    }
                }
                service
                    .registration_cache
                    .finish_registration(completion, wire_record);
                // Go answers with the NodeView returned by HandleNodeFromAuthPath,
                // i.e. the node as it was before AutoApproveRoutes ran (verified
                // against v0.29.5: RegisterNode reports empty approved_routes, a
                // following GetNode reports the auto-approved ones).
                let response = RegisterNodeResponse {
                    node: Some(service.node_proto(&node, &[], false).await?),
                };
                // Go's HandleNodeFromAuthPath releases the machine-key lock on
                // return; the approval below takes the same locks again.
                drop(publication_scope);
                drop(node_key_lock);
                drop(registration_lock);
                // grpcv1.go RegisterNode: the node is now persisted and known to
                // the policy manager, so State.AutoApproveRoutes can match the
                // owner's addresses against the autoApprovers.
                service
                    .auto_approve_registered_node(&node)
                    .await
                    .map_err(|error| {
                        Status::unknown(format!(
                            "auto approving routes: {}",
                            machine_error_to_status(error).message()
                        ))
                    })?;
                Ok(response)
            })
            .await
            .map_err(|error| Status::internal(format!("finishing node registration: {error}")))?
        }
    }

    fn upstream_public_descriptor_name(name: &str) -> Option<&'static str> {
        PUBLIC_HEADSCALE_DESCRIPTOR_RENAMES
            .iter()
            .find_map(|(from, to)| (*from == name).then_some(*to))
    }

    fn bearer_token(metadata: &MetadataMap) -> Result<&str, Status> {
        let value = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("authorization token not supplied"))?;
        let header = value
            .to_str()
            .map_err(|_| Status::unauthenticated("invalid authorization metadata"))?;
        header.strip_prefix(AUTH_PREFIX).ok_or_else(|| {
            Status::unauthenticated(r#"missing "Bearer " prefix in "Authorization" header"#)
        })
    }

    #[async_trait]
    impl HeadscaleService for HeadscaleAdminService {
        async fn create_user(
            &self,
            request: Request<CreateUserRequest>,
        ) -> Result<Response<CreateUserResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let guard = self.policy.lock_mutation().await;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                let _guard = guard;
                let user = service
                    .users
                    .create_for_state(
                        &body.name,
                        &body.display_name,
                        &body.email,
                        &body.picture_url,
                    )
                    .await
                    .map_err(|e| create_user_error_to_status(&e))?;
                service.refresh_policy_users().await.map_err(|error| {
                    Status::internal(format!(
                        "creating user: updating policy manager after user creation: {error}"
                    ))
                })?;
                service.policy.refresh();
                Ok(Response::new(CreateUserResponse {
                    user: Some(user_record_to_proto(&user)),
                }))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing user creation: {error}")))?
        }

        async fn rename_user(
            &self,
            request: Request<RenameUserRequest>,
        ) -> Result<Response<RenameUserResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let guard = self.policy.lock_mutation().await;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                let _guard = guard;
                if service
                    .users
                    .get_for_registration(body.old_id)
                    .await
                    .map_err(direct_user_error_to_status)?
                    .is_none()
                {
                    return Err(upstream_user_not_found_status());
                }
                service
                    .users
                    .rename_for_state(body.old_id, &body.new_name)
                    .await
                    .map_err(direct_user_error_to_status)?;
                let change = service.refresh_policy_users().await.map_err(|error| {
                    Status::unknown(format!(
                        "updating policy manager after user update: {error}"
                    ))
                })?;
                // Go UpdateUser refreshes the manager's account directory;
                // cached Node.User associations retain their prior projection.
                service.policy.notify_user_change(change);
                // Go performs this lookup after committing and dispatching.
                // Empty NewName is a zero struct-WHERE field: it selects all
                // users, and a failed/ambiguous lookup does not undo the write.
                let user = service
                    .users
                    .get_for_registration_by_name(&body.new_name)
                    .await
                    .map_err(direct_user_error_to_status)?
                    .ok_or_else(upstream_user_not_found_status)?
                    .user;
                Ok(Response::new(RenameUserResponse {
                    user: Some(user_record_to_proto(&user)),
                }))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing user rename: {error}")))?
        }

        async fn delete_user(
            &self,
            request: Request<DeleteUserRequest>,
        ) -> Result<Response<DeleteUserResponse>, Status> {
            self.authorize(&request).await?;
            let id = request.into_inner().id;
            let guard = self.policy.lock_mutation().await;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                let _guard = guard;
                let Some(user) = service
                    .users
                    .get_for_registration(id)
                    .await
                    .map_err(direct_user_error_to_status)?
                else {
                    return Err(upstream_user_not_found_status());
                };
                let user = user.user;
                if !service.users.checks_user_owned_nodes_in_storage()
                    && service.machines.list().await.into_iter().any(|node| {
                        node.tags.is_empty()
                            && node.user_id.map_or_else(
                                || !user.name.is_empty() && node.user == user.name,
                                |owner| owner == user.id,
                            )
                    })
                {
                    return Err(upstream_user_not_empty_status());
                }
                service
                    .users
                    .delete_by_id(id)
                    .await
                    .map_err(direct_user_error_to_status)?;
                let change = service.refresh_policy_users().await.map_err(|error| {
                    Status::unknown(format!("updating policy after user deletion: {error}"))
                })?;
                if change.policy_changed {
                    service.policy.notify_user_change(change);
                } else {
                    service.notify_user_removed_full_update();
                }
                Ok(Response::new(DeleteUserResponse {}))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing user deletion: {error}")))?
        }

        async fn list_users(
            &self,
            request: Request<ListUsersRequest>,
        ) -> Result<Response<ListUsersResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let mut users = self
                .users
                .list_for_state(&body.name, &body.email, body.id)
                .await
                .map_err(direct_user_error_to_status)?;
            users.sort_by_key(|u| u.id);
            Ok(Response::new(ListUsersResponse {
                users: users.iter().map(user_record_to_proto).collect(),
            }))
        }

        async fn create_pre_auth_key(
            &self,
            request: Request<CreatePreAuthKeyRequest>,
        ) -> Result<Response<CreatePreAuthKeyResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                for tag in &body.acl_tags {
                    validate_tag(tag)?;
                }
                if body.user == 0
                    && body.acl_tags.is_empty()
                    && !service.preauth.checks_key_owner_in_storage()
                {
                    return Err(Status::unknown(
                        "auth-key must be either tagged or owned by user",
                    ));
                }
                let user = if body.user == 0 {
                    String::new()
                } else {
                    let user = service
                        .users
                        .get_for_registration(body.user)
                        .await
                        .map_err(direct_user_error_to_status)?
                        .ok_or_else(|| Status::unknown("user not found"))?
                        .user;
                    // Native mint uses the numeric ID. Retain the established
                    // display selector for adapters taking the fallback path.
                    user_record_admin_name(&user)
                };
                let expiration = Some(match body.expiration.as_ref() {
                    Some(timestamp) => {
                        let nanos = i64::from(timestamp.nanos);
                        let seconds = timestamp
                            .seconds
                            .checked_add(nanos.div_euclid(1_000_000_000))
                            .ok_or_else(|| Status::invalid_argument("expiration out of range"))?;
                        chrono::DateTime::from_timestamp(
                            seconds,
                            nanos.rem_euclid(1_000_000_000) as u32,
                        )
                        .ok_or_else(|| Status::invalid_argument("expiration out of range"))?
                    }
                    None => chrono::DateTime::from_timestamp(GO_ZERO_TIME_UNIX_SECONDS, 0)
                        .expect("Go zero timestamp is representable"),
                });
                let mint = PreauthMintRequest {
                    user,
                    ttl_secs: 0,
                    reusable: body.reusable,
                    ephemeral: body.ephemeral,
                    tags: body.acl_tags,
                };
                let native = service
                    .preauth
                    .mint_with_user_id(
                        (body.user != 0).then_some(body.user),
                        mint.clone(),
                        expiration,
                    )
                    .await
                    .map_err(preauth_error_to_status)?;
                let key = if let Some(view) = native {
                    preauth_native_view_to_proto(&view)
                } else {
                    let created = service
                        .preauth
                        .mint_with_precise_expiration(mint, expiration)
                        .await
                        .map_err(preauth_error_to_status)?;
                    preauth_key_to_proto(&created, &service.users).await?
                };
                Ok(Response::new(CreatePreAuthKeyResponse {
                    pre_auth_key: Some(key),
                }))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing preauth key creation: {error}")))?
        }

        async fn expire_pre_auth_key(
            &self,
            request: Request<ExpirePreAuthKeyRequest>,
        ) -> Result<Response<ExpirePreAuthKeyResponse>, Status> {
            self.authorize(&request).await?;
            let id = request.into_inner().id;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                service
                    .preauth
                    .expire_by_id(id)
                    .await
                    .map_err(preauth_error_to_status)?;
                Ok(Response::new(ExpirePreAuthKeyResponse {}))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing preauth key expiry: {error}")))?
        }

        async fn delete_pre_auth_key(
            &self,
            request: Request<DeletePreAuthKeyRequest>,
        ) -> Result<Response<DeletePreAuthKeyResponse>, Status> {
            self.authorize(&request).await?;
            let id = request.into_inner().id;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                service
                    .preauth
                    .delete_by_id(id)
                    .await
                    .map_err(preauth_error_to_status)?;
                Ok(Response::new(DeletePreAuthKeyResponse {}))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing preauth key deletion: {error}")))?
        }

        async fn list_pre_auth_keys(
            &self,
            request: Request<ListPreAuthKeysRequest>,
        ) -> Result<Response<ListPreAuthKeysResponse>, Status> {
            self.authorize(&request).await?;
            let native_views = self
                .preauth
                .list_with_associations()
                .await
                .map_err(preauth_error_to_status)?;
            let mut pre_auth_keys = if let Some(views) = native_views {
                views.iter().map(preauth_native_view_to_proto).collect()
            } else {
                let keys = self
                    .preauth
                    .list_checked()
                    .await
                    .map_err(preauth_error_to_status)?;
                let mut projected = Vec::with_capacity(keys.len());
                for key in &keys {
                    projected.push(listed_preauth_key_to_proto(key, &self.users).await?);
                }
                projected
            };
            pre_auth_keys.sort_by_key(|key| key.id);
            Ok(Response::new(ListPreAuthKeysResponse { pre_auth_keys }))
        }

        async fn debug_create_node(
            &self,
            request: Request<DebugCreateNodeRequest>,
        ) -> Result<Response<DebugCreateNodeResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let user = self.user_by_stored_name(&body.user).await?;
            // Go's StringToIPPrefix preserves input order and duplicates for
            // this echo. Unlike approved routes, it adds no exit-route pair.
            let mut routes = Vec::with_capacity(body.routes.len());
            for route in &body.routes {
                routes.extend(normalize_advertised_routes([route]).map_err(Status::unknown)?);
            }
            let registration_id = registration_cache_key_from_register_key(&body.key)?;
            let node_key = self.unique_node_key().await?;
            let machine_key = random_key_hex()?;
            let zero_time = chrono::DateTime::from_timestamp(GO_ZERO_TIME_UNIX_SECONDS, 0)
                .ok_or_else(|| Status::internal("Go zero timestamp is not representable"))?;
            let mut pending = MachineRecord::new_at_with_addresses(
                Utc::now(),
                node_key.clone(),
                machine_key.clone(),
                String::new(),
                body.name.clone(),
                None,
                None,
                false,
            );
            pending.register_method = RegisterMethod::Unspecified as i32;
            pending.expiry = Some(zero_time);
            pending.replace_host_info(crate::tailscale_wire::wire::HostInfo {
                hostname: body.name.clone(),
                ..Default::default()
            });
            // Only the registration identity/name/zero expiry enter Go's
            // auth cache. TestOS and routes belong to the synthetic echo.
            self.registration_cache.insert(registration_id, pending);
            Ok(Response::new(DebugCreateNodeResponse {
                node: Some(Node {
                    id: 0,
                    node_key: prefix_key("nodekey:", &node_key),
                    machine_key: prefix_key("mkey:", &machine_key),
                    disco_key: ZERO_DISCO_KEY.to_owned(),
                    name: body.name,
                    user: Some(user_record_to_proto(&user)),
                    last_seen: Some(unix_to_timestamp(GO_ZERO_TIME_UNIX_SECONDS)),
                    expiry: Some(unix_to_timestamp(GO_ZERO_TIME_UNIX_SECONDS)),
                    created_at: Some(unix_to_timestamp(GO_ZERO_TIME_UNIX_SECONDS)),
                    available_routes: routes,
                    register_method: RegisterMethod::Unspecified as i32,
                    ..Default::default()
                }),
            }))
        }

        async fn get_node(
            &self,
            request: Request<GetNodeRequest>,
        ) -> Result<Response<GetNodeResponse>, Status> {
            self.authorize(&request).await?;
            let node = self
                .machine_view_by_id(request.into_inner().node_id)
                .await?;
            Ok(Response::new(GetNodeResponse {
                node: Some(self.node_view_proto(&node, &[], false).await?),
            }))
        }

        async fn set_tags(
            &self,
            request: Request<SetTagsRequest>,
        ) -> Result<Response<SetTagsResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            if body.tags.is_empty() {
                return Err(Status::invalid_argument(
                    "cannot remove all tags from a node - tagged nodes must have at least one tag",
                ));
            }
            for tag in &body.tags {
                validate_tag(tag).map_err(|error| Status::unknown(error.message()))?;
            }
            let node = self.machine_by_id(body.node_id).await?;
            let invalid_tags = body
                .tags
                .iter()
                .filter(|tag| !self.policy.tag_exists(tag))
                .cloned()
                .collect::<Vec<_>>();
            if !invalid_tags.is_empty() {
                return Err(Status::invalid_argument(format!(
                    "requested tags [{}] are invalid or not permitted",
                    invalid_tags.join(" ")
                )));
            }
            let view = self
                .machines
                .mutate_with_view(
                    &self.machines.mutation_selector(&node),
                    MachineAdminMutation::Tags(body.tags),
                )
                .await
                .map_err(|error| {
                    node_mutation_error_to_status(error, NodeMutationRpc::Tags, body.node_id)
                })?;
            Ok(Response::new(SetTagsResponse {
                node: Some(self.node_view_proto(&view, &[], false).await?),
            }))
        }

        async fn set_approved_routes(
            &self,
            request: Request<SetApprovedRoutesRequest>,
        ) -> Result<Response<SetApprovedRoutesResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let routes = normalize_routes(body.routes)
                .map_err(|e| Status::unknown(format!("parsing route: {e}")))?;
            let missing_node = || {
                Status::invalid_argument(format!(
                    "node no longer exists in NodeStore: {}",
                    body.node_id
                ))
            };
            let selector = self
                .node_mutation_selector(body.node_id)
                .await
                .map_err(|error| {
                    if error.code() == tonic::Code::NotFound {
                        missing_node()
                    } else {
                        error
                    }
                })?;
            let view = self
                .machines
                .mutate_with_view(&selector, MachineAdminMutation::ApprovedRoutes(routes))
                .await
                .map_err(|error| {
                    node_mutation_error_to_status(error, NodeMutationRpc::Routes, body.node_id)
                })?;
            let machines = self
                .machines
                .list_checked()
                .await
                .map_err(machine_error_to_status)?;
            let route_sets = route_sets_for_machines(&self.primary_routes, &machines);
            let primary_routes = route_sets.primary_routes_for(&view.record.id);
            Ok(Response::new(SetApprovedRoutesResponse {
                node: Some(self.node_view_proto(&view, &primary_routes, false).await?),
            }))
        }

        async fn register_node(
            &self,
            request: Request<RegisterNodeRequest>,
        ) -> Result<Response<RegisterNodeResponse>, Status> {
            self.authorize(&request).await?;
            Ok(Response::new(
                self.register_node_body(request.into_inner()).await?,
            ))
        }

        async fn auth_register(
            &self,
            request: Request<AuthRegisterRequest>,
        ) -> Result<Response<AuthRegisterResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let response = self
                .register_node_body(RegisterNodeRequest {
                    user: body.user,
                    key: body.auth_id,
                })
                .await?;
            Ok(Response::new(AuthRegisterResponse {
                node: response.node,
            }))
        }

        async fn auth_approve(
            &self,
            request: Request<AuthApproveRequest>,
        ) -> Result<Response<AuthApproveResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let key = auth_id_cache_key(&body.auth_id)?;
            if !self.registration_cache.approve_without_node(&key) {
                return Err(Status::not_found(format!(
                    "no pending auth session for auth_id {}",
                    body.auth_id
                )));
            }
            Ok(Response::new(AuthApproveResponse {}))
        }

        async fn auth_reject(
            &self,
            request: Request<AuthRejectRequest>,
        ) -> Result<Response<AuthRejectResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let key = auth_id_cache_key(&body.auth_id)?;
            if !self
                .registration_cache
                .reject(&key, "auth request rejected")
            {
                return Err(Status::not_found(format!(
                    "no pending auth session for auth_id {}",
                    body.auth_id
                )));
            }
            Ok(Response::new(AuthRejectResponse {}))
        }

        async fn delete_node(
            &self,
            request: Request<DeleteNodeRequest>,
        ) -> Result<Response<DeleteNodeResponse>, Status> {
            self.authorize(&request).await?;
            let body_node_id = request.into_inner().node_id;
            let node = self.machine_by_id(body_node_id).await?;
            self.machines
                .delete(&self.machines.mutation_selector(&node))
                .await
                .map_err(|error| Status::unknown(node_state_error_message(error, body_node_id)))?;
            Ok(Response::new(DeleteNodeResponse {}))
        }

        async fn expire_node(
            &self,
            request: Request<ExpireNodeRequest>,
        ) -> Result<Response<ExpireNodeResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            if body.disable_expiry && body.expiry.is_some() {
                return Err(Status::invalid_argument(
                    "cannot set both disable_expiry and expiry",
                ));
            }
            let selector = self
                .node_mutation_selector(body.node_id)
                .await
                .map_err(|error| {
                    if error.code() == tonic::Code::NotFound {
                        Status::unknown(format!(
                            "node no longer exists in NodeStore: {}",
                            body.node_id
                        ))
                    } else {
                        error
                    }
                })?;
            let expiry = if body.disable_expiry {
                None
            } else {
                Some(
                    body.expiry
                        .as_ref()
                        .map(timestamp_to_datetime)
                        .transpose()?
                        .unwrap_or_else(chrono::Utc::now),
                )
            };
            let view = self
                .machines
                .mutate_with_view(&selector, MachineAdminMutation::Expiry(expiry))
                .await
                .map_err(|error| {
                    node_mutation_error_to_status(error, NodeMutationRpc::Expiry, body.node_id)
                })?;
            let mut node = self.node_view_proto(&view, &[], false).await?;
            // AsTime normalizes protobuf nanos. Preserve the applied instant
            // even for a legacy adapter that stores whole seconds only.
            node.expiry = expiry.map(datetime_to_timestamp);
            Ok(Response::new(ExpireNodeResponse { node: Some(node) }))
        }

        async fn rename_node(
            &self,
            request: Request<RenameNodeRequest>,
        ) -> Result<Response<RenameNodeResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let selector = self
                .node_mutation_selector(body.node_id)
                .await
                .map_err(|error| {
                    if error.code() == tonic::Code::NotFound {
                        Status::unknown(format!(
                            "node no longer exists in NodeStore: {}",
                            body.node_id
                        ))
                    } else {
                        error
                    }
                })?;
            let view = self
                .machines
                .mutate_with_view(&selector, MachineAdminMutation::Rename(body.new_name))
                .await
                .map_err(|error| {
                    node_mutation_error_to_status(error, NodeMutationRpc::Rename, body.node_id)
                })?;
            Ok(Response::new(RenameNodeResponse {
                node: Some(self.node_view_proto(&view, &[], false).await?),
            }))
        }

        async fn list_nodes(
            &self,
            request: Request<ListNodesRequest>,
        ) -> Result<Response<ListNodesResponse>, Status> {
            self.authorize(&request).await?;
            let filter_user = request.into_inner().user;
            let owner = if filter_user.is_empty() {
                None
            } else {
                Some(
                    self.users
                        .get(&filter_user)
                        .await
                        .map_err(user_lookup_error_to_unknown)?
                        .ok_or_else(|| Status::unknown("user not found"))?
                        .id,
                )
            };
            let views = self
                .machines
                .list_views()
                .await
                .map_err(machine_error_to_status)?;
            let machines = views
                .iter()
                .map(|view| view.record.clone())
                .collect::<Vec<_>>();
            let route_sets = route_sets_for_machines(&self.primary_routes, &machines);
            let mut nodes = Vec::with_capacity(views.len());
            for view in views {
                let record = &view.record;
                if let Some(owner) = owner
                    && (!record.tags.is_empty()
                        || !record
                            .user_id
                            .map_or_else(|| record.user == filter_user, |id| id == owner))
                {
                    continue;
                }
                let subnet_routes = route_sets.subnet_routes_for(&record.id);
                nodes.push(self.node_view_proto(&view, &subnet_routes, true).await?);
            }
            nodes.sort_by_key(|node| node.id);
            Ok(Response::new(ListNodesResponse { nodes }))
        }

        async fn backfill_node_i_ps(
            &self,
            request: Request<BackfillNodeIPsRequest>,
        ) -> Result<Response<BackfillNodeIPsResponse>, Status> {
            self.authorize(&request).await?;
            if !request.into_inner().confirmed {
                return Err(Status::unknown("not confirmed, aborting"));
            }
            let changes = self
                .machines
                .backfill_node_ips(self.ip_allocator.as_deref())
                .await
                .map_err(|error| match error {
                    MachineAdminError::BadRequest(message) => Status::unknown(message),
                    error => Status::unknown(error.to_string()),
                })?;
            Ok(Response::new(BackfillNodeIPsResponse { changes }))
        }

        async fn create_api_key(
            &self,
            request: Request<CreateApiKeyRequest>,
        ) -> Result<Response<CreateApiKeyResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let expiration_precise = body
                .expiration
                .as_ref()
                .map(timestamp_to_datetime)
                .transpose()?;
            let expiration = Some(
                expiration_precise.map_or(GO_ZERO_TIME_UNIX_SECONDS, |expiry| expiry.timestamp()),
            );
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                let created = service
                    .api_keys
                    .mint_precise(ApiKeyMintRequest { expiration }, expiration_precise)
                    .await
                    .map_err(api_key_raw_error_to_status)?;
                Ok(Response::new(CreateApiKeyResponse {
                    api_key: created.api_key,
                }))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing API key creation: {error}")))?
        }

        async fn expire_api_key(
            &self,
            request: Request<ExpireApiKeyRequest>,
        ) -> Result<Response<ExpireApiKeyResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let selector = ApiKeySelector::from_parts(body.prefix, body.id)?;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                match selector {
                    ApiKeySelector::Id(id) => service.api_keys.expire_by_id(id).await,
                    ApiKeySelector::Prefix(prefix) => {
                        service.api_keys.expire_by_prefix(&prefix).await
                    }
                }
                .map_err(api_key_raw_error_to_status)?;
                Ok(Response::new(ExpireApiKeyResponse {}))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing API key expiry: {error}")))?
        }

        async fn list_api_keys(
            &self,
            request: Request<ListApiKeysRequest>,
        ) -> Result<Response<ListApiKeysResponse>, Status> {
            self.authorize(&request).await?;
            let mut api_keys = self
                .api_keys
                .list_for_state()
                .await
                .map_err(api_key_raw_error_to_status)?
                .iter()
                .map(admin_key_to_proto)
                .collect::<Vec<_>>();
            api_keys.sort_by_key(|key| key.id);
            Ok(Response::new(ListApiKeysResponse { api_keys }))
        }

        async fn delete_api_key(
            &self,
            request: Request<DeleteApiKeyRequest>,
        ) -> Result<Response<DeleteApiKeyResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let selector = ApiKeySelector::from_parts(body.prefix, body.id)?;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                match selector {
                    ApiKeySelector::Id(id) => service.api_keys.delete_by_id(id).await,
                    ApiKeySelector::Prefix(prefix) => {
                        service.api_keys.delete_by_prefix(&prefix).await
                    }
                }
                .map_err(api_key_raw_error_to_status)?;
                Ok(Response::new(DeleteApiKeyResponse {}))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing API key deletion: {error}")))?
        }

        async fn get_policy(
            &self,
            request: Request<GetPolicyRequest>,
        ) -> Result<Response<GetPolicyResponse>, Status> {
            self.authorize(&request).await?;
            match &self.policy_mode {
                PolicyMode::Database => {
                    let policy_persistence = self.policy_persistence.as_ref().ok_or_else(|| {
                        Status::unknown(
                            "loading ACL from database: policy database is not configured",
                        )
                    })?;
                    let policy = policy_persistence
                        .get_latest_policy_with_timestamp()
                        .await
                        .map_err(|e| Status::unknown(format!("loading ACL from database: {e}")))?;
                    let Some((policy, updated_at)) = policy else {
                        return Err(Status::unknown(
                            "loading ACL from database: acl policy not found",
                        ));
                    };
                    Ok(Response::new(GetPolicyResponse {
                        policy: policy.policy,
                        updated_at: Some(updated_at),
                    }))
                }
                PolicyMode::File { path } => {
                    let bytes = tokio::fs::read(path).await.map_err(|e| {
                        Status::unknown(format!(
                            "reading policy from path {:?}: {e}",
                            path.display().to_string()
                        ))
                    })?;
                    // Go os.ReadFile permits these bytes, but protobuf rejects
                    // invalid UTF-8 while grpc encodes the response string.
                    let policy = String::from_utf8(bytes).map_err(|_| {
                        Status::internal(
                            "grpc: error while marshaling: string field contains invalid UTF-8",
                        )
                    })?;
                    Ok(Response::new(GetPolicyResponse {
                        policy,
                        updated_at: None,
                    }))
                }
                PolicyMode::Memory => {
                    let policy = String::from_utf8(self.policy.raw_bytes().unwrap_or_default())
                        .map_err(|_| {
                            Status::internal(
                                "grpc: error while marshaling: string field contains invalid UTF-8",
                            )
                        })?;
                    Ok(Response::new(GetPolicyResponse {
                        policy,
                        updated_at: self.policy.updated_at().map(unix_to_timestamp),
                    }))
                }
                PolicyMode::Unsupported { mode } => Err(Status::unknown(format!(
                    "no supported policy mode found in configuration, policy.mode: {mode:?}"
                ))),
            }
        }

        async fn set_policy(
            &self,
            request: Request<SetPolicyRequest>,
        ) -> Result<Response<SetPolicyResponse>, Status> {
            self.authorize(&request).await?;
            let policy = request.into_inner().policy;
            if matches!(
                self.policy_mode,
                PolicyMode::File { .. } | PolicyMode::Unsupported { .. }
            ) {
                return Err(Status::unknown(
                    "update is disabled for modes other than 'database'",
                ));
            }
            // Go State.SetPolicy treats zero bytes as no replacement. It still
            // clears SSH approvals before the database append and reload below.
            // Go's unmarshalPolicy is the only policy entrypoint, so parse with
            // the native bytes decoder; its metadata-stripped source feeds the
            // validation below while the operator's original text is stored.
            let parsed = if policy.is_empty() {
                None
            } else {
                Some(
                    crate::policy::parse_hujson_policy_bytes(policy.as_bytes()).map_err(
                        |error| {
                            Status::unknown(format!(
                                "setting policy: {}",
                                native_policy_parse_error(error)
                            ))
                        },
                    )?,
                )
            };
            let guard = self.policy.lock_mutation().await;
            let service = Self::clone(self);
            crate::tailscale_wire::complete_state_mutation(async move {
                let _guard = guard;
                if let Some((mut doc, source)) = parsed {
                    service
                        .validate_candidate_policy(&mut doc, &source, "setting policy")
                        .await?;
                    // Install before persistence, as State.SetPolicy does.
                    // A later database/reload failure leaves this live policy
                    // in place and does not dispatch a success notification.
                    service
                        .policy
                        .try_set_quiet(doc, policy.clone())
                        .map_err(|error| Status::unknown(format!("setting policy: {error}")))?;
                } else {
                    service.policy.invalidate_ssh_auth();
                }
                service.registration_cache.clear_ssh_auth();

                let (policy, updated_at) = match &service.policy_mode {
                    PolicyMode::Database => {
                        let policy_persistence = service.policy_persistence.as_ref().ok_or_else(|| {
                            Status::unknown(
                                "persisting policy to database: policy database is not configured",
                            )
                        })?;
                        let (persisted, updated_at) = policy_persistence
                            .set_policy_with_timestamp(&policy)
                            .await
                            .map_err(|e| {
                                Status::unknown(format!("persisting policy to database: {e}"))
                            })?;
                        // Reload the actual latest row, not the request or the
                        // append result. An external writer can have appended
                        // another row; a failed second read is an RPC failure.
                        service
                            .reload_policy_from_config_inner()
                            .await
                            .map_err(|error| {
                                Status::new(
                                    error.code(),
                                    format!("reloading policy: {}", error.message()),
                                )
                            })?;
                        (persisted.policy, updated_at)
                    }
                    PolicyMode::Memory => {
                        crate::admin::machines::apply_policy_auto_approvals(
                            &service.policy,
                            service.machines.as_ref(),
                        )
                        .await
                        .map_err(machine_error_to_status)?;
                        service.policy.notify_change();
                        (
                            policy,
                            unix_to_timestamp(
                                service.policy.updated_at().unwrap_or_else(current_unix_i64),
                            ),
                        )
                    }
                    PolicyMode::File { .. } => unreachable!("file mode returned before parsing"),
                    PolicyMode::Unsupported { .. } => {
                        unreachable!("unsupported mode returned before parsing")
                    }
                };
                Ok(Response::new(SetPolicyResponse {
                    policy,
                    updated_at: Some(updated_at),
                }))
            })
            .await
            .map_err(|error| Status::internal(format!("finishing policy update: {error}")))?
        }

        async fn check_policy(
            &self,
            request: Request<CheckPolicyRequest>,
        ) -> Result<Response<CheckPolicyResponse>, Status> {
            self.authorize(&request).await?;
            let policy = request.into_inner().policy;
            // The upstream RPC reads users and nodes before constructing the
            // sandbox, so storage failures precede malformed-policy errors.
            let identities = self.users.policy_users().await.map_err(|error| {
                let error = match error {
                    UserRegistryError::Store(message) => message,
                    other => other.to_string(),
                };
                Status::internal(format!("loading users: {error}"))
            })?;
            let nodes = self
                .machines
                .policy_nodes_for_check()
                .await
                .map_err(machine_error_to_status)?;
            // NewPolicyManager(nil) is a valid sandbox with no loaded policy.
            let (mut doc, source) = if policy.is_empty() {
                (PolicyDoc::default(), String::new())
            } else {
                crate::policy::parse_hujson_policy_bytes(policy.as_bytes())
                    .map_err(|error| Status::invalid_argument(native_policy_parse_error(error)))?
            };
            Self::validate_candidate_policy_users(
                &mut doc,
                &source,
                "checking policy",
                identities,
            )?;
            Self::validate_candidate_policy_nodes(&doc, &source, "checking policy", &nodes)?;
            Ok(Response::new(CheckPolicyResponse {}))
        }

        async fn health(
            &self,
            request: Request<HealthRequest>,
        ) -> Result<Response<HealthResponse>, Status> {
            self.authorize(&request).await?;
            if let Some(database_health) = &self.database_health {
                database_health
                    .ping()
                    .await
                    .map_err(|e| Status::unknown(format!("pinging database: {e}")))?;
            }
            Ok(Response::new(HealthResponse {
                database_connectivity: true,
            }))
        }
    }

    fn native_policy_parse_error(error: PolicyParseError) -> String {
        let message = match error {
            PolicyParseError::Json(message) | PolicyParseError::Schema(message) => message,
        };
        format!("parsing policy: {message}")
    }

    enum ApiKeySelector {
        Id(u64),
        Prefix(String),
    }

    impl ApiKeySelector {
        fn from_parts(prefix: String, id: u64) -> Result<Self, Status> {
            match (prefix.is_empty(), id) {
                (true, 0) => Err(Status::invalid_argument("must provide id or prefix")),
                (false, 0) => Ok(Self::Prefix(prefix)),
                (true, id) => Ok(Self::Id(id)),
                (false, _) => Err(Status::invalid_argument(
                    "provide either id or prefix, not both",
                )),
            }
        }
    }

    fn admin_key_to_proto(key: &ApiKeyAdminKey) -> ApiKey {
        ApiKey {
            id: key.id,
            prefix: key.prefix.clone(),
            expiration: key
                .expiration_precise
                .map(datetime_to_timestamp)
                .or_else(|| key.expiration.map(unix_to_timestamp)),
            created_at: key
                .created_at_precise
                .map(datetime_to_timestamp)
                .or_else(|| nonzero_i64_timestamp(key.created_at)),
            last_seen: key
                .last_seen_precise
                .map(datetime_to_timestamp)
                .or_else(|| key.last_seen.map(unix_to_timestamp)),
        }
    }

    fn unix_to_timestamp(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    fn datetime_to_timestamp(value: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: value.timestamp(),
            nanos: value.timestamp_subsec_nanos() as i32,
        }
    }

    fn current_unix_i64() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    fn api_key_raw_error_to_status(e: ApiKeyAdminError) -> Status {
        match e {
            ApiKeyAdminError::NotFound => Status::unknown("record not found"),
            ApiKeyAdminError::Store(msg) => Status::unknown(msg),
        }
    }

    fn preauth_native_view_to_proto(view: &PreauthAdminKeyView) -> PreAuthKey {
        let key = &view.key;
        PreAuthKey {
            user: view.user.as_ref().map(user_record_to_proto),
            id: key.id,
            key: key.key.clone(),
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.redemptions > 0,
            acl_tags: key.tags.clone(),
            created_at: view.created_at.map(datetime_to_timestamp),
            expiration: view.expiration.map(datetime_to_timestamp),
        }
    }

    async fn preauth_key_to_proto(
        key: &PreauthAdminKey,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<PreAuthKey, Status> {
        preauth_key_to_proto_with_display_key(key, users, key.key.clone()).await
    }

    async fn listed_preauth_key_to_proto(
        key: &PreauthAdminKey,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<PreAuthKey, Status> {
        let display_key = listed_preauth_display_key(&key.key);
        preauth_key_to_proto_with_display_key(key, users, display_key).await
    }

    async fn preauth_key_to_proto_with_display_key(
        key: &PreauthAdminKey,
        users: &Arc<dyn UserAdmin>,
        display_key: String,
    ) -> Result<PreAuthKey, Status> {
        Ok(PreAuthKey {
            user: preauth_user_to_proto(key, users).await?,
            id: key.id,
            key: display_key,
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.redemptions > 0,
            expiration: key
                .expires_at_precise
                .map(datetime_to_timestamp)
                .or_else(|| nonzero_preauth_expiration_timestamp(key.expires_at)),
            created_at: key
                .created_at_precise
                .map(datetime_to_timestamp)
                .or_else(|| nonzero_u64_timestamp(key.created_at)),
            acl_tags: key.tags.clone(),
        })
    }

    fn nonzero_preauth_expiration_timestamp(seconds: u64) -> Option<prost_types::Timestamp> {
        if seconds == PREAUTH_NEVER_EXPIRES_AT {
            None
        } else if seconds == 0 {
            Some(unix_to_timestamp(GO_ZERO_TIME_UNIX_SECONDS))
        } else {
            Some(unix_to_timestamp(saturating_u64_to_i64(seconds)))
        }
    }

    fn listed_preauth_display_key(key: &str) -> String {
        const PREAUTH_KEY_PREFIX: &str = "hskey-auth-";
        const PREAUTH_KEY_DISPLAY_PREFIX_LEN: usize = 12;

        let Some(rest) = key.strip_prefix(PREAUTH_KEY_PREFIX) else {
            return key.to_string();
        };
        if rest.len() < PREAUTH_KEY_DISPLAY_PREFIX_LEN {
            return key.to_string();
        }
        let prefix = &rest[..PREAUTH_KEY_DISPLAY_PREFIX_LEN];

        format!("{PREAUTH_KEY_PREFIX}{prefix}-***")
    }

    async fn preauth_user_to_proto(
        key: &PreauthAdminKey,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<Option<ProtoUser>, Status> {
        preauth_user_selector_to_proto(&key.user, users).await
    }

    async fn preauth_user_selector_to_proto(
        selector: &str,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<Option<ProtoUser>, Status> {
        if selector.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            users
                .get(selector)
                .await
                .map_err(user_error_to_status)?
                .map_or_else(
                    || ProtoUser {
                        id: 0,
                        name: selector.to_owned(),
                        created_at: None,
                        display_name: String::new(),
                        email: String::new(),
                        provider_id: String::new(),
                        provider: String::new(),
                        profile_pic_url: String::new(),
                    },
                    |user| user_record_to_proto(&user),
                ),
        ))
    }

    fn preauth_error_to_status(e: PreauthAdminError) -> Status {
        match e {
            PreauthAdminError::Unknown(_) => Status::not_found("preauth key not found"),
            PreauthAdminError::Invalid(msg) => Status::invalid_argument(msg),
            PreauthAdminError::Store(msg) => Status::unknown(msg),
        }
    }

    fn set_registration_user_identity(record: &mut MachineRecord, user: &UserRecord) {
        let login_name = if !user.email.is_empty() {
            user.email.clone()
        } else if !user.name.is_empty() {
            user.name.clone()
        } else if !user.provider_id.is_empty() {
            user.provider_id.clone()
        } else {
            user.id.to_string()
        };
        let display_name = if user.display_name.is_empty() {
            login_name.clone()
        } else {
            user.display_name.clone()
        };
        record.set_user_identity(
            Some(user.id),
            login_name,
            display_name,
            user.profile_pic_url.clone(),
        );
        let user_created_at = user.created_at_precise.or_else(|| {
            i64::try_from(user.created_at)
                .ok()
                .filter(|timestamp| *timestamp > 0)
                .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0))
        });
        record.set_user_account_metadata(user.provider.clone(), user_created_at);
    }

    #[cfg(test)]
    fn machine_admin_to_wire_record(machine: &MachineAdminRecord) -> MachineRecord {
        let created_at = machine.created_at_precise.unwrap_or_else(|| {
            chrono::DateTime::from_timestamp(machine.created_at as i64, 0).unwrap_or_else(Utc::now)
        });
        let last_seen = machine.last_seen_precise.unwrap_or_else(|| {
            chrono::DateTime::from_timestamp(machine.last_seen as i64, 0).unwrap_or(created_at)
        });
        let ipv4 = machine.ipv4.parse().ok().or_else(|| {
            machine
                .ipv6
                .is_none()
                .then(|| cgnat_ip_from_key(&machine.id))
        });
        let mut record = MachineRecord::new_at_with_addresses(
            created_at,
            machine.id.clone(),
            machine.machine_key_hex.clone(),
            machine.user.clone(),
            machine.name.clone(),
            ipv4,
            machine
                .ipv6
                .as_deref()
                .filter(|ipv6| !ipv6.is_empty())
                .and_then(|ipv6| ipv6.parse().ok()),
            false,
        );
        record.node_id = (machine.node_id != 0).then_some(machine.node_id);
        record.user_id = machine.user_id;
        record.auth_key_id = machine.auth_key_id;
        record.expiry = machine.expiry_precise.or_else(|| {
            machine
                .expiry
                .and_then(|expiry| chrono::DateTime::from_timestamp(expiry as i64, 0))
        });
        record.last_seen = last_seen;
        record.os.clone_from(&machine.os);
        record.os_version.clone_from(&machine.version);
        record.forced_tags.clone_from(&machine.tags);
        record.available_routes.clone_from(&machine.routes);
        record.approved_routes.clone_from(&machine.approved_routes);
        record.register_method = machine.register_method;
        record.disco_key = (!machine.disco_key.is_empty()).then_some(machine.disco_key.clone());
        record
    }

    fn machine_admin_to_wire_record_with_pending(
        machine: &MachineAdminRecord,
        pending: &MachineRecord,
    ) -> MachineRecord {
        let mut record = pending.clone();
        record.node_id = (machine.node_id != 0).then_some(machine.node_id);
        record.node_key_hex.clone_from(&machine.id);
        record.machine_key_hex.clone_from(&machine.machine_key_hex);
        record.user.clone_from(&machine.user);
        record.user_id = machine.user_id;
        record.hostname.clone_from(&machine.name);
        record.ipv4 = machine.ipv4.parse().ok().or_else(|| {
            machine
                .ipv6
                .is_none()
                .then(|| cgnat_ip_from_key(&machine.id))
        });
        record.ipv6 = machine
            .ipv6
            .as_deref()
            .filter(|ipv6| !ipv6.is_empty())
            .and_then(|ipv6| ipv6.parse().ok());
        record.expiry = machine.expiry_precise.or_else(|| {
            machine
                .expiry
                .and_then(|expiry| chrono::DateTime::from_timestamp(expiry as i64, 0))
        });
        if let Some(last_seen) = machine
            .last_seen_precise
            .or_else(|| chrono::DateTime::from_timestamp(machine.last_seen as i64, 0))
        {
            record.last_seen = last_seen;
        }
        record.os.clone_from(&machine.os);
        record.os_version.clone_from(&machine.version);
        record.forced_tags.clone_from(&machine.tags);
        record.available_routes.clone_from(&machine.routes);
        record.approved_routes.clone_from(&machine.approved_routes);
        record.register_method = machine.register_method;
        if !machine.disco_key.is_empty() {
            record.disco_key = Some(machine.disco_key.clone());
        }
        record
    }

    fn wire_record_to_machine_admin(record: MachineRecord) -> MachineAdminRecord {
        let expired = record.is_expired_at(Utc::now());
        MachineAdminRecord {
            node_id: record.node_id.unwrap_or_default(),
            id: record.node_key_hex,
            name: record.hostname,
            user: record.user,
            user_id: record.user_id,
            auth_key_id: record.auth_key_id,
            ipv4: record.ipv4.map(|ip| ip.to_string()).unwrap_or_default(),
            ipv6: record.ipv6.map(|ipv6| ipv6.to_string()),
            online: !expired,
            last_seen: record.last_seen.timestamp().max(0) as u64,
            last_seen_precise: Some(record.last_seen),
            created_at: record.created_at.timestamp().max(0) as u64,
            created_at_precise: Some(record.created_at),
            expiry: record.expiry.map(|expiry| expiry.timestamp().max(0) as u64),
            expiry_precise: record.expiry,
            machine_key_hex: record.machine_key_hex,
            disco_key: record.disco_key.unwrap_or_default(),
            os: if record.os.is_empty() {
                "unknown".into()
            } else {
                record.os
            },
            version: if record.os_version.is_empty() {
                "unknown".into()
            } else {
                record.os_version
            },
            tags: record.forced_tags,
            routes: record.available_routes,
            approved_routes: record.approved_routes,
            register_method: record.register_method,
            expired,
        }
    }

    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded value
    async fn machine_to_node_with_routes_and_user(
        machine: &MachineAdminRecord,
        users: &Arc<dyn UserAdmin>,
        preauth: &Arc<dyn PreauthAdmin>,
        subnet_routes: &[String],
        cached_user: Option<Option<UserRecord>>,
        cached_key: Option<Option<crate::admin::machines::NativeAuthKey>>,
    ) -> Result<Node, Status> {
        let user = match cached_user {
            Some(user) => user.as_ref().map(user_record_to_proto),
            None => machine_user_to_proto(machine, users).await?,
        };
        let pre_auth_key = match cached_key {
            Some(Some(key)) => Some(native_auth_key_to_proto(&key, users).await?),
            Some(None) => None,
            None => machine_preauth_key_to_proto(machine, users, preauth).await?,
        };
        Ok(Node {
            id: machine_numeric_id(machine),
            machine_key: prefix_key("mkey:", &machine.machine_key_hex),
            node_key: prefix_key("nodekey:", &machine.id),
            disco_key: if machine.disco_key.is_empty() {
                ZERO_DISCO_KEY.to_string()
            } else {
                machine.disco_key.clone()
            },
            ip_addresses: node_ip_addresses(machine),
            name: machine.name.clone(),
            user,
            last_seen: machine
                .last_seen_precise
                .map(datetime_to_timestamp)
                .or_else(|| nonzero_u64_timestamp(machine.last_seen)),
            expiry: machine
                .expiry_precise
                .map(datetime_to_timestamp)
                .or_else(|| {
                    machine
                        .expiry
                        .map(saturating_u64_to_i64)
                        .map(unix_to_timestamp)
                }),
            pre_auth_key,
            created_at: machine
                .created_at_precise
                .map(datetime_to_timestamp)
                .or_else(|| nonzero_u64_timestamp(machine.created_at)),
            register_method: machine.register_method,
            given_name: machine.name.clone(),
            online: machine.online,
            approved_routes: machine
                .approved_routes
                .iter()
                .map(|route| {
                    // Go's proto projection uses Prefix.String, while the
                    // persisted JSON slice uses the empty MarshalText value.
                    if route.is_empty() {
                        "invalid Prefix".into()
                    } else {
                        route.clone()
                    }
                })
                .collect(),
            available_routes: machine.routes.clone(),
            subnet_routes: subnet_routes.to_vec(),
            tags: machine.tags.clone(),
        })
    }

    async fn native_auth_key_to_proto(
        key: &crate::admin::machines::NativeAuthKey,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<PreAuthKey, Status> {
        let user = match &key.user {
            Some(user) => user.as_ref().map(user_record_to_proto),
            None => preauth_user_selector_to_proto(&key.user_selector, users).await?,
        };
        Ok(PreAuthKey {
            user,
            id: key.id,
            key: key.display_key.clone(),
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used(),
            acl_tags: key.tags.clone(),
            created_at: key.created_at.map(datetime_to_timestamp),
            expiration: key.expiration.map(datetime_to_timestamp),
        })
    }

    async fn machine_preauth_key_to_proto(
        machine: &MachineAdminRecord,
        users: &Arc<dyn UserAdmin>,
        preauth: &Arc<dyn PreauthAdmin>,
    ) -> Result<Option<PreAuthKey>, Status> {
        let Some(auth_key_id) = machine.auth_key_id else {
            return Ok(None);
        };
        let Ok(auth_key_id) = u64::try_from(auth_key_id) else {
            return Ok(None);
        };
        if let Some(views) = preauth
            .list_with_associations()
            .await
            .map_err(preauth_error_to_status)?
        {
            return Ok(views
                .iter()
                .find(|view| view.key.id == auth_key_id)
                .map(preauth_native_view_to_proto));
        }
        let keys = preauth
            .list_checked()
            .await
            .map_err(preauth_error_to_status)?;
        let Some(key) = keys.iter().find(|key| key.id == auth_key_id) else {
            return Ok(None);
        };
        listed_preauth_key_to_proto(key, users).await.map(Some)
    }

    fn tagged_devices_user_to_proto() -> ProtoUser {
        ProtoUser {
            id: 2_147_455_555,
            name: "tagged-devices".into(),
            created_at: Some(unix_to_timestamp(GO_ZERO_TIME_UNIX_SECONDS)),
            display_name: "Tagged Devices".into(),
            email: String::new(),
            provider_id: String::new(),
            provider: String::new(),
            profile_pic_url: String::new(),
        }
    }

    fn node_ip_addresses(machine: &MachineAdminRecord) -> Vec<String> {
        let mut addresses = Vec::with_capacity(1 + usize::from(machine.ipv6.is_some()));
        if !machine.ipv4.is_empty() {
            addresses.push(machine.ipv4.clone());
        }
        if let Some(ipv6) = machine.ipv6.as_ref().filter(|ipv6| !ipv6.is_empty()) {
            addresses.push(ipv6.clone());
        }
        addresses
    }

    fn machine_numeric_id(machine: &MachineAdminRecord) -> u64 {
        if machine.node_id == 0 {
            stable_id_from_key(&machine.id)
        } else {
            machine.node_id
        }
    }

    struct MachineRouteSets {
        primary_routes: BTreeMap<String, Vec<String>>,
        exit_routes: BTreeMap<String, Vec<String>>,
    }

    impl MachineRouteSets {
        fn primary_routes_for(&self, id: &str) -> Vec<String> {
            self.primary_routes.get(id).cloned().unwrap_or_default()
        }

        fn subnet_routes_for(&self, id: &str) -> Vec<String> {
            let mut routes = self.primary_routes_for(id);
            routes.extend(self.exit_routes.get(id).cloned().unwrap_or_default());
            routes.sort();
            routes.dedup();
            routes
        }
    }

    fn route_sets_for_machines(
        primary_state: &Arc<Mutex<PrimaryRouteState>>,
        machines: &[MachineAdminRecord],
    ) -> MachineRouteSets {
        let mut state = primary_state.lock();
        let _ = state.sync_routes(
            machines
                .iter()
                .filter(|machine| machine.online && !machine.expired)
                .map(|machine| {
                    (
                        machine_numeric_id(machine),
                        active_approved_routes(&machine.routes, &machine.approved_routes),
                    )
                }),
        );

        let mut primary_routes = BTreeMap::new();
        let mut exit_routes = BTreeMap::new();
        for machine in machines {
            // Go's nodesToProto appends Node.ExitRoutes() (announced AND
            // approved exit prefixes) without regard to online/expiry state;
            // only the HA primary election is limited to serving nodes
            // (verified in-process against v0.29.5: an offline and an expired
            // node still list their approved exit routes).
            let exit = active_exit_routes(&machine.routes, &machine.approved_routes);
            if !exit.is_empty() {
                exit_routes.insert(machine.id.clone(), exit);
            }
            if !machine.online || machine.expired {
                continue;
            }
            let node_id = machine_numeric_id(machine);
            let primary = state.primary_routes(node_id);
            if !primary.is_empty() {
                primary_routes.insert(machine.id.clone(), primary);
            }
        }

        MachineRouteSets {
            primary_routes,
            exit_routes,
        }
    }

    const REGISTRATION_ID_LENGTH: usize = 24;
    const UPSTREAM_AUTH_ID_PREFIX: &str = "hskey-authreq-";

    fn validate_auth_id_cache_key(id: &str) -> Result<String, String> {
        match id.strip_prefix(UPSTREAM_AUTH_ID_PREFIX) {
            Some(rest) if rest.len() == REGISTRATION_ID_LENGTH => Ok(rest.to_string()),
            Some(rest) => Err(format!(
                "auth ID has invalid length: expected {}, got {}",
                UPSTREAM_AUTH_ID_PREFIX.len() + REGISTRATION_ID_LENGTH,
                UPSTREAM_AUTH_ID_PREFIX.len() + rest.len()
            )),
            None => Err(format!(
                "auth ID has invalid prefix: expected prefix {UPSTREAM_AUTH_ID_PREFIX:?}"
            )),
        }
    }

    fn auth_id_cache_key(id: &str) -> Result<String, Status> {
        validate_auth_id_cache_key(id)
            .map_err(|message| Status::invalid_argument(format!("invalid auth_id: {message}")))
    }

    fn registration_cache_key_from_register_key(key: &str) -> Result<String, Status> {
        validate_auth_id_cache_key(key).map_err(Status::unknown)
    }

    fn random_key_hex() -> Result<String, Status> {
        crate::tailscale_wire::noise::generate_x25519_public()
            .map(hex::encode)
            .map_err(|error| Status::internal(format!("generating public key: {error}")))
    }

    fn cgnat_ip_from_key(key: &str) -> Ipv4Addr {
        crate::tailscale_wire::legacy_registration_ipv4(key)
    }

    fn prefix_key(prefix: &str, value: &str) -> String {
        if value.is_empty() || value.starts_with(prefix) {
            value.to_string()
        } else {
            format!("{prefix}{value}")
        }
    }

    fn nonzero_u64_timestamp(seconds: u64) -> Option<prost_types::Timestamp> {
        if seconds == 0 {
            None
        } else {
            Some(unix_to_timestamp(saturating_u64_to_i64(seconds)))
        }
    }

    fn nonzero_i64_timestamp(seconds: i64) -> Option<prost_types::Timestamp> {
        if seconds == 0 {
            None
        } else {
            Some(unix_to_timestamp(seconds))
        }
    }

    async fn machine_user_to_proto(
        machine: &MachineAdminRecord,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<Option<ProtoUser>, Status> {
        if let Some(id) = machine.user_id {
            return users
                .get_for_node_association(id)
                .await
                .map(|user| user.as_ref().map(user_record_to_proto))
                .map_err(user_lookup_error_to_unknown);
        }
        if machine.user.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            users
                .get(&machine.user)
                .await
                .map_err(user_error_to_status)?
                .map_or_else(
                    || ProtoUser {
                        id: stable_id_from_key(&machine.user),
                        name: machine.user.clone(),
                        created_at: None,
                        display_name: String::new(),
                        email: String::new(),
                        provider_id: String::new(),
                        provider: String::new(),
                        profile_pic_url: String::new(),
                    },
                    |user| user_record_to_proto(&user),
                ),
        ))
    }

    fn timestamp_to_datetime(
        ts: &prost_types::Timestamp,
    ) -> Result<chrono::DateTime<chrono::Utc>, Status> {
        let nanos = i64::from(ts.nanos);
        let seconds = ts
            .seconds
            .checked_add(nanos.div_euclid(1_000_000_000))
            .ok_or_else(|| Status::invalid_argument("timestamp out of range"))?;
        chrono::DateTime::from_timestamp(seconds, nanos.rem_euclid(1_000_000_000) as u32)
            .ok_or_else(|| Status::invalid_argument("timestamp out of range"))
    }

    #[derive(Clone, Copy)]
    enum NodeMutationRpc {
        Tags,
        Routes,
        Expiry,
        Rename,
    }

    fn node_state_error_message(error: MachineAdminError, node_id: u64) -> String {
        match error {
            MachineAdminError::NotFound(_) => {
                format!("node no longer exists in NodeStore: {node_id}")
            }
            MachineAdminError::BadRequest(message)
            | MachineAdminError::Storage(message)
            | MachineAdminError::Policy(message) => message,
        }
    }

    fn node_mutation_error_to_status(
        error: MachineAdminError,
        operation: NodeMutationRpc,
        node_id: u64,
    ) -> Status {
        let message = if matches!(operation, NodeMutationRpc::Tags)
            && matches!(&error, MachineAdminError::NotFound(_))
        {
            format!("node not found: {node_id}")
        } else {
            node_state_error_message(error, node_id)
        };
        match operation {
            NodeMutationRpc::Tags | NodeMutationRpc::Routes => Status::invalid_argument(message),
            NodeMutationRpc::Expiry | NodeMutationRpc::Rename => Status::unknown(message),
        }
    }

    fn machine_error_to_status(e: MachineAdminError) -> Status {
        match e {
            MachineAdminError::NotFound(_) => Status::not_found("node not found"),
            MachineAdminError::BadRequest(msg) => Status::invalid_argument(msg),
            MachineAdminError::Policy(msg) | MachineAdminError::Storage(msg) => {
                Status::unknown(msg)
            }
        }
    }

    fn validate_tag(tag: &str) -> Result<(), Status> {
        if !tag.starts_with("tag:") {
            return Err(Status::invalid_argument(
                "tag must start with the string 'tag:'",
            ));
        }
        if headscale_api_acl::go_unicode::to_lowercase(tag) != tag {
            return Err(Status::invalid_argument("tag should be lowercase"));
        }
        if tag.split_whitespace().count() > 1 {
            return Err(Status::invalid_argument("tags must not contain spaces"));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn apply_requested_tags(
        policy: &PolicyStore,
        record: &mut MachineAdminRecord,
    ) -> Result<(), Status> {
        crate::admin::machines::validate_auth_path_tags(policy, record)
            .map_err(Status::invalid_argument)
    }

    fn user_record_admin_name(user: &UserRecord) -> String {
        if !user.name.is_empty() {
            user.name.clone()
        } else if !user.email.is_empty() {
            user.email.clone()
        } else if !user.provider_id.is_empty() {
            user.provider_id.clone()
        } else {
            user.id.to_string()
        }
    }

    fn user_record_to_proto(user: &UserRecord) -> ProtoUser {
        ProtoUser {
            id: user.id,
            name: user_record_admin_name(user),
            created_at: Some(user.created_at_precise.map_or_else(
                || unix_to_timestamp(saturating_u64_to_i64(user.created_at)),
                datetime_to_timestamp,
            )),
            display_name: user.display_name.clone(),
            email: user.email.clone(),
            provider_id: user.provider_id.clone(),
            provider: user.provider.clone(),
            profile_pic_url: user.profile_pic_url.clone(),
        }
    }

    fn saturating_u64_to_i64(v: u64) -> i64 {
        i64::try_from(v).unwrap_or(i64::MAX)
    }

    fn user_error_to_status(e: UserRegistryError) -> Status {
        match e {
            UserRegistryError::InvalidName(msg) => Status::invalid_argument(msg),
            UserRegistryError::Exists(msg) => Status::already_exists(msg),
            UserRegistryError::Missing(msg) => Status::not_found(msg),
            UserRegistryError::CannotChangeOidcUser => {
                Status::invalid_argument("cannot edit OIDC user")
            }
            UserRegistryError::Store(msg) => Status::internal(msg),
        }
    }

    fn user_lookup_error_to_unknown(e: UserRegistryError) -> Status {
        match e {
            UserRegistryError::Missing(_) => Status::unknown("user not found"),
            UserRegistryError::Store(msg) => Status::unknown(msg),
            other => Status::unknown(other.to_string()),
        }
    }

    fn create_user_error_to_status(e: &UserRegistryError) -> Status {
        match e {
            UserRegistryError::Exists(_) => Status::internal(
                "creating user: creating user: constraint failed: UNIQUE constraint failed: users.name (2067)",
            ),
            UserRegistryError::Store(msg) => Status::internal(format!("creating user: {msg}")),
            other => Status::internal(format!("creating user: {other}")),
        }
    }

    fn direct_user_error_to_status(e: UserRegistryError) -> Status {
        match e {
            UserRegistryError::Missing(_) => upstream_user_not_found_status(),
            UserRegistryError::Exists(_) => Status::unknown(
                "updating user: constraint failed: UNIQUE constraint failed: users.name (2067)",
            ),
            UserRegistryError::Store(msg) if msg.contains("user not empty: node(s) found") => {
                upstream_user_not_empty_status()
            }
            UserRegistryError::Store(msg) => Status::unknown(msg),
            other => Status::unknown(other.to_string()),
        }
    }

    fn upstream_user_not_found_status() -> Status {
        Status::unknown("user not found")
    }

    fn upstream_user_not_empty_status() -> Status {
        Status::unknown("user not empty: node(s) found")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn machine_admin_wire_conversions_preserve_numeric_user_id() {
            let machine = MachineAdminRecord {
                node_id: 123,
                id: "aa".repeat(32),
                name: "alice-laptop".into(),
                user: "alice".into(),
                user_id: Some(42),
                auth_key_id: Some(88),
                ipv4: "100.64.0.7".into(),
                ipv6: None,
                online: true,
                last_seen: 1_780_000_000,
                last_seen_precise: None,
                created_at: 1_780_000_000,
                created_at_precise: None,
                expiry: None,
                expiry_precise: None,
                machine_key_hex: "bb".repeat(32),
                disco_key: "discokey:abc".into(),
                os: "linux".into(),
                version: "1.80.0".into(),
                tags: Vec::new(),
                routes: Vec::new(),
                approved_routes: Vec::new(),
                register_method: RegisterMethod::Cli as i32,
                expired: false,
            };

            let record = machine_admin_to_wire_record(&machine);
            assert_eq!(record.user_id, Some(42));
            assert_eq!(record.auth_key_id, Some(88));
            let roundtrip = wire_record_to_machine_admin(record);
            assert_eq!(roundtrip.user_id, Some(42));
            assert_eq!(roundtrip.auth_key_id, Some(88));

            let mut pending = MachineRecord::new_at(
                Utc::now(),
                machine.id.clone(),
                machine.machine_key_hex.clone(),
                "pending-user".into(),
                "pending-name".into(),
                Ipv4Addr::new(100, 64, 0, 99),
                false,
            );
            pending.user_id = Some(7);

            let overlay = machine_admin_to_wire_record_with_pending(&machine, &pending);
            assert_eq!(overlay.user, "alice");
            assert_eq!(overlay.user_id, Some(42));
            assert_eq!(overlay.hostname, "alice-laptop");
        }

        #[test]
        fn listed_preauth_display_key_masks_prefixes_containing_dash() {
            let display = listed_preauth_display_key(
                "hskey-auth-cdTCY4M-EMkI-ZL-fd2lbOiv4rJRG0eYsUOQQdThmKYqA2NoUYDeHbA_wMb7psc1yu0uwQqsxvrXC",
            );

            assert_eq!(display, "hskey-auth-cdTCY4M-EMkI-***");
        }
    }
}

#[cfg(all(test, feature = "admin"))]
mod upstream_tests {
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::to_bytes;
    use chrono::Utc;
    use futures::{StreamExt as _, stream};
    use prost::Message as _;
    use tonic::{
        Request,
        metadata::AsciiMetadataValue,
        transport::{Endpoint, Server},
    };
    use tonic_reflection::pb::v1::{
        ServerReflectionRequest, server_reflection_client::ServerReflectionClient,
        server_reflection_request::MessageRequest, server_reflection_response::MessageResponse,
    };
    use tower::ServiceExt;

    use super::upstream::{DatabaseHealthCheck, HeadscaleAdminService, apply_requested_tags};
    use crate::admin::{
        ApiKeyAdmin, ApiKeyMintRequest, MachineAdminRecord, PersistentApiKeyAdmin,
        PersistentMachineAdmin, PersistentPreauthAdmin, PersistentUserAdmin, WireMachineAdmin,
    };
    use crate::generated::headscale_service_client::HeadscaleServiceClient;
    use crate::generated::headscale_service_server::HeadscaleService;
    use crate::generated::{
        AuthApproveRequest, AuthRegisterRequest, AuthRejectRequest, BackfillNodeIPsRequest,
        CheckPolicyRequest, CreateApiKeyRequest, CreatePreAuthKeyRequest, CreateUserRequest,
        DebugCreateNodeRequest, DeleteApiKeyRequest, DeleteNodeRequest, DeletePreAuthKeyRequest,
        DeleteUserRequest, ExpireApiKeyRequest, ExpireNodeRequest, ExpirePreAuthKeyRequest,
        GetNodeRequest, GetPolicyRequest, HealthRequest, ListApiKeysRequest, ListNodesRequest,
        ListPreAuthKeysRequest, ListUsersRequest, RegisterMethod, RegisterNodeRequest,
        RenameNodeRequest, RenameUserRequest, SetApprovedRoutesRequest, SetPolicyRequest,
        SetTagsRequest,
    };
    use crate::generated::{google_api::HttpRule, google_api::http_rule::Pattern};
    use crate::policy::{PeerMapNode, PolicyStore, parse_hujson_policy};
    use crate::tailscale_wire::wire::{MachineRecord, stable_id_from_key};
    use crate::tailscale_wire::{
        AllocError, IpAllocator, MachineRegistry, RegistrationCache, RegistrationWaitOutcome,
        WireState,
        noise::{NoisePeerMachineKey, ServerNoiseKey, inner_router as machine_router},
        test_support::{MockIpAllocator, MockRedeemer},
    };

    struct FixedDebugAllocator;

    impl IpAllocator for FixedDebugAllocator {
        fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
            Ok(Ipv4Addr::new(100, 64, 0, 42))
        }

        fn allocate_ipv6(&self, _node_key_hex: &str) -> Result<Option<Ipv6Addr>, AllocError> {
            Ok(Some("fd7a:115c:a1e0::42".parse().unwrap()))
        }
    }

    struct Ipv6OnlyDebugAllocator;

    impl IpAllocator for Ipv6OnlyDebugAllocator {
        fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
            Err(AllocError::Internal(
                "IPv4 allocator should not be called when disabled".into(),
            ))
        }

        fn ipv4_enabled(&self) -> bool {
            false
        }

        fn allocate_ipv6(&self, _node_key_hex: &str) -> Result<Option<Ipv6Addr>, AllocError> {
            Ok(Some("fd7a:115c:a1e0::77".parse().unwrap()))
        }
    }

    struct FailingDatabaseHealth;

    #[async_trait::async_trait]
    impl DatabaseHealthCheck for FailingDatabaseHealth {
        async fn ping(&self) -> Result<(), String> {
            Err("forced offline".to_string())
        }
    }

    async fn admin_service() -> HeadscaleAdminService {
        admin_service_with_machines().await.0
    }

    async fn admin_service_with_machines() -> (HeadscaleAdminService, Arc<MachineRegistry>) {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let machines = Arc::new(MachineRegistry::new());
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines.clone())),
        )
        .with_database_pool(db.pool().clone());
        let service = service.with_policy_pool(db.pool().clone());
        (service, machines)
    }

    async fn admin_service_with_api_keys() -> (HeadscaleAdminService, Arc<PersistentApiKeyAdmin>) {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let api_keys = Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone()));
        let machines = Arc::new(MachineRegistry::new());
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            api_keys.clone(),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        )
        .with_database_pool(db.pool().clone());
        let service = service.with_policy_pool(db.pool().clone());
        (service, api_keys)
    }

    async fn admin_service_with_persistent_machines()
    -> (HeadscaleAdminService, headscale_db::Database) {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        (
            admin_service_with_persistent_machines_for_pool(db.pool().clone()),
            db,
        )
    }

    fn admin_service_with_persistent_machines_for_pool(
        pool: sqlx::SqlitePool,
    ) -> HeadscaleAdminService {
        let users = Arc::new(PersistentUserAdmin::new(pool.clone()));
        let machines =
            Arc::new(PersistentMachineAdmin::new(pool.clone()).with_user_admin(users.clone()));
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(pool.clone())),
            Arc::new(PersistentPreauthAdmin::new_for_test(pool.clone()).with_user_admin(users)),
            PolicyStore::new(),
            machines,
        )
        .with_database_pool(pool.clone());
        service.with_policy_pool(pool)
    }

    async fn admin_service_with_policy_db() -> (HeadscaleAdminService, headscale_db::Database) {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new()))),
        )
        .with_database_pool(db.pool().clone())
        .with_policy_pool(db.pool().clone());
        (service, db)
    }

    /// Create a user through the gRPC surface and return its numeric id.
    async fn create_test_user(service: &HeadscaleAdminService, name: &str) -> u64 {
        service
            .create_user(Request::new(CreateUserRequest {
                name: name.into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("created user")
            .id
    }

    fn fixture_machine(id: &str, user: &str, name: &str) -> MachineRecord {
        MachineRecord::new_at(
            Utc::now(),
            id.to_string(),
            "bb".repeat(32),
            user.to_string(),
            name.to_string(),
            Ipv4Addr::new(100, 64, 0, 7),
            false,
        )
    }

    fn fixture_machine_with_routes(
        id: &str,
        user: &str,
        name: &str,
        routes: Vec<String>,
    ) -> MachineRecord {
        let mut machine = fixture_machine(id, user, name);
        machine.available_routes = routes;
        machine
    }

    fn route_via_policy(alice_via: &str, bob_via: &str) -> String {
        format!(
            r#"{{
              "tagOwners": {{
                "tag:router-a": ["router@"],
                "tag:router-b": ["router@"]
              }},
              "grants": [
                {{
                  "src": ["alice@"],
                  "dst": ["10.77.0.0/24"],
                  "ip": ["*"],
                  "via": ["{alice_via}"]
                }},
                {{
                  "src": ["bob@"],
                  "dst": ["10.77.0.0/24"],
                  "ip": ["*"],
                  "via": ["{bob_via}"]
                }}
              ]
            }}"#
        )
    }

    struct RouteViaNodeSpec {
        node_key: String,
        machine_key: String,
        user: String,
        hostname: String,
        ipv4: Ipv4Addr,
        tags: Vec<String>,
        routes: Vec<String>,
    }

    fn insert_route_via_node(machines: &MachineRegistry, spec: RouteViaNodeSpec) -> PeerMapNode {
        let mut rec = MachineRecord::new_at(
            Utc::now(),
            spec.node_key.clone(),
            spec.machine_key,
            spec.user.clone(),
            spec.hostname,
            spec.ipv4,
            false,
        );
        rec.available_routes.clone_from(&spec.routes);
        rec.approved_routes.clone_from(&spec.routes);
        rec.forced_tags.clone_from(&spec.tags);
        machines.upsert(spec.node_key.clone(), rec);

        PeerMapNode {
            id: stable_id_from_key(&spec.node_key),
            addr: spec.ipv4.to_string(),
            addrs: vec![spec.ipv4.to_string()],
            user: Some(spec.user),
            tags: spec.tags,
            routes: spec.routes,
        }
    }

    fn assert_via_routes(
        policy: &PolicyStore,
        nodes: &[PeerMapNode],
        owners: &std::collections::BTreeMap<u64, u64>,
        viewer_key: &str,
        peer_key: &str,
        include: &[String],
        exclude: &[String],
    ) {
        let got = policy
            .via_routes_for_peer_with_user_ids(
                nodes,
                stable_id_from_key(viewer_key),
                stable_id_from_key(peer_key),
                owners,
            )
            .expect("policy is loaded");
        assert_eq!(got.include.as_slice(), include);
        assert_eq!(got.exclude.as_slice(), exclude);
    }

    fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        while *pos < buf.len() {
            let byte = buf[*pos];
            *pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err("protobuf varint overflow".to_string());
            }
        }
        Err("truncated protobuf varint".to_string())
    }

    fn for_each_field<'a>(
        buf: &'a [u8],
        mut f: impl FnMut(u64, u64, &'a [u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut pos = 0usize;
        while pos < buf.len() {
            let tag = read_varint(buf, &mut pos)?;
            let number = tag >> 3;
            let wire_type = tag & 0x07;
            match wire_type {
                0 => {
                    let start = pos;
                    let _ = read_varint(buf, &mut pos)?;
                    f(number, wire_type, &buf[start..pos])?;
                }
                1 => {
                    let end = pos.checked_add(8).ok_or("protobuf field offset overflow")?;
                    let data = buf
                        .get(pos..end)
                        .ok_or("truncated fixed64 protobuf field")?;
                    pos = end;
                    f(number, wire_type, data)?;
                }
                2 => {
                    let len = usize::try_from(read_varint(buf, &mut pos)?)
                        .map_err(|_| "protobuf field length overflow")?;
                    let end = pos
                        .checked_add(len)
                        .ok_or("protobuf field offset overflow")?;
                    let data = buf
                        .get(pos..end)
                        .ok_or("truncated length-delimited protobuf field")?;
                    pos = end;
                    f(number, wire_type, data)?;
                }
                5 => {
                    let end = pos.checked_add(4).ok_or("protobuf field offset overflow")?;
                    let data = buf
                        .get(pos..end)
                        .ok_or("truncated fixed32 protobuf field")?;
                    pos = end;
                    f(number, wire_type, data)?;
                }
                other => return Err(format!("unsupported protobuf wire type {other}")),
            }
        }
        Ok(())
    }

    fn length_fields(buf: &[u8], wanted: u64) -> Result<Vec<&[u8]>, String> {
        let mut out = Vec::new();
        for_each_field(buf, |number, wire_type, data| {
            if number == wanted && wire_type == 2 {
                out.push(data);
            }
            Ok(())
        })?;
        Ok(out)
    }

    fn string_field(buf: &[u8], wanted: u64) -> Result<Option<String>, String> {
        length_fields(buf, wanted)?
            .into_iter()
            .next()
            .map(|bytes| {
                std::str::from_utf8(bytes)
                    .map(str::to_string)
                    .map_err(|err| format!("invalid descriptor string: {err}"))
            })
            .transpose()
    }

    fn http_rule_for_method(method_name: &str) -> HttpRule {
        const GOOGLE_API_HTTP_EXTENSION_FIELD: u64 = 72_295_728;

        for file in length_fields(crate::generated::FILE_DESCRIPTOR_SET, 1)
            .expect("descriptor set fields parse")
        {
            if string_field(file, 1).expect("file name parses").as_deref()
                != Some("headscale.proto")
            {
                continue;
            }
            for service in length_fields(file, 6).expect("service fields parse") {
                if string_field(service, 1)
                    .expect("service name parses")
                    .as_deref()
                    != Some("HeadscaleService")
                {
                    continue;
                }
                for method in length_fields(service, 2).expect("method fields parse") {
                    if string_field(method, 1)
                        .expect("method name parses")
                        .as_deref()
                        != Some(method_name)
                    {
                        continue;
                    }
                    let options = length_fields(method, 4)
                        .expect("method options parse")
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| panic!("{method_name} has no method options"));
                    let http_rule = length_fields(options, GOOGLE_API_HTTP_EXTENSION_FIELD)
                        .expect("method option extensions parse")
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| panic!("{method_name} has no google.api.http option"));
                    return HttpRule::decode(http_rule)
                        .unwrap_or_else(|err| panic!("{method_name} http rule decodes: {err}"));
                }
            }
        }

        panic!("{method_name} not found in headscale service descriptor");
    }

    fn assert_http_rule(method: &str, expected_pattern: Pattern, expected_body: &str) {
        let rule = http_rule_for_method(method);
        assert_eq!(rule.pattern, Some(expected_pattern), "{method} pattern");
        assert_eq!(rule.body, expected_body, "{method} body");
        assert!(rule.response_body.is_empty(), "{method} response_body");
        assert!(
            rule.additional_bindings.is_empty(),
            "{method} additional bindings"
        );
    }

    #[tokio::test]
    async fn upstream_user_grpc_create_list_rename_delete() {
        let service = admin_service().await;

        let created = service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: "Alice Smith".into(),
                email: "alice@example.com".into(),
                picture_url: "https://example.com/alice.png".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("created user");
        assert_eq!(created.id, 1);
        assert_eq!(created.name, "alice");
        assert_eq!(created.display_name, "Alice Smith");
        assert_eq!(created.email, "alice@example.com");
        assert_eq!(created.profile_pic_url, "https://example.com/alice.png");
        assert!(created.created_at.is_some());

        let listed = service
            .list_users(Request::new(ListUsersRequest {
                id: 0,
                name: "alice".into(),
                email: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.users.len(), 1);
        assert_eq!(listed.users[0].id, created.id);

        let renamed = service
            .rename_user(Request::new(RenameUserRequest {
                old_id: created.id,
                new_name: "bob".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("renamed user");
        assert_eq!(renamed.id, created.id);
        assert_eq!(renamed.name, "bob");

        let listed = service
            .list_users(Request::new(ListUsersRequest {
                id: created.id,
                name: String::new(),
                email: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.users.len(), 1);
        assert_eq!(listed.users[0].name, "bob");

        service
            .delete_user(Request::new(DeleteUserRequest { id: created.id }))
            .await
            .unwrap();

        let listed = service
            .list_users(Request::new(ListUsersRequest {
                id: 0,
                name: String::new(),
                email: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.users.len(), 0);
    }

    #[tokio::test]
    async fn upstream_user_grpc_reports_exact_error_text() {
        enum Call {
            CreateDuplicate,
            RenameMissing,
            RenameDuplicate,
            DeleteMissing,
            ListMissingId,
            ListMissingName,
            ListMissingEmail,
        }

        enum Expected {
            Error {
                code: tonic::Code,
                message: &'static str,
            },
            EmptyList,
        }

        let cases = [
            (
                "create duplicate",
                Call::CreateDuplicate,
                Expected::Error {
                    code: tonic::Code::Internal,
                    message: "creating user: creating user: constraint failed: UNIQUE constraint failed: users.name (2067)",
                },
            ),
            (
                "rename missing id",
                Call::RenameMissing,
                Expected::Error {
                    code: tonic::Code::Unknown,
                    message: "user not found",
                },
            ),
            (
                "rename duplicate name",
                Call::RenameDuplicate,
                Expected::Error {
                    code: tonic::Code::Unknown,
                    message: "updating user: constraint failed: UNIQUE constraint failed: users.name (2067)",
                },
            ),
            (
                "delete missing id",
                Call::DeleteMissing,
                Expected::Error {
                    code: tonic::Code::Unknown,
                    message: "user not found",
                },
            ),
            ("list missing id", Call::ListMissingId, Expected::EmptyList),
            (
                "list missing name",
                Call::ListMissingName,
                Expected::EmptyList,
            ),
            (
                "list missing email",
                Call::ListMissingEmail,
                Expected::EmptyList,
            ),
        ];

        for (name, call, expected) in cases {
            let service = admin_service().await;
            let result = match call {
                Call::CreateDuplicate => {
                    service
                        .create_user(Request::new(CreateUserRequest {
                            name: "alice".into(),
                            display_name: String::new(),
                            email: String::new(),
                            picture_url: String::new(),
                        }))
                        .await
                        .unwrap();
                    service
                        .create_user(Request::new(CreateUserRequest {
                            name: "alice".into(),
                            display_name: String::new(),
                            email: String::new(),
                            picture_url: String::new(),
                        }))
                        .await
                        .map(|_| Vec::new())
                }
                Call::RenameMissing => service
                    .rename_user(Request::new(RenameUserRequest {
                        old_id: 99,
                        new_name: "alice".into(),
                    }))
                    .await
                    .map(|_| Vec::new()),
                Call::RenameDuplicate => {
                    let alice = service
                        .create_user(Request::new(CreateUserRequest {
                            name: "alice".into(),
                            display_name: String::new(),
                            email: String::new(),
                            picture_url: String::new(),
                        }))
                        .await
                        .unwrap()
                        .into_inner()
                        .user
                        .expect("alice");
                    service
                        .create_user(Request::new(CreateUserRequest {
                            name: "bob".into(),
                            display_name: String::new(),
                            email: String::new(),
                            picture_url: String::new(),
                        }))
                        .await
                        .unwrap();
                    service
                        .rename_user(Request::new(RenameUserRequest {
                            old_id: alice.id,
                            new_name: "bob".into(),
                        }))
                        .await
                        .map(|_| Vec::new())
                }
                Call::DeleteMissing => service
                    .delete_user(Request::new(DeleteUserRequest { id: 99 }))
                    .await
                    .map(|_| Vec::new()),
                Call::ListMissingId => service
                    .list_users(Request::new(ListUsersRequest {
                        id: 99,
                        name: String::new(),
                        email: String::new(),
                    }))
                    .await
                    .map(|response| response.into_inner().users),
                Call::ListMissingName => service
                    .list_users(Request::new(ListUsersRequest {
                        id: 0,
                        name: "missing".into(),
                        email: String::new(),
                    }))
                    .await
                    .map(|response| response.into_inner().users),
                Call::ListMissingEmail => service
                    .list_users(Request::new(ListUsersRequest {
                        id: 0,
                        name: String::new(),
                        email: "missing@example.com".into(),
                    }))
                    .await
                    .map(|response| response.into_inner().users),
            };

            match expected {
                Expected::Error { code, message } => {
                    let err = result.unwrap_err();
                    assert_eq!(err.code(), code, "{name}");
                    assert_eq!(err.message(), message, "{name}");
                }
                Expected::EmptyList => {
                    let users = result.unwrap_or_else(|err| panic!("{name}: {err}"));
                    assert!(users.is_empty(), "{name}");
                }
            }
        }
    }

    #[tokio::test]
    async fn upstream_user_grpc_list_users_selector_priority() {
        let service = admin_service().await;
        let alice = service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: "alice@example.com".into(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("alice");
        let bob = service
            .create_user(Request::new(CreateUserRequest {
                name: "bob".into(),
                display_name: String::new(),
                email: "bob@example.com".into(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("bob");

        let listed = service
            .list_users(Request::new(ListUsersRequest {
                id: bob.id,
                name: "alice".into(),
                email: "bob@example.com".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.users.len(), 1);
        assert_eq!(listed.users[0].id, alice.id);

        let listed = service
            .list_users(Request::new(ListUsersRequest {
                id: bob.id,
                name: String::new(),
                email: "alice@example.com".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.users.len(), 1);
        assert_eq!(listed.users[0].id, alice.id);
    }

    #[tokio::test]
    async fn upstream_user_grpc_delete_refuses_user_owned_nodes_but_allows_tagged_nodes() {
        // Go's DestroyUser checks the nodes table by user_id (ListNodesByUser);
        // tagged nodes have user_id NULL and never block deletion. Use the
        // persistent composition so the node actually lives in that table (a
        // node held only in the volatile registry is invisible to the check).
        let (service, db) = admin_service_with_persistent_machines().await;
        let alice = service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("alice");

        let node_key = "ad".repeat(32);
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "ae".repeat(32)),
                node_key: format!("nodekey:{node_key}"),
                host_info: serde_json::json!({"Hostname": "alpha"}),
                ipv4: Some("100.64.0.7".into()),
                hostname: "alpha".into(),
                given_name: "alpha".into(),
                user_id: Some(i64::try_from(alice.id).unwrap()),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let node_id = 1;

        let err = service
            .delete_user(Request::new(DeleteUserRequest { id: alice.id }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "user not empty: node(s) found");

        service
            .set_policy(Request::new(SetPolicyRequest {
                policy: r#"{"tagOwners":{"tag:server":["alice@"]}}"#.into(),
            }))
            .await
            .expect("tag owner policy");
        service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap();

        service
            .delete_user(Request::new(DeleteUserRequest { id: alice.id }))
            .await
            .unwrap();

        let listed = service
            .list_users(Request::new(ListUsersRequest {
                id: 0,
                name: String::new(),
                email: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.users.len(), 0);

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let tagged = listed
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .expect("tagged node survives user deletion");
        assert_eq!(
            tagged.user.as_ref().expect("tagged node user").name,
            "tagged-devices"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn upstream_grpc_api_key_auth_mode_enforces_bearer_token() {
        let (service, api_keys) = admin_service_with_api_keys().await;
        let service = service.require_api_key_auth();
        let _mounted = service.clone().into_service_server();
        let _auth_mounted = service.clone().into_authenticated_service_server();

        // Go's grpcAuthenticationInterceptor (app.go): a token that fails to
        // parse/look up (empty, unknown, malformed) makes ValidateAPIKey return
        // an error => `Internal "validating token"`; only a well-formed but
        // expired key yields `Unauthenticated "invalid token"`. Verified against
        // the real v0.29.5 server (bad key => Internal, expired key =>
        // Unauthenticated).
        for (name, metadata, expected_code, expected_message) in [
            (
                "missing authorization metadata",
                None,
                tonic::Code::Unauthenticated,
                "authorization token not supplied",
            ),
            (
                "opaque authorization metadata",
                Some(AsciiMetadataValue::try_from(&b"Bearer \xfa"[..]).unwrap()),
                tonic::Code::Unauthenticated,
                "invalid authorization metadata",
            ),
            (
                "non-bearer authorization scheme",
                Some("Token abc".parse().unwrap()),
                tonic::Code::Unauthenticated,
                r#"missing "Bearer " prefix in "Authorization" header"#,
            ),
            (
                "bearer prefix without required space",
                Some("Bearer".parse().unwrap()),
                tonic::Code::Unauthenticated,
                r#"missing "Bearer " prefix in "Authorization" header"#,
            ),
            (
                "lowercase bearer prefix",
                Some("bearer invalid".parse().unwrap()),
                tonic::Code::Unauthenticated,
                r#"missing "Bearer " prefix in "Authorization" header"#,
            ),
            (
                "empty bearer token",
                Some("Bearer ".parse().unwrap()),
                tonic::Code::Internal,
                "validating token",
            ),
            (
                "invalid bearer token",
                Some("Bearer invalid".parse().unwrap()),
                tonic::Code::Internal,
                "validating token",
            ),
        ] {
            let mut request = Request::new(HealthRequest {});
            if let Some(metadata) = metadata {
                request.metadata_mut().insert("authorization", metadata);
            }
            let err = service
                .health(request)
                .await
                .expect_err(&format!("{name} unexpectedly authenticated"));
            assert_eq!(err.code(), expected_code, "{name}");
            assert_eq!(err.message(), expected_message, "{name}");
        }

        let created = api_keys
            .mint(ApiKeyMintRequest { expiration: None })
            .await
            .expect("mint api key");
        let mut valid = Request::new(HealthRequest {});
        valid.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", created.api_key).parse().unwrap(),
        );
        let health = service.health(valid).await.unwrap().into_inner();
        assert!(health.database_connectivity);

        // A well-formed but expired key is the only `valid == false` path in
        // Go's interceptor => `Unauthenticated "invalid token"`.
        let expired_at = chrono::Utc::now() - chrono::Duration::hours(1);
        let expired = api_keys
            .mint_precise(
                ApiKeyMintRequest {
                    expiration: Some(expired_at.timestamp()),
                },
                Some(expired_at),
            )
            .await
            .expect("mint expired api key");
        let mut expired_request = Request::new(HealthRequest {});
        expired_request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", expired.api_key).parse().unwrap(),
        );
        let err = service
            .health(expired_request)
            .await
            .expect_err("expired key unexpectedly authenticated");
        assert_eq!(err.code(), tonic::Code::Unauthenticated, "expired key");
        assert_eq!(err.message(), "invalid token", "expired key");
    }

    #[test]
    fn upstream_grpc_public_descriptor_advertises_only_headscale_service() {
        let descriptors = HeadscaleAdminService::public_file_descriptor_set()
            .expect("public descriptor set decodes");
        let service = descriptors
            .file
            .iter()
            .filter(|file| file.package.as_deref() == Some("headscale.v1"))
            .flat_map(|file| file.service.iter())
            .find(|service| service.name.as_deref() == Some("HeadscaleService"))
            .expect("HeadscaleService present in descriptor set");
        let methods = service
            .method
            .iter()
            .filter_map(|method| method.name.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(
            methods,
            vec![
                "CreateUser",
                "RenameUser",
                "DeleteUser",
                "ListUsers",
                "CreatePreAuthKey",
                "ExpirePreAuthKey",
                "DeletePreAuthKey",
                "ListPreAuthKeys",
                "DebugCreateNode",
                "GetNode",
                "SetTags",
                "SetApprovedRoutes",
                "RegisterNode",
                "DeleteNode",
                "ExpireNode",
                "RenameNode",
                "ListNodes",
                "BackfillNodeIPs",
                "AuthRegister",
                "AuthApprove",
                "AuthReject",
                "CreateApiKey",
                "ExpireApiKey",
                "ListApiKeys",
                "DeleteApiKey",
                "GetPolicy",
                "SetPolicy",
                "CheckPolicy",
                "Health",
            ],
            "public descriptor must stay on the current upstream HeadscaleService surface"
        );

        let services = descriptors
            .file
            .iter()
            .filter(|file| file.package.as_deref() == Some("headscale.v1"))
            .flat_map(|file| file.service.iter())
            .filter_map(|service| service.name.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(services, vec!["HeadscaleService"]);

        let file_names = descriptors
            .file
            .iter()
            .filter_map(|file| file.name.as_deref())
            .collect::<Vec<_>>();
        assert!(file_names.contains(&"headscale/v1/headscale.proto"));
        assert!(file_names.contains(&"headscale/v1/node.proto"));
        assert!(file_names.contains(&"headscale/v1/auth.proto"));
        assert!(!file_names.contains(&"headscale.proto"));
        assert!(!file_names.contains(&"node.proto"));
        assert!(!file_names.contains(&"auth.proto"));
        assert!(file_names.contains(&"google/api/annotations.proto"));
        assert!(file_names.contains(&"google/api/http.proto"));
        assert!(file_names.contains(&"google/protobuf/descriptor.proto"));
        assert!(!file_names.contains(&"resources.proto"));
        assert!(!file_names.contains(&"payments.proto"));
        assert!(!file_names.contains(&"health.proto"));

        let headscale_file = descriptors
            .file
            .iter()
            .find(|file| file.name.as_deref() == Some("headscale/v1/headscale.proto"))
            .expect("headscale/v1/headscale.proto present");
        assert!(
            headscale_file
                .dependency
                .contains(&"google/api/annotations.proto".to_string()),
            "public descriptor should preserve grpc-gateway annotation dependency"
        );
        assert!(
            headscale_file
                .dependency
                .contains(&"headscale/v1/auth.proto".to_string()),
            "public descriptor dependencies should use upstream filenames"
        );

        let _reflection =
            HeadscaleAdminService::reflection_service().expect("reflection service builds");
    }

    #[test]
    fn upstream_grpc_public_descriptor_preserves_http_annotations() {
        let cases = [
            ("CreateUser", Pattern::Post("/api/v1/user".into()), "*"),
            (
                "RenameUser",
                Pattern::Post("/api/v1/user/{old_id}/rename/{new_name}".into()),
                "",
            ),
            (
                "DeleteUser",
                Pattern::Delete("/api/v1/user/{id}".into()),
                "",
            ),
            ("ListUsers", Pattern::Get("/api/v1/user".into()), ""),
            (
                "CreatePreAuthKey",
                Pattern::Post("/api/v1/preauthkey".into()),
                "*",
            ),
            (
                "ExpirePreAuthKey",
                Pattern::Post("/api/v1/preauthkey/expire".into()),
                "*",
            ),
            (
                "DeletePreAuthKey",
                Pattern::Delete("/api/v1/preauthkey".into()),
                "",
            ),
            (
                "ListPreAuthKeys",
                Pattern::Get("/api/v1/preauthkey".into()),
                "",
            ),
            (
                "DebugCreateNode",
                Pattern::Post("/api/v1/debug/node".into()),
                "*",
            ),
            ("GetNode", Pattern::Get("/api/v1/node/{node_id}".into()), ""),
            (
                "SetTags",
                Pattern::Post("/api/v1/node/{node_id}/tags".into()),
                "*",
            ),
            (
                "SetApprovedRoutes",
                Pattern::Post("/api/v1/node/{node_id}/approve_routes".into()),
                "*",
            ),
            (
                "RegisterNode",
                Pattern::Post("/api/v1/node/register".into()),
                "",
            ),
            (
                "DeleteNode",
                Pattern::Delete("/api/v1/node/{node_id}".into()),
                "",
            ),
            (
                "ExpireNode",
                Pattern::Post("/api/v1/node/{node_id}/expire".into()),
                "",
            ),
            (
                "RenameNode",
                Pattern::Post("/api/v1/node/{node_id}/rename/{new_name}".into()),
                "",
            ),
            ("ListNodes", Pattern::Get("/api/v1/node".into()), ""),
            (
                "BackfillNodeIPs",
                Pattern::Post("/api/v1/node/backfillips".into()),
                "",
            ),
            (
                "AuthRegister",
                Pattern::Post("/api/v1/auth/register".into()),
                "*",
            ),
            (
                "AuthApprove",
                Pattern::Post("/api/v1/auth/approve".into()),
                "*",
            ),
            (
                "AuthReject",
                Pattern::Post("/api/v1/auth/reject".into()),
                "*",
            ),
            ("CreateApiKey", Pattern::Post("/api/v1/apikey".into()), "*"),
            (
                "ExpireApiKey",
                Pattern::Post("/api/v1/apikey/expire".into()),
                "*",
            ),
            ("ListApiKeys", Pattern::Get("/api/v1/apikey".into()), ""),
            (
                "DeleteApiKey",
                Pattern::Delete("/api/v1/apikey/{prefix}".into()),
                "",
            ),
            ("GetPolicy", Pattern::Get("/api/v1/policy".into()), ""),
            ("SetPolicy", Pattern::Put("/api/v1/policy".into()), "*"),
            (
                "CheckPolicy",
                Pattern::Post("/api/v1/policy/check".into()),
                "*",
            ),
            ("Health", Pattern::Get("/api/v1/health".into()), ""),
        ];

        for (method, pattern, body) in cases {
            assert_http_rule(method, pattern, body);
        }
    }

    #[tokio::test]
    async fn upstream_grpc_reflection_advertises_only_public_headscale_service() {
        let reflection =
            HeadscaleAdminService::reflection_service().expect("reflection service builds");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reflection listener");
        let local_addr = listener.local_addr().expect("local reflection address");
        let incoming = stream::unfold(listener, |listener| async {
            match listener.accept().await {
                Ok((socket, _addr)) => Some((Ok::<_, std::io::Error>(socket), listener)),
                Err(err) => Some((Err(err), listener)),
            }
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(reflection)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("reflection server exits cleanly");
        });

        let channel = Endpoint::from_shared(format!("http://{local_addr}"))
            .expect("reflection endpoint")
            .connect()
            .await
            .expect("connect reflection client");
        let mut client = ServerReflectionClient::new(channel);
        let requests = stream::iter([
            ServerReflectionRequest {
                host: String::new(),
                message_request: Some(MessageRequest::ListServices(String::new())),
            },
            ServerReflectionRequest {
                host: String::new(),
                message_request: Some(MessageRequest::FileByFilename(
                    "headscale/v1/headscale.proto".into(),
                )),
            },
        ]);
        let mut responses = client
            .server_reflection_info(Request::new(requests))
            .await
            .expect("reflection request starts")
            .into_inner();

        let response = responses
            .next()
            .await
            .expect("list services response")
            .expect("list services succeeds");
        let service_names = match response
            .message_response
            .expect("list services message response")
        {
            MessageResponse::ListServicesResponse(response) => response
                .service
                .into_iter()
                .map(|service| service.name)
                .collect::<Vec<_>>(),
            other => panic!("unexpected reflection response: {other:?}"),
        };
        assert_eq!(service_names, vec!["headscale.v1.HeadscaleService"]);

        let response = responses
            .next()
            .await
            .expect("upstream filename descriptor response")
            .expect("upstream filename descriptor is served");
        let descriptors = match response
            .message_response
            .expect("file descriptor message response")
        {
            MessageResponse::FileDescriptorResponse(response) => response
                .file_descriptor_proto
                .into_iter()
                .map(|bytes| {
                    prost_types::FileDescriptorProto::decode(bytes.as_slice())
                        .expect("file descriptor decodes")
                })
                .collect::<Vec<_>>(),
            other => panic!("unexpected reflection response: {other:?}"),
        };
        let file_names = descriptors
            .iter()
            .filter_map(|file| file.name.as_deref())
            .collect::<Vec<_>>();
        assert!(file_names.contains(&"headscale/v1/headscale.proto"));
        assert!(!file_names.contains(&"headscale.proto"));

        drop(responses);

        let requests = stream::iter([ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::FileByFilename("headscale.proto".into())),
        }]);
        let mut responses = client
            .server_reflection_info(Request::new(requests))
            .await
            .expect("bare descriptor request starts")
            .into_inner();
        let err = responses
            .next()
            .await
            .expect("bare descriptor response")
            .expect_err("bare generated descriptor filename is not served");
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(err.message().contains("headscale.proto"));
        drop(responses);

        let requests = stream::iter([ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::FileByFilename("payments.proto".into())),
        }]);
        let mut responses = client
            .server_reflection_info(Request::new(requests))
            .await
            .expect("internal descriptor request starts")
            .into_inner();
        let err = responses
            .next()
            .await
            .expect("internal descriptor response")
            .expect_err("internal Octra descriptor is not served");
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(err.message().contains("payments.proto"));

        drop(responses);
        drop(client);
        let _ = shutdown_tx.send(());
        server.await.expect("reflection server task joins");
    }

    #[tokio::test]
    async fn upstream_auth_grpc_transport_error_envelopes_match_headscale_go() {
        let service = admin_service().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind headscale grpc listener");
        let local_addr = listener.local_addr().expect("local headscale grpc address");
        let incoming = stream::unfold(listener, |listener| async {
            match listener.accept().await {
                Ok((socket, _addr)) => Some((Ok::<_, std::io::Error>(socket), listener)),
                Err(err) => Some((Err(err), listener)),
            }
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_service_server())
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("headscale grpc server exits cleanly");
        });

        let mut client = HeadscaleServiceClient::connect(format!("http://{local_addr}"))
            .await
            .expect("connect headscale grpc client");

        enum Call {
            Register,
            Approve,
            Reject,
        }

        struct Case {
            name: &'static str,
            call: Call,
            auth_id: &'static str,
            expected_code: tonic::Code,
            expected_message: &'static str,
        }

        for case in [
            Case {
                name: "auth register bare short auth id",
                call: Call::Register,
                auth_id: "short",
                expected_code: tonic::Code::Unknown,
                expected_message: "auth ID has invalid prefix: expected prefix \"hskey-authreq-\"",
            },
            Case {
                name: "auth register prefixed long auth id",
                call: Call::Register,
                auth_id: "hskey-authreq-abcdefghijklmnopqrstuvwxy",
                expected_code: tonic::Code::Unknown,
                expected_message: "auth ID has invalid length: expected 38, got 39",
            },
            Case {
                name: "auth approve no pending session",
                call: Call::Approve,
                auth_id: "hskey-authreq-aaaaaaaaaaaaaaaaaaaaaaaa",
                expected_code: tonic::Code::NotFound,
                expected_message: "no pending auth session for auth_id hskey-authreq-aaaaaaaaaaaaaaaaaaaaaaaa",
            },
            Case {
                name: "auth approve bare auth id",
                call: Call::Approve,
                auth_id: "cccccccccccccccccccccccc",
                expected_code: tonic::Code::InvalidArgument,
                expected_message: "invalid auth_id: auth ID has invalid prefix: expected prefix \"hskey-authreq-\"",
            },
            Case {
                name: "auth reject no pending session",
                call: Call::Reject,
                auth_id: "hskey-authreq-bbbbbbbbbbbbbbbbbbbbbbbb",
                expected_code: tonic::Code::NotFound,
                expected_message: "no pending auth session for auth_id hskey-authreq-bbbbbbbbbbbbbbbbbbbbbbbb",
            },
            Case {
                name: "auth reject prefixed short auth id",
                call: Call::Reject,
                auth_id: "hskey-authreq-short",
                expected_code: tonic::Code::InvalidArgument,
                expected_message: "invalid auth_id: auth ID has invalid length: expected 38, got 19",
            },
        ] {
            let err = match case.call {
                Call::Register => client
                    .auth_register(Request::new(AuthRegisterRequest {
                        user: "alice".into(),
                        auth_id: case.auth_id.into(),
                    }))
                    .await
                    .map(|_| ()),
                Call::Approve => client
                    .auth_approve(Request::new(AuthApproveRequest {
                        auth_id: case.auth_id.into(),
                    }))
                    .await
                    .map(|_| ()),
                Call::Reject => client
                    .auth_reject(Request::new(AuthRejectRequest {
                        auth_id: case.auth_id.into(),
                    }))
                    .await
                    .map(|_| ()),
            }
            .unwrap_err();
            assert_eq!(err.code(), case.expected_code, "{}", case.name);
            assert_eq!(err.message(), case.expected_message, "{}", case.name);
        }

        drop(client);
        let _ = shutdown_tx.send(());
        server.await.expect("headscale grpc server task joins");
    }

    #[tokio::test]
    async fn upstream_node_grpc_debug_create_then_register() {
        let (service, _machines) = admin_service_with_machines().await;
        const REGISTRATION_ID: &str = "abcdefghijklmnopqrstuvwx";
        const AUTH_ID: &str = "hskey-authreq-abcdefghijklmnopqrstuvwx";
        assert_eq!(REGISTRATION_ID.len(), 24);

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let debug_node = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: AUTH_ID.into(),
                name: "debug-router".into(),
                routes: vec!["10.0.0.0/24".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("debug node");
        assert_eq!(debug_node.name, "debug-router");
        assert!(debug_node.node_key.starts_with("nodekey:"));
        assert!(debug_node.machine_key.starts_with("mkey:"));
        assert_eq!(debug_node.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(
            debug_node.register_method,
            RegisterMethod::Unspecified as i32
        );

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(listed.nodes.is_empty(), "debug node stays pending");

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: AUTH_ID.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.node_key, debug_node.node_key);
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        assert_eq!(registered.available_routes, [] as [String; 0]);

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.nodes.len(), 1);
        assert_eq!(listed.nodes[0].node_key, debug_node.node_key);

        let err = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: AUTH_ID.into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "node not found in registration cache");
    }

    #[tokio::test]
    async fn upstream_node_grpc_debug_create_preserves_single_exit_route_advertisement() {
        let (service, _machines) = admin_service_with_machines().await;
        const REGISTRATION_ID: &str = "debugexitrouteonly123456";
        const AUTH_ID: &str = "hskey-authreq-debugexitrouteonly123456";
        assert_eq!(REGISTRATION_ID.len(), 24);

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let debug_node = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: AUTH_ID.into(),
                name: "debug-exit-router".into(),
                routes: vec!["0.0.0.0/0".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("debug node");
        assert_eq!(debug_node.available_routes, vec!["0.0.0.0/0"]);
        assert_eq!(debug_node.approved_routes, [] as [String; 0]);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: AUTH_ID.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.node_key, debug_node.node_key);
        assert_eq!(registered.available_routes, [] as [String; 0]);
        assert_eq!(registered.approved_routes, [] as [String; 0]);
    }

    #[tokio::test]
    async fn upstream_node_grpc_register_node_uses_configured_allocator() {
        let (service, _machines) = admin_service_with_machines().await;
        let service = service.with_ip_allocator(Arc::new(FixedDebugAllocator));
        const REGISTRATION_ID: &str = "debugallocatorabcdefghij";
        assert_eq!(REGISTRATION_ID.len(), 24);
        let auth_id = format!("hskey-authreq-{REGISTRATION_ID}");

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let debug_node = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: auth_id.clone(),
                name: "debug-router".into(),
                routes: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("debug node");
        assert_eq!(debug_node.ip_addresses, [] as [String; 0]);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: auth_id,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.node_key, debug_node.node_key);
        assert_eq!(
            registered.ip_addresses,
            vec!["100.64.0.42".to_string(), "fd7a:115c:a1e0::42".to_string()]
        );
    }

    #[tokio::test]
    async fn upstream_node_grpc_register_node_accepts_ipv6_only_allocator() {
        let (service, _machines) = admin_service_with_machines().await;
        let service = service.with_ip_allocator(Arc::new(Ipv6OnlyDebugAllocator));
        const REGISTRATION_ID: &str = "debugv6onlyabcdefghijklm";
        assert_eq!(REGISTRATION_ID.len(), 24);
        let auth_id = format!("hskey-authreq-{REGISTRATION_ID}");

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let debug_node = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: auth_id.clone(),
                name: "debug-v6".into(),
                routes: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("debug node");
        assert_eq!(debug_node.ip_addresses, [] as [String; 0]);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: auth_id,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.ip_addresses, vec!["fd7a:115c:a1e0::77"]);
    }

    #[tokio::test]
    async fn upstream_auth_grpc_register_delegates_to_register_node() {
        let (service, _machines) = admin_service_with_machines().await;
        const REGISTRATION_ID: &str = "authregisterabcdefghijkl";
        assert_eq!(REGISTRATION_ID.len(), 24);

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let debug_node = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{REGISTRATION_ID}"),
                name: "auth-debug".into(),
                routes: vec!["10.42.0.0/24".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("debug node");

        let registered = service
            .auth_register(Request::new(AuthRegisterRequest {
                user: "alice".into(),
                auth_id: format!("hskey-authreq-{REGISTRATION_ID}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.node_key, debug_node.node_key);
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        // Go: routes live only on the DebugCreateNode echo; the registered node
        // advertises none (cached RegistrationData has no Hostinfo).
        assert_eq!(debug_node.available_routes, vec!["10.42.0.0/24"]);
        assert_eq!(registered.available_routes, [] as [String; 0]);

        let err = service
            .auth_register(Request::new(AuthRegisterRequest {
                user: "alice".into(),
                auth_id: "short".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(
            err.message(),
            "auth ID has invalid prefix: expected prefix \"hskey-authreq-\""
        );

        let err = service
            .auth_register(Request::new(AuthRegisterRequest {
                user: "alice".into(),
                auth_id: "hskey-authreq-short".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(
            err.message(),
            "auth ID has invalid length: expected 38, got 19"
        );
    }

    #[tokio::test]
    async fn upstream_register_grpc_missing_user_and_cache_errors_match_headscale_go() {
        let (service, _machines) = admin_service_with_machines().await;
        const REGISTRATION_ID: &str = "missingregister123456789";
        const AUTH_ID: &str = "hskey-authreq-missingregister123456789";
        assert_eq!(REGISTRATION_ID.len(), 24);

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        enum Call {
            RegisterNode,
            AuthRegister,
        }

        struct Case {
            name: &'static str,
            call: Call,
            user: &'static str,
            expected_message: &'static str,
        }

        for case in [
            Case {
                name: "register node missing user",
                call: Call::RegisterNode,
                user: "missing",
                expected_message: "looking up user: user not found",
            },
            Case {
                name: "register node missing cache entry",
                call: Call::RegisterNode,
                user: "alice",
                expected_message: "node not found in registration cache",
            },
            Case {
                name: "auth register missing user",
                call: Call::AuthRegister,
                user: "missing",
                expected_message: "looking up user: user not found",
            },
            Case {
                name: "auth register missing cache entry",
                call: Call::AuthRegister,
                user: "alice",
                expected_message: "node not found in registration cache",
            },
        ] {
            let err = match case.call {
                Call::RegisterNode => service
                    .register_node(Request::new(RegisterNodeRequest {
                        user: case.user.into(),
                        key: AUTH_ID.into(),
                    }))
                    .await
                    .unwrap_err(),
                Call::AuthRegister => service
                    .auth_register(Request::new(AuthRegisterRequest {
                        user: case.user.into(),
                        auth_id: AUTH_ID.into(),
                    }))
                    .await
                    .unwrap_err(),
            };
            assert_eq!(err.code(), tonic::Code::Unknown, "{}", case.name);
            assert_eq!(err.message(), case.expected_message, "{}", case.name);
        }
    }

    #[tokio::test]
    async fn upstream_auth_grpc_terminal_error_text_matches_headscale_go() {
        let service = admin_service().await;

        enum Call {
            Approve,
            Reject,
        }

        struct Case {
            name: &'static str,
            call: Call,
            auth_id: &'static str,
            expected_code: tonic::Code,
            expected_message: &'static str,
        }

        for case in [
            Case {
                name: "approve missing pending session",
                call: Call::Approve,
                auth_id: "hskey-authreq-aaaaaaaaaaaaaaaaaaaaaaaa",
                expected_code: tonic::Code::NotFound,
                expected_message: "no pending auth session for auth_id hskey-authreq-aaaaaaaaaaaaaaaaaaaaaaaa",
            },
            Case {
                name: "reject missing pending session",
                call: Call::Reject,
                auth_id: "hskey-authreq-bbbbbbbbbbbbbbbbbbbbbbbb",
                expected_code: tonic::Code::NotFound,
                expected_message: "no pending auth session for auth_id hskey-authreq-bbbbbbbbbbbbbbbbbbbbbbbb",
            },
            Case {
                name: "approve invalid prefixed auth id",
                call: Call::Approve,
                auth_id: "hskey-authreq-short",
                expected_code: tonic::Code::InvalidArgument,
                expected_message: "invalid auth_id: auth ID has invalid length: expected 38, got 19",
            },
            Case {
                name: "reject bare auth id",
                call: Call::Reject,
                auth_id: "cccccccccccccccccccccccc",
                expected_code: tonic::Code::InvalidArgument,
                expected_message: "invalid auth_id: auth ID has invalid prefix: expected prefix \"hskey-authreq-\"",
            },
        ] {
            let err = match case.call {
                Call::Approve => service
                    .auth_approve(Request::new(AuthApproveRequest {
                        auth_id: case.auth_id.into(),
                    }))
                    .await
                    .unwrap_err(),
                Call::Reject => service
                    .auth_reject(Request::new(AuthRejectRequest {
                        auth_id: case.auth_id.into(),
                    }))
                    .await
                    .unwrap_err(),
            };
            assert_eq!(err.code(), case.expected_code, "{}", case.name);
            assert_eq!(err.message(), case.expected_message, "{}", case.name);
        }
    }

    #[tokio::test]
    async fn upstream_auth_grpc_approve_and_reject_signal_pending_cache() {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let registration_cache = Arc::new(RegistrationCache::new());
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new()))),
        )
        .with_registration_cache(registration_cache.clone());

        let approve_id = "a".repeat(24);
        registration_cache.insert(
            approve_id.clone(),
            fixture_machine("approve-node", "", "approve-pending"),
        );
        let approve_wait = {
            let registration_cache = registration_cache.clone();
            let approve_id = approve_id.clone();
            tokio::spawn(async move { registration_cache.wait_for_registration(&approve_id).await })
        };
        tokio::task::yield_now().await;
        service
            .auth_approve(Request::new(AuthApproveRequest {
                auth_id: format!("hskey-authreq-{approve_id}"),
            }))
            .await
            .unwrap();
        assert!(matches!(
            approve_wait.await.unwrap(),
            RegistrationWaitOutcome::ApprovedWithoutNode
        ));

        let reject_id = "b".repeat(24);
        registration_cache.insert(
            reject_id.clone(),
            fixture_machine("reject-node", "", "reject-pending"),
        );
        let reject_wait = {
            let registration_cache = registration_cache.clone();
            let reject_id = reject_id.clone();
            tokio::spawn(async move { registration_cache.wait_for_registration(&reject_id).await })
        };
        tokio::task::yield_now().await;
        service
            .auth_reject(Request::new(AuthRejectRequest {
                auth_id: format!("hskey-authreq-{reject_id}"),
            }))
            .await
            .unwrap();
        match reject_wait.await.unwrap() {
            RegistrationWaitOutcome::Rejected(reason) => {
                assert_eq!(reason, "auth request rejected");
            }
            other => panic!("expected rejected wait outcome, got {other:?}"),
        }

        let err = service
            .auth_approve(Request::new(AuthApproveRequest {
                auth_id: "c".repeat(24),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "invalid auth_id: auth ID has invalid prefix: expected prefix \"hskey-authreq-\""
        );
    }

    #[tokio::test]
    async fn upstream_auth_grpc_register_rejects_completed_auth_sessions() {
        let (service, _db) = admin_service_with_persistent_machines().await;
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        for (auth_id, node_name, approve) in [
            (
                "hskey-authreq-cccccccccccccccccccccccc",
                "approved-terminal-node",
                true,
            ),
            (
                "hskey-authreq-dddddddddddddddddddddddd",
                "rejected-terminal-node",
                false,
            ),
        ] {
            service
                .debug_create_node(Request::new(DebugCreateNodeRequest {
                    user: "alice".into(),
                    key: auth_id.into(),
                    name: node_name.into(),
                    routes: Vec::new(),
                }))
                .await
                .unwrap();

            if approve {
                service
                    .auth_approve(Request::new(AuthApproveRequest {
                        auth_id: auth_id.into(),
                    }))
                    .await
                    .unwrap();
            } else {
                service
                    .auth_reject(Request::new(AuthRejectRequest {
                        auth_id: auth_id.into(),
                    }))
                    .await
                    .unwrap();
            }

            let err = service
                .auth_register(Request::new(AuthRegisterRequest {
                    user: "alice".into(),
                    auth_id: auth_id.into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::FailedPrecondition);
            assert_eq!(err.message(), "auth request already completed");
        }

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.nodes.len(), 0);
    }

    #[tokio::test]
    async fn upstream_auth_grpc_approve_and_reject_ignore_expired_cache_entries() {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let registration_cache = Arc::new(RegistrationCache::with_tuning(
            Duration::ZERO,
            Duration::from_secs(60),
        ));
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new()))),
        )
        .with_registration_cache(registration_cache.clone());

        let approve_id = "e".repeat(24);
        registration_cache.insert(
            approve_id.clone(),
            fixture_machine("approve-expired", "", "approve-expired"),
        );
        let err = service
            .auth_approve(Request::new(AuthApproveRequest {
                auth_id: format!("hskey-authreq-{approve_id}"),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(
            err.message(),
            "no pending auth session for auth_id hskey-authreq-eeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert!(registration_cache.is_empty());

        let reject_id = "f".repeat(24);
        registration_cache.insert(
            reject_id.clone(),
            fixture_machine("reject-expired", "", "reject-expired"),
        );
        let err = service
            .auth_reject(Request::new(AuthRejectRequest {
                auth_id: format!("hskey-authreq-{reject_id}"),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(
            err.message(),
            "no pending auth session for auth_id hskey-authreq-ffffffffffffffffffffffff"
        );
        assert!(registration_cache.is_empty());
    }

    #[tokio::test]
    async fn upstream_node_grpc_register_consumes_wire_web_registration_cache() {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let machines = Arc::new(MachineRegistry::new());
        let registration_cache = Arc::new(RegistrationCache::new());
        let policy = PolicyStore::new();
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone())
                    .with_user_admin(users.clone()),
            ),
            policy.clone(),
            Arc::new(WireMachineAdmin::new(machines.clone())),
        )
        .with_registration_cache(registration_cache.clone());

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let dir = tempfile::tempdir().unwrap();
        let state = WireState {
            server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap()),
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: machines.clone(),
            registration_store: None,
            registration_gate: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
            native_derp: None,
            policy: Arc::new(policy),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: Some("https://headscale.example".into()),
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: registration_cache.clone(),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
            mapresponse_debug: Arc::new(crate::tailscale_wire::MapResponseDebugStore::disabled()),
        };
        let app = machine_router(state.clone());
        let node_key_hex = "77".repeat(32);
        let machine_key_hex = "88".repeat(32);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Expiry": "2026-06-01T00:00:00Z",
            "Hostinfo": {
                "Hostname": "wire-pending",
                "RoutableIPs": ["10.77.0.0/24"],
                "RequestTags": ["tag:server", "tag:server"]
            }
        });
        let mut initial_req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        initial_req
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.clone()));
        let resp = app.clone().oneshot(initial_req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 8192).await.unwrap();
        let pending_response: crate::tailscale_wire::RegisterResponse =
            serde_json::from_slice(&raw).unwrap();
        assert!(!pending_response.machine_authorized);
        let auth_id = pending_response
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .expect("web AuthURL prefix");
        let registration_id = auth_id
            .strip_prefix("hskey-authreq-")
            .expect("AuthURL uses current-upstream auth ID prefix");
        assert_eq!(auth_id.len(), "hskey-authreq-".len() + 24);
        assert_eq!(registration_id.len(), 24);
        assert_eq!(registration_cache.len(), 1);

        let followup_body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Followup": pending_response.auth_url,
        });
        let followup_task = {
            let app = app.clone();
            let node_key_hex = node_key_hex.clone();
            let machine_key_hex = machine_key_hex.clone();
            tokio::spawn(async move {
                let mut req = axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/register"))
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&followup_body).unwrap(),
                    ))
                    .unwrap();
                req.extensions_mut()
                    .insert(NoisePeerMachineKey(machine_key_hex));
                app.oneshot(req).await.unwrap()
            })
        };
        tokio::task::yield_now().await;
        assert!(
            !followup_task.is_finished(),
            "follow-up register should wait for CLI approval"
        );

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: auth_id.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(registered.name, "wire-pending");
        assert_eq!(registered.tags, vec!["tag:server"]);
        assert!(registered.expiry.is_none());
        assert_eq!(registered.available_routes, vec!["10.77.0.0/24"]);
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        assert!(registration_cache.is_empty());
        let stored = machines.get(&node_key_hex).unwrap();
        assert!(stored.user.is_empty(), "tagged nodes have no user owner");
        assert_eq!(stored.forced_tags, vec!["tag:server"]);
        assert!(
            stored.expiry.is_none(),
            "tagged RequestTags registration disables node-key expiry"
        );

        let followup_resp = followup_task
            .await
            .expect("follow-up task should not panic");
        assert_eq!(followup_resp.status(), axum::http::StatusCode::OK);
        let raw = to_bytes(followup_resp.into_body(), 8192).await.unwrap();
        let followup_response: crate::tailscale_wire::RegisterResponse =
            serde_json::from_slice(&raw).unwrap();
        assert!(followup_response.machine_authorized);
        assert_eq!(followup_response.user.display_name, "Tagged Devices");
        assert_eq!(followup_response.login.login_name, "tagged-devices");
        assert_eq!(followup_response.auth_url, "");
    }

    #[tokio::test]
    async fn upstream_node_grpc_persistent_machines_use_numeric_go_ids() {
        let (service, db) = admin_service_with_persistent_machines().await;
        const REGISTRATION_ID: &str = "abcdefghijklmnopqrstuvwx";

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let pending = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{REGISTRATION_ID}"),
                name: "debug-router".into(),
                routes: vec!["10.0.0.0/24".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("pending node");
        assert_ne!(pending.id, 1, "pending wire-only node uses fallback id");

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{REGISTRATION_ID}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.id, 1);
        assert_eq!(registered.node_key, pending.node_key);
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        // Go's DebugCreateNode only echoes the routes back on the synthetic
        // response; the cached RegistrationData carries no Hostinfo, so the node
        // created by auth register advertises no routes (verified against the
        // real v0.29.5 server).
        assert_eq!(pending.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(registered.available_routes, [] as [String; 0]);

        let got = service
            .get_node(Request::new(GetNodeRequest { node_id: 1 }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("node");
        assert_eq!(got.id, 1);
        assert_eq!(got.user.as_ref().unwrap().id, 1);

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.nodes.len(), 1);
        assert_eq!(listed.nodes[0].id, 1);

        let renamed = service
            .rename_node(Request::new(RenameNodeRequest {
                node_id: 1,
                new_name: "debug-renamed".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("renamed node");
        // Go RenameNode only changes given_name; `name` keeps the client's raw
        // hostname (verified against the real v0.29.5 server).
        assert_eq!(renamed.name, "debug-router");
        assert_eq!(renamed.given_name, "debug-renamed");

        let given_name: String = sqlx::query_scalar("SELECT given_name FROM nodes WHERE id = 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(given_name, "debug-renamed");

        service
            .delete_node(Request::new(DeleteNodeRequest { node_id: 1 }))
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn upstream_node_grpc_persistent_machines_project_preauth_key() {
        let (service, db) = admin_service_with_persistent_machines().await;
        const REGISTRATION_ID: &str = "bcdefghijklmnopqrstuvwxy";

        let user = service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("created user");
        assert_ne!(
            user.created_at.as_ref().expect("creation timestamp").nanos,
            0
        );

        let created_key = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: user.id,
                reusable: true,
                ephemeral: true,
                expiration: Some(prost_types::Timestamp {
                    seconds: 4_102_444_800,
                    nanos: 123_456_789,
                }),
                acl_tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .pre_auth_key
            .expect("created preauth key");

        let pending = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{REGISTRATION_ID}"),
                name: "debug-router".into(),
                routes: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("pending node");
        assert!(pending.pre_auth_key.is_none());

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{REGISTRATION_ID}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert!(registered.pre_auth_key.is_none());

        sqlx::query("UPDATE nodes SET auth_key_id = ?, register_method = ? WHERE id = ?")
            .bind(i64::try_from(created_key.id).expect("preauth id fits i64"))
            .bind(headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY)
            .bind(i64::try_from(registered.id).expect("node id fits i64"))
            .execute(db.pool())
            .await
            .unwrap();

        let got = service
            .get_node(Request::new(GetNodeRequest {
                node_id: registered.id,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("node");
        assert_eq!(got.register_method, RegisterMethod::AuthKey as i32);
        let projected = got.pre_auth_key.as_ref().expect("preauth key");
        assert_eq!(projected.id, created_key.id);
        assert_eq!(projected.user.as_ref().unwrap().id, user.id);
        assert_eq!(projected.user.as_ref().unwrap().name, "alice");
        assert!(projected.reusable);
        assert!(projected.ephemeral);
        assert_eq!(projected.acl_tags, vec!["tag:server"]);
        assert_ne!(projected.key, created_key.key);
        assert!(projected.key.starts_with("hskey-auth-"));
        assert!(projected.key.ends_with("-***"));
        assert_eq!(
            projected.expiration.as_ref().unwrap().seconds,
            4_102_444_800
        );

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.nodes.len(), 1);
        let listed_key = listed.nodes[0].pre_auth_key.as_ref().expect("preauth key");
        assert_eq!(listed_key.id, created_key.id);
        assert_eq!(listed_key.key, projected.key);
        assert_eq!(listed_key.acl_tags, vec!["tag:server"]);
    }

    #[tokio::test]
    async fn upstream_node_grpc_persistent_register_rekeys_and_projects_live_registry() {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let machines =
            Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users.clone()));
        let wire_registry = Arc::new(MachineRegistry::new());
        let registration_cache = Arc::new(RegistrationCache::new());
        let policy = PolicyStore::new();
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone())
                    .with_user_admin(users.clone()),
            ),
            policy,
            machines,
        )
        .with_database_pool(db.pool().clone())
        .with_policy_pool(db.pool().clone())
        .with_registration_cache(registration_cache.clone())
        .with_wire_registry(wire_registry.clone());
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let machine_key_hex = "d1".repeat(32);
        let first_node_key = "d2".repeat(32);
        let second_node_key = "d3".repeat(32);
        let first_id = "w".repeat(24);
        let second_id = "x".repeat(24);
        let mut first = MachineRecord::new_at(
            Utc::now(),
            first_node_key.clone(),
            machine_key_hex.clone(),
            String::new(),
            "cli-first".into(),
            Ipv4Addr::new(100, 64, 0, 50),
            false,
        );
        first.forced_tags = vec!["tag:server".into()];
        first.available_routes = vec!["10.50.0.0/24".into()];
        first.expiry = Some(Utc::now() + chrono::Duration::days(30));
        registration_cache.insert(first_id.clone(), first);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{first_id}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.id, 1);
        assert_eq!(registered.node_key, format!("nodekey:{first_node_key}"));
        assert_eq!(registered.tags, vec!["tag:server"]);
        assert!(registered.expiry.is_none());
        assert!(wire_registry.get(&first_node_key).is_some());

        let mut second = MachineRecord::new_at(
            Utc::now(),
            second_node_key.clone(),
            machine_key_hex.clone(),
            String::new(),
            "cli-second".into(),
            Ipv4Addr::new(100, 64, 99, 99),
            false,
        );
        second.available_routes = vec!["10.60.0.0/24".into()];
        registration_cache.insert(second_id.clone(), second);

        let reauth = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{second_id}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("reauth node");

        assert_eq!(reauth.id, 1);
        assert_eq!(reauth.node_key, format!("nodekey:{second_node_key}"));
        assert!(
            reauth.tags.is_empty(),
            "empty requested tags clear old tags"
        );
        assert_eq!(reauth.ip_addresses, vec!["100.64.0.50"]);
        assert_eq!(reauth.available_routes, vec!["10.60.0.0/24"]);
        assert!(wire_registry.get(&first_node_key).is_none());
        let live = wire_registry.get(&second_node_key).unwrap();
        assert_eq!(live.machine_key_hex, machine_key_hex);
        assert_eq!(live.ipv4, Some(Ipv4Addr::new(100, 64, 0, 50)));
        assert_eq!(live.forced_tags, [] as [String; 0]);
        assert_eq!(live.available_routes, vec!["10.60.0.0/24"]);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), 1)
            .await
            .unwrap();
        assert_eq!(row.node_key, format!("nodekey:{second_node_key}"));
        assert_eq!(
            row.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_CLI
        );
        assert_eq!(row.ipv4.as_deref(), Some("100.64.0.50"));
        assert_eq!(row.tag_list(), Vec::<String>::new());
        assert_eq!(row.host_info_value()["RoutableIPs"][0], "10.60.0.0/24");
        assert!(registration_cache.is_empty());
    }

    #[tokio::test]
    async fn upstream_node_grpc_register_route_autoapproval_projects_policy_churn() {
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let machines =
            Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users.clone()));
        let wire_registry = Arc::new(MachineRegistry::new());
        let registration_cache = Arc::new(RegistrationCache::new());
        let policy = PolicyStore::new();
        let raw_policy = r#"{
            "autoApprovers": {
                "routes": {"10.70.0.0/16": ["alice@"]}
            }
        }"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone())
                    .with_user_admin(users.clone()),
            ),
            policy,
            machines,
        )
        .with_database_pool(db.pool().clone())
        .with_policy_pool(db.pool().clone())
        .with_registration_cache(registration_cache.clone())
        .with_wire_registry(wire_registry.clone());
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let node_key_hex = "a7".repeat(32);
        let machine_key_hex = "a8".repeat(32);
        let registration_id = "routeautoapprovalabcdefg";
        assert_eq!(registration_id.len(), 24);
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            node_key_hex.clone(),
            machine_key_hex,
            String::new(),
            "route-router".into(),
            Ipv4Addr::new(100, 64, 0, 70),
            false,
        );
        pending.available_routes = vec!["10.70.1.0/24".into()];
        registration_cache.insert(registration_id.to_string(), pending);
        let history_len = wire_registry.map_change_history().len();

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{registration_id}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");

        assert_eq!(registered.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(registered.available_routes, vec!["10.70.1.0/24"]);
        // Go's RegisterNode replies with the NodeView taken before
        // State.AutoApproveRoutes ran; the approval is visible afterwards
        // (verified in-process against v0.29.5: response approved=[], a
        // following GetNode approved=[10.70.1.0/24]).
        assert_eq!(registered.approved_routes, [] as [String; 0]);
        let got = service
            .get_node(Request::new(GetNodeRequest {
                node_id: registered.id,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("node after auto approval");
        assert_eq!(got.approved_routes, vec!["10.70.1.0/24"]);
        let live = wire_registry.get(&node_key_hex).expect("live projection");
        assert_eq!(live.approved_routes, vec!["10.70.1.0/24"]);

        let changes = wire_registry.map_change_history();
        let new_changes = &changes[history_len..];
        // Go: HandleNodeFromAuthPath returns reauthChange(.., policyChanged) =
        // PolicyChange because the new node's addresses join alice's
        // autoApprover set (a bare NodeAdded only when the policy is
        // unaffected); RegisterNode then runs State.AutoApproveRoutes, whose
        // SetApprovedRoutes always yields PolicyChange. Neither carries an
        // origin node.
        assert_eq!(
            new_changes.len(),
            2,
            "RegisterNode route autoapproval should project two policy changes"
        );
        for change in new_changes {
            assert_eq!(change.reason_labels(), vec!["policy change"]);
            assert_eq!(change.origin_node_id, None);
            assert!(change.content.include_policy);
            assert!(change.content.requires_runtime_peer_computation);
        }
    }

    #[tokio::test]
    async fn upstream_node_grpc_register_autoapproval_with_registry_owning_machine_admin() {
        // Production composition: the persistent machine admin owns the live
        // registry (headscale-cli server.rs), so RegisterNode's trailing
        // State.AutoApproveRoutes step mutates the live node through it.
        let db = headscale_db::Database::in_memory()
            .await
            .expect("open in-memory db");
        db.migrate().await.expect("migrate");
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let wire_registry = Arc::new(MachineRegistry::new());
        let machines = Arc::new(
            PersistentMachineAdmin::new(db.pool().clone())
                .with_user_admin(users.clone())
                .with_wire_registry(wire_registry.clone()),
        );
        let registration_cache = Arc::new(RegistrationCache::new());
        let policy = PolicyStore::new();
        let raw_policy = r#"{
            "autoApprovers": {
                "routes": {"10.71.0.0/16": ["alice@"]}
            }
        }"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone())
                    .with_user_admin(users.clone()),
            ),
            policy,
            machines,
        )
        .with_database_pool(db.pool().clone())
        .with_policy_pool(db.pool().clone())
        .with_registration_cache(registration_cache.clone())
        .with_wire_registry(wire_registry.clone());
        create_test_user(&service, "alice").await;

        let node_key_hex = "a9".repeat(32);
        let registration_id = "routeautoapprovalowned0001";
        let registration_id = &registration_id[..24];
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            node_key_hex.clone(),
            "aa".repeat(32),
            String::new(),
            "owned-router".into(),
            Ipv4Addr::new(100, 64, 0, 71),
            false,
        );
        pending.available_routes = vec!["10.71.1.0/24".into(), "10.72.1.0/24".into()];
        registration_cache.insert(registration_id.to_string(), pending);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{registration_id}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.approved_routes, [] as [String; 0]);

        let got = service
            .get_node(Request::new(GetNodeRequest {
                node_id: registered.id,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("node after auto approval");
        assert_eq!(got.available_routes, vec!["10.71.1.0/24", "10.72.1.0/24"]);
        assert_eq!(got.approved_routes, vec!["10.71.1.0/24"]);
        let live = wire_registry.get(&node_key_hex).expect("live projection");
        assert_eq!(live.approved_routes, vec!["10.71.1.0/24"]);
        let row = headscale_db::headscale_nodes::get_by_id(
            db.pool(),
            i64::try_from(registered.id).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(row.approved_route_list(), vec!["10.71.1.0/24"]);
        db.close().await;
    }

    #[tokio::test]
    async fn upstream_node_grpc_persistent_register_survives_restarted_service() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("headscale.db");
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let db = headscale_db::Database::new(&db_url)
            .await
            .expect("open file-backed db");
        db.migrate().await.expect("migrate");
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let machines =
            Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users.clone()));
        let wire_registry = Arc::new(MachineRegistry::new());
        let registration_cache = Arc::new(RegistrationCache::new());
        let policy = PolicyStore::new();
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone())
                    .with_user_admin(users.clone()),
            ),
            policy,
            machines.clone(),
        )
        .with_database_pool(db.pool().clone())
        .with_policy_pool(db.pool().clone())
        .with_registration_cache(registration_cache.clone())
        .with_wire_registry(wire_registry.clone());
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        let node_key_hex = "e1".repeat(32);
        let machine_key_hex = "e2".repeat(32);
        let registration_id = "r".repeat(24);
        // Go's typed disco keys require `discokey:` + 64 hex chars.
        let disco_key = format!("discokey:{}", "e3".repeat(32));
        // Go endpoints are netip.AddrPort: IPv6 needs the bracketed form.
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            node_key_hex.clone(),
            machine_key_hex.clone(),
            String::new(),
            "restart-web".into(),
            Ipv4Addr::new(100, 64, 0, 80),
            false,
        );
        pending.forced_tags = vec!["tag:server".into()];
        pending.available_routes = vec!["10.80.0.0/24".into()];
        pending.disco_key = Some(disco_key.clone());
        pending.endpoints = vec!["192.0.2.80:41641".into(), "[2001:db8::80]:41641".into()];
        pending.home_derp = 8;
        pending.os = "linux".into();
        pending.os_version = "6.10.0".into();
        pending.ssh_host_keys = vec!["ssh-ed25519 AAAAC3NzaCli".into()];
        pending.expiry = Some(Utc::now() + chrono::Duration::days(30));
        registration_cache.insert(registration_id.clone(), pending);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{registration_id}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.id, 1);
        assert!(registered.user.is_none());
        assert_eq!(registered.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(registered.machine_key, format!("mkey:{machine_key_hex}"));
        assert_eq!(registered.disco_key, disco_key);
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        assert_eq!(registered.tags, vec!["tag:server"]);
        assert_eq!(registered.available_routes, vec!["10.80.0.0/24"]);
        assert!(registered.expiry.is_none());
        let live = wire_registry.get(&node_key_hex).expect("live projection");
        assert_eq!(live.disco_key.as_deref(), Some(disco_key.as_str()));
        assert_eq!(
            live.endpoints,
            vec!["192.0.2.80:41641", "[2001:db8::80]:41641"]
        );
        assert_eq!(live.home_derp, 8);
        assert_eq!(live.os, "linux");
        assert_eq!(live.os_version, "6.10.0");
        assert_eq!(live.ssh_host_keys, vec!["ssh-ed25519 AAAAC3NzaCli"]);

        drop(service);
        drop(machines);
        drop(users);
        drop(registration_cache);
        drop(wire_registry);
        db.close().await;

        let reopened = headscale_db::Database::new(&db_url)
            .await
            .expect("reopen file-backed db");
        reopened.migrate().await.expect("rerun migrations");
        let row = headscale_db::headscale_nodes::get_by_id(reopened.pool(), 1)
            .await
            .unwrap();
        assert_eq!(row.user_id, None);
        assert_eq!(row.auth_key_id, None);
        assert_eq!(
            row.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_CLI
        );
        assert_eq!(row.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(row.machine_key, format!("mkey:{machine_key_hex}"));
        assert_eq!(row.ipv4.as_deref(), Some("100.64.0.80"));
        assert_eq!(row.tag_list(), vec!["tag:server"]);
        assert_eq!(row.disco_key, disco_key);
        assert_eq!(
            row.endpoint_list(),
            vec!["192.0.2.80:41641", "[2001:db8::80]:41641"]
        );
        let host_info = row.host_info_value();
        assert_eq!(host_info["RoutableIPs"][0], "10.80.0.0/24");
        assert_eq!(
            host_info
                .get("NetInfo")
                .and_then(|v| v.get("PreferredDERP"))
                .and_then(serde_json::Value::as_i64),
            Some(8)
        );
        assert_eq!(host_info.get("OS").and_then(|v| v.as_str()), Some("linux"));
        assert_eq!(
            host_info.get("OSVersion").and_then(|v| v.as_str()),
            Some("6.10.0")
        );
        assert_eq!(
            host_info
                .get("sshHostKeys")
                .and_then(|v| v.as_array())
                .and_then(|keys| keys.first())
                .and_then(|v| v.as_str()),
            Some("ssh-ed25519 AAAAC3NzaCli")
        );

        let fresh_users = Arc::new(PersistentUserAdmin::new(reopened.pool().clone()));
        let fresh_machines = PersistentMachineAdmin::new(reopened.pool().clone())
            .with_user_admin(fresh_users.clone());
        let fresh_registry = MachineRegistry::new();
        assert_eq!(
            fresh_machines
                .hydrate_wire_registry(&fresh_registry)
                .await
                .unwrap(),
            1
        );
        let hydrated = fresh_registry.get(&node_key_hex).expect("hydrated node");
        assert_eq!(hydrated.disco_key.as_deref(), Some(disco_key.as_str()));
        assert_eq!(
            hydrated.endpoints,
            vec!["192.0.2.80:41641", "[2001:db8::80]:41641"]
        );
        assert_eq!(hydrated.home_derp, 8);
        assert_eq!(hydrated.ssh_host_keys, vec!["ssh-ed25519 AAAAC3NzaCli"]);

        let fresh_service =
            admin_service_with_persistent_machines_for_pool(reopened.pool().clone());
        let listed = fresh_service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.nodes.len(), 1);
        let listed_node = &listed.nodes[0];
        assert_eq!(listed_node.id, 1);
        let listed_user = listed_node.user.as_ref().expect("tagged node user");
        assert_eq!(listed_user.name, "tagged-devices");
        assert_eq!(listed_node.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(listed_node.machine_key, format!("mkey:{machine_key_hex}"));
        assert_eq!(listed_node.disco_key, disco_key);
        assert_eq!(listed_node.register_method, RegisterMethod::Cli as i32);
        assert_eq!(listed_node.tags, vec!["tag:server"]);
        assert_eq!(listed_node.available_routes, vec!["10.80.0.0/24"]);
        assert!(listed_node.expiry.is_none());

        let got = fresh_service
            .get_node(Request::new(GetNodeRequest { node_id: 1 }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("node after restart");
        assert_eq!(got.node_key, listed_node.node_key);
        assert_eq!(got.disco_key, disco_key);
        assert_eq!(got.available_routes, listed_node.available_routes);
        drop(fresh_service);
        reopened.close().await;
    }

    #[tokio::test]
    async fn persistent_node_grpc_set_approved_routes_survives_fresh_service() {
        let (service, db) = admin_service_with_persistent_machines().await;
        const REGISTRATION_ID: &str = "exitrouteabcdefghijklmno";
        let registration_cache = Arc::new(RegistrationCache::new());
        let service = service.with_registration_cache(registration_cache.clone());

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        // Go's DebugCreateNode registers a node with no Hostinfo, so it cannot
        // announce the exit routes; queue a client registration that does (the
        // routes come from the cached RegistrationData.Hostinfo in Go).
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "ee".repeat(32),
            "ef".repeat(32),
            String::new(),
            "exit-router".into(),
            Ipv4Addr::new(100, 64, 0, 90),
            false,
        );
        pending.available_routes = vec!["0.0.0.0/0".into(), "::/0".into()];
        registration_cache.insert(REGISTRATION_ID.to_string(), pending);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{REGISTRATION_ID}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");

        let updated = service
            .set_approved_routes(Request::new(SetApprovedRoutesRequest {
                node_id: registered.id,
                routes: vec!["0.0.0.0/0".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("updated node");
        assert_eq!(updated.approved_routes, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(updated.subnet_routes, [] as [String; 0]);

        let raw_routes: String =
            sqlx::query_scalar("SELECT approved_routes FROM nodes WHERE id = ?")
                .bind(registered.id as i64)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(raw_routes, r#"["0.0.0.0/0","::/0"]"#);

        let fresh_service = admin_service_with_persistent_machines_for_pool(db.pool().clone());
        let listed = fresh_service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let listed_node = listed
            .nodes
            .iter()
            .find(|node| node.id == registered.id)
            .expect("fresh service listed node");
        assert_eq!(listed_node.approved_routes, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(listed_node.subnet_routes, vec!["0.0.0.0/0", "::/0"]);
    }

    #[tokio::test]
    async fn persistent_node_grpc_ip_addresses_emit_ipv4_then_ipv6() {
        let (service, db) = admin_service_with_persistent_machines().await;
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: serde_json::json!({"Hostname": "dual-stack"}),
                ipv4: Some("100.64.0.9".into()),
                ipv6: Some("fd7a:115c:a1e0::9".into()),
                hostname: "dual-stack".into(),
                given_name: "dual-stack".into(),
                user_id: Some(1),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let node = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .nodes
            .pop()
            .expect("node");

        assert_eq!(
            node.ip_addresses,
            vec!["100.64.0.9".to_string(), "fd7a:115c:a1e0::9".to_string()]
        );
        db.close().await;
    }

    #[tokio::test]
    async fn upstream_node_grpc_list_get_rename_tags_expire_delete() {
        let (service, machines) = admin_service_with_machines().await;
        let node_key = "aa".repeat(32);
        machines.upsert(
            node_key.clone(),
            fixture_machine_with_routes(&node_key, "alice", "alpha", vec!["10.0.0.0/24".into()]),
        );
        let node_id = stable_id_from_key(&node_key);
        let _guard = MachineRegistry::track_stream_connection(machines.clone(), node_id);

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.nodes.len(), 1);
        assert_eq!(listed.nodes[0].id, node_id);
        assert_eq!(listed.nodes[0].node_key, format!("nodekey:{node_key}"));
        assert_eq!(
            listed.nodes[0].machine_key,
            format!("mkey:{}", "bb".repeat(32))
        );
        assert_eq!(listed.nodes[0].ip_addresses, vec!["100.64.0.7".to_string()]);
        assert_eq!(listed.nodes[0].available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(listed.nodes[0].user.as_ref().unwrap().name, "alice");

        let got = service
            .get_node(Request::new(GetNodeRequest { node_id }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("node");
        assert_eq!(got.name, "alpha");

        service
            .set_policy(Request::new(SetPolicyRequest {
                policy: r#"{"tagOwners":{"tag:server":["alice@"]}}"#.into(),
            }))
            .await
            .expect("tag owner policy");

        let tagged = service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("tagged node");
        assert_eq!(tagged.tags, vec!["tag:server".to_string()]);

        let routed = service
            .set_approved_routes(Request::new(SetApprovedRoutesRequest {
                node_id,
                routes: vec!["10.0.0.0/24".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("routed node");
        assert_eq!(routed.approved_routes, vec!["10.0.0.0/24"]);
        assert_eq!(routed.subnet_routes, vec!["10.0.0.0/24"]);

        let preapproved = service
            .set_approved_routes(Request::new(SetApprovedRoutesRequest {
                node_id,
                routes: vec!["10.1.0.0/24".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("preapproved node");
        assert_eq!(preapproved.approved_routes, vec!["10.1.0.0/24"]);
        assert_eq!(preapproved.subnet_routes, [] as [String; 0]);

        let renamed = service
            .rename_node(Request::new(RenameNodeRequest {
                node_id,
                new_name: "beta".into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("renamed node");
        // Go RenameNode only changes given_name; `name` keeps the raw hostname.
        assert_eq!(renamed.name, "alpha");
        assert_eq!(renamed.given_name, "beta");

        let expired = service
            .expire_node(Request::new(ExpireNodeRequest {
                node_id,
                expiry: Some(prost_types::Timestamp {
                    seconds: 4_102_444_800,
                    nanos: 0,
                }),
                disable_expiry: false,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("expired node");
        assert_eq!(expired.expiry.as_ref().unwrap().seconds, 4_102_444_800);

        let unexpired = service
            .expire_node(Request::new(ExpireNodeRequest {
                node_id,
                expiry: None,
                disable_expiry: true,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("unexpired node");
        assert!(unexpired.expiry.is_none());

        let err = service
            .expire_node(Request::new(ExpireNodeRequest {
                node_id,
                expiry: Some(prost_types::Timestamp {
                    seconds: 4_102_444_800,
                    nanos: 0,
                }),
                disable_expiry: true,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        service
            .delete_node(Request::new(DeleteNodeRequest { node_id }))
            .await
            .unwrap();
        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.nodes.len(), 0);
    }

    #[tokio::test]
    async fn upstream_node_grpc_list_nodes_validates_user_filter_and_tagged_owner() {
        let (service, machines) = admin_service_with_machines().await;
        for name in ["alice", "bob"] {
            service
                .create_user(Request::new(CreateUserRequest {
                    name: name.into(),
                    display_name: String::new(),
                    email: String::new(),
                    picture_url: String::new(),
                }))
                .await
                .unwrap();
        }

        let alice_key = "ad".repeat(32);
        let bob_key = "be".repeat(32);
        machines.upsert(
            alice_key.clone(),
            fixture_machine(&alice_key, "alice", "alpha"),
        );
        machines.upsert(bob_key.clone(), fixture_machine(&bob_key, "bob", "bravo"));
        let alice_id = stable_id_from_key(&alice_key);

        let alice_nodes = service
            .list_nodes(Request::new(ListNodesRequest {
                user: "alice".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            alice_nodes
                .nodes
                .iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            vec![alice_id]
        );
        assert_eq!(alice_nodes.nodes[0].user.as_ref().unwrap().name, "alice");

        let err = service
            .list_nodes(Request::new(ListNodesRequest {
                user: "carol".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "user not found");

        service
            .set_policy(Request::new(SetPolicyRequest {
                policy: r#"{"tagOwners":{"tag:server":["alice@"]}}"#.into(),
            }))
            .await
            .expect("tag owner policy");
        service
            .set_tags(Request::new(SetTagsRequest {
                node_id: alice_id,
                tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap();

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let tagged = listed
            .nodes
            .iter()
            .find(|node| node.id == alice_id)
            .expect("tagged node is listed");
        let user = tagged.user.as_ref().expect("tagged list node user");
        assert_eq!(user.id, 2_147_455_555);
        assert_eq!(user.name, "tagged-devices");
        assert_eq!(user.display_name, "Tagged Devices");
        assert_eq!(
            user.created_at.as_ref().map(|value| value.seconds),
            Some(-62_135_596_800)
        );

        let alice_nodes = service
            .list_nodes(Request::new(ListNodesRequest {
                user: "alice".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            alice_nodes.nodes.is_empty(),
            "tagged nodes are no longer user-owned in upstream ListNodes"
        );
    }

    #[tokio::test]
    async fn upstream_node_grpc_reports_missing_and_bad_tags() {
        let (service, machines) = admin_service_with_machines().await;
        let node_key = "cc".repeat(32);
        machines.upsert(
            node_key.clone(),
            fixture_machine(&node_key, "alice", "alpha"),
        );
        let node_id = stable_id_from_key(&node_key);

        let err = service
            .get_node(Request::new(GetNodeRequest { node_id: 42 }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(err.message(), "node not found");

        let err = service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: vec!["Tag:Server".into()],
            }))
            .await
            .unwrap_err();
        // Go SetTags returns validateTag's error unwrapped, which tonic maps to
        // Unknown (verified against the real v0.29.5 server).
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "tag must start with the string 'tag:'");

        let err = service
            .set_tags(Request::new(SetTagsRequest {
                node_id: 99_999,
                tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(err.message(), "node not found");

        let err = service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "requested tags [tag:server] are invalid or not permitted"
        );

        let err = service
            .set_approved_routes(Request::new(SetApprovedRoutesRequest {
                node_id,
                routes: vec!["not-a-prefix".into()],
            }))
            .await
            .unwrap_err();
        // Go wraps netip.ParsePrefix's error with fmt.Errorf (no gRPC status),
        // so the code is Unknown (verified against the real v0.29.5 server).
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(
            err.message(),
            "parsing route: netip.ParsePrefix(\"not-a-prefix\"): no '/'"
        );

        let err = service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "cannot remove all tags from a node - tagged nodes must have at least one tag"
        );

        // Go's DebugCreateNode resolves the user before parsing the auth ID
        // (`user not found` otherwise), so the user must exist to reach the
        // AuthIDFromString errors below.
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();

        for (key, expected_message) in [
            (
                "short",
                "auth ID has invalid prefix: expected prefix \"hskey-authreq-\"",
            ),
            (
                "abcdefghijklmnopqrstuvwx",
                "auth ID has invalid prefix: expected prefix \"hskey-authreq-\"",
            ),
            (
                "hskey-authreq-short",
                "auth ID has invalid length: expected 38, got 19",
            ),
        ] {
            let err = service
                .debug_create_node(Request::new(DebugCreateNodeRequest {
                    user: "alice".into(),
                    key: key.into(),
                    name: "debug".into(),
                    routes: Vec::new(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unknown, "{key}");
            assert_eq!(err.message(), expected_message, "{key}");
        }

        for (key, expected_message) in [
            (
                "abcdefghijklmnopqrstuvwx",
                "auth ID has invalid prefix: expected prefix \"hskey-authreq-\"",
            ),
            (
                "hskey-authreq-short",
                "auth ID has invalid length: expected 38, got 19",
            ),
        ] {
            let err = service
                .register_node(Request::new(RegisterNodeRequest {
                    user: "alice".into(),
                    key: key.into(),
                }))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unknown, "{key}");
            assert_eq!(err.message(), expected_message, "{key}");
        }
    }

    #[test]
    fn upstream_node_grpc_request_tags_require_tag_owner_policy() {
        let policy = PolicyStore::new();
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let mut record = MachineAdminRecord {
            node_id: 0,
            id: "dd".repeat(32),
            name: "bob-laptop".into(),
            user: "bob".into(),
            user_id: None,
            auth_key_id: None,
            ipv4: "100.64.0.7".into(),
            ipv6: None,
            online: true,
            last_seen: 0,
            last_seen_precise: None,
            created_at: 0,
            created_at_precise: None,
            expiry: Some(1_780_000_000),
            expiry_precise: None,
            machine_key_hex: "bb".repeat(32),
            disco_key: String::new(),
            os: "unknown".into(),
            version: "unknown".into(),
            tags: vec!["tag:server".into()],
            routes: Vec::new(),
            approved_routes: Vec::new(),
            register_method: RegisterMethod::Cli as i32,
            expired: false,
        };

        let err = apply_requested_tags(&policy, &mut record).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            err.message(),
            "requested tags [tag:server] are invalid or not permitted"
        );
    }

    #[tokio::test]
    async fn upstream_node_grpc_routes_pick_single_primary() {
        let (service, machines) = admin_service_with_machines().await;
        let node_a = "11".repeat(32);
        let node_b = "22".repeat(32);
        let route = "10.0.0.0/24".to_string();

        let mut machine_a =
            fixture_machine_with_routes(&node_a, "alice", "alpha", vec![route.clone()]);
        machine_a.approved_routes = vec![route.clone()];
        machines.upsert(node_a.clone(), machine_a);

        let mut machine_b = fixture_machine_with_routes(&node_b, "alice", "beta", vec![route]);
        machine_b.approved_routes = vec!["10.0.0.0/24".into()];
        machines.upsert(node_b.clone(), machine_b);
        let _guard_a =
            MachineRegistry::track_stream_connection(machines.clone(), stable_id_from_key(&node_a));
        let _guard_b =
            MachineRegistry::track_stream_connection(machines.clone(), stable_id_from_key(&node_b));

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        let primary_count = listed
            .nodes
            .iter()
            .filter(|node| node.subnet_routes == vec!["10.0.0.0/24"])
            .count();
        assert_eq!(primary_count, 1);
    }

    #[tokio::test]
    async fn upstream_node_grpc_routes_keep_primary_sticky_after_old_owner_returns() {
        let (service, machines) = admin_service_with_machines().await;
        let route = "10.44.0.0/24".to_string();
        let nodes = [
            ("61".repeat(32), "alpha", 61),
            ("62".repeat(32), "beta", 62),
            ("63".repeat(32), "gamma", 63),
        ];

        let mut guards = Vec::new();
        for (node_key, name, octet) in &nodes {
            let mut machine =
                fixture_machine_with_routes(node_key, "alice", name, vec![route.clone()]);
            machine.ipv4 = Some(Ipv4Addr::new(100, 64, 0, *octet));
            machine.approved_routes = vec![route.clone()];
            machines.upsert(node_key.clone(), machine);
            guards.push(MachineRegistry::track_stream_connection(
                machines.clone(),
                stable_id_from_key(node_key),
            ));
        }
        assert_eq!(guards.len(), 3);

        let first = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let first_owner_id = first
            .nodes
            .iter()
            .find(|node| node.subnet_routes == vec![route.clone()])
            .expect("initial primary")
            .id;
        let first_owner_key = nodes
            .iter()
            .find(|(node_key, _, _)| stable_id_from_key(node_key) == first_owner_id)
            .expect("primary key")
            .0
            .clone();
        let old_primary = machines.get(&first_owner_key).expect("old primary");
        assert!(machines.delete(&first_owner_key));

        let second = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let second_owner_id = second
            .nodes
            .iter()
            .find(|node| node.subnet_routes == vec![route.clone()])
            .expect("replacement primary")
            .id;
        assert_ne!(second_owner_id, first_owner_id);

        machines.upsert(first_owner_key, old_primary);
        let third = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let third_owner_id = third
            .nodes
            .iter()
            .find(|node| node.subnet_routes == vec![route.clone()])
            .expect("sticky primary")
            .id;
        assert_eq!(third_owner_id, second_owner_id);
    }

    #[tokio::test]
    async fn upstream_node_grpc_exit_routes_are_serving_not_primary_routes() {
        let (service, machines) = admin_service_with_machines().await;
        let node_key = "64".repeat(32);
        let mut machine = fixture_machine_with_routes(
            &node_key,
            "alice",
            "exit",
            vec!["0.0.0.0/0".into(), "::/0".into()],
        );
        machine.approved_routes = Vec::new();
        machines.upsert(node_key.clone(), machine);
        let node_id = stable_id_from_key(&node_key);
        let _guard = MachineRegistry::track_stream_connection(machines.clone(), node_id);

        let updated = service
            .set_approved_routes(Request::new(SetApprovedRoutesRequest {
                node_id,
                routes: vec!["0.0.0.0/0".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("updated node");
        assert_eq!(updated.approved_routes, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(updated.subnet_routes, [] as [String; 0]);

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let listed_node = listed
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .expect("listed node");
        assert_eq!(listed_node.subnet_routes, vec!["0.0.0.0/0", "::/0"]);
    }

    #[tokio::test]
    async fn upstream_node_grpc_expired_nodes_do_not_serve_subnet_routes() {
        let (service, machines) = admin_service_with_machines().await;
        let node_key = "65".repeat(32);
        let mut machine = fixture_machine_with_routes(
            &node_key,
            "alice",
            "expired-router",
            vec!["10.9.0.0/24".into()],
        );
        machine.approved_routes = vec!["10.9.0.0/24".into()];
        machine.expiry = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        machines.upsert(node_key.clone(), machine);
        let node_id = stable_id_from_key(&node_key);

        let listed = service
            .list_nodes(Request::new(ListNodesRequest {
                user: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let listed_node = listed
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .expect("listed expired node");
        assert!(!listed_node.online);
        assert_eq!(listed_node.approved_routes, vec!["10.9.0.0/24"]);
        assert_eq!(listed_node.subnet_routes, [] as [String; 0]);
    }

    #[tokio::test]
    async fn upstream_node_grpc_backfill_requires_confirmation() {
        let service = admin_service().await;

        let err = service
            .backfill_node_i_ps(Request::new(BackfillNodeIPsRequest { confirmed: false }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);

        let ok = service
            .backfill_node_i_ps(Request::new(BackfillNodeIPsRequest { confirmed: true }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ok.changes, [] as [String; 0]);
    }

    #[tokio::test]
    async fn persistent_node_grpc_backfill_assigns_missing_ipv4() {
        let (service, db) = admin_service_with_persistent_machines().await;
        let service = service.with_ip_allocator(Arc::new(MockIpAllocator));
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: serde_json::json!({"Hostname": "needs-ip"}),
                ipv4: None,
                ipv6: Some("fd7a:115c:a1e0::10".into()),
                hostname: "needs-ip".into(),
                given_name: "needs-ip".into(),
                user_id: Some(1),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let changes = service
            .backfill_node_i_ps(Request::new(BackfillNodeIPsRequest { confirmed: true }))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), 1)
            .await
            .unwrap();

        assert_eq!(changes.len(), 1);
        assert!(changes[0].starts_with("assigned IPv4 \"100."));
        assert!(row.ipv4.as_deref().unwrap_or_default().starts_with("100."));
        assert_eq!(row.ipv6.as_deref(), Some("fd7a:115c:a1e0::10"));
        db.close().await;
    }

    #[tokio::test]
    async fn persistent_node_grpc_backfill_removes_ipv4_and_assigns_missing_ipv6() {
        let (service, db) = admin_service_with_persistent_machines().await;
        let service = service.with_ip_allocator(Arc::new(Ipv6OnlyDebugAllocator));
        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: serde_json::json!({"Hostname": "needs-v6"}),
                ipv4: Some("100.64.0.10".into()),
                ipv6: None,
                hostname: "needs-v6".into(),
                given_name: "needs-v6".into(),
                user_id: Some(1),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let changes = service
            .backfill_node_i_ps(Request::new(BackfillNodeIPsRequest { confirmed: true }))
            .await
            .unwrap()
            .into_inner()
            .changes;
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), 1)
            .await
            .unwrap();

        assert_eq!(
            changes,
            // Go's db.BackfillNodeIPs (ip.go) runs, per node: assign v4, assign v6,
            // remove v4, remove v6 - so the assignment line precedes the removal.
            vec![
                "assigned IPv6 \"fd7a:115c:a1e0::77\" to Node(1) \"needs-v6\"",
                "removing IPv4 \"100.64.0.10\" from Node(1) \"needs-v6\""
            ]
        );
        assert!(row.ipv4.is_none());
        assert_eq!(row.ipv6.as_deref(), Some("fd7a:115c:a1e0::77"));
        db.close().await;
    }

    #[tokio::test]
    async fn upstream_api_key_grpc_create_list_expire_delete() {
        let service = admin_service().await;

        let created = service
            .create_api_key(Request::new(CreateApiKeyRequest {
                expiration: Some(prost_types::Timestamp {
                    seconds: 4_102_444_800,
                    nanos: 0,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(created.api_key.starts_with("hskey-api-"));
        let second = service
            .create_api_key(Request::new(CreateApiKeyRequest {
                expiration: Some(prost_types::Timestamp {
                    seconds: 4_102_444_801,
                    nanos: 0,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(second.api_key.starts_with("hskey-api-"));

        let listed = service
            .list_api_keys(Request::new(ListApiKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.api_keys.len(), 2);
        let ids = listed.api_keys.iter().map(|key| key.id).collect::<Vec<_>>();
        assert_eq!(ids, {
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            sorted
        });
        let key = &listed.api_keys[0];
        assert!(key.id > 0);
        assert!(key.prefix.starts_with("hskey-api-"));
        assert!(key.prefix.ends_with("-***"));
        assert_eq!(key.expiration.as_ref().unwrap().seconds, 4_102_444_800);
        assert!(key.created_at.is_some());

        for id in ids {
            service
                .expire_api_key(Request::new(ExpireApiKeyRequest {
                    prefix: String::new(),
                    id,
                }))
                .await
                .unwrap();

            service
                .delete_api_key(Request::new(DeleteApiKeyRequest {
                    prefix: String::new(),
                    id,
                }))
                .await
                .unwrap();
        }

        let listed = service
            .list_api_keys(Request::new(ListApiKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.api_keys.len(), 0);
    }

    #[tokio::test]
    async fn upstream_key_grpc_create_list_uses_go_zero_time_expiration() {
        const GO_ZERO_TIME_UNIX_SECONDS: i64 = -62_135_596_800;

        let service = admin_service().await;

        let created_api_key = service
            .create_api_key(Request::new(CreateApiKeyRequest { expiration: None }))
            .await
            .unwrap()
            .into_inner();
        assert!(created_api_key.api_key.starts_with("hskey-api-"));
        let listed = service
            .list_api_keys(Request::new(ListApiKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        let key = listed
            .api_keys
            .iter()
            .find(|key| key.id == 1)
            .expect("created api key");
        assert_eq!(
            key.expiration.as_ref().map(|ts| ts.seconds),
            Some(GO_ZERO_TIME_UNIX_SECONDS)
        );
        assert!(key.created_at.is_some());
        assert!(key.last_seen.is_none());

        let user = service
            .create_user(Request::new(CreateUserRequest {
                name: "zero-expiration".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("created user");
        let created_preauth = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: user.id,
                reusable: false,
                ephemeral: false,
                expiration: None,
                acl_tags: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pre_auth_key
            .expect("created preauth key");
        assert_eq!(
            created_preauth.expiration.as_ref().map(|ts| ts.seconds),
            Some(GO_ZERO_TIME_UNIX_SECONDS)
        );

        let listed = service
            .list_pre_auth_keys(Request::new(ListPreAuthKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        let key = listed
            .pre_auth_keys
            .iter()
            .find(|key| key.id == created_preauth.id)
            .expect("created preauth key");
        assert_eq!(
            key.expiration.as_ref().map(|ts| ts.seconds),
            Some(GO_ZERO_TIME_UNIX_SECONDS)
        );
        assert!(key.created_at.is_some());
    }

    #[tokio::test]
    async fn upstream_api_key_grpc_requires_exactly_one_selector() {
        let service = admin_service().await;

        let err = service
            .expire_api_key(Request::new(ExpireApiKeyRequest {
                prefix: String::new(),
                id: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "must provide id or prefix");

        let err = service
            .delete_api_key(Request::new(DeleteApiKeyRequest {
                prefix: String::new(),
                id: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "must provide id or prefix");

        let err = service
            .delete_api_key(Request::new(DeleteApiKeyRequest {
                prefix: "hskey-api-abcdefghijkl-***".into(),
                id: 1,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "provide either id or prefix, not both");

        let err = service
            .expire_api_key(Request::new(ExpireApiKeyRequest {
                prefix: "hskey-api-abcdefghijkl-***".into(),
                id: 1,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "provide either id or prefix, not both");
    }

    #[tokio::test]
    async fn upstream_api_key_grpc_missing_id_errors_before_mutation() {
        // Go (grpcv1.go ExpireApiKey/DeleteApiKey) surfaces gorm's raw
        // `record not found` (code Unknown) for a missing id or prefix; verified
        // against the real v0.29.5 server.
        let service = admin_service().await;

        let err = service
            .expire_api_key(Request::new(ExpireApiKeyRequest {
                prefix: String::new(),
                id: 999,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "record not found");

        let err = service
            .delete_api_key(Request::new(DeleteApiKeyRequest {
                prefix: String::new(),
                id: 999,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "record not found");

        let err = service
            .expire_api_key(Request::new(ExpireApiKeyRequest {
                prefix: "hskey-api-abcdefghijkl-***".into(),
                id: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "record not found");

        let err = service
            .delete_api_key(Request::new(DeleteApiKeyRequest {
                prefix: "hskey-api-abcdefghijkl-***".into(),
                id: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "record not found");
    }

    #[tokio::test]
    async fn upstream_preauth_grpc_create_list_expire_delete() {
        let service = admin_service().await;

        let user = service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("created user");

        let created = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: user.id,
                reusable: true,
                ephemeral: true,
                expiration: Some(prost_types::Timestamp {
                    seconds: 4_102_444_800,
                    nanos: 123_456_789,
                }),
                acl_tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .pre_auth_key
            .expect("created preauth key");
        assert!(created.id > 0);
        assert!(created.key.starts_with("hskey-auth-"));
        assert!(created.reusable);
        assert!(created.ephemeral);
        assert_eq!(created.acl_tags, vec!["tag:server".to_string()]);
        assert_eq!(created.user.as_ref().unwrap().id, user.id);
        assert_eq!(created.user.as_ref().unwrap().created_at, user.created_at,);
        assert_ne!(
            created
                .created_at
                .as_ref()
                .expect("creation timestamp")
                .nanos,
            0
        );
        assert_eq!(created.expiration.as_ref().unwrap().seconds, 4_102_444_800);
        assert_eq!(created.expiration.as_ref().unwrap().nanos, 123_456_789);
        assert!(!created.key.ends_with("-***"));

        let listed = service
            .list_pre_auth_keys(Request::new(ListPreAuthKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.pre_auth_keys.len(), 1);
        assert_eq!(listed.pre_auth_keys[0].id, created.id);
        assert_ne!(listed.pre_auth_keys[0].key, created.key);
        assert!(listed.pre_auth_keys[0].key.starts_with("hskey-auth-"));
        assert!(listed.pre_auth_keys[0].key.ends_with("-***"));
        assert_eq!(
            listed.pre_auth_keys[0].expiration.as_ref().unwrap().seconds,
            4_102_444_800
        );
        assert_eq!(
            listed.pre_auth_keys[0].expiration.as_ref().unwrap().nanos,
            123_456_789
        );

        service
            .expire_pre_auth_key(Request::new(ExpirePreAuthKeyRequest { id: created.id }))
            .await
            .unwrap();

        service
            .delete_pre_auth_key(Request::new(DeletePreAuthKeyRequest { id: created.id }))
            .await
            .unwrap();

        let listed = service
            .list_pre_auth_keys(Request::new(ListPreAuthKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.pre_auth_keys.len(), 0);
    }

    #[tokio::test]
    async fn upstream_preauth_grpc_creates_for_oidc_username_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("headscale.db");
        let db = headscale_db::Database::new(&format!("sqlite://{}?mode=rwc", db_path.display()))
            .await
            .expect("open sqlite db");
        db.migrate().await.expect("migrate");
        let users = PersistentUserAdmin::new(db.pool().clone());
        let oidc_user = crate::oidc::OidcUserStore::create_or_update_oidc_user(
            &users,
            crate::oidc::OidcUserProfile {
                name: String::new(),
                display_name: "Alice OIDC".into(),
                email: "alice@example.com".into(),
                provider_identifier: "https://issuer.example/preauth-user".into(),
                provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap();
        let service = admin_service_with_persistent_machines_for_pool(db.pool().clone());

        let created = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: oidc_user.id,
                reusable: false,
                ephemeral: false,
                expiration: None,
                acl_tags: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pre_auth_key
            .expect("created preauth key");

        let user = created.user.expect("created key has user");
        assert_eq!(user.id, oidc_user.id);
        assert_eq!(user.name, "alice@example.com");
        assert_eq!(user.provider, crate::oidc::REGISTER_METHOD_OIDC);

        let listed = service
            .list_pre_auth_keys(Request::new(ListPreAuthKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.pre_auth_keys.len(), 1);
        assert_eq!(listed.pre_auth_keys[0].id, created.id);
        assert_eq!(
            listed.pre_auth_keys[0].user.as_ref().unwrap().name,
            "alice@example.com"
        );
    }

    #[tokio::test]
    async fn upstream_preauth_grpc_validates_user_id_and_tags() {
        let service = admin_service().await;

        let err = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: 0,
                reusable: false,
                ephemeral: false,
                expiration: None,
                acl_tags: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(
            err.message(),
            "auth-key must be either tagged or owned by user"
        );

        let err = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: 42,
                reusable: false,
                ephemeral: false,
                expiration: None,
                acl_tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "user not found");

        let err = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: 0,
                reusable: false,
                ephemeral: false,
                expiration: None,
                acl_tags: vec!["Tag:Server".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: 0,
                reusable: false,
                ephemeral: false,
                expiration: None,
                acl_tags: vec!["tag:bad tag".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "tags must not contain spaces");

        let created = service
            .create_pre_auth_key(Request::new(CreatePreAuthKeyRequest {
                user: 0,
                reusable: false,
                ephemeral: false,
                expiration: None,
                acl_tags: vec!["tag:infra".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .pre_auth_key
            .expect("created tags-only key");
        assert!(created.user.is_none());
        assert_eq!(created.acl_tags, vec!["tag:infra".to_string()]);
    }

    #[tokio::test]
    async fn upstream_policy_grpc_set_get_and_validate() {
        let service = admin_service().await;
        let raw = r#"{
          "acls": [
            {"action": "accept", "src": ["*"], "dst": ["*:*"]},
          ],
        }"#;

        let set = service
            .set_policy(Request::new(SetPolicyRequest { policy: raw.into() }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(set.policy, raw);
        assert!(set.updated_at.is_some());

        let got = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy, raw);
        assert!(got.updated_at.is_some());

        service
            .check_policy(Request::new(CheckPolicyRequest { policy: raw.into() }))
            .await
            .unwrap();
        let candidate = r#"{"acls":[]}"#;
        service
            .check_policy(Request::new(CheckPolicyRequest {
                policy: candidate.into(),
            }))
            .await
            .unwrap();
        let got_after_check = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got_after_check.policy, raw);

        // Go SetPolicy wraps the parse error with fmt.Errorf (code Unknown) while
        // CheckPolicy returns status.Error(InvalidArgument, ...); both verified
        // against the real v0.29.5 server.
        let parse_error = "parsing policy: parsing HuJSON: hujson: line 1, column 2: parsing value: unexpected EOF";
        let err = service
            .set_policy(Request::new(SetPolicyRequest { policy: "{".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), format!("setting policy: {parse_error}"));

        let err = service
            .check_policy(Request::new(CheckPolicyRequest { policy: "{".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), parse_error);
    }

    #[tokio::test]
    async fn upstream_policy_grpc_evaluates_policy_tests_before_success() {
        let (service, machines) = admin_service_with_machines().await;
        // Go resolves `alice@` through the users table and owns nodes by numeric
        // user id, so the owners must exist and be referenced by id.
        let alice_id = create_test_user(&service, "alice").await;
        let bob_id = create_test_user(&service, "bob").await;
        let alice_key = "91".repeat(32);
        let server_key = "92".repeat(32);
        let mut alice_node = MachineRecord::new_at(
            Utc::now(),
            alice_key.clone(),
            "93".repeat(32),
            "alice".into(),
            "alice-laptop".into(),
            Ipv4Addr::new(100, 64, 0, 1),
            false,
        );
        alice_node.user_id = Some(alice_id);
        machines.upsert(alice_key, alice_node);
        let mut server_node = MachineRecord::new_at(
            Utc::now(),
            server_key.clone(),
            "94".repeat(32),
            "bob".into(),
            "server".into(),
            Ipv4Addr::new(100, 64, 0, 2),
            false,
        );
        server_node.user_id = Some(bob_id);
        machines.upsert(server_key, server_node);

        let passing = r#"{
          "acls": [
            {"action": "accept", "proto": "tcp", "src": ["alice@"], "dst": ["100.64.0.2:22"]}
          ],
          "tests": [
            {"src": "alice@", "accept": ["100.64.0.2:22"], "deny": ["100.64.0.2:80"]}
          ]
        }"#;
        service
            .check_policy(Request::new(CheckPolicyRequest {
                policy: passing.into(),
            }))
            .await
            .unwrap();
        service
            .set_policy(Request::new(SetPolicyRequest {
                policy: passing.into(),
            }))
            .await
            .unwrap();

        let failing = r#"{
          "acls": [
            {"action": "accept", "proto": "tcp", "src": ["alice@"], "dst": ["100.64.0.2:22"]}
          ],
          "tests": [
            {"src": "alice@", "accept": ["100.64.0.2:80"]}
          ]
        }"#;
        let err = service
            .check_policy(Request::new(CheckPolicyRequest {
                policy: failing.into(),
            }))
            .await
            .unwrap_err();
        // Go: CheckPolicy => InvalidArgument, SetPolicy => Unknown with a
        // "setting policy: " prefix; the per-test breakdown comes from
        // PolicyTestResults.Errors() (verified against the real v0.29.5 server).
        let failure = "test(s) failed:\nalice@ -> 100.64.0.2:80: expected ALLOWED, got DENIED";
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), failure);

        let err = service
            .set_policy(Request::new(SetPolicyRequest {
                policy: failing.into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), format!("setting policy: {failure}"));

        let got = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy, passing);
    }

    #[tokio::test]
    async fn upstream_policy_grpc_evaluates_ssh_tests_before_success() {
        let (service, machines) = admin_service_with_machines().await;
        // Go resolves `alice@` through the users table and owns nodes by numeric
        // user id, so the owner must exist and be referenced by id.
        let alice_id = create_test_user(&service, "alice").await;
        let node_key = "95".repeat(32);
        let mut node = MachineRecord::new_at(
            Utc::now(),
            node_key.clone(),
            "96".repeat(32),
            "alice".into(),
            "alice-laptop".into(),
            Ipv4Addr::new(100, 64, 0, 3),
            false,
        );
        node.user_id = Some(alice_id);
        machines.upsert(node_key, node);
        let passing = r#"{
          "ssh": [
            {"action": "accept", "src": ["alice@"], "dst": ["autogroup:self"], "users": ["root"]}
          ],
          "sshTests": [
            {"src": "alice@", "dst": ["autogroup:self"], "accept": ["root"]}
          ]
        }"#;

        service
            .check_policy(Request::new(CheckPolicyRequest {
                policy: passing.into(),
            }))
            .await
            .unwrap();
        service
            .set_policy(Request::new(SetPolicyRequest {
                policy: passing.into(),
            }))
            .await
            .unwrap();

        let failing = r#"{
          "ssh": [
            {"action": "accept", "src": ["alice@"], "dst": ["autogroup:self"], "users": ["root"]}
          ],
          "sshTests": [
            {"src": "alice@", "dst": ["autogroup:self"], "accept": ["ubuntu"]}
          ]
        }"#;
        let err = service
            .check_policy(Request::new(CheckPolicyRequest {
                policy: failing.into(),
            }))
            .await
            .unwrap_err();
        // Go: CheckPolicy => InvalidArgument, SetPolicy => Unknown with a
        // "setting policy: " prefix (verified against the real v0.29.5 server).
        let failure =
            "test(s) failed:\nalice@/ubuntu -> alice-laptop: expected ALLOWED, got DENIED";
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), failure);

        let err = service
            .set_policy(Request::new(SetPolicyRequest {
                policy: failing.into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), format!("setting policy: {failure}"));

        let got = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy, passing);
    }

    #[tokio::test]
    async fn upstream_policy_grpc_database_get_missing_policy_errors() {
        let (service, _db) = admin_service_with_policy_db().await;
        let err = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert!(err.message().contains("acl policy not found"));
    }

    #[tokio::test]
    async fn upstream_policy_grpc_file_mode_reads_file_and_rejects_set() {
        let (service, _machines) = admin_service_with_machines().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acl.hujson");
        let raw = "{\n  // file mode keeps raw HuJSON\n  \"acls\": []\n}";
        fs::write(&path, raw).unwrap();
        let service = service.with_policy_file(path);

        let got = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy, raw);
        assert!(got.updated_at.is_none());

        let err = service
            .set_policy(Request::new(SetPolicyRequest { policy: "{".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert!(err.message().contains("update is disabled"));
    }

    #[tokio::test]
    async fn upstream_policy_grpc_unsupported_mode_matches_go_errors() {
        let service = admin_service().await.with_unsupported_policy_mode("consul");
        let get_error = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap_err();
        assert_eq!(get_error.code(), tonic::Code::Unknown);
        assert_eq!(
            get_error.message(),
            "no supported policy mode found in configuration, policy.mode: \"consul\""
        );
        let set_error = service
            .set_policy(Request::new(SetPolicyRequest { policy: "{".into() }))
            .await
            .unwrap_err();
        assert_eq!(set_error.code(), tonic::Code::Unknown);
        assert_eq!(
            set_error.message(),
            "update is disabled for modes other than 'database'"
        );
    }

    #[tokio::test]
    async fn upstream_policy_reload_rejects_ambiguous_users_without_replacing_live_policy() {
        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        sqlx::query("INSERT INTO users (id,name,email,provider_identifier,created_at,updated_at) VALUES (2,'yala','',NULL,0,0),(7,'yala','yala@example.com','https://idp.test/subject',0,0)")
            .execute(db.pool()).await.unwrap();
        let base = r#"{"acls":[]}"#;
        let bad = r#"{"groups":{"group:admins":["yala@"]}}"#;
        let policy = PolicyStore::new();
        policy.set(
            crate::policy::parse_hujson_policy(base).unwrap(),
            base.into(),
        );
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        // Go's ReloadPolicy validates against the policy manager's own user
        // list (loaded at startup / refreshed on user changes), not a fresh
        // database read; mirror the startup load for the rows inserted above.
        policy
            .set_users_quiet(
                crate::admin::users::UserAdmin::policy_users(users.as_ref())
                    .await
                    .unwrap(),
            )
            .unwrap();
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            policy.clone(),
            Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new()))),
        )
        .with_policy_pool(db.pool().clone());
        headscale_db::policies::set(db.pool(), bad).await.unwrap();
        let error = service.reload_policy_from_config().await.unwrap_err();
        assert!(error.message().contains("multiple users found"));
        assert_eq!(policy.raw().as_deref(), Some(base));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.hujson");
        fs::write(&path, bad).unwrap();
        let service = service.with_policy_file(path);
        let error = service.reload_policy_from_config().await.unwrap_err();
        assert!(error.message().contains("multiple users found"));
        assert_eq!(policy.raw().as_deref(), Some(base));
    }

    #[tokio::test]
    async fn upstream_policy_reload_from_file_updates_live_policy_and_auto_approvals() {
        let (service, machines) = admin_service_with_machines().await;
        // Go resolves `alice@` through the users table and owns nodes by numeric
        // user id, so the owner must exist and be referenced by id.
        let alice_id = create_test_user(&service, "alice").await;
        let node_key = "97".repeat(32);
        let mut rec = MachineRecord::new_at(
            Utc::now(),
            node_key.clone(),
            "98".repeat(32),
            "alice".into(),
            "router".into(),
            Ipv4Addr::new(100, 64, 0, 9),
            false,
        );
        rec.user_id = Some(alice_id);
        rec.available_routes = vec!["10.88.1.0/24".into(), "10.99.1.0/24".into()];
        machines.upsert(node_key.clone(), rec);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acl.hujson");
        fs::write(&path, r#"{"acls":[]}"#).unwrap();
        let service = service.with_policy_file(path.clone());

        assert!(service.reload_policy_from_config().await.unwrap());
        let got = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy, r#"{"acls":[]}"#);

        let raw = r#"{
          "autoApprovers": {
            "routes": {"10.88.0.0/16": ["alice@"]}
          }
        }"#;
        fs::write(&path, raw).unwrap();

        assert!(service.reload_policy_from_config().await.unwrap());

        let got = service
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy, raw);
        let rec = machines.get(&node_key).expect("node remains registered");
        assert_eq!(rec.approved_routes, vec!["10.88.1.0/24"]);
    }

    #[tokio::test]
    async fn upstream_policy_reload_from_file_recomputes_grants_via_route_steering() {
        let (service, machines) = admin_service_with_machines().await;
        let route = "10.77.0.0/24".to_string();
        let router_a = "a1".repeat(32);
        let router_b = "b2".repeat(32);
        let alice = "c3".repeat(32);
        let bob = "d4".repeat(32);
        let nodes = vec![
            insert_route_via_node(
                &machines,
                RouteViaNodeSpec {
                    node_key: router_a.clone(),
                    machine_key: "a2".repeat(32),
                    user: "router".into(),
                    hostname: "router-a".into(),
                    ipv4: Ipv4Addr::new(100, 64, 0, 21),
                    tags: vec!["tag:router-a".into()],
                    routes: vec![route.clone()],
                },
            ),
            insert_route_via_node(
                &machines,
                RouteViaNodeSpec {
                    node_key: router_b.clone(),
                    machine_key: "b3".repeat(32),
                    user: "router".into(),
                    hostname: "router-b".into(),
                    ipv4: Ipv4Addr::new(100, 64, 0, 22),
                    tags: vec!["tag:router-b".into()],
                    routes: vec![route.clone()],
                },
            ),
            insert_route_via_node(
                &machines,
                RouteViaNodeSpec {
                    node_key: alice.clone(),
                    machine_key: "c4".repeat(32),
                    user: "alice".into(),
                    hostname: "alice".into(),
                    ipv4: Ipv4Addr::new(100, 64, 0, 23),
                    tags: Vec::new(),
                    routes: Vec::new(),
                },
            ),
            insert_route_via_node(
                &machines,
                RouteViaNodeSpec {
                    node_key: bob.clone(),
                    machine_key: "d5".repeat(32),
                    user: "bob".into(),
                    hostname: "bob".into(),
                    ipv4: Ipv4Addr::new(100, 64, 0, 24),
                    tags: Vec::new(),
                    routes: Vec::new(),
                },
            ),
        ];

        // Go owns a node by numeric user id and resolves `alice@` through the
        // users table: create both users and hand their ids to the evaluation.
        let alice_user = create_test_user(&service, "alice").await;
        let bob_user = create_test_user(&service, "bob").await;
        let owners = std::collections::BTreeMap::from([
            (stable_id_from_key(&alice), alice_user),
            (stable_id_from_key(&bob), bob_user),
        ]);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("acl.hujson");
        fs::write(&path, route_via_policy("tag:router-a", "tag:router-b")).unwrap();
        let service = service.with_policy_file(path.clone());

        assert!(service.reload_policy_from_config().await.unwrap());
        assert_via_routes(
            service.policy_for_test(),
            &nodes,
            &owners,
            &alice,
            &router_a,
            std::slice::from_ref(&route),
            &[],
        );
        assert_via_routes(
            service.policy_for_test(),
            &nodes,
            &owners,
            &alice,
            &router_b,
            &[],
            std::slice::from_ref(&route),
        );
        assert_via_routes(
            service.policy_for_test(),
            &nodes,
            &owners,
            &bob,
            &router_a,
            &[],
            std::slice::from_ref(&route),
        );
        assert_via_routes(
            service.policy_for_test(),
            &nodes,
            &owners,
            &bob,
            &router_b,
            std::slice::from_ref(&route),
            &[],
        );

        fs::write(&path, route_via_policy("tag:router-b", "tag:router-b")).unwrap();

        assert!(service.reload_policy_from_config().await.unwrap());
        assert_via_routes(
            service.policy_for_test(),
            &nodes,
            &owners,
            &alice,
            &router_a,
            &[],
            std::slice::from_ref(&route),
        );
        assert_via_routes(
            service.policy_for_test(),
            &nodes,
            &owners,
            &alice,
            &router_b,
            std::slice::from_ref(&route),
            &[],
        );
        assert_via_routes(
            service.policy_for_test(),
            &nodes,
            &owners,
            &bob,
            &router_b,
            std::slice::from_ref(&route),
            &[],
        );
    }

    #[tokio::test]
    async fn upstream_policy_grpc_persists_and_loads_database_policy() {
        let (service, db) = admin_service_with_policy_db().await;
        let raw1 = r#"{
          // first policy row
          "acls": [{"action": "accept", "src": ["*"], "dst": ["*:22"]}]
        }"#;
        let raw2 = r#"{
          // newest policy row
          "acls": [{"action": "accept", "src": ["*"], "dst": ["*:443"]}]
        }"#;

        service
            .set_policy(Request::new(SetPolicyRequest {
                policy: raw1.into(),
            }))
            .await
            .unwrap();
        let set = service
            .set_policy(Request::new(SetPolicyRequest {
                policy: raw2.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(set.policy, raw2);
        assert!(set.updated_at.is_some());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 2);
        let latest = headscale_db::policies::get_latest(db.pool())
            .await
            .unwrap()
            .expect("latest policy");
        assert_eq!(latest.data, raw2);

        let fresh_policy = PolicyStore::new();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let fresh = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            fresh_policy.clone(),
            Arc::new(WireMachineAdmin::new(Arc::new(MachineRegistry::new()))),
        )
        .with_database_pool(db.pool().clone())
        .with_policy_pool(db.pool().clone());

        let got = fresh
            .get_policy(Request::new(GetPolicyRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(got.policy, raw2);
        assert_eq!(got.updated_at.map(|ts| ts.seconds), Some(latest.updated_at));
        assert!(!fresh_policy.is_loaded());

        assert!(fresh.load_policy_from_persistence().await.unwrap());
        assert_eq!(fresh_policy.raw().unwrap(), raw2);
        assert_eq!(fresh_policy.updated_at(), Some(latest.updated_at));
    }

    #[tokio::test]
    async fn upstream_policy_grpc_auto_approves_existing_node_routes() {
        let (service, machines) = admin_service_with_machines().await;
        // Go resolves `alice@` through the users table (policy manager users),
        // and a node is owned by a numeric user id, so the owner must exist.
        let alice = service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("alice");
        let node_key = "8d".repeat(32);
        let mut rec = MachineRecord::new_at(
            Utc::now(),
            node_key.clone(),
            "8e".repeat(32),
            "alice".into(),
            "router".into(),
            Ipv4Addr::new(100, 64, 0, 8),
            false,
        );
        rec.user_id = Some(alice.id);
        rec.available_routes = vec!["10.88.1.0/24".into(), "10.99.1.0/24".into()];
        machines.upsert(node_key.clone(), rec);

        let raw = r#"{
          "autoApprovers": {
            "routes": {"10.88.0.0/16": ["alice@"]}
          }
        }"#;
        service
            .set_policy(Request::new(SetPolicyRequest { policy: raw.into() }))
            .await
            .unwrap();

        let rec = machines.get(&node_key).expect("node remains registered");
        assert_eq!(rec.available_routes, vec!["10.88.1.0/24", "10.99.1.0/24"]);
        assert_eq!(rec.approved_routes, vec!["10.88.1.0/24"]);
    }

    #[tokio::test]
    async fn upstream_health_grpc_reports_database_connectivity() {
        let service = admin_service().await;

        let health = service
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(health.database_connectivity);
    }

    #[tokio::test]
    async fn upstream_health_grpc_fails_when_database_ping_fails() {
        let service = admin_service()
            .await
            .with_database_health(Arc::new(FailingDatabaseHealth));

        let err = service
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unknown);
        assert_eq!(err.message(), "pinging database: forced offline");
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
