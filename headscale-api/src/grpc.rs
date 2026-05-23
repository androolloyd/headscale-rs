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
/// The full headscale-go service contains users, nodes, pre-auth keys,
/// routes, policies, API keys, and debug/version operations. This
/// adapter wires implemented admin-backed RPC slices first and leaves
/// the remaining methods out of the generated descriptor until those
/// backing behaviours exist in Rust.
#[cfg(feature = "admin")]
pub mod upstream {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use async_trait::async_trait;
    use chrono::Utc;
    use parking_lot::Mutex;
    use rand_core::RngCore;
    use tonic::{Request, Response, Status, metadata::MetadataMap};

    use crate::admin::{
        ApiKeyAdmin, ApiKeyAdminError, ApiKeyAdminKey, ApiKeyMintRequest, MachineAdmin,
        MachineAdminError, MachineAdminRecord, PreauthAdmin, PreauthAdminError, PreauthAdminKey,
        PreauthMintRequest, UserAdmin, UserRecord, UserRegistry, UserRegistryError,
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
        PolicyCheckNode, PolicyDoc, PolicyStore, check_policy_semantics, parse_hujson_policy,
        validate_requested_tags_for_node,
    };
    use crate::tailscale_wire::routes::{
        PrimaryRouteState, active_approved_routes, active_exit_routes, normalize_routes,
    };
    use crate::tailscale_wire::wire::stable_id_from_key;
    use crate::tailscale_wire::{IpAllocator, MachineRecord, MachineRegistry};

    const AUTH_PREFIX: &str = "Bearer ";

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

    #[cfg(feature = "admin")]
    #[async_trait]
    impl PolicyPersistence for sqlx::SqlitePool {
        async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String> {
            headscale_db::policies::get_latest(self)
                .await
                .map(|row| {
                    row.map(|policy| PersistedPolicy {
                        policy: policy.data,
                        updated_at: policy.updated_at,
                    })
                })
                .map_err(|e| e.to_string())
        }

        async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String> {
            headscale_db::policies::set(self, policy)
                .await
                .map(|policy| PersistedPolicy {
                    policy: policy.data,
                    updated_at: policy.updated_at,
                })
                .map_err(|e| e.to_string())
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

        pub fn with_policy_persistence(
            mut self,
            policy_persistence: Arc<dyn PolicyPersistence>,
        ) -> Self {
            self.policy_persistence = Some(policy_persistence);
            self.policy_mode = PolicyMode::Database;
            self
        }

        #[cfg(feature = "admin")]
        pub fn with_policy_pool(self, pool: sqlx::SqlitePool) -> Self {
            self.with_policy_persistence(Arc::new(pool))
        }

        pub fn with_policy_file(mut self, path: impl Into<PathBuf>) -> Self {
            self.policy_mode = PolicyMode::File { path: path.into() };
            self
        }

        pub async fn load_policy_from_persistence(&self) -> Result<bool, Status> {
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
            let doc = parse_hujson_policy(&policy.policy).map_err(|e| {
                Status::invalid_argument(format!("loading policy from database: {e}"))
            })?;
            self.policy.set_at(doc, policy.policy, policy.updated_at);
            Ok(true)
        }

        /// Reload the configured policy source and fan out route/policy changes.
        ///
        /// This is the production SIGHUP path: headscale-go v0.28 reloads the
        /// ACL policy on SIGHUP rather than reparsing the full server config.
        pub async fn reload_policy_from_config(&self) -> Result<bool, Status> {
            let loaded = match &self.policy_mode {
                PolicyMode::File { path } => {
                    if path.as_os_str().is_empty() {
                        return Ok(false);
                    }
                    let raw = tokio::fs::read_to_string(path).await.map_err(|e| {
                        Status::unknown(format!("reloading policy file {}: {e}", path.display()))
                    })?;
                    if raw.is_empty() {
                        return Ok(false);
                    }
                    let doc = parse_hujson_policy(&raw).map_err(|e| {
                        Status::invalid_argument(format!(
                            "reloading policy file {}: {e}",
                            path.display()
                        ))
                    })?;
                    self.validate_candidate_policy(&doc, "reloading policy")
                        .await?;
                    self.policy.set(doc, raw);
                    true
                }
                PolicyMode::Database => self.load_policy_from_persistence().await?,
                PolicyMode::Memory => false,
            };

            if loaded {
                crate::admin::machines::apply_policy_auto_approvals(
                    &self.policy,
                    self.machines.as_ref(),
                )
                .await
                .map_err(machine_error_to_status)?;
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
            if self.api_keys.validate(&token).await {
                Ok(())
            } else {
                Err(Status::unauthenticated("invalid token"))
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
            self.wire_registry = Some(wire_registry);
            self
        }

        pub fn with_ip_allocator(mut self, ip_allocator: Arc<dyn IpAllocator>) -> Self {
            self.ip_allocator = Some(ip_allocator);
            self
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
                .register_encoded_file_descriptor_set(crate::generated::FILE_DESCRIPTOR_SET)
                .build_v1()
        }

        async fn authorize<T>(&self, request: &Request<T>) -> Result<(), Status> {
            self.authorize_api_key_metadata(request.metadata()).await
        }

        async fn machine_by_id(&self, node_id: u64) -> Result<MachineAdminRecord, Status> {
            self.machines
                .list()
                .await
                .into_iter()
                .find(|node| machine_numeric_id(node) == node_id)
                .ok_or_else(|| Status::not_found("node not found"))
        }

        async fn validate_candidate_policy(
            &self,
            doc: &PolicyDoc,
            context: &str,
        ) -> Result<(), Status> {
            let machines = self.machines.list().await;
            let nodes = machines
                .iter()
                .map(policy_check_node_from_machine)
                .collect::<Vec<_>>();
            check_policy_semantics(doc, &nodes)
                .map_err(|e| Status::invalid_argument(format!("{context}: {e}")))
        }

        async fn debug_machine_record(
            &self,
            user: &str,
            name: &str,
            routes: Vec<String>,
        ) -> MachineAdminRecord {
            let node_key = self.unique_node_key().await;
            let now = chrono::Utc::now().timestamp().max(0) as u64;
            MachineAdminRecord {
                node_id: 0,
                ipv4: String::new(),
                ipv6: None,
                id: node_key,
                name: name.to_string(),
                user: user.to_string(),
                online: false,
                last_seen: now,
                created_at: now,
                expiry: None,
                machine_key_hex: random_key_hex(),
                os: "TestOS".into(),
                version: "unknown".into(),
                tags: Vec::new(),
                routes,
                approved_routes: Vec::new(),
                register_method: RegisterMethod::Unspecified as i32,
                expired: false,
            }
        }

        async fn prepare_registration_addresses(
            &self,
            record: &mut MachineAdminRecord,
        ) -> Result<(), Status> {
            if let Some(existing) = self.machines.existing_auth_path_record(record).await {
                record.ipv4 = existing.ipv4;
                record.ipv6 = existing.ipv6;
                return Ok(());
            }
            let Some(ip_allocator) = self.ip_allocator.as_deref() else {
                return Ok(());
            };

            let ipv4 = if ip_allocator.ipv4_enabled() {
                Some(ip_allocator.allocate(&record.id).map_err(|e| {
                    Status::internal(format!("allocating IPs: allocating IPv4 address: {e}"))
                })?)
            } else {
                None
            };
            let ipv6 = ip_allocator.allocate_ipv6(&record.id).map_err(|e| {
                Status::internal(format!("allocating IPs: allocating IPv6 address: {e}"))
            })?;
            if ipv4.is_none() && ipv6.is_none() {
                return Err(Status::internal("allocating IPs: no IP prefixes enabled"));
            }
            record.ipv4 = ipv4.map(|ip| ip.to_string()).unwrap_or_default();
            record.ipv6 = ipv6.map(|ip| ip.to_string());
            Ok(())
        }

        async fn unique_node_key(&self) -> String {
            loop {
                let node_key = random_key_hex();
                if self.machines.get(&node_key).await.is_none()
                    && !self.registration_cache.contains_node_key(&node_key)
                {
                    return node_key;
                }
            }
        }

        async fn register_node_body(
            &self,
            body: RegisterNodeRequest,
        ) -> Result<RegisterNodeResponse, Status> {
            validate_registration_id(&body.key)?;
            let user = self
                .users
                .get(&body.user)
                .await
                .map_err(user_error_to_status)?
                .ok_or_else(|| Status::not_found("user not found"))?;
            let pending = self
                .registration_cache
                .get(&body.key)
                .ok_or_else(|| Status::not_found("registration not found"))?;
            let mut record = wire_record_to_machine_admin(pending.clone());
            record.user = user.name;
            record.register_method = RegisterMethod::Cli as i32;
            self.prepare_registration_addresses(&mut record).await?;
            apply_requested_tags(&self.policy, &mut record)?;

            let result = self
                .machines
                .complete_registration(record, &self.policy, Some(pending.clone()))
                .await
                .map_err(machine_error_to_status)?;
            let node = result.record;
            let wire_record = machine_admin_to_wire_record_with_pending(&node, &pending);
            if let Some(registry) = &self.wire_registry {
                if let Some(old_node_key_hex) = result.replaced_node_key_hex.as_deref() {
                    registry.replace_node_key(
                        old_node_key_hex,
                        wire_record.node_key_hex.clone(),
                        wire_record.clone(),
                    );
                } else {
                    registry.upsert(wire_record.node_key_hex.clone(), wire_record.clone());
                }
            }
            self.registration_cache.complete(&body.key, wire_record);
            Ok(RegisterNodeResponse {
                node: Some(machine_to_node(&node, &self.users).await?),
            })
        }
    }

    fn bearer_token(metadata: &MetadataMap) -> Result<&str, Status> {
        let value = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("Authorization token is not supplied"))?;
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
            let user = self
                .users
                .create_detailed(
                    &body.name,
                    &body.display_name,
                    &body.email,
                    &body.picture_url,
                )
                .await
                .map_err(user_error_to_status)?;
            self.policy.refresh();
            Ok(Response::new(CreateUserResponse {
                user: Some(user_record_to_proto(&user)),
            }))
        }

        async fn rename_user(
            &self,
            request: Request<RenameUserRequest>,
        ) -> Result<Response<RenameUserResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let user = self
                .users
                .rename_by_id(body.old_id, &body.new_name)
                .await
                .map_err(user_error_to_status)?;
            self.policy.refresh();
            Ok(Response::new(RenameUserResponse {
                user: Some(user_record_to_proto(&user)),
            }))
        }

        async fn delete_user(
            &self,
            request: Request<DeleteUserRequest>,
        ) -> Result<Response<DeleteUserResponse>, Status> {
            self.authorize(&request).await?;
            self.users
                .delete_by_id(request.into_inner().id)
                .await
                .map_err(user_error_to_status)?;
            self.policy.refresh();
            Ok(Response::new(DeleteUserResponse {}))
        }

        async fn list_users(
            &self,
            request: Request<ListUsersRequest>,
        ) -> Result<Response<ListUsersResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let mut users = match (body.name.is_empty(), body.email.is_empty(), body.id) {
                (false, _, _) => self
                    .users
                    .get(&body.name)
                    .await
                    .map_err(user_error_to_status)?
                    .into_iter()
                    .collect::<Vec<_>>(),
                (true, false, _) => self
                    .users
                    .all()
                    .await
                    .map_err(user_error_to_status)?
                    .into_iter()
                    .filter(|u| u.email == body.email)
                    .collect(),
                (true, true, id) if id != 0 => self
                    .users
                    .get_by_id(id)
                    .await
                    .map_err(user_error_to_status)?
                    .into_iter()
                    .collect::<Vec<_>>(),
                _ => self.users.all().await.map_err(user_error_to_status)?,
            };
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
            for tag in &body.acl_tags {
                validate_tag(tag)?;
            }
            let user = if body.user == 0 {
                String::new()
            } else {
                self.users
                    .get_by_id(body.user)
                    .await
                    .map_err(user_error_to_status)?
                    .ok_or_else(|| Status::not_found("user not found"))?
                    .name
            };
            let expiration = body
                .expiration
                .as_ref()
                .map(timestamp_to_unix)
                .transpose()?;
            let created = self
                .preauth
                .mint_with_expiration(
                    PreauthMintRequest {
                        user,
                        ttl_secs: 0,
                        reusable: body.reusable,
                        ephemeral: body.ephemeral,
                        tags: body.acl_tags,
                    },
                    expiration,
                )
                .await
                .map_err(preauth_error_to_status)?;
            Ok(Response::new(CreatePreAuthKeyResponse {
                pre_auth_key: Some(preauth_key_to_proto(&created, &self.users).await?),
            }))
        }

        async fn expire_pre_auth_key(
            &self,
            request: Request<ExpirePreAuthKeyRequest>,
        ) -> Result<Response<ExpirePreAuthKeyResponse>, Status> {
            self.authorize(&request).await?;
            let id = request.into_inner().id;
            self.preauth
                .expire_by_id(id)
                .await
                .map_err(preauth_error_to_status)?;
            Ok(Response::new(ExpirePreAuthKeyResponse {}))
        }

        async fn delete_pre_auth_key(
            &self,
            request: Request<DeletePreAuthKeyRequest>,
        ) -> Result<Response<DeletePreAuthKeyResponse>, Status> {
            self.authorize(&request).await?;
            let id = request.into_inner().id;
            self.preauth
                .delete_by_id(id)
                .await
                .map_err(preauth_error_to_status)?;
            Ok(Response::new(DeletePreAuthKeyResponse {}))
        }

        async fn list_pre_auth_keys(
            &self,
            request: Request<ListPreAuthKeysRequest>,
        ) -> Result<Response<ListPreAuthKeysResponse>, Status> {
            self.authorize(&request).await?;
            let keys = self.preauth.list().await;
            let mut pre_auth_keys = Vec::with_capacity(keys.len());
            for key in &keys {
                pre_auth_keys.push(preauth_key_to_proto(key, &self.users).await?);
            }
            pre_auth_keys.sort_by_key(|key| key.id);
            Ok(Response::new(ListPreAuthKeysResponse { pre_auth_keys }))
        }

        async fn debug_create_node(
            &self,
            request: Request<DebugCreateNodeRequest>,
        ) -> Result<Response<DebugCreateNodeResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            validate_registration_id(&body.key)?;
            let user = self
                .users
                .get(&body.user)
                .await
                .map_err(user_error_to_status)?
                .ok_or_else(|| Status::not_found("user not found"))?;
            let routes = normalize_routes(body.routes)
                .map_err(|e| Status::invalid_argument(format!("parsing route: {e}")))?;
            let record = self
                .debug_machine_record(&user.name, &body.name, routes)
                .await;
            self.registration_cache
                .insert(body.key, machine_admin_to_wire_record(&record));
            Ok(Response::new(DebugCreateNodeResponse {
                node: Some(machine_to_node(&record, &self.users).await?),
            }))
        }

        async fn get_node(
            &self,
            request: Request<GetNodeRequest>,
        ) -> Result<Response<GetNodeResponse>, Status> {
            self.authorize(&request).await?;
            let node = self.machine_by_id(request.into_inner().node_id).await?;
            Ok(Response::new(GetNodeResponse {
                node: Some(machine_to_node(&node, &self.users).await?),
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
                validate_tag(tag)?;
            }
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
            let node = self.machine_by_id(body.node_id).await?;
            self.machines
                .set_tags(&node.id, body.tags)
                .await
                .map_err(machine_error_to_status)?;
            let node = self
                .machines
                .get(&node.id)
                .await
                .ok_or_else(|| Status::not_found("node not found"))?;
            Ok(Response::new(SetTagsResponse {
                node: Some(machine_to_node(&node, &self.users).await?),
            }))
        }

        async fn set_approved_routes(
            &self,
            request: Request<SetApprovedRoutesRequest>,
        ) -> Result<Response<SetApprovedRoutesResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let node = self.machine_by_id(body.node_id).await?;
            let routes = normalize_routes(body.routes)
                .map_err(|e| Status::invalid_argument(format!("parsing route: {e}")))?;
            self.machines
                .set_approved_routes(&node.id, routes)
                .await
                .map_err(machine_error_to_status)?;
            let node = self
                .machines
                .get(&node.id)
                .await
                .ok_or_else(|| Status::not_found("node not found"))?;
            let machines = self.machines.list().await;
            let route_sets = route_sets_for_machines(&self.primary_routes, &machines);
            let primary_routes = route_sets.primary_routes_for(&node.id);
            Ok(Response::new(SetApprovedRoutesResponse {
                node: Some(machine_to_node_with_routes(&node, &self.users, &primary_routes).await?),
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
            let key = auth_id_cache_key(&body.auth_id)?;
            let response = self
                .register_node_body(RegisterNodeRequest {
                    user: body.user,
                    key,
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
            let node = self.machine_by_id(request.into_inner().node_id).await?;
            self.machines
                .delete(&node.id)
                .await
                .map_err(machine_error_to_status)?;
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
            let node = self.machine_by_id(body.node_id).await?;
            if body.disable_expiry {
                self.machines
                    .disable_expiry(&node.id)
                    .await
                    .map_err(machine_error_to_status)?;
            } else {
                let expiry = body
                    .expiry
                    .as_ref()
                    .map(timestamp_to_datetime)
                    .transpose()?
                    .unwrap_or_else(chrono::Utc::now);
                self.machines
                    .expire_at(&node.id, Some(expiry))
                    .await
                    .map_err(machine_error_to_status)?;
            }
            let node = self
                .machines
                .get(&node.id)
                .await
                .ok_or_else(|| Status::not_found("node not found"))?;
            Ok(Response::new(ExpireNodeResponse {
                node: Some(machine_to_node(&node, &self.users).await?),
            }))
        }

        async fn rename_node(
            &self,
            request: Request<RenameNodeRequest>,
        ) -> Result<Response<RenameNodeResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let node = self.machine_by_id(body.node_id).await?;
            self.machines
                .rename(&node.id, &body.new_name)
                .await
                .map_err(machine_error_to_status)?;
            let node = self
                .machines
                .get(&node.id)
                .await
                .ok_or_else(|| Status::not_found("node not found"))?;
            Ok(Response::new(RenameNodeResponse {
                node: Some(machine_to_node(&node, &self.users).await?),
            }))
        }

        async fn list_nodes(
            &self,
            request: Request<ListNodesRequest>,
        ) -> Result<Response<ListNodesResponse>, Status> {
            self.authorize(&request).await?;
            let filter_user = request.into_inner().user;
            let machines = self.machines.list().await;
            let route_sets = route_sets_for_machines(&self.primary_routes, &machines);
            let mut nodes = Vec::with_capacity(machines.len());
            for node in machines {
                if !filter_user.is_empty() && node.user != filter_user {
                    continue;
                }
                let subnet_routes = route_sets.subnet_routes_for(&node.id);
                nodes.push(machine_to_node_with_routes(&node, &self.users, &subnet_routes).await?);
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
                .map_err(machine_error_to_status)?;
            Ok(Response::new(BackfillNodeIPsResponse { changes }))
        }

        async fn create_api_key(
            &self,
            request: Request<CreateApiKeyRequest>,
        ) -> Result<Response<CreateApiKeyResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let expiration = body
                .expiration
                .as_ref()
                .map(timestamp_to_unix)
                .transpose()?;
            let created = self
                .api_keys
                .mint(ApiKeyMintRequest { expiration })
                .await
                .map_err(admin_error_to_status)?;
            Ok(Response::new(CreateApiKeyResponse {
                api_key: created.api_key,
            }))
        }

        async fn expire_api_key(
            &self,
            request: Request<ExpireApiKeyRequest>,
        ) -> Result<Response<ExpireApiKeyResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let selector = ApiKeySelector::from_parts(body.prefix, body.id)?;
            match selector {
                ApiKeySelector::Id(id) => self.api_keys.expire_by_id(id).await,
                ApiKeySelector::Prefix(prefix) => self.api_keys.expire_by_prefix(&prefix).await,
            }
            .map_err(admin_error_to_status)?;
            Ok(Response::new(ExpireApiKeyResponse {}))
        }

        async fn list_api_keys(
            &self,
            request: Request<ListApiKeysRequest>,
        ) -> Result<Response<ListApiKeysResponse>, Status> {
            self.authorize(&request).await?;
            let api_keys = self
                .api_keys
                .list()
                .await
                .iter()
                .map(admin_key_to_proto)
                .collect();
            Ok(Response::new(ListApiKeysResponse { api_keys }))
        }

        async fn delete_api_key(
            &self,
            request: Request<DeleteApiKeyRequest>,
        ) -> Result<Response<DeleteApiKeyResponse>, Status> {
            self.authorize(&request).await?;
            let body = request.into_inner();
            let selector = ApiKeySelector::from_parts(body.prefix, body.id)?;
            match selector {
                ApiKeySelector::Id(id) => self.api_keys.delete_by_id(id).await,
                ApiKeySelector::Prefix(prefix) => self.api_keys.delete_by_prefix(&prefix).await,
            }
            .map_err(admin_error_to_status)?;
            Ok(Response::new(DeleteApiKeyResponse {}))
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
                        .get_latest_policy()
                        .await
                        .map_err(|e| Status::unknown(format!("loading ACL from database: {e}")))?;
                    let Some(policy) = policy else {
                        return Err(Status::unknown(
                            "loading ACL from database: acl policy not found",
                        ));
                    };
                    Ok(Response::new(GetPolicyResponse {
                        policy: policy.policy,
                        updated_at: Some(unix_to_timestamp(policy.updated_at)),
                    }))
                }
                PolicyMode::File { path } => {
                    let policy = tokio::fs::read_to_string(path).await.map_err(|e| {
                        Status::unknown(format!(
                            "reading policy from path {:?}: {e}",
                            path.display().to_string()
                        ))
                    })?;
                    Ok(Response::new(GetPolicyResponse {
                        policy,
                        updated_at: None,
                    }))
                }
                PolicyMode::Memory => Ok(Response::new(GetPolicyResponse {
                    policy: self.policy.raw().unwrap_or_default(),
                    updated_at: self.policy.updated_at().map(unix_to_timestamp),
                })),
            }
        }

        async fn set_policy(
            &self,
            request: Request<SetPolicyRequest>,
        ) -> Result<Response<SetPolicyResponse>, Status> {
            self.authorize(&request).await?;
            let policy = request.into_inner().policy;
            if matches!(self.policy_mode, PolicyMode::File { .. }) {
                return Err(Status::unknown(
                    "update is disabled for modes other than 'database'",
                ));
            }
            let doc = parse_hujson_policy(&policy)
                .map_err(|e| Status::invalid_argument(format!("setting policy: {e}")))?;
            self.validate_candidate_policy(&doc, "setting policy")
                .await?;
            let (policy, updated_at) = match &self.policy_mode {
                PolicyMode::Database => {
                    let policy_persistence = self.policy_persistence.as_ref().ok_or_else(|| {
                        Status::unknown(
                            "persisting policy to database: policy database is not configured",
                        )
                    })?;
                    let persisted = policy_persistence.set_policy(&policy).await.map_err(|e| {
                        Status::unknown(format!("persisting policy to database: {e}"))
                    })?;
                    self.policy
                        .set_at(doc, persisted.policy.clone(), persisted.updated_at);
                    (persisted.policy, persisted.updated_at)
                }
                PolicyMode::Memory => {
                    self.policy.set(doc, policy.clone());
                    (
                        policy,
                        self.policy.updated_at().unwrap_or_else(current_unix_i64),
                    )
                }
                PolicyMode::File { .. } => unreachable!("file mode returned before parsing"),
            };
            crate::admin::machines::apply_policy_auto_approvals(
                &self.policy,
                self.machines.as_ref(),
            )
            .await
            .map_err(machine_error_to_status)?;
            Ok(Response::new(SetPolicyResponse {
                policy,
                updated_at: Some(unix_to_timestamp(updated_at)),
            }))
        }

        async fn check_policy(
            &self,
            request: Request<CheckPolicyRequest>,
        ) -> Result<Response<CheckPolicyResponse>, Status> {
            self.authorize(&request).await?;
            let policy = request.into_inner().policy;
            let doc = parse_hujson_policy(&policy)
                .map_err(|e| Status::invalid_argument(format!("checking policy: {e}")))?;
            self.validate_candidate_policy(&doc, "checking policy")
                .await?;
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
                    .map_err(|e| Status::unknown(format!("database ping failed: {e}")))?;
            }
            Ok(Response::new(HealthResponse {
                database_connectivity: true,
            }))
        }
    }

    enum ApiKeySelector {
        Id(u64),
        Prefix(String),
    }

    impl ApiKeySelector {
        fn from_parts(prefix: String, id: u64) -> Result<Self, Status> {
            match (prefix.trim().is_empty(), id) {
                (true, 0) => Err(Status::invalid_argument(
                    "either prefix or id must be provided",
                )),
                (false, 0) => Ok(Self::Prefix(prefix)),
                (true, id) => Ok(Self::Id(id)),
                (false, _) => Err(Status::invalid_argument(
                    "only one of prefix or id can be provided",
                )),
            }
        }
    }

    fn admin_key_to_proto(key: &ApiKeyAdminKey) -> ApiKey {
        ApiKey {
            id: key.id,
            prefix: key.prefix.clone(),
            expiration: key.expiration.map(unix_to_timestamp),
            created_at: Some(unix_to_timestamp(key.created_at)),
            last_seen: key.last_seen.map(unix_to_timestamp),
        }
    }

    fn unix_to_timestamp(seconds: i64) -> prost_types::Timestamp {
        prost_types::Timestamp { seconds, nanos: 0 }
    }

    fn timestamp_to_unix(ts: &prost_types::Timestamp) -> Result<i64, Status> {
        if !(0..1_000_000_000).contains(&ts.nanos) {
            return Err(Status::invalid_argument("timestamp nanos out of range"));
        }
        Ok(ts.seconds)
    }

    fn current_unix_i64() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    fn admin_error_to_status(e: ApiKeyAdminError) -> Status {
        match e {
            ApiKeyAdminError::NotFound => Status::not_found("api key not found"),
            ApiKeyAdminError::Store(msg) => Status::internal(msg),
        }
    }

    async fn preauth_key_to_proto(
        key: &PreauthAdminKey,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<PreAuthKey, Status> {
        Ok(PreAuthKey {
            user: preauth_user_to_proto(key, users).await?,
            id: key.id,
            key: key.key.clone(),
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.redemptions > 0,
            expiration: Some(unix_to_timestamp(saturating_u64_to_i64(key.expires_at))),
            created_at: Some(unix_to_timestamp(saturating_u64_to_i64(key.created_at))),
            acl_tags: key.tags.clone(),
        })
    }

    async fn preauth_user_to_proto(
        key: &PreauthAdminKey,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<Option<ProtoUser>, Status> {
        if key.user.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            users
                .get(&key.user)
                .await
                .map_err(user_error_to_status)?
                .map_or_else(
                    || ProtoUser {
                        id: 0,
                        name: key.user.clone(),
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
        }
    }

    async fn machine_to_node(
        machine: &MachineAdminRecord,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<Node, Status> {
        machine_to_node_with_routes(machine, users, &[]).await
    }

    fn machine_admin_to_wire_record(machine: &MachineAdminRecord) -> MachineRecord {
        let created_at =
            chrono::DateTime::from_timestamp(machine.created_at as i64, 0).unwrap_or_else(Utc::now);
        let last_seen =
            chrono::DateTime::from_timestamp(machine.last_seen as i64, 0).unwrap_or(created_at);
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
        record.expiry = machine
            .expiry
            .and_then(|expiry| chrono::DateTime::from_timestamp(expiry as i64, 0));
        record.last_seen = last_seen;
        record.os.clone_from(&machine.os);
        record.os_version.clone_from(&machine.version);
        record.forced_tags.clone_from(&machine.tags);
        record.available_routes.clone_from(&machine.routes);
        record.approved_routes.clone_from(&machine.approved_routes);
        record.register_method = machine.register_method;
        record
    }

    fn machine_admin_to_wire_record_with_pending(
        machine: &MachineAdminRecord,
        pending: &MachineRecord,
    ) -> MachineRecord {
        let mut record = pending.clone();
        record.node_key_hex.clone_from(&machine.id);
        record.machine_key_hex.clone_from(&machine.machine_key_hex);
        record.user.clone_from(&machine.user);
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
        record.expiry = machine
            .expiry
            .and_then(|expiry| chrono::DateTime::from_timestamp(expiry as i64, 0));
        if let Some(last_seen) = chrono::DateTime::from_timestamp(machine.last_seen as i64, 0) {
            record.last_seen = last_seen;
        }
        record.os.clone_from(&machine.os);
        record.os_version.clone_from(&machine.version);
        record.forced_tags.clone_from(&machine.tags);
        record.available_routes.clone_from(&machine.routes);
        record.approved_routes.clone_from(&machine.approved_routes);
        record.register_method = machine.register_method;
        record
    }

    fn wire_record_to_machine_admin(record: MachineRecord) -> MachineAdminRecord {
        let expired = record.is_expired_at(Utc::now());
        MachineAdminRecord {
            node_id: 0,
            id: record.node_key_hex,
            name: record.hostname,
            user: record.user,
            ipv4: record.ipv4.map(|ip| ip.to_string()).unwrap_or_default(),
            ipv6: record.ipv6.map(|ipv6| ipv6.to_string()),
            online: !expired,
            last_seen: record.last_seen.timestamp().max(0) as u64,
            created_at: record.created_at.timestamp().max(0) as u64,
            expiry: record.expiry.map(|expiry| expiry.timestamp().max(0) as u64),
            machine_key_hex: record.machine_key_hex,
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

    async fn machine_to_node_with_routes(
        machine: &MachineAdminRecord,
        users: &Arc<dyn UserAdmin>,
        subnet_routes: &[String],
    ) -> Result<Node, Status> {
        let user = machine_user_to_proto(machine, users).await?;
        Ok(Node {
            id: machine_numeric_id(machine),
            machine_key: prefix_key("mkey:", &machine.machine_key_hex),
            node_key: prefix_key("nodekey:", &machine.id),
            disco_key: String::new(),
            ip_addresses: node_ip_addresses(machine),
            name: machine.name.clone(),
            user,
            last_seen: nonzero_u64_timestamp(machine.last_seen),
            expiry: machine
                .expiry
                .map(saturating_u64_to_i64)
                .map(unix_to_timestamp),
            pre_auth_key: None,
            created_at: nonzero_u64_timestamp(machine.created_at),
            register_method: machine.register_method,
            given_name: machine.name.clone(),
            online: machine.online,
            approved_routes: machine.approved_routes.clone(),
            available_routes: machine.routes.clone(),
            subnet_routes: subnet_routes.to_vec(),
            tags: machine.tags.clone(),
        })
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

    fn policy_check_node_from_machine(machine: &MachineAdminRecord) -> PolicyCheckNode {
        PolicyCheckNode {
            id: machine_numeric_id(machine),
            name: machine.name.clone(),
            user: (!machine.user.is_empty()).then(|| machine.user.clone()),
            addrs: node_ip_addresses(machine),
            tags: machine.tags.clone(),
        }
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
        for machine in machines
            .iter()
            .filter(|machine| machine.online && !machine.expired)
        {
            let node_id = machine_numeric_id(machine);
            let primary = state.primary_routes(node_id);
            if !primary.is_empty() {
                primary_routes.insert(machine.id.clone(), primary);
            }

            let exit = active_exit_routes(&machine.routes, &machine.approved_routes);
            if !exit.is_empty() {
                exit_routes.insert(machine.id.clone(), exit);
            }
        }

        MachineRouteSets {
            primary_routes,
            exit_routes,
        }
    }

    const REGISTRATION_ID_LENGTH: usize = 24;
    const UPSTREAM_AUTH_ID_PREFIX: &str = "hskey-authreq-";

    fn validate_registration_id(id: &str) -> Result<(), Status> {
        if id.len() != REGISTRATION_ID_LENGTH {
            return Err(Status::invalid_argument(format!(
                "registration ID must be {REGISTRATION_ID_LENGTH} characters long"
            )));
        }
        Ok(())
    }

    fn auth_id_cache_key(id: &str) -> Result<String, Status> {
        if id.len() == REGISTRATION_ID_LENGTH {
            return Ok(id.to_string());
        }

        match id.strip_prefix(UPSTREAM_AUTH_ID_PREFIX) {
            Some(rest) if rest.len() == REGISTRATION_ID_LENGTH => Ok(rest.to_string()),
            Some(rest) => Err(Status::invalid_argument(format!(
                "invalid auth_id: expected {REGISTRATION_ID_LENGTH} characters after \
                 {UPSTREAM_AUTH_ID_PREFIX:?}, got {}",
                rest.len()
            ))),
            None => Err(Status::invalid_argument(format!(
                "invalid auth_id: expected a {REGISTRATION_ID_LENGTH}-character registration ID \
                 or an auth ID prefixed with {UPSTREAM_AUTH_ID_PREFIX:?}"
            ))),
        }
    }

    fn random_key_hex() -> String {
        let mut raw = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut raw);
        hex::encode(raw)
    }

    fn cgnat_ip_from_key(key: &str) -> Ipv4Addr {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in key.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let host = ((h as u32) % ((1u32 << 22) - 3)) + 2;
        const CGNAT_BASE: u32 = 0x6440_0000;
        Ipv4Addr::from((CGNAT_BASE | host).to_be_bytes())
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

    async fn machine_user_to_proto(
        machine: &MachineAdminRecord,
        users: &Arc<dyn UserAdmin>,
    ) -> Result<Option<ProtoUser>, Status> {
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
        if !(0..1_000_000_000).contains(&ts.nanos) {
            return Err(Status::invalid_argument("timestamp nanos out of range"));
        }
        chrono::DateTime::from_timestamp(ts.seconds, ts.nanos as u32)
            .ok_or_else(|| Status::invalid_argument("timestamp out of range"))
    }

    fn machine_error_to_status(e: MachineAdminError) -> Status {
        match e {
            MachineAdminError::NotFound(_) => Status::not_found("node not found"),
            MachineAdminError::BadRequest(msg) => Status::invalid_argument(msg),
        }
    }

    fn validate_tag(tag: &str) -> Result<(), Status> {
        if !tag.starts_with("tag:") {
            return Err(Status::invalid_argument(
                "tag must start with the string 'tag:'",
            ));
        }
        if tag.to_lowercase() != tag {
            return Err(Status::invalid_argument("tag should be lowercase"));
        }
        if tag.split_whitespace().count() > 1 {
            return Err(Status::invalid_argument("tag should not contains space"));
        }
        Ok(())
    }

    pub(super) fn apply_requested_tags(
        policy: &PolicyStore,
        record: &mut MachineAdminRecord,
    ) -> Result<(), Status> {
        if record.tags.is_empty() {
            return Ok(());
        }

        if validate_requested_tags_for_node(
            policy,
            &machine_primary_addr(record),
            record.user.as_str(),
            &mut record.tags,
        )
        .map_err(Status::invalid_argument)?
        {
            record.expiry = None;
        }

        Ok(())
    }

    fn machine_primary_addr(record: &MachineAdminRecord) -> String {
        if record.ipv4.trim().is_empty() {
            record
                .ipv6
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or_default()
                .to_string()
        } else {
            record.ipv4.trim().to_string()
        }
    }

    fn user_record_to_proto(user: &UserRecord) -> ProtoUser {
        ProtoUser {
            id: user.id,
            name: user.name.clone(),
            created_at: Some(unix_to_timestamp(saturating_u64_to_i64(user.created_at))),
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
}

#[cfg(all(test, feature = "admin"))]
mod upstream_tests {
    use std::fs;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use axum::body::to_bytes;
    use chrono::Utc;
    use prost::Message as _;
    use tonic::Request;
    use tower::ServiceExt;

    use super::upstream::{DatabaseHealthCheck, HeadscaleAdminService, apply_requested_tags};
    use crate::admin::{
        ApiKeyAdmin, ApiKeyMintRequest, MachineAdminRecord, PersistentApiKeyAdmin,
        PersistentMachineAdmin, PersistentPreauthAdmin, PersistentUserAdmin, WireMachineAdmin,
    };
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
    use crate::policy::{PolicyStore, parse_hujson_policy};
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
        assert!(listed.users.is_empty());
    }

    #[tokio::test]
    async fn upstream_user_grpc_reports_invalid_duplicate_and_missing() {
        let service = admin_service().await;

        let err = service
            .create_user(Request::new(CreateUserRequest {
                name: "Alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap();
        let err = service
            .create_user(Request::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);

        let err = service
            .delete_user(Request::new(DeleteUserRequest { id: 99 }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn upstream_grpc_api_key_auth_mode_enforces_bearer_token() {
        let (service, api_keys) = admin_service_with_api_keys().await;
        let service = service.require_api_key_auth();
        let _mounted = service.clone().into_service_server();
        let _auth_mounted = service.clone().into_authenticated_service_server();

        let err = service
            .health(Request::new(HealthRequest {}))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "Authorization token is not supplied");

        let mut malformed = Request::new(HealthRequest {});
        malformed
            .metadata_mut()
            .insert("authorization", "Token abc".parse().unwrap());
        let err = service.health(malformed).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            err.message(),
            r#"missing "Bearer " prefix in "Authorization" header"#
        );

        let mut invalid = Request::new(HealthRequest {});
        invalid
            .metadata_mut()
            .insert("authorization", "Bearer invalid".parse().unwrap());
        let err = service.health(invalid).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
        assert_eq!(err.message(), "invalid token");

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
    }

    #[test]
    fn upstream_grpc_reflection_descriptor_advertises_headscale_service() {
        let descriptors =
            prost_types::FileDescriptorSet::decode(crate::generated::FILE_DESCRIPTOR_SET)
                .expect("generated descriptor set decodes");
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
        assert!(methods.contains(&"CreateUser"));
        assert!(methods.contains(&"RegisterNode"));
        assert!(methods.contains(&"AuthRegister"));
        assert!(methods.contains(&"AuthApprove"));
        assert!(methods.contains(&"AuthReject"));
        assert!(methods.contains(&"SetApprovedRoutes"));
        assert!(methods.contains(&"Health"));
        assert!(!methods.iter().any(|method| method.contains("Version")));

        let _reflection =
            HeadscaleAdminService::reflection_service().expect("reflection service builds");
    }

    #[tokio::test]
    async fn upstream_node_grpc_debug_create_then_register() {
        let (service, _machines) = admin_service_with_machines().await;
        const REGISTRATION_ID: &str = "abcdefghijklmnopqrstuvwx";
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
                key: REGISTRATION_ID.into(),
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
                key: REGISTRATION_ID.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.node_key, debug_node.node_key);
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        assert_eq!(registered.available_routes, vec!["10.0.0.0/24"]);

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
                key: REGISTRATION_ID.into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn upstream_node_grpc_register_node_uses_configured_allocator() {
        let (service, _machines) = admin_service_with_machines().await;
        let service = service.with_ip_allocator(Arc::new(FixedDebugAllocator));
        const REGISTRATION_ID: &str = "debugallocatorabcdefghij";
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
                key: REGISTRATION_ID.into(),
                name: "debug-router".into(),
                routes: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("debug node");
        assert!(debug_node.ip_addresses.is_empty());

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: REGISTRATION_ID.into(),
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
                key: REGISTRATION_ID.into(),
                name: "debug-v6".into(),
                routes: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("debug node");
        assert!(debug_node.ip_addresses.is_empty());

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: REGISTRATION_ID.into(),
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
                key: REGISTRATION_ID.into(),
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
        assert_eq!(registered.available_routes, vec!["10.42.0.0/24"]);

        let err = service
            .auth_register(Request::new(AuthRegisterRequest {
                user: "alice".into(),
                auth_id: "short".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("invalid auth_id"));
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
            .auth_reject(Request::new(AuthRejectRequest { auth_id: reject_id }))
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
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(err.message().contains("no pending auth session"));
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
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
            policy: Arc::new(policy),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: Some("https://headscale.example".into()),
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: registration_cache.clone(),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
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
        let registration_id = pending_response
            .auth_url
            .strip_prefix("https://headscale.example/register/")
            .expect("web AuthURL prefix");
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
                key: registration_id.into(),
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
        assert_eq!(stored.user, "alice");
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
        assert!(followup_response.auth_url.is_empty());
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
                key: REGISTRATION_ID.into(),
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
                key: REGISTRATION_ID.into(),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.id, 1);
        assert_eq!(registered.node_key, pending.node_key);
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        assert_eq!(registered.available_routes, vec!["10.0.0.0/24"]);

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
        assert_eq!(renamed.name, "debug-renamed");

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
                key: first_id,
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
                key: second_id,
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
        assert!(live.forced_tags.is_empty());
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
        pending.disco_key = Some("discokey:web-restart".into());
        pending.endpoints = vec!["192.0.2.80:41641".into(), "2001:db8::80:41641".into()];
        pending.home_derp = 8;
        pending.os = "linux".into();
        pending.os_version = "6.10.0".into();
        pending.ssh_host_keys = vec!["ssh-ed25519 AAAAC3NzaCli".into()];
        pending.expiry = Some(Utc::now() + chrono::Duration::days(30));
        registration_cache.insert(registration_id.clone(), pending);

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: registration_id,
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("registered node");
        assert_eq!(registered.id, 1);
        assert_eq!(registered.user.as_ref().unwrap().id, 1);
        assert_eq!(registered.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(registered.machine_key, format!("mkey:{machine_key_hex}"));
        assert_eq!(registered.register_method, RegisterMethod::Cli as i32);
        assert_eq!(registered.tags, vec!["tag:server"]);
        assert_eq!(registered.available_routes, vec!["10.80.0.0/24"]);
        assert!(registered.expiry.is_none());
        let live = wire_registry.get(&node_key_hex).expect("live projection");
        assert_eq!(live.disco_key.as_deref(), Some("discokey:web-restart"));
        assert_eq!(
            live.endpoints,
            vec!["192.0.2.80:41641", "2001:db8::80:41641"]
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
        assert_eq!(row.user_id, Some(1));
        assert_eq!(row.auth_key_id, None);
        assert_eq!(
            row.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_CLI
        );
        assert_eq!(row.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(row.machine_key, format!("mkey:{machine_key_hex}"));
        assert_eq!(row.ipv4.as_deref(), Some("100.64.0.80"));
        assert_eq!(row.tag_list(), vec!["tag:server"]);
        assert_eq!(row.disco_key, "discokey:web-restart");
        assert_eq!(
            row.endpoint_list(),
            vec!["192.0.2.80:41641", "2001:db8::80:41641"]
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
        assert_eq!(hydrated.disco_key.as_deref(), Some("discokey:web-restart"));
        assert_eq!(
            hydrated.endpoints,
            vec!["192.0.2.80:41641", "2001:db8::80:41641"]
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
        assert_eq!(listed_node.user.as_ref().unwrap().id, 1);
        assert_eq!(listed_node.node_key, format!("nodekey:{node_key_hex}"));
        assert_eq!(listed_node.machine_key, format!("mkey:{machine_key_hex}"));
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
        assert_eq!(got.available_routes, listed_node.available_routes);
        drop(fresh_service);
        reopened.close().await;
    }

    #[tokio::test]
    async fn persistent_node_grpc_set_approved_routes_survives_fresh_service() {
        let (service, db) = admin_service_with_persistent_machines().await;
        const REGISTRATION_ID: &str = "exitrouteabcdefghijklmno";

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
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: REGISTRATION_ID.into(),
                name: "exit-router".into(),
                routes: vec!["0.0.0.0/0".into(), "::/0".into()],
            }))
            .await
            .unwrap();

        let registered = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: REGISTRATION_ID.into(),
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
        assert!(updated.subnet_routes.is_empty());

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
        assert!(preapproved.subnet_routes.is_empty());

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
        assert_eq!(renamed.name, "beta");

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
        assert!(listed.nodes.is_empty());
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

        let err = service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: vec!["Tag:Server".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("requested tags"));

        let err = service
            .set_approved_routes(Request::new(SetApprovedRoutesRequest {
                node_id,
                routes: vec!["not-a-prefix".into()],
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service
            .set_tags(Request::new(SetTagsRequest {
                node_id,
                tags: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service
            .debug_create_node(Request::new(DebugCreateNodeRequest {
                user: "alice".into(),
                key: "short".into(),
                name: "debug".into(),
                routes: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service
            .register_node(Request::new(RegisterNodeRequest {
                user: "alice".into(),
                key: "abcdefghijklmnopqrstuvwx".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
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
            ipv4: "100.64.0.7".into(),
            ipv6: None,
            online: true,
            last_seen: 0,
            created_at: 0,
            expiry: Some(1_780_000_000),
            machine_key_hex: "bb".repeat(32),
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
        assert!(err.message().contains("requested tags [tag:server]"));
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
        assert!(updated.subnet_routes.is_empty());

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
        assert!(listed_node.subnet_routes.is_empty());
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
        assert!(ok.changes.is_empty());
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
            vec![
                "removing IPv4 \"100.64.0.10\" from Node(1) \"needs-v6\"",
                "assigned IPv6 \"fd7a:115c:a1e0::77\" to Node(1) \"needs-v6\""
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

        let listed = service
            .list_api_keys(Request::new(ListApiKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.api_keys.len(), 1);
        let key = &listed.api_keys[0];
        assert!(key.id > 0);
        assert!(key.prefix.starts_with("hskey-api-"));
        assert!(key.prefix.ends_with("-***"));
        assert_eq!(key.expiration.as_ref().unwrap().seconds, 4_102_444_800);
        assert!(key.created_at.is_some());

        service
            .expire_api_key(Request::new(ExpireApiKeyRequest {
                prefix: String::new(),
                id: key.id,
            }))
            .await
            .unwrap();

        service
            .delete_api_key(Request::new(DeleteApiKeyRequest {
                prefix: String::new(),
                id: key.id,
            }))
            .await
            .unwrap();

        let listed = service
            .list_api_keys(Request::new(ListApiKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(listed.api_keys.is_empty());
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

        let err = service
            .delete_api_key(Request::new(DeleteApiKeyRequest {
                prefix: "hskey-api-abcdefghijkl-***".into(),
                id: 1,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
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
                    nanos: 0,
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
        assert_eq!(created.expiration.as_ref().unwrap().seconds, 4_102_444_800);

        let listed = service
            .list_pre_auth_keys(Request::new(ListPreAuthKeysRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.pre_auth_keys.len(), 1);
        assert_eq!(listed.pre_auth_keys[0].id, created.id);
        assert_eq!(
            listed.pre_auth_keys[0].expiration.as_ref().unwrap().seconds,
            4_102_444_800
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
        assert!(listed.pre_auth_keys.is_empty());
    }

    #[tokio::test]
    async fn upstream_preauth_grpc_validates_user_id_and_tags() {
        let service = admin_service().await;

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
        assert_eq!(err.code(), tonic::Code::NotFound);

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

        let err = service
            .set_policy(Request::new(SetPolicyRequest { policy: "{".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let err = service
            .check_policy(Request::new(CheckPolicyRequest { policy: "{".into() }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn upstream_policy_grpc_evaluates_policy_tests_before_success() {
        let (service, machines) = admin_service_with_machines().await;
        let alice_key = "91".repeat(32);
        let server_key = "92".repeat(32);
        machines.upsert(
            alice_key.clone(),
            MachineRecord::new_at(
                Utc::now(),
                alice_key,
                "93".repeat(32),
                "alice".into(),
                "alice-laptop".into(),
                Ipv4Addr::new(100, 64, 0, 1),
                false,
            ),
        );
        machines.upsert(
            server_key.clone(),
            MachineRecord::new_at(
                Utc::now(),
                server_key,
                "94".repeat(32),
                "bob".into(),
                "server".into(),
                Ipv4Addr::new(100, 64, 0, 2),
                false,
            ),
        );

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
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("cannot reach accept destination"));

        let err = service
            .set_policy(Request::new(SetPolicyRequest {
                policy: failing.into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("cannot reach accept destination"));

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
        let node_key = "95".repeat(32);
        machines.upsert(
            node_key.clone(),
            MachineRecord::new_at(
                Utc::now(),
                node_key,
                "96".repeat(32),
                "alice".into(),
                "alice-laptop".into(),
                Ipv4Addr::new(100, 64, 0, 3),
                false,
            ),
        );
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
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("cannot SSH to destination"));

        let err = service
            .set_policy(Request::new(SetPolicyRequest {
                policy: failing.into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("cannot SSH to destination"));

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
    async fn upstream_policy_reload_from_file_updates_live_policy_and_auto_approvals() {
        let (service, machines) = admin_service_with_machines().await;
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
        assert_eq!(err.message(), "database ping failed: forced offline");
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
