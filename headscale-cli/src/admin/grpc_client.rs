//! gRPC client transport for upstream-compatible admin commands.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use headscale_api::generated::{
    ApiKey, AuthApproveRequest, AuthRegisterRequest, AuthRejectRequest, BackfillNodeIPsRequest,
    BackfillNodeIPsResponse, CheckPolicyRequest, CreateApiKeyRequest, CreatePreAuthKeyRequest,
    CreateUserRequest, DebugCreateNodeRequest, DeleteApiKeyRequest, DeleteNodeRequest,
    DeletePreAuthKeyRequest, DeleteUserRequest, ExpireApiKeyRequest, ExpireNodeRequest,
    ExpirePreAuthKeyRequest, GetNodeRequest, GetPolicyRequest, GetPolicyResponse, HealthRequest,
    HealthResponse, ListApiKeysRequest, ListNodesRequest, ListPreAuthKeysRequest, ListUsersRequest,
    Node, PreAuthKey, RegisterNodeRequest, RenameNodeRequest, RenameUserRequest,
    SetApprovedRoutesRequest, SetPolicyRequest, SetPolicyResponse, SetTagsRequest, User,
    headscale_service_client::HeadscaleServiceClient,
};
use hyper_util::rt::TokioIo;
use rand_core::{OsRng, RngCore};
#[cfg(test)]
use tokio::net::TcpStream;
use tokio::net::UnixStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint, Uri};
use tonic::{Code, Request, Status};
use tower::service_fn;

use super::AdminError;

mod upstream_balancer;
mod upstream_connection;
mod upstream_dns;
mod upstream_nss;
mod upstream_retry;
mod upstream_rfc6724;
mod upstream_service_config;
mod upstream_target;
mod upstream_transport;
use upstream_target::RemoteTarget;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UPSTREAM_MIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_UNIX_SOCKET: &str = "/var/run/headscale/headscale.sock";

#[derive(Clone)]
pub struct GrpcAdminClient {
    client: HeadscaleServiceClient<upstream_retry::RetryChannel>,
    api_key: Option<String>,
    upstream_rpc_errors: bool,
    upstream_service_options: bool,
    command_deadline: Option<tokio::time::Instant>,
    call_budget: RpcBudget,
    service_config: Option<upstream_service_config::SharedConfig>,
}

impl GrpcAdminClient {
    /// Standalone v0.29.5 command context: retry dialing within one deadline,
    /// then carry its remaining budget through every unary RPC and response.
    pub async fn connect_upstream(
        address: Option<&str>,
        api_key: Option<&str>,
        unix_socket: Option<&Path>,
        insecure: bool,
        timeout: Option<Duration>,
    ) -> Result<Self, AdminError> {
        let timeout = timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| AdminError::Local("gRPC timeout is out of range".into()))?;
        // Go checks remote credentials before dialing, even if its newly
        // created context has already expired.
        if address.is_some_and(|address| !address.is_empty()) && api_key.is_none_or(str::is_empty) {
            return Err(AdminError::Local(
                "HEADSCALE_CLI_API_KEY environment variable needs to be set".into(),
            ));
        }
        let target = address.filter(|value| !value.is_empty()).map_or_else(
            || {
                unix_socket.map_or_else(
                    || DEFAULT_UNIX_SOCKET.into(),
                    |path| path.display().to_string(),
                )
            },
            str::to_string,
        );
        if address.is_none_or(str::is_empty) {
            tracing::debug!(
                socket = %target,
                "HEADSCALE_CLI_ADDRESS environment is not set, connecting to unix socket."
            );
        }
        #[cfg(unix)]
        if address.is_none_or(str::is_empty) {
            probe_socket_permissions(
                unix_socket.unwrap_or_else(|| Path::new(DEFAULT_UNIX_SOCKET)),
            )?;
        }
        let remote_target = address
            .filter(|address| !address.is_empty())
            .map(RemoteTarget::parse)
            .transpose()
            .map_err(|error| AdminError::Connection(format!("connecting to {target}: {error}")))?;
        let expired =
            || AdminError::Connection(format!("connecting to {target}: context deadline exceeded"));
        let mut backoff = UpstreamConnectBackoff::default();
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(expired());
            }
            let retry_delay = backoff.next_delay();
            let connect_budget = retry_delay.max(UPSTREAM_MIN_CONNECT_TIMEOUT);
            // grpc-go gives a dial at least 20 seconds, increasing that budget
            // with backoff. The command context can expire before either one.
            let attempt_deadline = deadline.min(tokio::time::Instant::now() + connect_budget);
            let attempt = Self::connect_upstream_once(
                remote_target.as_ref(),
                api_key,
                unix_socket,
                insecure,
                timeout,
                connect_budget,
            );
            match tokio::time::timeout_at(attempt_deadline, attempt).await {
                Ok(Ok(mut client)) => {
                    client.command_deadline = Some(deadline);
                    client.upstream_service_options = true;
                    return Ok(client.with_upstream_rpc_errors(true));
                }
                Ok(Err(AdminError::Local(error))) => return Err(AdminError::Local(error)),
                Err(_) if tokio::time::Instant::now() >= deadline => return Err(expired()),
                Ok(Err(_)) | Err(_) => {}
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(retry_delay.min(remaining)).await;
        }
    }

    async fn connect_upstream_once(
        target: Option<&RemoteTarget>,
        api_key: Option<&str>,
        unix_socket: Option<&Path>,
        insecure: bool,
        timeout: Duration,
        connect_budget: Duration,
    ) -> Result<Self, AdminError> {
        if let Some(target) = target {
            let service_config = match target {
                RemoteTarget::Tcp {
                    dns: true,
                    dns_server: Some(resolver),
                    ..
                } => Some(resolver.service_config()),
                _ => None,
            };
            let origin = format!("https://{}", target.authority())
                .parse::<Uri>()
                .map_err(|error| AdminError::Connection(error.to_string()))?;
            let tls = upstream_transport::tls_config(insecure)
                .map_err(|error| AdminError::Connection(error.to_string()))?;
            let channel = match target {
                RemoteTarget::Tcp {
                    endpoint: target,
                    dns,
                    dns_server,
                } => {
                    let (host, port) = upstream_target::tcp_destination(target, *dns)
                        .map_err(|error| AdminError::Connection(error.to_string()))?;
                    if *dns {
                        upstream_transport::connect(
                            origin,
                            upstream_transport::Destination::Dns {
                                host,
                                port,
                                resolver: dns_server
                                    .clone()
                                    .unwrap_or_else(upstream_dns::DnsAuthority::system),
                            },
                            Some(tls),
                            timeout,
                            connect_budget,
                        )
                        .await
                    } else {
                        upstream_transport::connect(
                            origin,
                            upstream_transport::Destination::Host(host, port),
                            Some(tls),
                            timeout,
                            connect_budget,
                        )
                        .await
                    }
                }
                RemoteTarget::Unix(path) => {
                    upstream_transport::connect(
                        origin,
                        upstream_transport::Destination::Unix(path.clone()),
                        Some(tls),
                        timeout,
                        connect_budget,
                    )
                    .await
                }
            }
            .map_err(|error| AdminError::Connection(error.to_string()))?;
            let mut client = Self::from_connection(channel, api_key.map(str::to_string));
            client.service_config = service_config;
            Ok(client)
        } else {
            let socket =
                unix_socket.map_or_else(|| PathBuf::from(DEFAULT_UNIX_SOCKET), Path::to_path_buf);
            Ok(Self::from_connection(
                upstream_transport::connect(
                    Uri::from_static("http://[::]:50051"),
                    upstream_transport::Destination::Unix(socket),
                    None,
                    timeout,
                    connect_budget,
                )
                .await
                .map_err(|error| AdminError::Connection(error.to_string()))?,
                None,
            ))
        }
    }

    pub async fn connect(
        address: Option<&str>,
        api_key: Option<&str>,
        unix_socket: Option<&Path>,
        insecure: bool,
        timeout: Option<Duration>,
    ) -> Result<Self, AdminError> {
        let timeout = timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT);
        if let Some(address) = address.filter(|value| !value.trim().is_empty()) {
            let api_key = api_key.filter(|value| !value.is_empty()).ok_or_else(|| {
                AdminError::Local(
                    "HEADSCALE_CLI_API_KEY environment variable needs to be set".into(),
                )
            })?;
            let channel = remote_channel(address, insecure, timeout).await?;
            Ok(Self::from_channel(channel, Some(api_key.to_string())))
        } else {
            let socket =
                unix_socket.map_or_else(|| PathBuf::from(DEFAULT_UNIX_SOCKET), Path::to_path_buf);
            let channel = unix_channel(socket, timeout).await?;
            Ok(Self::from_channel(channel, None))
        }
    }

    pub fn from_channel(channel: Channel, api_key: Option<String>) -> Self {
        Self::from_connection(
            upstream_connection::Connection::from_channel(channel),
            api_key,
        )
    }

    fn from_connection(channel: upstream_connection::Connection, api_key: Option<String>) -> Self {
        Self {
            client: HeadscaleServiceClient::new(upstream_retry::RetryChannel::new(channel)),
            api_key,
            upstream_rpc_errors: false,
            upstream_service_options: false,
            command_deadline: None,
            call_budget: RpcBudget::default(),
            service_config: None,
        }
    }

    /// Use pinned headscale CLI command context, gRPC status text and exit 1.
    /// Direct client callers retain typed errors unless they opt in.
    pub fn with_upstream_rpc_errors(mut self, enabled: bool) -> Self {
        self.upstream_rpc_errors = enabled;
        self
    }

    fn rpc_error(&self, context: &str, status: &Status) -> AdminError {
        if self.upstream_rpc_errors {
            policy_status_to_admin_error(context, status)
        } else {
            status_to_admin_error(status)
        }
    }

    pub async fn create_user(
        &mut self,
        name: &str,
        display_name: &str,
        email: &str,
        picture_url: &str,
    ) -> Result<User, AdminError> {
        let request = self.request(CreateUserRequest {
            name: name.to_string(),
            display_name: display_name.to_string(),
            email: email.to_string(),
            picture_url: picture_url.to_string(),
        })?;
        let response =
            with_cli_deadline(self.call_budget.clone(), self.client.create_user(request))
                .await
                .map_err(|status| self.rpc_error("creating user", &status))?
                .into_inner();
        response
            .user
            .ok_or_else(|| AdminError::Decode("CreateUser response omitted user".into()))
    }

    pub async fn create_api_key(&mut self, expiration: Option<i64>) -> Result<String, AdminError> {
        self.create_api_key_precise(expiration.map(unix_to_timestamp))
            .await
    }

    pub async fn create_api_key_precise(
        &mut self,
        expiration: Option<prost_types::Timestamp>,
    ) -> Result<String, AdminError> {
        let request = self.request(CreateApiKeyRequest { expiration })?;
        Ok(with_cli_deadline(
            self.call_budget.clone(),
            self.client.create_api_key(request),
        )
        .await
        .map_err(|status| self.rpc_error("creating api key", &status))?
        .into_inner()
        .api_key)
    }

    pub async fn list_api_keys(&mut self) -> Result<Vec<ApiKey>, AdminError> {
        let request = self.request(ListApiKeysRequest {})?;
        Ok(
            with_cli_deadline(self.call_budget.clone(), self.client.list_api_keys(request))
                .await
                .map_err(|status| self.rpc_error("listing api keys", &status))?
                .into_inner()
                .api_keys,
        )
    }

    pub async fn create_pre_auth_key(
        &mut self,
        user: u64,
        reusable: bool,
        ephemeral: bool,
        expiration: Option<prost_types::Timestamp>,
        acl_tags: Vec<String>,
    ) -> Result<PreAuthKey, AdminError> {
        let request = self.request(CreatePreAuthKeyRequest {
            user,
            reusable,
            ephemeral,
            expiration,
            acl_tags,
        })?;
        let response = with_cli_deadline(
            self.call_budget.clone(),
            self.client.create_pre_auth_key(request),
        )
        .await
        .map_err(|status| self.rpc_error("creating preauthkey", &status))?
        .into_inner();
        response
            .pre_auth_key
            .ok_or_else(|| AdminError::Decode("CreatePreAuthKey response omitted key".into()))
    }

    pub async fn list_pre_auth_keys(&mut self) -> Result<Vec<PreAuthKey>, AdminError> {
        let request = self.request(ListPreAuthKeysRequest {})?;
        Ok(with_cli_deadline(
            self.call_budget.clone(),
            self.client.list_pre_auth_keys(request),
        )
        .await
        .map_err(|status| self.rpc_error("listing preauthkeys", &status))?
        .into_inner()
        .pre_auth_keys)
    }

    pub async fn expire_pre_auth_key(&mut self, id: u64) -> Result<(), AdminError> {
        let request = self.request(ExpirePreAuthKeyRequest { id })?;
        with_cli_deadline(
            self.call_budget.clone(),
            self.client.expire_pre_auth_key(request),
        )
        .await
        .map_err(|status| self.rpc_error("expiring preauthkey", &status))?;
        Ok(())
    }

    pub async fn delete_pre_auth_key(&mut self, id: u64) -> Result<(), AdminError> {
        let request = self.request(DeletePreAuthKeyRequest { id })?;
        with_cli_deadline(
            self.call_budget.clone(),
            self.client.delete_pre_auth_key(request),
        )
        .await
        .map_err(|status| self.rpc_error("deleting preauthkey", &status))?;
        Ok(())
    }

    pub async fn get_policy(&mut self) -> Result<GetPolicyResponse, AdminError> {
        let request = self.request(GetPolicyRequest {})?;
        Ok(
            with_cli_deadline(self.call_budget.clone(), self.client.get_policy(request))
                .await
                .map_err(|status| policy_status_to_admin_error("loading ACL policy", &status))?
                .into_inner(),
        )
    }

    pub async fn set_policy(&mut self, policy: String) -> Result<SetPolicyResponse, AdminError> {
        let request = self.request(SetPolicyRequest { policy })?;
        Ok(
            with_cli_deadline(self.call_budget.clone(), self.client.set_policy(request))
                .await
                .map_err(|status| policy_status_to_admin_error("setting ACL policy", &status))?
                .into_inner(),
        )
    }

    pub async fn check_policy(&mut self, policy: String) -> Result<(), AdminError> {
        let request = self.request(CheckPolicyRequest { policy })?;
        with_cli_deadline(self.call_budget.clone(), self.client.check_policy(request))
            .await
            .map_err(|status| AdminError::Usage(go_rpc_status(&status)))?;
        Ok(())
    }

    pub async fn list_nodes(&mut self, user: Option<&str>) -> Result<Vec<Node>, AdminError> {
        let request = self.request(ListNodesRequest {
            user: user.unwrap_or_default().to_string(),
        })?;
        Ok(
            with_cli_deadline(self.call_budget.clone(), self.client.list_nodes(request))
                .await
                .map_err(|status| self.rpc_error("listing nodes", &status))?
                .into_inner()
                .nodes,
        )
    }

    pub async fn get_node(&mut self, node_id: u64) -> Result<Node, AdminError> {
        let request = self.request(GetNodeRequest { node_id })?;
        let response = with_cli_deadline(self.call_budget.clone(), self.client.get_node(request))
            .await
            .map_err(|status| self.rpc_error("getting node", &status))?
            .into_inner();
        required_node(response.node, "GetNode")
    }

    pub async fn register_node(&mut self, user: &str, key: &str) -> Result<Node, AdminError> {
        let request = self.request(RegisterNodeRequest {
            user: user.to_string(),
            key: key.to_string(),
        })?;
        let response =
            with_cli_deadline(self.call_budget.clone(), self.client.register_node(request))
                .await
                .map_err(|status| self.rpc_error("registering node", &status))?
                .into_inner();
        required_node(response.node, "RegisterNode")
    }

    pub async fn auth_register(&mut self, user: &str, auth_id: &str) -> Result<Node, AdminError> {
        let request = self.request(AuthRegisterRequest {
            user: user.to_string(),
            auth_id: auth_id.to_string(),
        })?;
        let response =
            with_cli_deadline(self.call_budget.clone(), self.client.auth_register(request))
                .await
                .map_err(|status| self.rpc_error("registering node", &status))?
                .into_inner();
        required_node(response.node, "AuthRegister")
    }

    pub async fn auth_approve(&mut self, auth_id: &str) -> Result<(), AdminError> {
        let request = self.request(AuthApproveRequest {
            auth_id: auth_id.to_string(),
        })?;
        with_cli_deadline(self.call_budget.clone(), self.client.auth_approve(request))
            .await
            .map_err(|status| self.rpc_error("approving auth request", &status))?;
        Ok(())
    }

    pub async fn auth_reject(&mut self, auth_id: &str) -> Result<(), AdminError> {
        let request = self.request(AuthRejectRequest {
            auth_id: auth_id.to_string(),
        })?;
        with_cli_deadline(self.call_budget.clone(), self.client.auth_reject(request))
            .await
            .map_err(|status| self.rpc_error("rejecting auth request", &status))?;
        Ok(())
    }

    pub async fn debug_create_node(
        &mut self,
        user: &str,
        key: &str,
        name: &str,
        routes: Vec<String>,
    ) -> Result<Node, AdminError> {
        let request = self.request(DebugCreateNodeRequest {
            user: user.to_string(),
            key: key.to_string(),
            name: name.to_string(),
            routes,
        })?;
        let response = with_cli_deadline(
            self.call_budget.clone(),
            self.client.debug_create_node(request),
        )
        .await
        .map_err(|status| self.rpc_error("creating node", &status))?
        .into_inner();
        required_node(response.node, "DebugCreateNode")
    }

    pub async fn set_tags(&mut self, node_id: u64, tags: Vec<String>) -> Result<Node, AdminError> {
        let request = self.request(SetTagsRequest { node_id, tags })?;
        let response = with_cli_deadline(self.call_budget.clone(), self.client.set_tags(request))
            .await
            .map_err(|status| self.rpc_error("setting tags", &status))?
            .into_inner();
        required_node(response.node, "SetTags")
    }

    pub async fn set_approved_routes(
        &mut self,
        node_id: u64,
        routes: Vec<String>,
    ) -> Result<Node, AdminError> {
        let request = self.request(SetApprovedRoutesRequest { node_id, routes })?;
        let response = with_cli_deadline(
            self.call_budget.clone(),
            self.client.set_approved_routes(request),
        )
        .await
        .map_err(|status| self.rpc_error("setting approved routes", &status))?
        .into_inner();
        required_node(response.node, "SetApprovedRoutes")
    }

    pub async fn expire_node(
        &mut self,
        node_id: u64,
        expiry: Option<prost_types::Timestamp>,
        disable_expiry: bool,
    ) -> Result<Node, AdminError> {
        let request = self.request(ExpireNodeRequest {
            node_id,
            expiry,
            disable_expiry,
        })?;
        let response =
            with_cli_deadline(self.call_budget.clone(), self.client.expire_node(request))
                .await
                .map_err(|status| {
                    self.rpc_error(
                        if disable_expiry {
                            "disabling node expiry"
                        } else {
                            "expiring node"
                        },
                        &status,
                    )
                })?
                .into_inner();
        required_node(response.node, "ExpireNode")
    }

    pub async fn rename_node(&mut self, node_id: u64, new_name: &str) -> Result<Node, AdminError> {
        let request = self.request(RenameNodeRequest {
            node_id,
            new_name: new_name.to_string(),
        })?;
        let response =
            with_cli_deadline(self.call_budget.clone(), self.client.rename_node(request))
                .await
                .map_err(|status| self.rpc_error("renaming node", &status))?
                .into_inner();
        required_node(response.node, "RenameNode")
    }

    pub async fn delete_node(&mut self, node_id: u64) -> Result<(), AdminError> {
        let request = self.request(DeleteNodeRequest { node_id })?;
        with_cli_deadline(self.call_budget.clone(), self.client.delete_node(request))
            .await
            .map_err(|status| self.rpc_error("deleting node", &status))?;
        Ok(())
    }

    pub async fn backfill_node_ips(
        &mut self,
        confirmed: bool,
    ) -> Result<BackfillNodeIPsResponse, AdminError> {
        let request = self.request(BackfillNodeIPsRequest { confirmed })?;
        Ok(with_cli_deadline(
            self.call_budget.clone(),
            self.client.backfill_node_i_ps(request),
        )
        .await
        .map_err(|status| self.rpc_error("backfilling IPs", &status))?
        .into_inner())
    }

    pub async fn health(&mut self) -> Result<HealthResponse, AdminError> {
        let request = self.request(HealthRequest {})?;
        Ok(
            with_cli_deadline(self.call_budget.clone(), self.client.health(request))
                .await
                .map_err(|status| self.rpc_error("checking health", &status))?
                .into_inner(),
        )
    }

    pub async fn expire_api_key(
        &mut self,
        prefix: Option<&str>,
        id: Option<u64>,
    ) -> Result<(), AdminError> {
        let request = self.request(ExpireApiKeyRequest {
            prefix: prefix.unwrap_or_default().to_string(),
            id: id.unwrap_or_default(),
        })?;
        with_cli_deadline(
            self.call_budget.clone(),
            self.client.expire_api_key(request),
        )
        .await
        .map_err(|status| self.rpc_error("expiring api key", &status))?;
        Ok(())
    }

    pub async fn delete_api_key(
        &mut self,
        prefix: Option<&str>,
        id: Option<u64>,
    ) -> Result<(), AdminError> {
        let request = self.request(DeleteApiKeyRequest {
            prefix: prefix.unwrap_or_default().to_string(),
            id: id.unwrap_or_default(),
        })?;
        with_cli_deadline(
            self.call_budget.clone(),
            self.client.delete_api_key(request),
        )
        .await
        .map_err(|status| self.rpc_error("deleting api key", &status))?;
        Ok(())
    }

    pub async fn rename_user_by_id(&mut self, id: u64, new_name: &str) -> Result<User, AdminError> {
        let request = self.request(RenameUserRequest {
            old_id: id,
            new_name: new_name.to_string(),
        })?;
        let response =
            with_cli_deadline(self.call_budget.clone(), self.client.rename_user(request))
                .await
                .map_err(|status| self.rpc_error("renaming user", &status))?
                .into_inner();
        response
            .user
            .ok_or_else(|| AdminError::Decode("RenameUser response omitted user".into()))
    }

    pub async fn list_users(
        &mut self,
        selector: UserSelector<'_>,
    ) -> Result<Vec<User>, AdminError> {
        let request = self.request(ListUsersRequest {
            id: selector.id.unwrap_or_default(),
            name: selector.name.unwrap_or_default().to_string(),
            email: selector.email.unwrap_or_default().to_string(),
        })?;
        Ok(
            with_cli_deadline(self.call_budget.clone(), self.client.list_users(request))
                .await
                .map_err(|status| self.rpc_error("listing users", &status))?
                .into_inner()
                .users,
        )
    }

    pub async fn delete_user_by_id(&mut self, id: u64) -> Result<(), AdminError> {
        let request = self.request(DeleteUserRequest { id })?;
        with_cli_deadline(self.call_budget.clone(), self.client.delete_user(request))
            .await
            .map_err(|status| self.rpc_error("destroying user", &status))?;
        Ok(())
    }

    fn request<T: prost::Message + upstream_service_config::RpcMethod>(
        &mut self,
        body: T,
    ) -> Result<Request<T>, AdminError> {
        self.call_budget = self.command_deadline.into();
        let mut retry_policy = None;
        if self.upstream_service_options {
            let (config, throttler) = self
                .service_config
                .as_ref()
                .map(|state| {
                    let state = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (state.current(), state.throttler())
                })
                .unwrap_or_default();
            let config = config
                .map(|config| config.method(T::NAME))
                .unwrap_or_default();
            self.call_budget.throttler = throttler;
            if let Some(nanos) = config.timeout_nanos {
                let now = tokio::time::Instant::now();
                let deadline = if nanos <= 0 {
                    Some(now)
                } else {
                    now.checked_add(Duration::from_nanos(nanos as u64))
                };
                if let Some(deadline) = deadline {
                    self.call_budget.deadline = Some(
                        self.command_deadline
                            .map_or(deadline, |command| command.min(deadline)),
                    );
                }
            }
            let maximum_request = config
                .max_request
                .unwrap_or(i64::from(i32::MAX))
                .min(isize::MAX as i64);
            let maximum_response = config
                .max_response
                .unwrap_or(4 * 1024 * 1024)
                .min(isize::MAX as i64);
            let length = body.encoded_len();
            if length as i128 > i128::from(maximum_request) {
                self.call_budget.preflight = Some(Status::resource_exhausted(format!(
                    "trying to send message larger than max ({length} vs. {maximum_request})"
                )));
            }
            self.call_budget.maximum_response = Some(maximum_response);
            self.client = self
                .client
                .clone()
                .max_encoding_message_size(usize::try_from(maximum_request).unwrap_or(0))
                .max_decoding_message_size(usize::try_from(maximum_response).unwrap_or(0));
            let outcome = Arc::new(std::sync::Mutex::new(None));
            self.call_budget.retry_outcome = Some(outcome.clone());
            retry_policy = Some(upstream_retry::CallPolicy {
                deadline: self.call_budget.deadline,
                retry: config.retry,
                throttler: self.call_budget.throttler.clone(),
                outcome,
                wait_for_ready: config.wait_for_ready.unwrap_or(false),
            });
        }
        let mut request = Request::new(body);
        if let Some(policy) = retry_policy {
            request.extensions_mut().insert(policy);
        }
        if let Some(deadline) = self.call_budget.deadline {
            request.set_timeout(deadline.saturating_duration_since(tokio::time::Instant::now()));
        }
        if let Some(api_key) = &self.api_key {
            let value = MetadataValue::try_from(format!("Bearer {api_key}"))
                .map_err(|e| AdminError::Local(format!("invalid API key metadata: {e}")))?;
            request.metadata_mut().insert("authorization", value);
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Default)]
struct RpcBudget {
    deadline: Option<tokio::time::Instant>,
    preflight: Option<Status>,
    maximum_response: Option<i64>,
    throttler: Option<Arc<upstream_service_config::RetryThrottler>>,
    retry_outcome: Option<Arc<std::sync::Mutex<Option<u32>>>>,
}

impl From<Option<tokio::time::Instant>> for RpcBudget {
    fn from(deadline: Option<tokio::time::Instant>) -> Self {
        Self {
            deadline,
            ..Self::default()
        }
    }
}

async fn with_cli_deadline<T: prost::Message>(
    budget: impl Into<RpcBudget>,
    call: impl std::future::Future<Output = Result<tonic::Response<T>, Status>>,
) -> Result<tonic::Response<T>, Status> {
    let budget = budget.into();
    if budget
        .deadline
        .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    {
        return Err(Status::deadline_exceeded("context deadline exceeded"));
    }
    if let Some(status) = budget.preflight {
        return Err(status);
    }
    let result = match budget.deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, call)
            .await
            .unwrap_or_else(|_| Err(Status::deadline_exceeded("context deadline exceeded")))
            .map_err(|status| {
                // Tonic maps its transport timer to Canceled. Preserve a
                // server-supplied Canceled status, but translate a local timer
                // to Go's command-context DeadlineExceeded status.
                let mut source = std::error::Error::source(&status);
                while let Some(error) = source {
                    if error.is::<tonic::TimeoutExpired>() {
                        return Status::deadline_exceeded("context deadline exceeded");
                    }
                    source = error.source();
                }
                status
            }),
        None => call.await,
    };
    let response = match result {
        Ok(response) => response,
        Err(mut status) => {
            let exhausted = budget.retry_outcome.as_ref().and_then(|outcome| {
                *outcome
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            });
            if let Some(attempts) = exhausted {
                let source = upstream_retry::RetryExhausted {
                    attempts,
                    status: status.clone(),
                };
                status.set_source(Arc::new(source));
            }
            return Err(status);
        }
    };
    if let Some(maximum) = budget.maximum_response {
        let length = response.get_ref().encoded_len();
        if length as i128 > i128::from(maximum) {
            return Err(Status::resource_exhausted(format!(
                "grpc: received message larger than max ({length} vs. {maximum})"
            )));
        }
    }
    if let Some(throttler) = budget.throttler {
        throttler.succeeded();
    }
    Ok(response)
}

fn unix_to_timestamp(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

fn required_node(node: Option<Node>, rpc: &str) -> Result<Node, AdminError> {
    node.ok_or_else(|| AdminError::Decode(format!("{rpc} response omitted node")))
}

#[derive(Copy, Clone, Debug, Default)]
pub struct UserSelector<'a> {
    pub id: Option<u64>,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
}

/// grpc-go v1.81.1's default connection backoff: the first delay is exactly
/// one second; later delays multiply by 1.6, cap at 120 seconds, then jitter
/// by +/-20%. Jitter is sampled independently of application credentials.
#[derive(Debug, Default)]
struct UpstreamConnectBackoff {
    retries: u32,
}

impl UpstreamConnectBackoff {
    // Go computes the jitter with float64 conversions of 53-bit integers.
    #[allow(clippy::cast_precision_loss)]
    fn next_delay(&mut self) -> Duration {
        let retries = self.retries;
        self.retries = self.retries.saturating_add(1);
        if retries == 0 {
            return Duration::from_secs(1);
        }
        // Match Go's float64 arithmetic in nanoseconds, including applying
        // jitter after the unjittered maximum has been enforced.
        let mut nanos: f64 = 1_000_000_000.0;
        for _ in 0..retries {
            if nanos >= 120_000_000_000.0 {
                break;
            }
            nanos *= 1.6;
        }
        nanos = nanos.min(120_000_000_000.0);
        let random = (OsRng.next_u64() >> 11) as f64 / ((1_u64 << 53) as f64);
        Duration::from_nanos((nanos * 0.2f64.mul_add(random * 2.0 - 1.0, 1.0)) as u64)
    }
}

#[cfg(unix)]
fn probe_socket_permissions(path: &Path) -> Result<(), AdminError> {
    use std::os::unix::fs::OpenOptionsExt;

    // Go opens the path for writing before dialing and reports only permission
    // failures. No bytes are read/written and no file is created or truncated.
    // NONBLOCK also avoids hanging on a misconfigured FIFO path.
    if let Err(error) = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        && error.kind() == io::ErrorKind::PermissionDenied
    {
        let detail = if error.raw_os_error() == Some(libc::EPERM) {
            "operation not permitted"
        } else {
            "permission denied"
        };
        return Err(AdminError::Connection(format!(
            "unable to read/write to headscale socket {:?}, do you have the correct permissions? open {}: {detail}",
            path.to_string_lossy(),
            path.display(),
        )));
    }
    Ok(())
}

async fn unix_channel(path: PathBuf, timeout: Duration) -> Result<Channel, AdminError> {
    let display_path = path.display().to_string();
    Endpoint::try_from("http://[::]:50051")
        .map_err(|e| AdminError::Connection(e.to_string()))?
        .timeout(timeout)
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|_| {
            AdminError::Connection(format!(
                "connecting to {display_path}: context deadline exceeded"
            ))
        })
}

fn remote_endpoint(uri: Uri, timeout: Duration) -> Result<Endpoint, AdminError> {
    if uri.scheme_str() == Some("https") {
        tls_endpoint(uri, false, timeout)
    } else {
        Ok(Endpoint::from(uri).timeout(timeout))
    }
}

async fn remote_channel(
    address: &str,
    insecure: bool,
    timeout: Duration,
) -> Result<Channel, AdminError> {
    let uri = remote_uri(address)?;
    if insecure && uri.scheme_str() == Some("https") {
        return insecure_tls_channel(uri, timeout).await;
    }

    remote_endpoint(uri, timeout)?
        .connect()
        .await
        .map_err(|e| AdminError::Connection(e.to_string()))
}

fn remote_uri(address: &str) -> Result<Uri, AdminError> {
    let uri = if address.contains("://") {
        address.to_string()
    } else {
        format!("https://{address}")
    };
    let uri = uri
        .parse::<Uri>()
        .map_err(|e| AdminError::Connection(e.to_string()))?;
    if uri.host().is_none() {
        return Err(AdminError::Connection(format!(
            "remote gRPC address {address:?} does not include a host"
        )));
    }
    Ok(uri)
}

async fn insecure_tls_channel(origin: Uri, timeout: Duration) -> Result<Channel, AdminError> {
    tls_endpoint(origin, true, timeout)?
        .connect()
        .await
        .map_err(|e| AdminError::Connection(e.to_string()))
}

fn tls_endpoint(uri: Uri, insecure: bool, timeout: Duration) -> Result<Endpoint, AdminError> {
    ensure_rustls_provider();
    let host = uri
        .host()
        .ok_or_else(|| AdminError::Connection("remote gRPC address missing host".into()))?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_string();
    // Use explicit TLS configuration on Endpoint::from rather than automatic
    // URI setup, so IPv6 brackets are removed before rustls parses the name.
    // Tonic owns ALPN verification for TCP and Unix transports alike.
    let endpoint = Endpoint::from(uri).timeout(timeout);
    let config = ClientTlsConfig::new().domain_name(host);
    let result = if insecure {
        endpoint.tls_config_with_verifier(config, Arc::new(NoCertificateVerification))
    } else {
        endpoint.tls_config(config.with_enabled_roots())
    };
    result.map_err(|error| AdminError::Connection(error.to_string()))
}

fn ensure_rustls_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        tokio_rustls::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                .signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn status_to_admin_error(status: &Status) -> AdminError {
    match status.code() {
        Code::Unauthenticated | Code::PermissionDenied => AdminError::Auth(status.message().into()),
        Code::NotFound => AdminError::NotFound(status.message().into()),
        Code::InvalidArgument | Code::AlreadyExists | Code::FailedPrecondition => {
            AdminError::BadRequest {
                status: 400,
                body: status.message().into(),
            }
        }
        Code::Unavailable => AdminError::Connection(status.message().into()),
        _ => AdminError::Server {
            status: 500,
            body: status.message().into(),
        },
    }
}

fn policy_status_to_admin_error(context: &str, status: &Status) -> AdminError {
    AdminError::Usage(format!("{context}: {}", go_rpc_status(status)))
}

fn go_rpc_status(status: &Status) -> String {
    if let Some(exhausted) = std::error::Error::source(status)
        .and_then(|source| source.downcast_ref::<upstream_retry::RetryExhausted>())
    {
        return format!(
            "max retries exhausted: failed after {} attempts: {}",
            exhausted.attempts,
            go_rpc_status(&exhausted.status)
        );
    }
    let code = match status.code() {
        Code::Ok => "OK".to_string(),
        Code::Cancelled => "Canceled".to_string(),
        code => format!("{code:?}"),
    };
    format!("rpc error: code = {code} desc = {}", status.message())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use headscale_api::admin::{
        InMemoryPreauthAdmin, NoopApiKeyAdmin, PersistentApiKeyAdmin, PersistentPreauthAdmin,
        PersistentUserAdmin, UserRegistry, WireMachineAdmin,
    };
    use headscale_api::grpc::upstream::HeadscaleAdminService;
    use headscale_api::policy::PolicyStore;
    use headscale_api::tailscale_wire::MachineRegistry;
    use headscale_api::tailscale_wire::tls::{self, SanConfig};
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{TcpListener, UnixListener};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::server::TlsStream;
    use tokio_stream::{StreamExt, wrappers::UnixListenerStream};
    use tonic::transport::Server;
    use tonic::transport::server::Connected;

    #[test]
    fn remote_addresses_default_to_https() {
        assert_eq!(
            remote_uri("127.0.0.1:50443").unwrap().scheme_str(),
            Some("https")
        );
        assert_eq!(
            remote_uri("http://127.0.0.1:50443").unwrap().scheme_str(),
            Some("http")
        );
    }

    #[test]
    fn insecure_does_not_downgrade_remote_endpoint_to_plaintext() {
        assert_eq!(
            tls_endpoint(
                remote_uri("127.0.0.1:50443").unwrap(),
                true,
                Duration::from_secs(5)
            )
            .unwrap()
            .uri()
            .scheme_str(),
            Some("https")
        );
    }

    #[test]
    fn grpc_status_maps_to_cli_exit_classes() {
        assert!(matches!(
            status_to_admin_error(&Status::unauthenticated("bad token")),
            AdminError::Auth(_)
        ));
        assert!(matches!(
            status_to_admin_error(&Status::not_found("missing")),
            AdminError::NotFound(_)
        ));
        assert!(matches!(
            status_to_admin_error(&Status::invalid_argument("bad")),
            AdminError::BadRequest { .. }
        ));
    }

    #[tokio::test]
    async fn grpc_client_uses_local_unix_socket_for_user_commands() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("headscale.sock");
        let machines = Arc::new(MachineRegistry::new());
        let service = HeadscaleAdminService::with_user_admin(
            Arc::new(UserRegistry::new()),
            Arc::new(NoopApiKeyAdmin),
            Arc::new(InMemoryPreauthAdmin::new()),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        );
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_service_server())
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await
        });

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false, None)
            .await
            .unwrap();
        let created = client
            .create_user("alice", "Alice Example", "alice@example.com", "")
            .await
            .unwrap();
        assert_eq!(created.name, "alice");
        assert_eq!(created.display_name, "Alice Example");
        assert_eq!(created.email, "alice@example.com");

        let listed = client.list_users(UserSelector::default()).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "alice");

        let filtered = client
            .list_users(UserSelector {
                id: None,
                name: Some("alice"),
                email: None,
            })
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);

        let renamed = client
            .rename_user_by_id(listed[0].id, "alice-renamed")
            .await
            .unwrap();
        assert_eq!(renamed.name, "alice-renamed");

        client.delete_user_by_id(listed[0].id).await.unwrap();
        assert!(
            client
                .list_users(UserSelector::default())
                .await
                .unwrap()
                .is_empty()
        );

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn grpc_client_uses_local_unix_socket_for_api_key_commands() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("headscale.sock");
        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let machines = Arc::new(MachineRegistry::new());
        let service = HeadscaleAdminService::with_user_admin(
            Arc::new(UserRegistry::new()),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(InMemoryPreauthAdmin::new()),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        );
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_service_server())
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await
        });

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false, None)
            .await
            .unwrap();
        let expiration = current_unix_i64() + 3600;
        let secret = client.create_api_key(Some(expiration)).await.unwrap();
        assert!(secret.starts_with("hskey-api-"));

        let listed = client.list_api_keys().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, 1);
        assert!(listed[0].expiration.is_some());
        assert!(listed[0].created_at.is_some());

        client
            .expire_api_key(None, Some(listed[0].id))
            .await
            .unwrap();
        let expired = client.list_api_keys().await.unwrap();
        assert_eq!(expired.len(), 1);

        client
            .delete_api_key(Some(&expired[0].prefix), None)
            .await
            .unwrap();
        assert!(client.list_api_keys().await.unwrap().is_empty());

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn grpc_client_uses_local_unix_socket_for_preauth_key_commands() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("headscale.sock");
        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let machines = Arc::new(MachineRegistry::new());
        let service = HeadscaleAdminService::with_user_admin(
            users.clone(),
            Arc::new(PersistentApiKeyAdmin::new_for_test(db.pool().clone())),
            Arc::new(
                PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users),
            ),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        );
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_service_server())
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await
        });

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false, None)
            .await
            .unwrap();
        let user = client.create_user("alice", "", "", "").await.unwrap();
        let expiration = current_unix_i64() + 3600;
        let key = client
            .create_pre_auth_key(
                user.id,
                true,
                true,
                Some(unix_to_timestamp(expiration)),
                vec!["tag:server".into()],
            )
            .await
            .unwrap();
        assert!(key.key.starts_with("hskey-auth-"));
        assert_eq!(key.user.as_ref().unwrap().name, "alice");
        assert_eq!(key.acl_tags, vec!["tag:server".to_string()]);

        let listed = client.list_pre_auth_keys().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, key.id);

        client.expire_pre_auth_key(key.id).await.unwrap();
        client.delete_pre_auth_key(key.id).await.unwrap();
        assert!(client.list_pre_auth_keys().await.unwrap().is_empty());

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn grpc_client_uses_local_unix_socket_for_policy_commands() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("headscale.sock");
        let machines = Arc::new(MachineRegistry::new());
        let service = HeadscaleAdminService::with_user_admin(
            Arc::new(UserRegistry::new()),
            Arc::new(NoopApiKeyAdmin),
            Arc::new(InMemoryPreauthAdmin::new()),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        );
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_service_server())
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await
        });

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false, None)
            .await
            .unwrap();
        let raw = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#.to_string();
        client.check_policy(raw.clone()).await.unwrap();
        let set = client.set_policy(raw.clone()).await.unwrap();
        assert_eq!(set.policy, raw);
        assert!(set.updated_at.is_some());
        let got = client.get_policy().await.unwrap();
        assert_eq!(got.policy, raw);
        assert!(client.check_policy("{".into()).await.is_err());

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn grpc_client_uses_local_unix_socket_for_node_commands() {
        let machines = Arc::new(MachineRegistry::new());
        let service = HeadscaleAdminService::with_user_admin(
            Arc::new(UserRegistry::new()),
            Arc::new(NoopApiKeyAdmin),
            Arc::new(InMemoryPreauthAdmin::new()),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        );
        let (_dir, socket, handle) = spawn_unix_service(service);

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false, None)
            .await
            .unwrap();
        client.create_user("alice", "", "", "").await.unwrap();
        let registration_id = "abcdefghijklmnopqrstuvwx";
        let auth_id = format!("hskey-authreq-{registration_id}");
        let pending = client
            .debug_create_node("alice", &auth_id, "node-one", vec!["10.10.0.0/24".into()])
            .await
            .unwrap();
        assert_eq!(pending.name, "node-one");
        assert_eq!(pending.available_routes, vec!["10.10.0.0/24".to_string()]);

        let registered = client.register_node("alice", &auth_id).await.unwrap();
        assert_eq!(registered.name, "node-one");
        assert_eq!(registered.user.as_ref().unwrap().name, "alice");
        // headscale-go's `debug create-node` caches the routes only on the
        // pending entry; the node created by `auth register` advertises none.
        assert!(registered.available_routes.is_empty());

        let auth_registration_id = "bbbbbbbbbbbbbbbbbbbbbbbb";
        client
            .debug_create_node(
                "alice",
                &format!("hskey-authreq-{auth_registration_id}"),
                "auth-node",
                Vec::new(),
            )
            .await
            .unwrap();
        let auth_registered = client
            .auth_register("alice", &format!("hskey-authreq-{auth_registration_id}"))
            .await
            .unwrap();
        assert_eq!(auth_registered.name, "auth-node");

        let approve_id = "cccccccccccccccccccccccc";
        client
            .debug_create_node(
                "alice",
                &format!("hskey-authreq-{approve_id}"),
                "approve-node",
                Vec::new(),
            )
            .await
            .unwrap();
        client
            .auth_approve(&format!("hskey-authreq-{approve_id}"))
            .await
            .unwrap();

        let reject_id = "dddddddddddddddddddddddd";
        client
            .debug_create_node(
                "alice",
                &format!("hskey-authreq-{reject_id}"),
                "reject-node",
                Vec::new(),
            )
            .await
            .unwrap();
        client
            .auth_reject(&format!("hskey-authreq-{reject_id}"))
            .await
            .unwrap();

        let listed = client.list_nodes(None).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|node| node.id == registered.id));
        assert!(listed.iter().any(|node| node.id == auth_registered.id));
        let filtered = client.list_nodes(Some("alice")).await.unwrap();
        assert_eq!(filtered.len(), 2);
        let fetched = client.get_node(registered.id).await.unwrap();
        assert_eq!(fetched.id, registered.id);

        client
            .set_policy(r#"{"tagOwners":{"tag:server":["alice@"]}}"#.into())
            .await
            .unwrap();
        let tagged = client
            .set_tags(registered.id, vec!["tag:server".into()])
            .await
            .unwrap();
        assert_eq!(tagged.tags, vec!["tag:server".to_string()]);

        let routed = client
            .set_approved_routes(registered.id, vec!["10.10.0.0/24".into()])
            .await
            .unwrap();
        assert_eq!(routed.approved_routes, vec!["10.10.0.0/24".to_string()]);

        let expired = client
            .expire_node(
                registered.id,
                Some(unix_to_timestamp(current_unix_i64() + 3600)),
                false,
            )
            .await
            .unwrap();
        assert!(expired.expiry.is_some());
        let unexpired = client.expire_node(registered.id, None, true).await.unwrap();
        assert!(unexpired.expiry.is_none());

        let renamed = client
            .rename_node(registered.id, "node-renamed")
            .await
            .unwrap();
        // Rename changes the DNS label (given_name); `name` stays the client's
        // own hostname, as in headscale-go.
        assert_eq!(renamed.given_name, "node-renamed");
        assert_eq!(renamed.name, "node-one");

        client.delete_node(registered.id).await.unwrap();
        client.delete_node(auth_registered.id).await.unwrap();
        assert!(client.list_nodes(None).await.unwrap().is_empty());
        assert!(matches!(
            client.get_node(registered.id).await,
            Err(AdminError::NotFound(_))
        ));

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn grpc_client_uses_local_unix_socket_for_health_and_backfillips() {
        let machines = Arc::new(MachineRegistry::new());
        let service = HeadscaleAdminService::with_user_admin(
            Arc::new(UserRegistry::new()),
            Arc::new(NoopApiKeyAdmin),
            Arc::new(InMemoryPreauthAdmin::new()),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        );
        let (_dir, socket, handle) = spawn_unix_service(service);

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false, None)
            .await
            .unwrap();
        let health = client.health().await.unwrap();
        assert!(health.database_connectivity);
        assert!(client.backfill_node_ips(false).await.is_err());
        let backfilled = client.backfill_node_ips(true).await.unwrap();
        assert!(backfilled.changes.is_empty());

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn grpc_client_insecure_remote_uses_tls_without_verifying_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let material =
            tls::load_or_generate(dir.path(), &SanConfig::with_hostname("localhost")).unwrap();
        let server_config =
            tls::build_grpc_server_config(&material.cert_pem, &material.key_pem).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let machines = Arc::new(MachineRegistry::new());
        let service = HeadscaleAdminService::with_user_admin(
            Arc::new(UserRegistry::new()),
            Arc::new(NoopApiKeyAdmin),
            Arc::new(InMemoryPreauthAdmin::new()),
            PolicyStore::new(),
            Arc::new(WireMachineAdmin::new(machines)),
        );
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).then({
            let acceptor = acceptor.clone();
            move |accepted| {
                let acceptor = acceptor.clone();
                async move {
                    let stream = accepted?;
                    acceptor
                        .accept(stream)
                        .await
                        .map(ConnectedTlsStream)
                        .map_err(io::Error::other)
                }
            }
        });
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_service_server())
                .serve_with_incoming(incoming)
                .await
        });

        let mut client = GrpcAdminClient::connect(
            Some(&addr.to_string()),
            Some("test-api-key"),
            None,
            true,
            None,
        )
        .await
        .unwrap();
        let created = client.create_user("remote", "", "", "").await.unwrap();
        assert_eq!(created.name, "remote");

        handle.abort();
        let _ = handle.await;
    }

    struct ConnectedTlsStream(TlsStream<TcpStream>);

    impl Connected for ConnectedTlsStream {
        type ConnectInfo = ();

        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    impl AsyncRead for ConnectedTlsStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for ConnectedTlsStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    fn current_unix_i64() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs() as i64)
    }

    fn spawn_unix_service(
        service: HeadscaleAdminService,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("headscale.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = tokio::spawn(async move {
            Server::builder()
                .add_service(service.into_service_server())
                .serve_with_incoming(UnixListenerStream::new(listener))
                .await
        });
        (dir, socket, handle)
    }
}
