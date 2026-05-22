//! gRPC client transport for upstream-compatible admin commands.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use headscale_api::generated::{
    ApiKey, CheckPolicyRequest, CreateApiKeyRequest, CreatePreAuthKeyRequest, CreateUserRequest,
    DeleteApiKeyRequest, DeleteUserRequest, ExpireApiKeyRequest, ExpirePreAuthKeyRequest,
    GetPolicyRequest, GetPolicyResponse, ListApiKeysRequest, ListPreAuthKeysRequest,
    ListUsersRequest, PreAuthKey, RenameUserRequest, SetPolicyRequest, SetPolicyResponse, User,
    headscale_service_client::HeadscaleServiceClient,
};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Request, Status};
use tower::service_fn;

use super::AdminError;

const DEFAULT_UNIX_SOCKET: &str = "/var/run/headscale/headscale.sock";

#[derive(Clone)]
pub struct GrpcAdminClient {
    client: HeadscaleServiceClient<Channel>,
    api_key: Option<String>,
}

impl GrpcAdminClient {
    pub async fn connect(
        address: Option<&str>,
        api_key: Option<&str>,
        unix_socket: Option<&Path>,
        insecure: bool,
    ) -> Result<Self, AdminError> {
        if let Some(address) = address.filter(|value| !value.trim().is_empty()) {
            let api_key = api_key
                .filter(|value| !value.is_empty())
                .ok_or_else(|| AdminError::Local("--api-key is required for remote gRPC".into()))?;
            let channel = remote_channel(address, insecure).await?;
            Ok(Self::from_channel(channel, Some(api_key.to_string())))
        } else {
            let socket =
                unix_socket.map_or_else(|| PathBuf::from(DEFAULT_UNIX_SOCKET), Path::to_path_buf);
            let channel = unix_channel(socket).await?;
            Ok(Self::from_channel(channel, None))
        }
    }

    pub fn from_channel(channel: Channel, api_key: Option<String>) -> Self {
        Self {
            client: HeadscaleServiceClient::new(channel),
            api_key,
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
        let response = self
            .client
            .create_user(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner();
        response
            .user
            .ok_or_else(|| AdminError::Decode("CreateUser response omitted user".into()))
    }

    pub async fn create_api_key(&mut self, expiration: Option<i64>) -> Result<String, AdminError> {
        let request = self.request(CreateApiKeyRequest {
            expiration: expiration.map(unix_to_timestamp),
        })?;
        Ok(self
            .client
            .create_api_key(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner()
            .api_key)
    }

    pub async fn list_api_keys(&mut self) -> Result<Vec<ApiKey>, AdminError> {
        let request = self.request(ListApiKeysRequest {})?;
        Ok(self
            .client
            .list_api_keys(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner()
            .api_keys)
    }

    pub async fn create_pre_auth_key(
        &mut self,
        user: u64,
        reusable: bool,
        ephemeral: bool,
        expiration: Option<i64>,
        acl_tags: Vec<String>,
    ) -> Result<PreAuthKey, AdminError> {
        let request = self.request(CreatePreAuthKeyRequest {
            user,
            reusable,
            ephemeral,
            expiration: expiration.map(unix_to_timestamp),
            acl_tags,
        })?;
        let response = self
            .client
            .create_pre_auth_key(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner();
        response
            .pre_auth_key
            .ok_or_else(|| AdminError::Decode("CreatePreAuthKey response omitted key".into()))
    }

    pub async fn list_pre_auth_keys(&mut self) -> Result<Vec<PreAuthKey>, AdminError> {
        let request = self.request(ListPreAuthKeysRequest {})?;
        Ok(self
            .client
            .list_pre_auth_keys(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner()
            .pre_auth_keys)
    }

    pub async fn expire_pre_auth_key(&mut self, id: u64) -> Result<(), AdminError> {
        let request = self.request(ExpirePreAuthKeyRequest { id })?;
        self.client
            .expire_pre_auth_key(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?;
        Ok(())
    }

    pub async fn get_policy(&mut self) -> Result<GetPolicyResponse, AdminError> {
        let request = self.request(GetPolicyRequest {})?;
        Ok(self
            .client
            .get_policy(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner())
    }

    pub async fn set_policy(&mut self, policy: String) -> Result<SetPolicyResponse, AdminError> {
        let request = self.request(SetPolicyRequest { policy })?;
        Ok(self
            .client
            .set_policy(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner())
    }

    pub async fn check_policy(&mut self, policy: String) -> Result<(), AdminError> {
        let request = self.request(CheckPolicyRequest { policy })?;
        self.client
            .check_policy(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?;
        Ok(())
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
        self.client
            .expire_api_key(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?;
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
        self.client
            .delete_api_key(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?;
        Ok(())
    }

    pub async fn rename_user_by_id(&mut self, id: u64, new_name: &str) -> Result<User, AdminError> {
        let request = self.request(RenameUserRequest {
            old_id: id,
            new_name: new_name.to_string(),
        })?;
        let response = self
            .client
            .rename_user(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
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
        Ok(self
            .client
            .list_users(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?
            .into_inner()
            .users)
    }

    pub async fn delete_user_by_id(&mut self, id: u64) -> Result<(), AdminError> {
        let request = self.request(DeleteUserRequest { id })?;
        self.client
            .delete_user(request)
            .await
            .map_err(|status| status_to_admin_error(&status))?;
        Ok(())
    }

    fn request<T>(&self, body: T) -> Result<Request<T>, AdminError> {
        let mut request = Request::new(body);
        if let Some(api_key) = &self.api_key {
            let value = MetadataValue::try_from(format!("Bearer {api_key}"))
                .map_err(|e| AdminError::Local(format!("invalid API key metadata: {e}")))?;
            request.metadata_mut().insert("authorization", value);
        }
        Ok(request)
    }
}

fn unix_to_timestamp(seconds: i64) -> prost_types::Timestamp {
    prost_types::Timestamp { seconds, nanos: 0 }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct UserSelector<'a> {
    pub id: Option<u64>,
    pub name: Option<&'a str>,
    pub email: Option<&'a str>,
}

async fn unix_channel(path: PathBuf) -> Result<Channel, AdminError> {
    Endpoint::try_from("http://[::]:50051")
        .map_err(|e| AdminError::Connection(e.to_string()))?
        .timeout(Duration::from_secs(10))
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await
        .map_err(|e| AdminError::Connection(e.to_string()))
}

fn remote_endpoint(uri: Uri) -> Result<Endpoint, AdminError> {
    ensure_rustls_provider();
    Endpoint::new(uri)
        .map(|endpoint| endpoint.timeout(Duration::from_secs(10)))
        .map_err(|e| AdminError::Connection(e.to_string()))
}

async fn remote_channel(address: &str, insecure: bool) -> Result<Channel, AdminError> {
    let uri = remote_uri(address)?;
    if insecure && uri.scheme_str() == Some("https") {
        return insecure_tls_channel(uri).await;
    }

    remote_endpoint(uri)?
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

async fn insecure_tls_channel(origin: Uri) -> Result<Channel, AdminError> {
    let connector_uri = connector_uri_for_tls_origin(&origin)?;
    Endpoint::from(connector_uri)
        .origin(origin)
        .timeout(Duration::from_secs(10))
        .connect_with_connector(service_fn(insecure_tls_stream))
        .await
        .map_err(|e| AdminError::Connection(e.to_string()))
}

fn connector_uri_for_tls_origin(origin: &Uri) -> Result<Uri, AdminError> {
    let authority = origin
        .authority()
        .ok_or_else(|| AdminError::Connection("remote gRPC address missing authority".into()))?;
    format!("http://{authority}")
        .parse::<Uri>()
        .map_err(|e| AdminError::Connection(e.to_string()))
}

async fn insecure_tls_stream(
    uri: Uri,
) -> Result<TokioIo<tokio_rustls::client::TlsStream<TcpStream>>, io::Error> {
    ensure_rustls_provider();
    let host = uri
        .host()
        .ok_or_else(|| io::Error::other("remote gRPC address missing host"))?
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    let stream = TcpStream::connect((host.as_str(), port)).await?;
    let server_name = ServerName::try_from(host)
        .map_err(|e| io::Error::other(format!("invalid TLS server name: {e}")))?;

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    config.alpn_protocols.push(b"h2".to_vec());

    TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map(TokioIo::new)
        .map_err(io::Error::other)
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use headscale_api::admin::{
        InMemoryPreauthAdmin, NoopApiKeyAdmin, PersistentApiKeyAdmin, PersistentPreauthAdmin,
        UserRegistry, WireMachineAdmin,
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
            remote_endpoint(remote_uri("127.0.0.1:50443").unwrap())
                .unwrap()
                .uri()
                .scheme_str(),
            Some("https")
        );
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
            connector_uri_for_tls_origin(&remote_uri("127.0.0.1:50443").unwrap())
                .unwrap()
                .scheme_str(),
            Some("http")
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

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false)
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

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false)
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
        let users = Arc::new(UserRegistry::new());
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

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false)
            .await
            .unwrap();
        let user = client.create_user("alice", "", "", "").await.unwrap();
        let expiration = current_unix_i64() + 3600;
        let key = client
            .create_pre_auth_key(
                user.id,
                true,
                true,
                Some(expiration),
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

        let mut client = GrpcAdminClient::connect(None, None, Some(&socket), false)
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

        let mut client =
            GrpcAdminClient::connect(Some(&addr.to_string()), Some("test-api-key"), None, true)
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
}
