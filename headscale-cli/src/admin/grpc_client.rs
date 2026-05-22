//! gRPC client transport for upstream-compatible admin commands.

use std::path::{Path, PathBuf};
use std::time::Duration;

use headscale_api::generated::{
    CreateUserRequest, DeleteUserRequest, ListUsersRequest, User,
    headscale_service_client::HeadscaleServiceClient,
};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
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
            let endpoint = remote_endpoint(address, insecure)?;
            let channel = endpoint
                .connect()
                .await
                .map_err(|e| AdminError::Connection(e.to_string()))?;
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

    pub async fn create_user(&mut self, name: &str) -> Result<User, AdminError> {
        let request = self.request(CreateUserRequest {
            name: name.to_string(),
            display_name: String::new(),
            email: String::new(),
            picture_url: String::new(),
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

    pub async fn list_users(&mut self, name: Option<&str>) -> Result<Vec<User>, AdminError> {
        let request = self.request(ListUsersRequest {
            id: 0,
            name: name.unwrap_or_default().to_string(),
            email: String::new(),
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

fn remote_endpoint(address: &str, insecure: bool) -> Result<Endpoint, AdminError> {
    let uri = if address.contains("://") {
        address.to_string()
    } else if insecure {
        format!("http://{address}")
    } else {
        format!("https://{address}")
    };
    Endpoint::from_shared(uri)
        .map(|endpoint| endpoint.timeout(Duration::from_secs(10)))
        .map_err(|e| AdminError::Connection(e.to_string()))
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
        InMemoryPreauthAdmin, NoopApiKeyAdmin, UserRegistry, WireMachineAdmin,
    };
    use headscale_api::grpc::upstream::HeadscaleAdminService;
    use headscale_api::policy::PolicyStore;
    use headscale_api::tailscale_wire::MachineRegistry;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;

    #[test]
    fn remote_endpoint_defaults_to_https_unless_insecure() {
        assert_eq!(
            remote_endpoint("127.0.0.1:50443", false)
                .unwrap()
                .uri()
                .scheme_str(),
            Some("https")
        );
        assert_eq!(
            remote_endpoint("127.0.0.1:50443", true)
                .unwrap()
                .uri()
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
        let created = client.create_user("alice").await.unwrap();
        assert_eq!(created.name, "alice");

        let listed = client.list_users(None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "alice");

        client.delete_user_by_id(listed[0].id).await.unwrap();
        assert!(client.list_users(None).await.unwrap().is_empty());

        handle.abort();
        let _ = handle.await;
    }
}
