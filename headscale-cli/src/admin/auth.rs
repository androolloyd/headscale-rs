//! `headscale auth {register,approve,reject}` over the upstream gRPC
//! admin API.

use serde::Serialize;

use super::AdminError;
use super::grpc_client::GrpcAdminClient;
use super::nodes::NodeOutput;
use super::output::{OutputFormat, print_structured};

pub async fn register_grpc(
    client: &mut GrpcAdminClient,
    user: &str,
    auth_id: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node = NodeOutput::from(client.auth_register(user, auth_id).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        let display_name = if node.given_name.is_empty() {
            node.name.as_str()
        } else {
            node.given_name.as_str()
        };
        println!("Node {display_name} registered");
    }
    Ok(())
}

pub async fn approve_grpc(
    client: &mut GrpcAdminClient,
    auth_id: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    client.auth_approve(auth_id).await?;
    print_result(fmt, "approved", auth_id, "Auth request approved")
}

pub async fn reject_grpc(
    client: &mut GrpcAdminClient,
    auth_id: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    client.auth_reject(auth_id).await?;
    print_result(fmt, "rejected", auth_id, "Auth request rejected")
}

fn print_result(
    fmt: OutputFormat,
    _status: &'static str,
    _auth_id: &str,
    message: &str,
) -> Result<(), AdminError> {
    #[derive(Serialize)]
    struct EmptyResponse {}

    if fmt.is_structured() {
        print_structured(fmt, &EmptyResponse {})
    } else {
        println!("{message}");
        Ok(())
    }
}
