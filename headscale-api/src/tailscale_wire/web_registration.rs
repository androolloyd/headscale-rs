//! Authenticated completion of the volatile web-registration cache.

use chrono::{DateTime, Utc};
use thiserror::Error;

use super::{MachineRecord, WireState, allocate_registration_addresses, complete_state_mutation};
use crate::policy::{PolicyCheckNode, validate_requested_tags_for_auth_path};

/// Identity established by the embedding authentication provider. Numeric IDs
/// are authoritative when available; legacy wire-only providers may use names.
#[derive(Clone, Debug, Default)]
pub struct WebRegistrationUser {
    pub id: Option<u64>,
    pub name: String,
    pub display_name: String,
    pub profile_pic_url: String,
    pub provider: String,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
pub struct CompletedWebRegistration {
    pub record: MachineRecord,
    pub new_node: bool,
}

#[derive(Debug, Error)]
pub enum WebRegistrationError {
    #[error("node not found in registration cache")]
    SessionExpired,
    #[error("{0}")]
    Store(String),
}

fn policy_node(record: &MachineRecord) -> PolicyCheckNode {
    PolicyCheckNode {
        id: record.stable_node_id_for_key(&record.node_key_hex),
        user_id: record.user_id,
        name: record.hostname.clone(),
        user: (!record.user.is_empty()).then(|| record.user.clone()),
        addrs: record.address_strings(),
        tags: record.forced_tags.clone(),
    }
}

impl WireState {
    /// Complete an already authenticated registration in the volatile registry.
    /// Persistent runtimes use their backend completion handlers instead.
    /// This method owns both registration guards through publication, reuses
    /// existing addresses and allocates a fresh node only after tag validation.
    pub async fn complete_volatile_web_registration(
        &self,
        registration_id: &str,
        user: WebRegistrationUser,
        node_expiry: Option<DateTime<Utc>>,
        register_method: i32,
    ) -> Result<CompletedWebRegistration, WebRegistrationError> {
        self.machines
            .try_configure_policy(&self.policy)
            .map_err(WebRegistrationError::Store)?;
        let (mut pending, hostinfo, completion) = self
            .registration_cache
            .pending_registration_completion(registration_id)
            .ok_or(WebRegistrationError::SessionExpired)?;
        let machine_key = pending.machine_key_hex.clone();
        let node_key = pending.node_key_hex.clone();
        let machine_guard = self.machines.lock_registration(&machine_key).await;
        let node_guard = self.machines.lock_node_key_registration(&node_key).await;
        let state = self.clone();
        complete_state_mutation(async move {
            let _guards = (machine_guard, node_guard);
            pending.set_user_identity(
                user.id,
                user.name.clone(),
                user.display_name,
                user.profile_pic_url,
            );
            pending.set_user_account_metadata(user.provider, user.created_at);
            state
                .machines
                .validate_registration_node_key(&pending.node_key_hex, &pending.machine_key_hex)
                .map_err(|error| WebRegistrationError::Store(error.to_string()))?;
            let existing = state
                .machines
                .auth_path_existing_machine(&pending.machine_key_hex, &user.name, user.id)
                .map_err(|error| WebRegistrationError::Store(error.into()))?;
            let new_node = existing.is_none();
            if let Some((_, existing)) = &existing {
                pending.ipv4 = existing.ipv4;
                pending.ipv6 = existing.ipv6;
            }
            let existing_policy_node = existing.as_ref().map(|(_, node)| policy_node(node));
            let existing_view = existing_policy_node.as_ref().map(PolicyCheckNode::as_view);
            let policy_nodes = if pending.forced_tags.is_empty() {
                Vec::new()
            } else {
                state
                    .machines
                    .snapshot()
                    .values()
                    .map(policy_node)
                    .collect::<Vec<_>>()
            };
            let node_views = policy_nodes
                .iter()
                .map(PolicyCheckNode::as_view)
                .collect::<Vec<_>>();
            let requested_tags = validate_requested_tags_for_auth_path(
                &state.policy,
                existing_view.as_ref(),
                &node_views,
                &user.name,
                user.id,
                &mut pending.forced_tags,
            )
            .map_err(WebRegistrationError::Store)?;
            pending.expiry = if requested_tags {
                None
            } else {
                node_expiry.or(pending.expiry)
            };
            if new_node {
                (pending.ipv4, pending.ipv6) = allocate_registration_addresses(
                    state.ip_allocator.as_ref(),
                    &pending.node_key_hex,
                )
                .map_err(WebRegistrationError::Store)?;
            }
            let record = state
                .machines
                .complete_web_registration_with_hostinfo(
                    pending,
                    &user.name,
                    register_method,
                    hostinfo,
                )
                .map_err(|error| WebRegistrationError::Store(error.to_string()))?;
            state
                .registration_cache
                .finish_registration(completion, record.clone());
            // oidc.go handleRegistration and grpcv1.go RegisterNode both run
            // State.AutoApproveRoutes right after HandleNodeFromAuthPath has
            // put the node in the NodeStore and the policy manager, and wrap a
            // failure as "auto approving routes: %w". The completion above
            // stays registered (the Go node is already persisted); the
            // approval's PolicyChange follows the registration's own change.
            super::register::auto_approve_registered_routes(
                &state.machines,
                &state.policy,
                None,
                &record,
            )
            .await
            .map_err(|error| {
                WebRegistrationError::Store(format!("auto approving routes: {error}"))
            })?;
            Ok(CompletedWebRegistration { record, new_node })
        })
        .await
        .map_err(|error| {
            WebRegistrationError::Store(format!("finishing node registration: {error}"))
        })?
    }
}
