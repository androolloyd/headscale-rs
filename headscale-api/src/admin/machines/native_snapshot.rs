// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Preserve native nullable shapes while the public wire model stays unchanged.

use chrono::{DateTime, Utc};
use headscale_db::headscale_nodes::{CachedNodeSnapshot, HeadscaleNodeRow};
use serde_json::Value;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use super::{MachineAdminError, key_with_prefix, precise_stored_timestamp, register_method_to_db};
use crate::admin::users::UserRecord;
use crate::tailscale_wire::{
    MachineRecord,
    hostinfo::{HostInfoSnapshot, merge_projection},
    wire::HostInfo,
};

#[derive(Clone)]
struct Projection {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    user_id: Option<u64>,
    auth_key_id: Option<i64>,
    register_method: i32,
    host_info: HostInfo,
    endpoints: Vec<String>,
    tags: Vec<String>,
    routes: Vec<String>,
    last_seen: DateTime<Utc>,
}

impl Projection {
    fn from_record(record: &MachineRecord) -> Self {
        Self {
            ipv4: record.ipv4,
            ipv6: record.ipv6,
            user_id: record.user_id,
            auth_key_id: record.auth_key_id,
            register_method: record.register_method,
            host_info: record.host_info_for_node(),
            endpoints: record.endpoints.clone(),
            tags: record.forced_tags.clone(),
            routes: record.approved_routes.clone(),
            last_seen: record.last_seen,
        }
    }
}

/// A node retains its loaded key; ordinary key/user admin writes do not
/// replace this association. Modern tokens retain only their display prefix.
#[derive(Clone)]
pub(crate) struct NativeAuthKey {
    pub(crate) id: u64,
    pub(crate) display_key: String,
    // Only the gRPC pre-auth key renderer (`full`) reads the stored selector.
    #[cfg(feature = "full")]
    pub(crate) user_selector: String,
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    pub(crate) user: Option<Option<UserRecord>>,
    pub(crate) reusable: bool,
    pub(crate) ephemeral: bool,
    used: Arc<AtomicBool>,
    pub(crate) tags: Vec<String>,
    pub(crate) created_at: Option<DateTime<Utc>>,
    pub(crate) expiration: Option<DateTime<Utc>>,
}

impl NativeAuthKey {
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    pub(crate) fn from_row(
        row: &headscale_db::preauth_keys::PreauthKeyRow,
        user: Option<Option<UserRecord>>,
    ) -> Result<Self, MachineAdminError> {
        let parse = |raw: &str| {
            precise_stored_timestamp(raw).ok_or_else(|| {
                MachineAdminError::Storage("invalid stored preauth key timestamp".into())
            })
        };
        Ok(Self {
            id: u64::try_from(row.id).map_err(|_| {
                MachineAdminError::Storage("invalid stored preauth key identity".into())
            })?,
            display_key: row.display_key(),
            #[cfg(feature = "full")]
            user_selector: row.user_id.clone(),
            user,
            reusable: row.reusable,
            ephemeral: row.ephemeral,
            used: Arc::new(AtomicBool::new(row.used_at.is_some())),
            tags: row
                .try_tag_list()
                .map_err(|error| MachineAdminError::Storage(error.to_string()))?,
            created_at: (!row.created_at_text.is_empty())
                .then(|| parse(&row.created_at_text))
                .transpose()?,
            expiration: row.expiration_text.as_deref().map(parse).transpose()?,
        })
    }

    pub(crate) fn used(&self) -> bool {
        self.used.load(Ordering::Acquire)
    }

    pub(crate) fn used_flag(&self) -> Arc<AtomicBool> {
        self.used.clone()
    }

    pub(crate) fn consume(&self) {
        if !self.reusable {
            self.used.store(true, Ordering::Release);
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct NativeNodeAssociations {
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    pub(crate) user: Option<Option<UserRecord>>,
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded key
    pub(crate) auth_key: Option<Option<NativeAuthKey>>,
}

#[derive(Clone)]
pub(crate) struct NativeNodePersistence {
    projection: Projection,
    ipv4: Option<String>,
    ipv6: Option<String>,
    user_id: Option<i64>,
    // None preserves legacy unqualified adapters; Some(None) is a known nil
    // Go User association, independent of the stored foreign key.
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    user_association: Option<Option<UserRecord>>,
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded key
    auth_key_association: Option<Option<NativeAuthKey>>,
    register_method: String,
    host_info: Option<Value>,
    endpoints_nil: bool,
    tags_nil: bool,
    routes_nil: bool,
    last_seen_nil: bool,
}

fn nil_slice(source: &str) -> bool {
    source.is_empty() || headscale_api_acl::go_json::trim(source.as_bytes()) == b"null"
}

pub(super) fn encode_hostinfo(hostinfo: &HostInfo) -> Result<Value, MachineAdminError> {
    if hostinfo
        .location
        .as_ref()
        .is_some_and(|value| !value.latitude.is_finite() || !value.longitude.is_finite())
        || hostinfo.net_info.as_ref().is_some_and(|value| {
            value
                .derp_latency
                .values()
                .any(|latency| !latency.is_finite())
        })
    {
        return Err(MachineAdminError::BadRequest(
            "unsupported non-finite Hostinfo value".into(),
        ));
    }
    serde_json::to_value(hostinfo)
        .map_err(|_| MachineAdminError::BadRequest("encoding cached Hostinfo".into()))
}

impl NativeNodePersistence {
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    pub(crate) fn user_association(&self, record: &MachineRecord) -> Option<Option<&UserRecord>> {
        if self.projection.user_id != record.user_id {
            return record.user_id.is_none().then_some(None);
        }
        self.user_association.as_ref().map(Option::as_ref)
    }

    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded key
    pub(crate) fn auth_key_association(
        &self,
        record: &MachineRecord,
    ) -> Option<Option<&NativeAuthKey>> {
        if self.projection.auth_key_id != record.auth_key_id {
            return record.auth_key_id.is_none().then_some(None);
        }
        self.auth_key_association.as_ref().map(Option::as_ref)
    }

    pub(crate) fn set_associations(&mut self, associations: NativeNodeAssociations) {
        self.user_association = associations.user;
        if associations.auth_key.is_some() {
            self.auth_key_association = associations.auth_key;
        }
    }

    pub(crate) fn policy_owner_and_addresses(&self, record: &MachineRecord) -> (u64, Vec<String>) {
        let owner = if self.projection.user_id == record.user_id {
            self.user_id
                .and_then(|id| u64::try_from(id).ok())
                .unwrap_or(0)
        } else {
            record.user_id.unwrap_or(0)
        };
        // Include non-nil typed zero/zoned addresses in policy equality even
        // when the stable public IP projection cannot represent those values.
        let ipv4 = if self.projection.ipv4 == record.ipv4 {
            self.ipv4.clone()
        } else {
            record.ipv4.map(|address| address.to_string())
        };
        let ipv6 = if self.projection.ipv6 == record.ipv6 {
            self.ipv6.clone()
        } else {
            record.ipv6.map(|address| address.to_string())
        };
        (
            owner,
            ipv4.into_iter()
                .chain(ipv6)
                .map(|address| headscale_api_acl::go_netip::addr_text(&address).unwrap_or(address))
                .collect(),
        )
    }

    pub(crate) fn map_endpoints_nil(&self, record: &MachineRecord) -> bool {
        self.endpoints_nil && self.projection.endpoints == record.endpoints
    }

    pub(crate) fn map_tags_nil(&self, record: &MachineRecord) -> bool {
        self.tags_nil && self.projection.tags == record.forced_tags
    }

    pub(crate) fn last_seen(&self, record: &MachineRecord) -> Option<DateTime<Utc>> {
        if self.last_seen_nil && self.projection.last_seen == record.last_seen {
            None
        } else {
            Some(record.last_seen)
        }
    }

    pub(crate) fn hostinfo_snapshot(&self) -> HostInfoSnapshot {
        HostInfoSnapshot {
            projection: self.projection.host_info.clone(),
            value: self.host_info.clone().unwrap_or(Value::Null),
        }
    }

    pub(crate) fn replace_hostinfo_snapshot(&mut self, snapshot: HostInfoSnapshot) {
        self.projection.host_info = snapshot.projection;
        self.host_info = (!snapshot.value.is_null()).then_some(snapshot.value);
    }

    pub(crate) fn capture(
        row: &HeadscaleNodeRow,
        record: &MachineRecord,
    ) -> Result<Self, MachineAdminError> {
        let host_info = row
            .try_host_info_value()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        Ok(Self {
            projection: Projection::from_record(record),
            ipv4: row.ipv4.clone(),
            ipv6: row.ipv6.clone(),
            user_id: row.user_id,
            user_association: row.user_id.is_none().then_some(None),
            auth_key_association: row.auth_key_id.is_none().then_some(None),
            register_method: row.register_method.clone(),
            host_info: (!host_info.is_null()).then_some(host_info),
            endpoints_nil: nil_slice(&row.endpoints),
            tags_nil: nil_slice(&row.tags),
            routes_nil: nil_slice(&row.approved_routes),
            last_seen_nil: row.last_seen.is_none() && row.last_seen_text.is_none(),
        })
    }

    pub(crate) fn from_snapshot(
        record: &MachineRecord,
        saved: &CachedNodeSnapshot,
        prior: Option<&Self>,
    ) -> Self {
        Self {
            projection: Projection::from_record(record),
            ipv4: saved.ipv4.clone(),
            ipv6: saved.ipv6.clone(),
            user_id: saved.user_id,
            user_association: prior
                .and_then(|prior| prior.user_association(record))
                .map(Option::<&UserRecord>::cloned)
                .or_else(|| record.user_id.is_none().then_some(None)),
            auth_key_association: prior
                .and_then(|prior| prior.auth_key_association(record))
                .map(Option::<&NativeAuthKey>::cloned)
                .or_else(|| record.auth_key_id.is_none().then_some(None)),
            register_method: saved.register_method.clone(),
            host_info: saved.host_info.clone().filter(|value| !value.is_null()),
            endpoints_nil: saved.endpoints.is_none(),
            tags_nil: saved.tags.is_none(),
            routes_nil: saved.approved_routes.is_none(),
            last_seen_nil: saved.last_seen.is_none(),
        }
    }

    pub(crate) fn snapshot(
        id: u64,
        record: &MachineRecord,
        native: Option<&Self>,
    ) -> Result<CachedNodeSnapshot, MachineAdminError> {
        let invalid_id = || MachineAdminError::BadRequest("invalid cached node identity".into());
        let id = i64::try_from(id).map_err(|_| invalid_id())?;
        let hostinfo = record.host_info_for_node();
        // Validate even when the baseline branch can retain native JSON.
        let after = encode_hostinfo(&hostinfo)?;
        let host_info = match native {
            Some(native) if native.projection.host_info == hostinfo => native.host_info.clone(),
            Some(native) => {
                let before = encode_hostinfo(&native.projection.host_info)?;
                let mut value = native.host_info.clone().unwrap_or(Value::Null);
                merge_projection(&mut value, &before, &after);
                Some(value)
            }
            None => Some(after),
        };
        let ipv4 = native
            .filter(|native| native.projection.ipv4 == record.ipv4)
            .map_or_else(
                || record.ipv4.map(|value| value.to_string()),
                |native| native.ipv4.clone(),
            );
        let ipv6 = native
            .filter(|native| native.projection.ipv6 == record.ipv6)
            .map_or_else(
                || record.ipv6.map(|value| value.to_string()),
                |native| native.ipv6.clone(),
            );
        let user_id = match native.filter(|native| native.projection.user_id == record.user_id) {
            Some(native) => native.user_id,
            None => record
                .user_id
                .map(i64::try_from)
                .transpose()
                .map_err(|_| invalid_id())?,
        };
        let register_method = native
            .filter(|native| native.projection.register_method == record.register_method)
            .map_or_else(
                || register_method_to_db(record.register_method),
                |native| native.register_method.clone(),
            );
        let endpoints_nil = native.is_some_and(|native| {
            native.endpoints_nil && native.projection.endpoints == record.endpoints
        });
        let tags_nil = native
            .is_some_and(|native| native.tags_nil && native.projection.tags == record.forced_tags);
        let routes_nil = native.is_some_and(|native| {
            native.routes_nil && native.projection.routes == record.approved_routes
        });
        let last_seen_nil = native.is_some_and(|native| {
            native.last_seen_nil && native.projection.last_seen == record.last_seen
        });
        Ok(CachedNodeSnapshot {
            id,
            machine_key: key_with_prefix("mkey:", &record.machine_key_hex),
            node_key: key_with_prefix("nodekey:", &record.node_key_hex),
            disco_key: record.disco_key.clone().unwrap_or_default(),
            endpoints: (!endpoints_nil).then(|| record.endpoints.clone()),
            host_info,
            ipv4,
            ipv6,
            hostname: record.raw_hostname.clone(),
            given_name: record.hostname.clone(),
            user_id,
            register_method,
            tags: (!tags_nil).then(|| record.forced_tags.clone()),
            last_seen: (!last_seen_nil).then_some(record.last_seen),
            approved_routes: (!routes_nil).then(|| record.approved_routes.clone()),
        })
    }
}
