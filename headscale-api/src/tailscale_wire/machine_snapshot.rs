//! An internal NodeStore view retains native associations and raw Hostinfo
//! with the records used for a response. Public wire records stay unchanged.

use std::{
    collections::{HashMap, hash_map},
    ops::Deref,
    sync::Arc,
};

use super::{MachineRecord, hostinfo::HostInfoSnapshot};

#[derive(Clone)]
pub(crate) struct MachineSnapshot {
    pub(super) records: Arc<HashMap<String, MachineRecord>>,
    pub(super) hostinfo: Arc<HashMap<u64, HostInfoSnapshot>>,
    pub(super) node_attrs: Option<Arc<HashMap<u64, Vec<String>>>>,
    #[cfg(feature = "admin")]
    pub(super) native: Arc<HashMap<u64, crate::admin::machines::NativeNodePersistence>>,
}

impl Deref for MachineSnapshot {
    type Target = HashMap<String, MachineRecord>;

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

impl<'a> IntoIterator for &'a MachineSnapshot {
    type Item = (&'a String, &'a MachineRecord);
    type IntoIter = hash_map::Iter<'a, String, MachineRecord>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.iter()
    }
}

/// Native nilness that public Vec fields cannot carry. Endpoint/tag nilness
/// is retained only while its saved projection still matches the record.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct MapNodeSlices {
    pub(super) addresses_nil: bool,
    pub(super) allowed_ips_nil: bool,
    pub(super) primary_routes_nil: bool,
    pub(super) endpoints_nil: bool,
    pub(super) tags_nil: bool,
}

impl MachineSnapshot {
    #[cfg(feature = "admin")]
    pub(crate) fn native_persistence(
        &self,
        id: u64,
    ) -> Option<crate::admin::machines::NativeNodePersistence> {
        let mut native = self.native.get(&id).cloned()?;
        if let Some(hostinfo) = self.hostinfo.get(&id) {
            native.replace_hostinfo_snapshot(hostinfo.clone());
        }
        Some(native)
    }

    #[cfg(test)]
    pub(super) fn from_records(records: HashMap<String, MachineRecord>) -> Self {
        Self {
            records: Arc::new(records),
            hostinfo: Arc::new(HashMap::new()),
            node_attrs: None,
            #[cfg(feature = "admin")]
            native: Arc::new(HashMap::new()),
        }
    }

    pub(crate) fn with_policy_attrs(mut self, policy: &crate::policy::PolicyStore) -> Self {
        let nodes = self
            .values()
            .map(|record| {
                let (user_id, user) = self.policy_identity(record);
                (record, user_id, user, self.policy_addresses(record))
            })
            .collect::<Vec<_>>();
        let attrs =
            policy.node_attrs_snapshot(nodes.iter().map(|(record, user_id, user, addrs)| {
                (
                    record.stable_node_id(),
                    crate::policy::NodeView {
                        user_id: *user_id,
                        addr: addrs.first().map(String::as_str),
                        addrs,
                        user: user.as_deref(),
                        tags: &record.forced_tags,
                    },
                )
            }));
        drop(nodes);
        self.node_attrs = Some(Arc::new(attrs));
        self
    }

    pub(crate) fn policy_node_attrs(&self, id: u64) -> Option<&[String]> {
        self.node_attrs.as_ref()?.get(&id).map(Vec::as_slice)
    }

    #[allow(clippy::option_option)]
    // tri-state: unset / explicit nil Go association / loaded user id
    // Without `admin` there is no native persistence to consult; the signature is shared.
    #[cfg_attr(not(feature = "admin"), allow(clippy::unused_self))]
    pub(crate) fn native_user_association_id(&self, record: &MachineRecord) -> Option<Option<u64>> {
        #[cfg(feature = "admin")]
        {
            self.native
                .get(&record.stable_node_id())
                .and_then(|native| native.user_association(record))
                .map(|user| user.map(|user| user.id))
        }
        #[cfg(not(feature = "admin"))]
        {
            let _ = record;
            None
        }
    }

    #[cfg(feature = "admin")]
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    pub(crate) fn cached_native_user(
        &self,
        record: &MachineRecord,
    ) -> Option<Option<crate::admin::users::UserRecord>> {
        self.native
            .get(&record.stable_node_id())
            .and_then(|native| native.user_association(record))
            .map(Option::<&crate::admin::users::UserRecord>::cloned)
    }

    pub(crate) fn policy_identity(&self, record: &MachineRecord) -> (Option<u64>, Option<String>) {
        let association = self.native_user_association_id(record);
        if association == Some(None) {
            return (None, None);
        }
        (
            association.unwrap_or(record.user_id),
            (!record.user.is_empty()).then(|| record.user.clone()),
        )
    }

    // Without `admin` there is no native persistence to consult; the signature is shared.
    #[cfg_attr(not(feature = "admin"), allow(clippy::unused_self))]
    pub(crate) fn policy_addresses(&self, record: &MachineRecord) -> Vec<String> {
        #[cfg(feature = "admin")]
        if let Some(native) = self.native.get(&record.stable_node_id()) {
            return native.policy_owner_and_addresses(record).1;
        }
        record.address_strings()
    }

    pub(super) fn map_address_prefixes(&self, record: &MachineRecord) -> Vec<String> {
        self.policy_addresses(record)
            .iter()
            .map(|address| {
                headscale_api_acl::go_netip::addr_host_prefix_text(address)
                    .expect("captured node addresses passed typed decoding")
            })
            .collect()
    }

    // Without `admin` there is no native persistence to consult; the signature is shared.
    #[cfg_attr(
        not(feature = "admin"),
        allow(clippy::unused_self, clippy::unnecessary_wraps)
    )]
    pub(super) fn map_last_seen(
        &self,
        record: &MachineRecord,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        #[cfg(feature = "admin")]
        if let Some(native) = self.native.get(&record.stable_node_id()) {
            return native.last_seen(record);
        }
        Some(record.last_seen)
    }

    pub(super) fn map_node_slices(
        &self,
        record: &MachineRecord,
        node: &super::wire::MapNode,
    ) -> MapNodeSlices {
        #[cfg(feature = "admin")]
        let native = self.native.get(&record.stable_node_id());
        MapNodeSlices {
            // Prefixes returns nil only when no IP pointer exists. Filtering
            // all IPv4 entries from a non-nil slice leaves non-nil empty [].
            addresses_nil: self.policy_addresses(record).is_empty(),
            // slices.Concat returns nil for a zero-length result.
            allowed_ips_nil: node.allowed_ips.is_empty(),
            primary_routes_nil: node.primary_routes.is_empty(),
            #[cfg(feature = "admin")]
            endpoints_nil: native.is_some_and(|native| native.map_endpoints_nil(record)),
            #[cfg(not(feature = "admin"))]
            endpoints_nil: false,
            #[cfg(feature = "admin")]
            tags_nil: native.is_some_and(|native| native.map_tags_nil(record)),
            #[cfg(not(feature = "admin"))]
            tags_nil: false,
        }
    }

    pub(crate) fn map_hostinfo_value(
        &self,
        record: &MachineRecord,
    ) -> Result<serde_json::Value, serde_json::Error> {
        let projection = record.host_info_for_node();
        match self.hostinfo.get(&record.stable_node_id()) {
            Some(snapshot) => snapshot.value_for(&projection),
            None => serde_json::to_value(&projection),
        }
    }
}
