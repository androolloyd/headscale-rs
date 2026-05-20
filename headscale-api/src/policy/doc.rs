//! Thin re-export facade over `headscale-api-acl`.
//!
//! Before the 2026-05-20 consolidation this module carried a serde
//! mirror of `octravpn_mesh::acl::AclDoc` (parser + eval). The
//! mirror duplicated 350+ LOC of types and matcher logic that was
//! also living, mostly identically, in `octravpn-mesh::acl`.
//!
//! Both implementations now share `headscale-api-acl` — the
//! canonical leaf crate that neither `headscale-api` nor
//! `octravpn-mesh` depend on indirectly. This file re-exports the
//! canonical types under their headscale-side names (`PolicyAction`
//! / `PolicyDoc` / `PolicyRule`) so existing callers — admin
//! handlers, the wire `/map` builder, tests — keep working with
//! zero source changes.

pub use headscale_api_acl::{
    AclAction as PolicyAction, AclDoc as PolicyDoc, AclRule as PolicyRule, AutoApprovers,
    NodeAttrGrant, NodeView, SshRule,
};
