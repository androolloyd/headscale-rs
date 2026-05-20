//! Thin re-export facade over `headscale-api-acl`.
//!
//! Pre-2026-05-20 this module carried a copy of the hujson stripper
//! and the `parse_hujson_policy` entry-point. Both now live in
//! `headscale-api-acl` so `octravpn-mesh` and `headscale-api` parse
//! identical bytes through the same state machine. This file keeps
//! the existing `headscale_api::policy::{parse_hujson_policy,
//! PolicyParseError}` symbols stable for admin callers + the
//! `headscale-cli` admin client.

pub use headscale_api_acl::{PolicyParseError, parse_hujson_policy};
