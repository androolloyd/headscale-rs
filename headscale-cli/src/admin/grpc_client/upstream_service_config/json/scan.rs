//! Adapt shared Go JSON scanning errors to the gRPC service-config envelope.

use super::super::invalid;
pub(super) use headscale_db::go_json::{Raw, trim};

pub(super) fn array(bytes: &[u8]) -> Result<Vec<Raw<'_>>, String> {
    headscale_db::go_json::array(bytes).map_err(|_| invalid())
}

pub(super) fn object(bytes: &[u8]) -> Result<Vec<(String, Raw<'_>)>, String> {
    headscale_db::go_json::object(bytes).map_err(|_| invalid())
}

pub(super) fn unquote(bytes: &[u8]) -> Result<String, String> {
    headscale_db::go_json::unquote(bytes).map_err(|_| invalid())
}
