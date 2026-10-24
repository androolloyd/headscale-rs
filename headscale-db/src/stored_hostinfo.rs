//! Native Gorm Hostinfo adapter over the shared pure tailcfg decoder.

use serde_json::Value;

use crate::{DbError, Result};

pub(crate) fn from_bytes(source: &[u8]) -> Result<Value> {
    headscale_api_acl::go_tailcfg_json::hostinfo_value(source)
        .map_err(|_| DbError::General("invalid persisted Hostinfo".into()))
}

pub(crate) fn text_from_bytes(source: &[u8]) -> Result<String> {
    Ok(serde_json::to_string(&from_bytes(source)?)?)
}

pub(crate) fn text_for_write(value: &Value) -> Result<Option<String>> {
    let value = headscale_api_acl::go_tailcfg_json::marshal_hostinfo_value(value)
        .map_err(|_| DbError::General("invalid persisted Hostinfo".into()))?;
    // Gorm JSONSerializer.Value stores a nil pointer as SQL NULL.
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(crate::stored_json::text_for_write(&value)?))
    }
}
