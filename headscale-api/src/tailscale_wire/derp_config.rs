//! DERP-map config loader.
//!
//! Wall 6 (closed 2026-05-19): stock `tailscale` v1.78+ refuses to
//! advance past `BackendState=Starting` without a reachable DERP
//! relay, even on a docker bridge network where peers could route
//! directly. The fix is to vendor a `tailscale/derp` sidecar into the
//! docker-compose stack and serve a one-region `DerpMap` from
//! `/machine/map`. See `docs/tailscale-interop-blocker.md` 2026-05-19
//! §"Wall 6 closed — interop passes" for the full citation.
//!
//! This module owns the small boundary between "JSON fixture on disk"
//! and "`Arc<DerpMap>` injected into [`super::WireState`]". The
//! interop harness writes a fixture at
//! `docker/devnet/tailscale-interop/derp-map.json` and points the
//! mesh-control daemon at it via `OCTRAVPN_DERP_MAP_PATH`. Non-interop
//! deployments leave the env var unset and the wire layer emits the
//! empty default — same behaviour as before Wall 6.
//!
//! ## Decision log
//!
//! - **Env var, not flag.** The `mesh serve` CLI is already
//!   feature-stacked with flags (listen, https-listen, cert-hostname,
//!   state-dir, tailnet-id, admin-token); adding `--derp-map=PATH`
//!   would push us past 6 args. Env vars are the right shape for
//!   "occasional override the docker harness sets".
//! - **JSON, not TOML.** The on-wire DERP map IS JSON; the fixture is
//!   literally the body the client sees after our serializer round-
//!   trips it. Keeping the on-disk format identical to the on-wire
//!   format keeps the diagnostic loop short — operators can `curl
//!   /machine/map | jq .DERPMap` and `cat derp-map.json` side-by-side.
//! - **`load_derp_map` returns `DerpMap` (not `Arc<DerpMap>`).** The
//!   caller wraps in an `Arc` for storage in `WireState`. Keeping the
//!   loader's return type plain makes the round-trip test simpler and
//!   the error path more obvious (a JSON-decode failure surfaces as
//!   `io::Error::other(serde…)`, no `Arc::new` ceremony).

use std::path::Path;

use super::wire::DerpMap;

/// Read a JSON DERP-map fixture from disk and deserialise into the
/// wire type. Errors propagate as `io::Error` so the call site at
/// startup can `?`-propagate alongside `tls::load_or_generate`.
pub fn load_derp_map(path: &Path) -> std::io::Result<DerpMap> {
    let bytes = std::fs::read(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("read DERP map fixture at {}: {e}", path.display()),
        )
    })?;
    let map: DerpMap = serde_json::from_slice(&bytes).map_err(|e| {
        std::io::Error::other(format!("parse DERP map fixture at {}: {e}", path.display()))
    })?;
    Ok(map)
}

/// The empty default. Equivalent to `DerpMap::default()`, exposed as a
/// named function so the call site at startup reads symmetrically
/// against [`load_derp_map`].
pub fn empty_derp_map() -> DerpMap {
    DerpMap::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Round-trip the canonical one-region interop fixture through
    /// `load_derp_map` + `serde_json::to_string`. Pins the JSON tag
    /// names (`Regions`, `RegionID`, `HostName`, `IPv4`, `DERPPort`,
    /// `InsecureForTests`) byte-identical to upstream `tailcfg`.
    #[test]
    fn round_trip_one_region_fixture() {
        let fixture = serde_json::json!({
            "OmitDefaultRegions": true,
            "Regions": {
                "1": {
                    "RegionID": 1,
                    "RegionCode": "interop",
                    "RegionName": "Interop test region",
                    "Nodes": [
                        {
                            "Name": "1a",
                            "RegionID": 1,
                            "HostName": "derp-1",
                            "IPv4": "",
                            "DERPPort": 443,
                            "InsecureForTests": true
                        }
                    ]
                }
            }
        });
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(fixture.to_string().as_bytes()).unwrap();
        let loaded = load_derp_map(f.path()).expect("loads fine");
        assert!(loaded.omit_default_regions);
        let region = loaded.regions.get(&1).expect("region 1 present");
        assert_eq!(region.region_id, 1);
        assert_eq!(region.region_code, "interop");
        assert_eq!(region.nodes.len(), 1);
        let node = &region.nodes[0];
        assert_eq!(node.host_name, "derp-1");
        assert_eq!(node.derp_port, 443);
        assert!(node.insecure_for_tests);

        // Re-emit and assert the upstream-required field names are in
        // the JSON byte stream.
        let json = serde_json::to_string(&loaded).unwrap();
        assert!(json.contains("\"Regions\""));
        assert!(json.contains("\"RegionID\""));
        assert!(json.contains("\"HostName\""));
        assert!(json.contains("\"DERPPort\""));
        assert!(json.contains("\"InsecureForTests\""));
        assert!(json.contains("\"OmitDefaultRegions\""));
    }

    #[test]
    fn missing_file_surfaces_as_io_error() {
        let bogus = std::path::Path::new("/nonexistent/octravpn-derp-map.json");
        let err = load_derp_map(bogus).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn malformed_json_surfaces_as_other_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"{not json").unwrap();
        let err = load_derp_map(f.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn empty_default_round_trips() {
        let empty = empty_derp_map();
        assert!(empty.regions.is_empty());
        assert!(!empty.omit_default_regions);
    }
}
