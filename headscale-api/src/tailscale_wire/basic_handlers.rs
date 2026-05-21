//! Basic unauthenticated control-plane endpoints shared with headscale-go.
//!
//! These live next to `/key` in the wire router because upstream serves
//! them from the same public control listener, before API bearer auth.

use std::collections::BTreeMap;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{DerpMap, WireState};

const ROBOTS_BODY: &str = "User-agent: *\nDisallow: /";
const SWAGGER_JSON: &str = include_str!("assets/headscale.swagger.json");
const FAVICON_PNG: &[u8] = include_bytes!("assets/favicon.png");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoInfo {
    pub version: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: String,
    pub commit: String,
    #[serde(rename = "buildTime")]
    pub build_time: String,
    pub go: GoInfo,
    pub dirty: bool,
}

pub async fn handle_robots() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        ROBOTS_BODY,
    )
        .into_response()
}

pub async fn handle_health() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/health+json; charset=utf-8",
        )],
        Json(HealthResponse {
            status: "pass".into(),
        }),
    )
        .into_response()
}

pub async fn handle_version() -> Response {
    Json(version_info()).into_response()
}

pub async fn handle_swagger() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        swagger_html(),
    )
        .into_response()
}

pub async fn handle_swagger_api_v1() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        SWAGGER_JSON,
    )
        .into_response()
}

pub async fn handle_favicon() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png")],
        FAVICON_PNG,
    )
        .into_response()
}

pub async fn handle_fallback(uri: Uri) -> Response {
    if uri.path() == "/k" || uri.path().starts_with(super::knock::KNOCK_PATH_PREFIX) {
        return StatusCode::NOT_FOUND.into_response();
    }
    handle_blank().await
}

pub async fn handle_blank() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        blank_html(),
    )
        .into_response()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpInfo {
    pub configured: bool,
    pub total_regions: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub regions: BTreeMap<u16, DebugDerpRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpRegion {
    pub region_id: u16,
    pub region_name: String,
    pub nodes: Vec<DebugDerpNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpNode {
    pub name: String,
    pub hostname: String,
    pub derp_port: u16,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub stun_port: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugRegistrationCacheInfo {
    #[serde(rename = "type")]
    pub cache_type: String,
    pub expiration: String,
    pub cleanup: String,
    pub status: String,
}

pub async fn handle_debug_routes(State(state): State<WireState>, headers: HeaderMap) -> Response {
    let snapshot = state.machines.snapshot();
    if wants_json(&headers) {
        let routes = state.machines.debug_routes_for_snapshot(&snapshot);
        match serde_json::to_string_pretty(&routes) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            state.machines.debug_routes_string_for_snapshot(&snapshot),
        )
            .into_response()
    }
}

pub async fn handle_debug_derp(State(state): State<WireState>, headers: HeaderMap) -> Response {
    if wants_json(&headers) {
        let info = debug_derp_info(&state.derp_map);
        match serde_json::to_string_pretty(&info) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            debug_derp_string(&state.derp_map),
        )
            .into_response()
    }
}

pub async fn handle_debug_registration_cache() -> Response {
    match serde_json::to_string_pretty(&debug_registration_cache_info()) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

pub async fn handle_windows(
    State(state): State<WireState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let url = control_url(state.public_control_url.as_deref(), &headers, &uri);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        windows_html(&url),
    )
        .into_response()
}

pub async fn handle_apple(
    State(state): State<WireState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let url = control_url(state.public_control_url.as_deref(), &headers, &uri);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        apple_html(&url),
    )
        .into_response()
}

pub async fn handle_apple_platform(
    Path(platform): Path<String>,
    State(state): State<WireState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(payload_type) = apple_payload_type(&platform) else {
        return http_error(
            StatusCode::BAD_REQUEST,
            "platform must be ios, macos-app-store or macos-standalone",
        );
    };
    let url = control_url(state.public_control_url.as_deref(), &headers, &uri);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/x-apple-aspen-config; charset=utf-8",
        )],
        apple_mobileconfig(&url, payload_type, &platform),
    )
        .into_response()
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        version: option_env!("HEADSCALE_RS_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        commit: option_env!("HEADSCALE_RS_COMMIT")
            .or(option_env!("GIT_COMMIT"))
            .unwrap_or("unknown")
            .to_string(),
        build_time: option_env!("HEADSCALE_RS_BUILD_TIME")
            .or(option_env!("SOURCE_DATE_EPOCH"))
            .unwrap_or("unknown")
            .to_string(),
        // Preserve the upstream JSON field name (`go`) for clients that
        // decode the headscale-go schema. The value makes the Rust
        // implementation explicit instead of pretending to be built by Go.
        go: GoInfo {
            version: option_env!("RUSTC_VERSION")
                .map(|v| format!("rustc {v}"))
                .unwrap_or_else(|| "rustc unknown".into()),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
        },
        dirty: option_env!("HEADSCALE_RS_DIRTY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
    }
}

fn http_error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{msg}\n"),
    )
        .into_response()
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("application/json"))
}

fn debug_derp_configured(derp_map: &DerpMap) -> bool {
    !derp_map.regions.is_empty() || derp_map.omit_default_regions
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn debug_derp_info(derp_map: &DerpMap) -> DebugDerpInfo {
    let configured = debug_derp_configured(derp_map);
    let mut info = DebugDerpInfo {
        configured,
        total_regions: if configured {
            derp_map.regions.len()
        } else {
            0
        },
        regions: BTreeMap::new(),
    };

    if !configured {
        return info;
    }

    for (region_id, region) in &derp_map.regions {
        let nodes = region
            .nodes
            .iter()
            .map(|node| DebugDerpNode {
                name: node.name.clone(),
                hostname: node.host_name.clone(),
                derp_port: node.derp_port,
                stun_port: node.stun_port,
            })
            .collect();
        info.regions.insert(
            *region_id,
            DebugDerpRegion {
                region_id: *region_id,
                region_name: region.region_name.clone(),
                nodes,
            },
        );
    }

    info
}

fn debug_derp_string(derp_map: &DerpMap) -> String {
    if !debug_derp_configured(derp_map) {
        return "DERP Map: not configured\n".to_string();
    }

    let mut out = String::from("=== DERP Map Configuration ===\n\n");
    out.push_str(&format!("Total Regions: {}\n\n", derp_map.regions.len()));

    let mut regions = derp_map.regions.iter().collect::<Vec<_>>();
    regions.sort_by_key(|(region_id, _)| **region_id);
    for (region_id, region) in regions {
        out.push_str(&format!("Region {region_id}: {}\n", region.region_name));
        out.push_str(&format!("  - Nodes: {}\n", region.nodes.len()));

        for node in &region.nodes {
            out.push_str(&format!(
                "    - {} ({}:{})\n",
                node.name, node.host_name, node.derp_port
            ));
            if node.stun_port != 0 {
                out.push_str(&format!("      STUN: {}\n", node.stun_port));
            }
        }
        out.push('\n');
    }

    out
}

fn debug_registration_cache_info() -> DebugRegistrationCacheInfo {
    DebugRegistrationCacheInfo {
        cache_type: "zcache".to_string(),
        expiration: "15m0s".to_string(),
        cleanup: "20m0s".to_string(),
        status: "active".to_string(),
    }
}

fn control_url(configured: Option<&str>, headers: &HeaderMap, uri: &Uri) -> String {
    if let Some(configured) = configured.map(str::trim).filter(|url| !url.is_empty()) {
        return configured.trim_end_matches('/').to_string();
    }

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.scheme_str())
        .unwrap_or("http")
        .split(',')
        .next()
        .unwrap_or("http")
        .trim();
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get(header::HOST).and_then(|v| v.to_str().ok()))
        .or_else(|| uri.authority().map(|a| a.as_str()))
        .unwrap_or("localhost")
        .split(',')
        .next()
        .unwrap_or("localhost")
        .trim();
    format!("{scheme}://{host}")
}

fn windows_html(url: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Headscale Windows configuration</title></head>
<body>
<h1>Connect Windows to Headscale</h1>
<p>Install <a href="https://tailscale.com/download/windows">Tailscale for Windows</a>, then run:</p>
<pre><code>tailscale up --login-server {url}</code></pre>
</body>
</html>"#
    )
}

fn apple_html(url: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Headscale Apple configuration</title></head>
<body>
<h1>Connect Apple devices to Headscale</h1>
<p>Install Tailscale from the <a href="https://apps.apple.com/app/tailscale/id1470499037">App Store</a>.</p>
<p>Download a configuration profile for this server:</p>
<ul>
<li><a href="/apple/ios">iOS profile</a></li>
<li><a href="/apple/macos-app-store">macOS AppStore profile</a></li>
<li><a href="/apple/macos-standalone">macOS Standalone profile</a></li>
</ul>
<pre><code>curl {url}/apple/macos-app-store</code></pre>
<pre><code>curl {url}/apple/macos-standalone</code></pre>
</body>
</html>"#
    )
}

fn apple_payload_type(platform: &str) -> Option<&'static str> {
    match platform {
        "ios" => Some("io.tailscale.ipn.ios"),
        "macos-app-store" => Some("io.tailscale.ipn.macos"),
        "macos-standalone" => Some("io.tailscale.ipn.macsys"),
        _ => None,
    }
}

fn swagger_html() -> &'static str {
    r#"
<html>
    <head>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3/swagger-ui.css">
    <link rel="icon" href="/favicon.ico">
    <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-standalone-preset.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js" charset="UTF-8"></script>
    </head>
    <body>
    <div id="swagger-ui"></div>
    <script>
        window.addEventListener('load', (event) => {
            const ui = SwaggerUIBundle({
                url: "/swagger/v1/openapiv2.json",
                dom_id: '#swagger-ui',
                presets: [
                  SwaggerUIBundle.presets.apis,
                  SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                deepLinking: true,
                // TODO(kradalby): Figure out why this does not work
                // layout: "StandaloneLayout",
              })
            window.ui = ui
        });
    </script>
    </body>
</html>"#
}

fn blank_html() -> &'static str {
    r#"<html lang="en"><head><meta charset="UTF-8"><link rel="icon" href="/favicon.ico"></head><body></body></html>"#
}

fn apple_mobileconfig(url: &str, payload_type: &str, platform: &str) -> String {
    let payload_uuid = match platform {
        "ios" => "00000000-0000-4000-8000-000000000001",
        "macos-app-store" => "00000000-0000-4000-8000-000000000002",
        "macos-standalone" => "00000000-0000-4000-8000-000000000003",
        _ => "00000000-0000-4000-8000-000000000000",
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>PayloadUUID</key>
    <string>00000000-0000-4000-8000-000000000010</string>
    <key>PayloadDisplayName</key>
    <string>Headscale</string>
    <key>PayloadDescription</key>
    <string>Configure Tailscale login server to: {url}</string>
    <key>PayloadIdentifier</key>
    <string>com.github.juanfont.headscale</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
      <dict>
        <key>PayloadType</key>
        <string>{payload_type}</string>
        <key>PayloadUUID</key>
        <string>{payload_uuid}</string>
        <key>PayloadIdentifier</key>
        <string>com.github.juanfont.headscale</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadEnabled</key>
        <true/>
        <key>ControlURL</key>
        <string>{url}</string>
      </dict>
    </array>
  </dict>
</plist>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        DerpMap, DerpRegion, DerpRegionNode, MachineRecord, MachineRegistry, WireState,
        noise::ServerNoiseKey,
        router,
        test_support::{MockIpAllocator, MockRedeemer},
        wire::stable_id_from_key,
    };
    use axum::body::to_bytes;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            derp_map: Arc::new(crate::tailscale_wire::wire::DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
        };
        (state, dir)
    }

    fn record(
        node_key: &str,
        host: u8,
        available_routes: &[&str],
        approved_routes: &[&str],
    ) -> MachineRecord {
        let mut rec = MachineRecord::new_at(
            Utc::now(),
            node_key.to_string(),
            format!("mkey-{node_key}"),
            "alice".to_string(),
            format!("host-{host}"),
            Ipv4Addr::new(100, 64, 0, host),
            false,
        );
        rec.available_routes = available_routes
            .iter()
            .map(|route| (*route).to_string())
            .collect();
        rec.approved_routes = approved_routes
            .iter()
            .map(|route| (*route).to_string())
            .collect();
        rec
    }

    fn derp_fixture() -> DerpMap {
        DerpMap {
            omit_default_regions: true,
            regions: HashMap::from([(
                1,
                DerpRegion {
                    region_id: 1,
                    region_code: "test".to_string(),
                    region_name: "Test region".to_string(),
                    avoid: false,
                    nodes: vec![DerpRegionNode {
                        name: "derp-1".to_string(),
                        region_id: 1,
                        host_name: "derp1.example.com".to_string(),
                        ipv4: "198.51.100.10".to_string(),
                        ipv6: String::new(),
                        derp_port: 443,
                        stun_port: 3478,
                        stun_only: false,
                        insecure_for_tests: false,
                    }],
                },
            )]),
        }
    }

    #[tokio::test]
    async fn robots_txt_matches_headscale_go_body() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/robots.txt")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], ROBOTS_BODY.as_bytes());
    }

    #[tokio::test]
    async fn health_endpoint_matches_headscale_go_pass_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/health+json; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.status, "pass");
    }

    #[tokio::test]
    async fn version_endpoint_keeps_headscale_go_json_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/version")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: VersionInfo = serde_json::from_slice(&body).unwrap();
        assert!(!parsed.version.is_empty());
        assert!(!parsed.commit.is_empty());
        assert!(!parsed.build_time.is_empty());
        assert!(parsed.go.version.starts_with("rustc "));
        assert!(!parsed.go.os.is_empty());
        assert!(!parsed.go.arch.is_empty());
    }

    #[tokio::test]
    async fn swagger_ui_matches_headscale_go_public_path() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/swagger")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://unpkg.com/swagger-ui-dist@3/swagger-ui.css"));
        assert!(body.contains("url: \"/swagger/v1/openapiv2.json\""));
        assert!(body.contains("<link rel=\"icon\" href=\"/favicon.ico\">"));
    }

    #[tokio::test]
    async fn swagger_api_v1_serves_upstream_openapi_document() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/swagger/v1/openapiv2.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["swagger"], "2.0");
        assert_eq!(parsed["info"]["title"], "headscale/v1/headscale.proto");
        assert!(parsed["paths"].get("/api/v1/node").is_some());
        assert!(parsed["paths"].get("/api/v1/preauthkey").is_some());
        assert!(parsed["definitions"].get("v1Node").is_some());
    }

    #[tokio::test]
    async fn favicon_serves_headscale_go_png_asset() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/favicon.ico")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(body.len(), FAVICON_PNG.len());
    }

    #[tokio::test]
    async fn debug_routes_text_matches_headscale_go_empty_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/routes")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"Available routes:\n\n\nCurrent primary routes:\n"
        );
    }

    #[tokio::test]
    async fn debug_routes_json_matches_headscale_go_route_state_shape() {
        let (state, _dir) = fixture_state();
        let node_a = "debug-node-a";
        let node_b = "debug-node-b";
        state.machines.upsert(
            node_a.to_string(),
            record(
                node_a,
                1,
                &["10.0.0.0/24", "0.0.0.0/0"],
                &["10.0.0.0/24", "0.0.0.0/0"],
            ),
        );
        state.machines.upsert(
            node_b.to_string(),
            record(node_b, 2, &["10.0.0.0/24"], &["10.0.0.0/24"]),
        );

        let id_a = stable_id_from_key(node_a);
        let id_b = stable_id_from_key(node_b);
        let primary = id_a.min(id_b);
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/routes")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let available = parsed["available_routes"].as_object().unwrap();
        assert_eq!(
            available.get(&id_a.to_string()).unwrap(),
            &serde_json::json!(["10.0.0.0/24"])
        );
        assert_eq!(
            available.get(&id_b.to_string()).unwrap(),
            &serde_json::json!(["10.0.0.0/24"])
        );
        assert_eq!(parsed["primary_routes"]["10.0.0.0/24"], primary);
        assert!(
            parsed["primary_routes"].get("0.0.0.0/0").is_none(),
            "exit routes are excluded from primary route debug state"
        );
    }

    #[tokio::test]
    async fn debug_derp_text_matches_headscale_go_unconfigured_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/derp")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"DERP Map: not configured\n");
    }

    #[tokio::test]
    async fn debug_derp_text_matches_headscale_go_configured_shape() {
        let (mut state, _dir) = fixture_state();
        state.derp_map = Arc::new(derp_fixture());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/derp")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(
            body,
            "=== DERP Map Configuration ===\n\nTotal Regions: 1\n\nRegion 1: Test region\n  - Nodes: 1\n    - derp-1 (derp1.example.com:443)\n      STUN: 3478\n\n"
        );
    }

    #[tokio::test]
    async fn debug_derp_json_matches_headscale_go_shape() {
        let (mut state, _dir) = fixture_state();
        state.derp_map = Arc::new(derp_fixture());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/derp")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["configured"], true);
        assert_eq!(parsed["total_regions"], 1);
        assert_eq!(parsed["regions"]["1"]["region_id"], 1);
        assert_eq!(parsed["regions"]["1"]["region_name"], "Test region");
        assert_eq!(parsed["regions"]["1"]["nodes"][0]["name"], "derp-1");
        assert_eq!(
            parsed["regions"]["1"]["nodes"][0]["hostname"],
            "derp1.example.com"
        );
        assert_eq!(parsed["regions"]["1"]["nodes"][0]["derp_port"], 443);
        assert_eq!(parsed["regions"]["1"]["nodes"][0]["stun_port"], 3478);
    }

    #[tokio::test]
    async fn debug_registration_cache_matches_headscale_go_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/registration-cache")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["type"], "zcache");
        assert_eq!(parsed["expiration"], "15m0s");
        assert_eq!(parsed["cleanup"], "20m0s");
        assert_eq!(parsed["status"], "active");
    }

    #[tokio::test]
    async fn unmatched_public_path_returns_headscale_go_blank_page() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/some/unknown/path")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], blank_html().as_bytes());
    }

    #[tokio::test]
    async fn windows_endpoint_uses_configured_login_server() {
        let (mut state, _dir) = fixture_state();
        state.public_control_url = Some("https://configured.example/".into());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/windows")
                    .header(header::HOST, "ignored.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://tailscale.com/download/windows"));
        assert!(body.contains("tailscale up --login-server https://configured.example"));
        assert!(!body.contains("ignored.example"));
    }

    #[tokio::test]
    async fn apple_endpoint_links_all_headscale_go_profile_paths() {
        let (mut state, _dir) = fixture_state();
        state.public_control_url = Some("https://configured.example".into());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple")
                    .header(header::HOST, "ignored.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://apps.apple.com/app/tailscale/id1470499037"));
        assert!(body.contains("/apple/ios"));
        assert!(body.contains("/apple/macos-app-store"));
        assert!(body.contains("/apple/macos-standalone"));
        assert!(body.contains("curl https://configured.example/apple/macos-app-store"));
        assert!(!body.contains("ignored.example"));
    }

    #[tokio::test]
    async fn apple_mobileconfig_ios_uses_configured_control_url() {
        let (mut state, _dir) = fixture_state();
        state.public_control_url = Some("https://configured.example/".into());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple/ios")
                    .header(header::HOST, "ignored.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-apple-aspen-config; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<string>io.tailscale.ipn.ios</string>"));
        assert!(body.contains("<key>ControlURL</key>"));
        assert!(body.contains("<string>https://configured.example</string>"));
        assert!(body.contains("<string>Headscale</string>"));
        assert!(!body.contains("ignored.example"));
    }

    #[tokio::test]
    async fn apple_mobileconfig_falls_back_to_request_host_when_unconfigured() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple/macos-app-store")
                    .header(header::HOST, "headscale.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<string>io.tailscale.ipn.macos</string>"));
        assert!(body.contains("<string>https://headscale.example</string>"));
    }

    #[tokio::test]
    async fn apple_mobileconfig_bad_platform_matches_headscale_go_error() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple/linux")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"platform must be ios, macos-app-store or macos-standalone\n"
        );
    }
}
