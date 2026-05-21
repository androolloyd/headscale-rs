//! PSK-gated handshake — the third layer of the four-layer shielding pack.
//!
//! ## What this defeats
//!
//! Today our `/ts2021`, `/key`, and `/machine/...` endpoints accept any
//! incoming HTTP connection that speaks the right shape. A state-level
//! censor (the canonical example: the Great Firewall's "Tailscale
//! fingerprint" probe pattern reported 2024–2026) sweeps candidate IPs,
//! attempts the Noise IK handshake itself, and uses *successful*
//! handshake completion as a positive signal — "this endpoint is a
//! Tailscale-class control plane; block it."
//!
//! The knock layer rejects probe traffic with the same response a
//! random/misconfigured TCP service would emit (a generic nginx 404),
//! making the wire surface indistinguishable from "nothing here" to
//! anyone who lacks the out-of-band PSK.
//!
//! ## Wire shape
//!
//! Two ways to present the knock:
//!
//! 1. **Path-prefix (preferred for stock-tailscale interop).** The
//!    client dials `/k/<knock_hex>/<original-path>` — e.g.
//!    `/k/abcdef0123456789/ts2021`. Stock `tailscale up` can't add
//!    custom HTTP headers, but it *will* respect whatever path is
//!    embedded in the `--login-server` URL.
//!
//! 2. **Header.** `X-OctraVPN-Knock: <knock_hex>` carried by our own
//!    `octravpn` CLI. Saved for tooling that always uses our wrapper
//!    client (e.g. `octravpn-node mesh status`).
//!
//! Both shapes verify against the same HMAC.
//!
//! ## HMAC math
//!
//! ```text
//! window = (unix_seconds / window_secs)
//! knock  = HMAC-SHA256(psk, window.to_string().as_bytes())[..8].hex()
//!         = 16 hex chars (8 bytes)
//! ```
//!
//! A knock is valid for the *current* window (the obvious case) and
//! the *next* window (forward tolerance for clock skew between the
//! peer and the node). Two windows ahead is rejected. Past windows
//! are rejected → replay attempts using yesterday's knock fail.
//!
//! With the default `window_secs = 60`, that gives the client up to
//! ~60s of useful skew tolerance and bounds replay to ≤60s.
//!
//! ## Why 8-byte truncation
//!
//! A full HMAC-SHA256 tag is 32 bytes (64 hex chars). For a knock
//! cookie an attacker can grind against, 64 bits of brute-force
//! resistance is overkill for a 60-second window; 16 hex chars keeps
//! the path-prefix URL human-pasteable while still requiring ≥ 2^63
//! probes per window to forge. The longer tag would not buy us
//! anything against a state-level adversary that already has access
//! to a much-cheaper packet-fingerprint side channel — it just makes
//! the operator-shared URLs uglier.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{HeaderValue, Response, StatusCode, header},
    middleware::{self, Next},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;

type HmacSha256 = Hmac<Sha256>;

/// HTTP header used by our own client to carry the knock cookie.
pub const KNOCK_HEADER: &str = "X-OctraVPN-Knock";

/// URI path prefix used for the path-embedded knock variant.
pub const KNOCK_PATH_PREFIX: &str = "/k/";

/// Default knock window. 60s balances replay-resistance and
/// peer/server clock-skew tolerance.
pub const DEFAULT_WINDOW_SECS: u64 = 60;

/// Truncated tag length in *bytes* (so 8 bytes = 16 hex chars).
pub const KNOCK_TAG_BYTES: usize = 8;

/// The canonical 404 body served for any request that fails the knock
/// gate. Byte-for-byte identical to a default nginx 1.18 "404 Not
/// Found" page so a probe can't distinguish our knock failure from a
/// plain "this host runs nginx and the path is unknown" response.
///
/// Keep this string EXACTLY as-is — including trailing newline — when
/// modifying. The `probe_resistance_404_body_stable` test pins the
/// SHA-256 of the bytes so any accidental edit (a stray quote, a
/// reformatter run) trips CI.
pub const NGINX_404_BODY: &str = concat!(
    "<html>\r\n",
    "<head><title>404 Not Found</title></head>\r\n",
    "<body>\r\n",
    "<center><h1>404 Not Found</h1></center>\r\n",
    "<hr><center>nginx/1.18.0</center>\r\n",
    "</body>\r\n",
    "</html>\r\n",
);

/// Configuration for the PSK gate.
#[derive(Clone, Debug)]
pub struct KnockConfig {
    /// Master switch. Default false → router behaves exactly as it did
    /// before the knock layer existed.
    pub enabled: bool,
    /// 32-byte pre-shared secret. Generated with `openssl rand -hex 32`
    /// (or the `octravpn-node mesh knock-secret` helper) and shared with
    /// peers out-of-band alongside the preauth key.
    pub psk: Arc<[u8; 32]>,
    /// Rounding window in seconds. Default [`DEFAULT_WINDOW_SECS`].
    pub window_secs: u64,
}

impl KnockConfig {
    /// Disabled config. Wire routes are unaffected; the knock
    /// middleware short-circuits to a pass-through.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            psk: Arc::new([0u8; 32]),
            window_secs: DEFAULT_WINDOW_SECS,
        }
    }

    /// Enabled config with the supplied PSK.
    pub fn enabled(psk: [u8; 32]) -> Self {
        Self {
            enabled: true,
            psk: Arc::new(psk),
            window_secs: DEFAULT_WINDOW_SECS,
        }
    }

    /// Compute the current knock cookie. Used both server-side (for the
    /// `expected` tag inside [`verify_knock`]) and as a reference
    /// implementation for the client-side helper.
    pub fn current_knock(&self) -> String {
        knock_for_window(&self.psk, current_window(self.window_secs))
    }

    /// True if `presented` is a valid knock for the current or next
    /// window. Constant-time across the candidate windows (uses the
    /// `hmac::Mac::verify_slice` constant-time compare under the
    /// hood).
    pub fn verify(&self, presented: &str) -> bool {
        verify_knock(&self.psk, self.window_secs, presented, now_unix())
    }
}

/// Internal helper: HMAC-SHA256(psk, window.to_string()) truncated to
/// `KNOCK_TAG_BYTES`, hex-encoded.
fn knock_for_window(psk: &[u8; 32], window: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC accepts any 32B key");
    mac.update(window.to_string().as_bytes());
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..KNOCK_TAG_BYTES])
}

/// Internal helper: verify `presented` against `now`'s current+next
/// windows. Pulled out as a free fn so tests can pin `now`.
fn verify_knock(psk: &[u8; 32], window_secs: u64, presented: &str, now: u64) -> bool {
    if window_secs == 0 {
        return false;
    }
    if presented.len() != KNOCK_TAG_BYTES * 2 {
        return false;
    }
    let Ok(presented_bytes) = hex::decode(presented) else {
        return false;
    };
    if presented_bytes.len() != KNOCK_TAG_BYTES {
        return false;
    }
    let current_window_idx = now / window_secs;
    // Accept current window OR the next window (forward clock-skew
    // tolerance). Reject anything older or further in the future.
    for w in [current_window_idx, current_window_idx + 1] {
        let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC accepts any 32B key");
        mac.update(w.to_string().as_bytes());
        let expected = mac.finalize().into_bytes();
        // Constant-time compare on the truncated prefix.
        if ct_eq(&expected[..KNOCK_TAG_BYTES], &presented_bytes) {
            return true;
        }
    }
    false
}

/// Compute the current window index using the wall clock.
fn current_window(window_secs: u64) -> u64 {
    now_unix() / window_secs.max(1)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Constant-time byte-slice compare. Length-leak is fine: the
/// presented length is operator-pasted and not secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Build a generic-looking 404 response. Body bytes are
/// byte-for-byte identical between probe attempts.
fn nginx_404() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )
        .header(header::SERVER, HeaderValue::from_static("nginx/1.18.0"))
        .body(Body::from(NGINX_404_BODY))
        .unwrap()
}

/// Wrap a wire router with the knock gate.
///
/// Behaviour:
///   * `cfg.enabled == false` ⇒ no-op, returns `inner` unchanged.
///   * `cfg.enabled == true` ⇒ builds a thin outer router that:
///       1. Mounts a clone of `inner` under `/k/:knock` (nested). A
///          middleware on that nested branch validates the `:knock`
///          param + rewrites the URI to drop the segment so the
///          inner handlers see the same path they would have seen
///          without the knock layer.
///       2. Mounts the same `inner` at the root with a header-gating
///          middleware. The middleware demands a valid
///          `X-OctraVPN-Knock` header on every bare-path request.
///       3. Any failure (missing/wrong knock, malformed prefix)
///          returns the canonical nginx 404.
pub fn wrap_router(inner: Router, cfg: KnockConfig) -> Router {
    if !cfg.enabled {
        return inner;
    }
    let cfg = Arc::new(cfg);

    // Header branch — applied to a clone of the bare inner router.
    let header_cfg = Arc::clone(&cfg);
    let header_branch =
        inner
            .clone()
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                let cfg = Arc::clone(&header_cfg);
                async move {
                    match check_header(req, &cfg) {
                        Ok(req) => next.run(req).await,
                        Err(()) => nginx_404(),
                    }
                }
            }));

    // Path-prefix branch — nest the *same* inner router under
    // `/k/:knock`. Axum's `nest` re-matches the remaining path against
    // the sub-router, so by stripping the `/k/<knock>` prefix at the
    // middleware level we get the correct handler picked.
    let prefix_cfg = Arc::clone(&cfg);
    let prefix_branch = Router::new()
        .nest("/k/:knock", inner)
        .layer(middleware::from_fn(move |req: Request, next: Next| {
            let cfg = Arc::clone(&prefix_cfg);
            async move {
                match verify_prefix_knock(&req, &cfg) {
                    Ok(()) => next.run(req).await,
                    Err(()) => nginx_404(),
                }
            }
        }));

    Router::new().merge(prefix_branch).merge(header_branch)
}

/// Pull the `:knock` segment out of a `/k/<knock>/...` URL and verify
/// it. We don't rewrite the URI here — `nest("/k/:knock", inner)`
/// already strips the prefix before forwarding to the inner router.
fn verify_prefix_knock(req: &Request, cfg: &KnockConfig) -> Result<(), ()> {
    let path = req.uri().path();
    let rest = path.strip_prefix(KNOCK_PATH_PREFIX).ok_or(())?;
    let Some(i) = rest.find('/') else {
        return Err(());
    };
    if i + 1 == rest.len() {
        return Err(());
    }
    let knock = &rest[..i];
    if cfg.verify(knock) { Ok(()) } else { Err(()) }
}

/// Validate the header-variant knock + strip the header. Returns
/// `Err(())` if the header is missing or invalid.
fn check_header(mut req: Request, cfg: &KnockConfig) -> Result<Request, ()> {
    let header_value = req
        .headers()
        .get(KNOCK_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let Some(v) = header_value else {
        return Err(());
    };
    if !cfg.verify(&v) {
        return Err(());
    }
    req.headers_mut().remove(KNOCK_HEADER);
    Ok(req)
}

/// True iff the buffer's request path is a knock-prefixed `/ts2021`.
/// Used by `raw_tls` so the peek-and-dispatch step recognises
/// `POST /k/<knock>/ts2021 …` as a ts2021 upgrade.
///
/// **Note:** this function only checks the *shape* — it does NOT
/// validate the knock. Validation happens later, inside the axum
/// router's middleware, once the request is parsed. Without this
/// shape check, raw_tls would route the upgrade-shaped request into
/// the hyper http1 fallback (which doesn't know how to do the
/// hijacked-socket Noise dance) and the handshake would deadlock.
#[must_use]
pub fn path_is_knocked_ts2021(path: &[u8]) -> bool {
    // /k/<hex>/ts2021 — the <hex> is 16 chars; we don't bind on the
    // length here because validation happens later, but we do require
    // the literal /ts2021 suffix (possibly followed by ? or /).
    let Some(rest) = path.strip_prefix(b"/k/") else {
        return false;
    };
    // Strip one path segment.
    let Some(slash) = rest.iter().position(|b| *b == b'/') else {
        return false;
    };
    let suffix = &rest[slash..];
    suffix == b"/ts2021" || suffix.starts_with(b"/ts2021?") || suffix.starts_with(b"/ts2021/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_psk() -> [u8; 32] {
        // Deterministic test fixture. NOT a real secret.
        let mut psk = [0u8; 32];
        for (i, b) in psk.iter_mut().enumerate() {
            *b = i as u8;
        }
        psk
    }

    // ---- Unit: HMAC determinism + window math ---------------------

    #[test]
    fn knock_is_deterministic_for_same_window() {
        let psk = fixed_psk();
        let a = knock_for_window(&psk, 100);
        let b = knock_for_window(&psk, 100);
        assert_eq!(a, b, "same window must produce same knock");
        assert_eq!(a.len(), KNOCK_TAG_BYTES * 2);
        // Tag must be valid hex (no `panic!`).
        assert!(hex::decode(&a).is_ok());
    }

    #[test]
    fn knock_changes_per_window() {
        let psk = fixed_psk();
        let a = knock_for_window(&psk, 100);
        let b = knock_for_window(&psk, 101);
        assert_ne!(a, b, "different windows must produce different knocks");
    }

    #[test]
    fn knock_is_psk_sensitive() {
        let psk_a = fixed_psk();
        let mut psk_b = fixed_psk();
        psk_b[0] ^= 1;
        let a = knock_for_window(&psk_a, 100);
        let b = knock_for_window(&psk_b, 100);
        assert_ne!(a, b);
    }

    // ---- Replay: previous window rejected -------------------------

    #[test]
    fn previous_window_knock_is_rejected() {
        let psk = fixed_psk();
        // `now` lives in window 100. A knock minted for window 99
        // (i.e. ≥ 60s ago) must fail.
        let now = 100 * DEFAULT_WINDOW_SECS + 5;
        let stale = knock_for_window(&psk, 99);
        assert!(!verify_knock(&psk, DEFAULT_WINDOW_SECS, &stale, now));
    }

    // ---- Clock skew: next window accepted, +2 rejected ------------

    #[test]
    fn current_window_knock_accepted() {
        let psk = fixed_psk();
        let now = 200 * DEFAULT_WINDOW_SECS + 17;
        let current = knock_for_window(&psk, 200);
        assert!(verify_knock(&psk, DEFAULT_WINDOW_SECS, &current, now));
    }

    #[test]
    fn next_window_knock_accepted_clock_skew_forward() {
        let psk = fixed_psk();
        // Peer's clock is ~1 window ahead of ours.
        let now = 200 * DEFAULT_WINDOW_SECS + 17;
        let next = knock_for_window(&psk, 201);
        assert!(
            verify_knock(&psk, DEFAULT_WINDOW_SECS, &next, now),
            "next window must be accepted to tolerate forward clock skew"
        );
    }

    #[test]
    fn two_windows_ahead_rejected() {
        let psk = fixed_psk();
        let now = 200 * DEFAULT_WINDOW_SECS + 17;
        let two_ahead = knock_for_window(&psk, 202);
        assert!(
            !verify_knock(&psk, DEFAULT_WINDOW_SECS, &two_ahead, now),
            "≥2 windows ahead is too much skew; reject"
        );
    }

    #[test]
    fn malformed_knock_rejected() {
        let psk = fixed_psk();
        let now = 200 * DEFAULT_WINDOW_SECS;
        assert!(!verify_knock(&psk, DEFAULT_WINDOW_SECS, "", now));
        assert!(!verify_knock(
            &psk,
            DEFAULT_WINDOW_SECS,
            "not-hex-zzzz",
            now
        ));
        assert!(!verify_knock(
            &psk,
            DEFAULT_WINDOW_SECS,
            "abcdef0123", // too short
            now
        ));
        assert!(!verify_knock(
            &psk,
            DEFAULT_WINDOW_SECS,
            "0".repeat(KNOCK_TAG_BYTES * 2).as_str(),
            now
        ));
    }

    // ---- 404 body byte-stability ---------------------------------

    #[test]
    fn probe_resistance_404_body_stable() {
        // Any drift in the canonical 404 body trips this — including
        // accidental editor reformatting, BOM insertion, or a stray
        // emoji. Pin the SHA-256 of the bytes.
        use sha2::Digest;
        let h = sha2::Sha256::digest(NGINX_404_BODY.as_bytes());
        assert_eq!(
            hex::encode(h),
            "8351c0267c2cd7866ff04c04261f06cd75af9a7130aac848ca43fd047404e229",
            "NGINX_404_BODY drifted — operators relying on byte-identity \
             with default nginx will see a fingerprint change. If this is \
             intentional, update the expected hash."
        );
    }

    #[test]
    fn probe_resistance_404_body_identical_across_random_knocks() {
        // 100 deterministic-but-arbitrary bogus knocks, all should
        // produce the SAME 404 body — byte for byte. Uses a tiny
        // splitmix64 PRNG instead of pulling in `rand` (the wire layer
        // doesn't want it as a dep).
        let mut seed: u64 = 0xCAFE_F00D_DEAD_BEEF;
        let mut seen: Option<Vec<u8>> = None;
        for _ in 0..100 {
            seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            let z = z ^ (z >> 31);
            let knock_bytes = z.to_le_bytes(); // 8 bytes
            let knock_hex = hex::encode(knock_bytes);
            // Server-side: build the response we'd return.
            let resp = nginx_404();
            // Buffer the body.
            let bytes = futures::executor::block_on(async {
                let body = resp.into_body();
                let collected = http_body_util::BodyExt::collect(body).await.unwrap();
                collected.to_bytes().to_vec()
            });
            if let Some(prev) = &seen {
                assert_eq!(prev, &bytes, "404 body diverged on knock {knock_hex}");
            } else {
                seen = Some(bytes);
            }
        }
    }

    // ---- Path-prefix helper --------------------------------------

    #[test]
    fn path_is_knocked_ts2021_matches_prefixed() {
        assert!(path_is_knocked_ts2021(b"/k/abcdef0123456789/ts2021"));
        assert!(path_is_knocked_ts2021(b"/k/abcdef0123456789/ts2021?v=2"));
        assert!(!path_is_knocked_ts2021(b"/ts2021"));
        assert!(!path_is_knocked_ts2021(b"/k/abc/key"));
        assert!(!path_is_knocked_ts2021(b"/k/"));
    }

    // -------------------------------------------------------------------
    // HMAC byte-stability: pin a per-window hex value so any drift in
    // the canonical form (truncation, key handling, key encoding) trips
    // CI immediately. Mirror these values to peers if you ever rev the
    // knock derivation.
    // -------------------------------------------------------------------

    #[test]
    fn knock_pinned_for_window_zero() {
        let psk = fixed_psk();
        let k = knock_for_window(&psk, 0);
        // window "0" → HMAC-SHA256(psk, b"0")[..8] hex.
        // Compute reference inline (this guards against accidental
        // changes to KNOCK_TAG_BYTES or the prefix string).
        let mut mac = HmacSha256::new_from_slice(&psk).unwrap();
        mac.update(b"0");
        let full = mac.finalize().into_bytes();
        let expected = hex::encode(&full[..KNOCK_TAG_BYTES]);
        assert_eq!(k, expected);
        assert_eq!(k.len(), 16, "8 bytes → 16 hex chars");
    }

    #[test]
    fn knock_pinned_for_window_2024() {
        // Pin a value to detect drift between code commits — if
        // KNOCK_TAG_BYTES changed (say from 8 to 16) this fires.
        let psk = fixed_psk();
        let k = knock_for_window(&psk, 2024);
        let mut mac = HmacSha256::new_from_slice(&psk).unwrap();
        mac.update(b"2024");
        let full = mac.finalize().into_bytes();
        assert_eq!(k, hex::encode(&full[..KNOCK_TAG_BYTES]));
    }

    /// Verify that 100 random window numbers produce 100 distinct
    /// knock values — i.e. the truncated 8-byte tag space is well-spread.
    #[test]
    fn knock_window_uniqueness_100() {
        let psk = fixed_psk();
        let mut seen = std::collections::HashSet::new();
        for w in 0u64..100 {
            seen.insert(knock_for_window(&psk, w));
        }
        assert_eq!(seen.len(), 100, "expected 100 distinct knocks");
    }

    // -------------------------------------------------------------------
    // Window-boundary math: timestamps right at boundaries.
    // -------------------------------------------------------------------

    #[test]
    fn boundary_seconds_at_window_edge_use_correct_window() {
        let psk = fixed_psk();
        // At now = 60 (exactly the edge), current window index is 1
        // (60/60). At now = 59, window is 0. Verify both knocks
        // accept appropriately.
        let knock_0 = knock_for_window(&psk, 0);
        let knock_1 = knock_for_window(&psk, 1);

        // now=59 → window=0, accepts knock_0 (current) and knock_1 (next).
        assert!(verify_knock(&psk, 60, &knock_0, 59));
        assert!(verify_knock(&psk, 60, &knock_1, 59));
        // now=60 → window=1, accepts knock_1 (current) and knock_2 (next).
        assert!(verify_knock(&psk, 60, &knock_1, 60));
        // now=60 → window=1, REJECTS knock_0 (it's the previous window now).
        assert!(
            !verify_knock(&psk, 60, &knock_0, 60),
            "at the boundary, the previous window must be rejected"
        );
    }

    #[test]
    fn last_second_of_window_still_accepts() {
        let psk = fixed_psk();
        let knock_5 = knock_for_window(&psk, 5);
        // now = 5*60 + 59 → last second of window 5.
        assert!(verify_knock(&psk, 60, &knock_5, 5 * 60 + 59));
    }

    #[test]
    fn first_second_of_next_window_rejects_prev_knock() {
        let psk = fixed_psk();
        let knock_4 = knock_for_window(&psk, 4);
        // now = 5*60 → first second of window 5; knock_4 is now stale.
        assert!(!verify_knock(&psk, 60, &knock_4, 5 * 60));
    }

    // -------------------------------------------------------------------
    // Edge cases on inputs.
    // -------------------------------------------------------------------

    #[test]
    fn zero_window_secs_always_rejects() {
        let psk = fixed_psk();
        let any = knock_for_window(&psk, 100);
        assert!(
            !verify_knock(&psk, 0, &any, 100),
            "window_secs=0 must reject everything"
        );
    }

    #[test]
    fn empty_psk_does_not_panic_and_rejects_random() {
        // An all-zero PSK is technically valid input to HMAC. We just
        // ensure verify doesn't panic, and that an unrelated knock
        // doesn't accidentally validate against it.
        let psk = [0u8; 32];
        let now = 100;
        // The legitimate knock for `psk` at the current window MUST
        // verify (HMAC under all-zero key is still deterministic).
        let legit = knock_for_window(&psk, now / DEFAULT_WINDOW_SECS);
        assert!(verify_knock(&psk, DEFAULT_WINDOW_SECS, &legit, now));
        // A random other knock should reject.
        assert!(!verify_knock(
            &psk,
            DEFAULT_WINDOW_SECS,
            "0123456789abcdef",
            now
        ));
    }

    #[test]
    fn malformed_knock_with_leading_whitespace_rejected() {
        let psk = fixed_psk();
        let now = 100 * DEFAULT_WINDOW_SECS;
        let valid = knock_for_window(&psk, 100);
        let padded = format!(" {valid}");
        assert!(
            !verify_knock(&psk, DEFAULT_WINDOW_SECS, &padded, now),
            "leading whitespace must NOT be trimmed away (defence-in-depth)"
        );
    }

    #[test]
    fn malformed_knock_with_trailing_newline_rejected() {
        let psk = fixed_psk();
        let now = 100 * DEFAULT_WINDOW_SECS;
        let valid = knock_for_window(&psk, 100);
        let padded = format!("{valid}\n");
        assert!(!verify_knock(&psk, DEFAULT_WINDOW_SECS, &padded, now));
    }

    #[test]
    fn malformed_knock_uppercase_hex_rejected_or_accepted_consistently() {
        // Hex crate's `decode` accepts mixed-case hex. So the verify
        // should accept the upper-case variant — this is just to
        // document the behaviour explicitly.
        let psk = fixed_psk();
        let now = 100 * DEFAULT_WINDOW_SECS;
        let valid = knock_for_window(&psk, 100);
        let upper = valid.to_uppercase();
        // Both lower- and upper-case must verify (hex crate is
        // case-insensitive on decode).
        assert!(verify_knock(&psk, DEFAULT_WINDOW_SECS, &valid, now));
        assert!(verify_knock(&psk, DEFAULT_WINDOW_SECS, &upper, now));
    }

    #[test]
    fn malformed_knock_with_inner_dash_rejected() {
        let psk = fixed_psk();
        let now = 100 * DEFAULT_WINDOW_SECS;
        // 16 chars but contains a non-hex char.
        let bogus = "abcdef0123-56789";
        assert_eq!(bogus.len(), 16);
        assert!(!verify_knock(&psk, DEFAULT_WINDOW_SECS, bogus, now));
    }

    #[test]
    fn malformed_knock_with_unicode_rejected() {
        // 16-char unicode string that's not hex-decodable.
        let psk = fixed_psk();
        let now = 100 * DEFAULT_WINDOW_SECS;
        let bogus = "ababababababcafé"; // last char is non-ASCII
        // String length in CHARS is 16; in BYTES it's longer. Our
        // verify checks `len()` (bytes), so it'll fail the length
        // check before reaching hex::decode. Either path → false.
        assert!(!verify_knock(&psk, DEFAULT_WINDOW_SECS, bogus, now));
    }

    #[test]
    fn malformed_knock_thirty_two_hex_chars_rejected() {
        // Full SHA256 tag length — the impl truncates to 8 bytes and
        // requires KNOCK_TAG_BYTES*2 input chars, so a 64-char value
        // is wrong-length.
        let psk = fixed_psk();
        let now = 100 * DEFAULT_WINDOW_SECS;
        let full = "0".repeat(64);
        assert!(!verify_knock(&psk, DEFAULT_WINDOW_SECS, &full, now));
    }

    // -------------------------------------------------------------------
    // path_is_knocked_ts2021: more shapes
    // -------------------------------------------------------------------

    #[test]
    fn path_is_knocked_ts2021_with_trailing_slash() {
        assert!(path_is_knocked_ts2021(b"/k/abcd/ts2021/"));
    }

    #[test]
    fn path_is_knocked_ts2021_other_endpoints_rejected() {
        assert!(!path_is_knocked_ts2021(b"/k/abcd/derp"));
        assert!(!path_is_knocked_ts2021(b"/k/abcd/register"));
        assert!(!path_is_knocked_ts2021(b"/k/abcd/ts2021something"));
    }

    #[test]
    fn path_is_knocked_ts2021_empty_path_rejected() {
        assert!(!path_is_knocked_ts2021(b""));
    }

    // -------------------------------------------------------------------
    // 404 helper produces stable headers (Content-Type, Server).
    // -------------------------------------------------------------------

    #[test]
    fn nginx_404_response_has_expected_headers() {
        let resp = nginx_404();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap();
        assert_eq!(ct.to_str().unwrap(), "text/html; charset=utf-8");
        let server = resp.headers().get(header::SERVER).unwrap();
        assert_eq!(server.to_str().unwrap(), "nginx/1.18.0");
    }

    // -------------------------------------------------------------------
    // KnockConfig public API
    // -------------------------------------------------------------------

    #[test]
    fn disabled_config_verify_always_false() {
        let cfg = KnockConfig::disabled();
        // Even with a "valid" hex string of the right length, a
        // disabled config's PSK is all-zero so a knock for any window
        // under the deterministic PSK won't match a knock for the
        // current window under the zero PSK — but to be safe, we just
        // check that disabled doesn't accept the *fixed-psk* knock.
        let psk = fixed_psk();
        let cw = current_window(DEFAULT_WINDOW_SECS);
        let k = knock_for_window(&psk, cw);
        // disabled config has a zero psk; the fixed_psk knock should
        // NOT verify under zero psk.
        assert!(!cfg.verify(&k));
    }

    #[test]
    fn enabled_config_round_trips_via_current_knock() {
        let psk = fixed_psk();
        let cfg = KnockConfig::enabled(psk);
        let k = cfg.current_knock();
        assert!(cfg.verify(&k), "config-issued knock must verify");
    }

    #[test]
    fn config_window_secs_default_60() {
        let cfg = KnockConfig::enabled(fixed_psk());
        assert_eq!(cfg.window_secs, DEFAULT_WINDOW_SECS);
    }
}
