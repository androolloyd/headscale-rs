//! OctraVPN admin GUI v0 — Tailscale-admin-equivalent web panel.
//!
//! This module is mounted by the operator at a dedicated port —
//! recommended `127.0.0.1:51822` (a new port; never 443 / 51820 /
//! 51821 which belong to the Tailscale wire / WireGuard / Headscale
//! gRPC surfaces). It serves two parallel route families:
//!
//! * `GET/POST /admin/*` — server-side rendered HTML (maud), with a
//!   session-cookie + CSRF auth flow for browsers.
//! * `GET/POST /api/v1/*` — same data shaped as JSON, with bearer-token
//!   auth (no cookie required).
//!
//! Both families read + mutate the same backing state:
//!
//! * Users live behind [`users::UserAdmin`]. Tests and ephemeral
//!   deployments can use [`users::UserRegistry`]; replacement-compatible
//!   deployments can use [`users::PersistentUserAdmin`] against the
//!   Go-shaped SQLite `users` table.
//! * Machines come from either [`crate::tailscale_wire::MachineRegistry`] via
//!   [`machines::WireMachineAdmin`] for wire-only Octra deployments, or from
//!   the Go-shaped SQLite `nodes` table via [`machines::PersistentMachineAdmin`]
//!   for replacement-compatible admin/gRPC deployments.
//! * Pre-auth keys come from the embedding host through the
//!   [`preauth::PreauthAdmin`] trait; OctraVPN's `PreauthMinter`
//!   implements this in the mesh crate's bridge code. An in-process
//!   default ([`preauth::InMemoryPreauthAdmin`]) is shipped here for
//!   tests + standalone deployments.
//!
//! ## Mount point
//!
//! ```ignore
//! # use std::sync::Arc;
//! use headscale_api::{admin, tailscale_wire};
//! let wire = tailscale_wire::WireState {
//!     // …populated by the embedding host…
//!     # server_noise_key: todo!(),
//!     # preauth: todo!(),
//!     # ip_allocator: todo!(),
//!     # machines: Arc::new(tailscale_wire::MachineRegistry::new()),
//!     # registration_store: None,
//!     # derp_map: crate::tailscale_wire::DerpMapStore::shared(Default::default()),
//!     # policy: Arc::new(Default::default()),
//!     # knock: tailscale_wire::KnockConfig::disabled(),
//!     # dns: Arc::new(Default::default()),
//!     # public_control_url: Some("https://headscale.example".into()),
//!     # runtime_config: Arc::new(tailscale_wire::RuntimeConfigSnapshot::default()),
//!     # registration_cache: Arc::new(tailscale_wire::RegistrationCache::new()),
//!     # pings: Arc::new(tailscale_wire::PingTracker::new()),
//!     # mapresponse_debug: Arc::new(tailscale_wire::MapResponseDebugStore::disabled()),
//! };
//! let admin_state = admin::AdminState::builder()
//!     .bearer_token("op-secret-token")
//!     .users(admin::UserRegistry::new())
//!     .machines(Arc::new(admin::WireMachineAdmin::new(wire.machines.clone())))
//!     .preauth(Arc::new(admin::InMemoryPreauthAdmin::new()))
//!     .derp_regions(wire.derp_map.snapshot().regions.len())
//!     .build();
//! let app = admin::router(admin_state);
//! // axum::serve(listener_on_51822, app).await.unwrap();
//! ```
//!
//! ## Feature flag
//!
//! Gated behind the `admin` cargo feature (default-on). Downstream
//! crates that only want the wire layer can disable it with
//! `default-features = false`.

pub mod api_keys;
pub mod auth;
pub mod machines;
pub mod preauth;
pub mod preauth_persistent;
pub mod users;
mod views;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRef, Path, RawQuery, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;

use crate::tailscale_wire::routes::normalize_routes;

pub use api_keys::{
    ApiKeyAdmin, ApiKeyAdminError, ApiKeyAdminKey, ApiKeyCreated, ApiKeyMintRequest,
    NoopApiKeyAdmin, PersistentApiKeyAdmin,
};
pub use auth::{AdminAuth, AuthOutcome, SESSION_COOKIE, SESSION_TTL_SECS};
pub use machines::{
    MachineAdmin, MachineAdminError, MachineAdminRecord, PersistentMachineAdmin,
    PersistentOidcRegistrationHandler, WireMachineAdmin,
};
pub use preauth::{
    InMemoryPreauthAdmin, PreauthAdmin, PreauthAdminError, PreauthAdminKey, PreauthMintRequest,
};
pub use preauth_persistent::PersistentPreauthAdmin;
pub use users::{PersistentUserAdmin, UserAdmin, UserRecord, UserRegistry, UserRegistryError};

use views::Section;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Composite state passed to every admin handler. Cheap to clone — all
/// fields are `Arc` / `Clone`.
#[derive(Clone)]
pub struct AdminState {
    pub auth: AdminAuth,
    pub users: Arc<dyn UserAdmin>,
    pub machines: Arc<dyn MachineAdmin>,
    pub preauth: Arc<dyn PreauthAdmin>,
    pub api_keys: Arc<dyn ApiKeyAdmin>,
    /// DERP region count for the read-only tailnet page. The full
    /// DERP map isn't passed through — the admin module doesn't need
    /// to introspect it for v0.
    pub derp_regions: usize,
    /// Live policy store, shared with the wire layer's
    /// [`crate::tailscale_wire::WireState::policy`]. Admin PUT mutates
    /// it; the store's `Notify` wakes parked `/map` long-pollers.
    pub policy: crate::policy::PolicyStore,
}

impl AdminState {
    /// Returns a fresh builder.
    pub fn builder() -> AdminStateBuilder {
        AdminStateBuilder::default()
    }
}

#[derive(Default)]
pub struct AdminStateBuilder {
    bearer_token: Option<String>,
    users: Option<Arc<dyn UserAdmin>>,
    machines: Option<Arc<dyn MachineAdmin>>,
    preauth: Option<Arc<dyn PreauthAdmin>>,
    api_keys: Option<Arc<dyn ApiKeyAdmin>>,
    derp_regions: usize,
    policy: Option<crate::policy::PolicyStore>,
}

impl AdminStateBuilder {
    pub fn bearer_token(mut self, t: impl Into<String>) -> Self {
        self.bearer_token = Some(t.into());
        self
    }
    pub fn users<U>(mut self, u: U) -> Self
    where
        U: UserAdmin + 'static,
    {
        self.users = Some(Arc::new(u));
        self
    }
    pub fn users_arc(mut self, u: Arc<dyn UserAdmin>) -> Self {
        self.users = Some(u);
        self
    }
    pub fn machines(mut self, m: Arc<dyn MachineAdmin>) -> Self {
        self.machines = Some(m);
        self
    }
    pub fn preauth(mut self, p: Arc<dyn PreauthAdmin>) -> Self {
        self.preauth = Some(p);
        self
    }
    pub fn api_keys(mut self, a: Arc<dyn ApiKeyAdmin>) -> Self {
        self.api_keys = Some(a);
        self
    }
    pub fn derp_regions(mut self, n: usize) -> Self {
        self.derp_regions = n;
        self
    }
    /// Attach a shared [`crate::policy::PolicyStore`]. If unset the
    /// builder constructs an empty store; the wire layer will then
    /// fall back to `allow_all_packet_filter` (interop default).
    /// Production callers MUST pass the same `Arc` they handed to
    /// `WireState::policy` so PUT propagates to /map.
    pub fn policy(mut self, p: crate::policy::PolicyStore) -> Self {
        self.policy = Some(p);
        self
    }
    pub fn build(self) -> AdminState {
        AdminState {
            auth: AdminAuth::new(self.bearer_token.unwrap_or_default()),
            users: self
                .users
                .unwrap_or_else(|| Arc::new(UserRegistry::new()) as Arc<dyn UserAdmin>),
            machines: self
                .machines
                .unwrap_or_else(|| Arc::new(NoopMachines) as Arc<dyn MachineAdmin>),
            preauth: self
                .preauth
                .unwrap_or_else(|| Arc::new(InMemoryPreauthAdmin::new()) as Arc<dyn PreauthAdmin>),
            api_keys: self
                .api_keys
                .unwrap_or_else(|| Arc::new(NoopApiKeyAdmin) as Arc<dyn ApiKeyAdmin>),
            derp_regions: self.derp_regions,
            policy: self.policy.unwrap_or_default(),
        }
    }
}

impl FromRef<AdminState> for AdminAuth {
    fn from_ref(input: &AdminState) -> Self {
        input.auth.clone()
    }
}

/// Fallback machine admin used when the builder doesn't get a real one
/// (mostly relevant to tests). Empty in every direction.
#[derive(Default)]
struct NoopMachines;

#[async_trait::async_trait]
impl MachineAdmin for NoopMachines {
    async fn list(&self) -> Vec<MachineAdminRecord> {
        Vec::new()
    }
    async fn get(&self, _: &str) -> Option<MachineAdminRecord> {
        None
    }
    async fn create(
        &self,
        record: MachineAdminRecord,
    ) -> Result<MachineAdminRecord, MachineAdminError> {
        Err(MachineAdminError::NotFound(record.id))
    }
    async fn expire_at(
        &self,
        id: &str,
        _expiry: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
    async fn disable_expiry(&self, id: &str) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
    async fn logout(&self, id: &str) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
    async fn rename(&self, id: &str, _h: &str) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
    async fn set_tags(&self, id: &str, _t: Vec<String>) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
    async fn set_approved_routes(
        &self,
        id: &str,
        _routes: Vec<String>,
    ) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
    async fn set_routes(&self, id: &str, _routes: Vec<String>) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
    async fn delete(&self, id: &str) -> Result<(), MachineAdminError> {
        Err(MachineAdminError::NotFound(id.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the admin router. Mount under a dedicated listener — never
/// share with the wire layer's `:443` or the WireGuard data plane.
pub fn router(state: AdminState) -> Router {
    let html = Router::new()
        .route("/admin/", get(page_dashboard))
        .route("/admin/machines", get(page_machines))
        .route("/admin/machines/:id", get(page_machine_detail))
        .route("/admin/machines/:id/expire", post(post_machine_expire))
        .route("/admin/machines/:id/delete", post(post_machine_delete))
        .route("/admin/users", get(page_users).post(post_users_create))
        .route("/admin/users/:name/delete", post(post_users_delete))
        .route(
            "/admin/preauthkeys",
            get(page_preauth).post(post_preauth_mint),
        )
        .route(
            "/admin/preauthkeys/:prefix/expire",
            post(post_preauth_expire),
        )
        .route("/admin/tailnet", get(page_tailnet))
        .route("/admin/policy", get(page_policy))
        .route("/admin/sessions", get(page_sessions))
        .route("/admin/login", get(page_login).post(post_login))
        .route("/admin/logout", get(get_logout));

    let api = Router::new()
        .route("/api/v1/users", get(api_users_list).post(api_users_create))
        .route(
            "/api/v1/users/:name",
            axum::routing::delete(api_users_delete),
        )
        .route("/api/v1/machines", get(api_machines_list))
        .route("/api/v1/machines/:id", get(api_machines_get))
        .route(
            "/api/v1/machines/:id",
            axum::routing::delete(api_machines_delete),
        )
        .route("/api/v1/machines/:id/expire", post(api_machines_expire))
        .route("/api/v1/machines/:id/logout", post(api_machines_logout))
        .route("/api/v1/machines/:id/rename", post(api_machines_rename))
        .route("/api/v1/machines/:id/tags", post(api_machines_tags))
        .route("/api/v1/machines/:id/routes", post(api_machines_routes))
        .route(
            "/api/v1/machines/:id/approve_routes",
            post(api_machines_routes),
        )
        .route(
            "/api/v1/preauthkeys",
            get(api_preauth_list).post(api_preauth_mint),
        )
        .route(
            "/api/v1/preauthkeys/:prefix/expire",
            post(api_preauth_expire),
        )
        .route(
            "/api/v1/apikey",
            get(api_keys_list)
                .post(api_keys_mint)
                .delete(api_keys_delete_body),
        )
        .route("/api/v1/apikey/expire", post(api_keys_expire))
        .route(
            "/api/v1/apikey/:prefix",
            axum::routing::delete(api_keys_delete),
        )
        .route("/api/v1/policy", get(api_policy_get).put(api_policy_put))
        .route("/api/v1/policy/validate", post(api_policy_validate))
        .route("/api/v1/tailnet", get(api_tailnet));

    Router::new().merge(html).merge(api).with_state(state)
}

// ---------------------------------------------------------------------------
// HTML guards
// ---------------------------------------------------------------------------

/// HTML auth gate: returns either an authorized `AuthOutcome` OR a
/// redirect to `/admin/login`. The unauthenticated path is the redirect
/// — anonymous bearer-token-less browser hits should land at the login
/// page, not see a 401.
///
/// The `Err` variant carries a fully-formed `Response`; clippy's
/// `result_large_err` lint fires on this shape because `Response` is
/// ~128B. Boxing the response would require an extra heap alloc per
/// auth check on every request — bad trade for a single-flag warning.
#[allow(clippy::result_large_err)]
fn guard_html(state: &AdminState, req: &Request) -> Result<AuthOutcome, Response> {
    let outcome = auth::evaluate_headers(req.headers(), &state.auth);
    if outcome.is_authenticated() {
        Ok(outcome)
    } else {
        Err(auth::redirect_to_login())
    }
}

/// JSON auth gate. Returns a 401 JSON body on anonymous access. See
/// [`guard_html`] for the rationale on the `allow(result_large_err)`.
#[allow(clippy::result_large_err)]
async fn guard_api(state: &AdminState, headers: HeaderMap) -> Result<AuthOutcome, Response> {
    let outcome = auth::evaluate_headers(&headers, &state.auth);
    if outcome.is_authenticated() {
        Ok(outcome)
    } else if let Some(token) = auth::bearer_token(&headers).map(str::to_owned)
        && state.api_keys.validate(&token).await
    {
        Ok(AuthOutcome::Bearer)
    } else {
        Err(auth::api_unauthorized())
    }
}

fn user_store_html_error(e: &UserRegistryError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html(
            views::shell(
                "User store error",
                Section::Users,
                true,
                views::error_page(500, &e.to_string()),
            )
            .into_string(),
        ),
    )
        .into_response()
}

fn user_store_api_error(e: &UserRegistryError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": e.to_string()})),
    )
        .into_response()
}

/// Verify the CSRF token from a form. For bearer-token clients this is
/// a no-op (they don't carry a session cookie). For session clients we
/// require the form to carry the `csrf` field bound to their session.
fn check_csrf(state: &AdminState, outcome: &AuthOutcome, form_csrf: Option<&str>) -> bool {
    match outcome {
        AuthOutcome::Bearer => true,
        AuthOutcome::Session { payload } => match form_csrf {
            Some(t) => state.auth.csrf_valid(payload, t),
            None => false,
        },
        AuthOutcome::Anonymous => false,
    }
}

// ---------------------------------------------------------------------------
// HTML page handlers
// ---------------------------------------------------------------------------

async fn page_dashboard(State(s): State<AdminState>, req: Request) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let machines = s.machines.list().await;
    let online = machines.iter().filter(|m| m.online).count();
    let preauth = s.preauth.list().await;
    let live = preauth
        .iter()
        .filter(|k| k.expires_at > auth::now_unix())
        .count();
    let user_count = match s.users.len().await {
        Ok(n) => n,
        Err(e) => return user_store_html_error(&e),
    };
    let body = views::shell(
        "Dashboard",
        Section::Dashboard,
        outcome.is_authenticated(),
        views::dashboard(machines.len(), online, user_count, live),
    );
    Html(body.into_string()).into_response()
}

async fn page_machines(State(s): State<AdminState>, req: Request) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let machines = s.machines.list().await;
    let csrf = outcome.csrf_token(&s.auth);
    let body = views::shell(
        "Machines",
        Section::Machines,
        true,
        views::machines_list(&machines, csrf.as_deref()),
    );
    Html(body.into_string()).into_response()
}

async fn page_machine_detail(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Some(m) = s.machines.get(&id).await else {
        return (
            StatusCode::NOT_FOUND,
            Html(
                views::shell(
                    "Not found",
                    Section::Machines,
                    true,
                    views::error_page(404, "machine not found"),
                )
                .into_string(),
            ),
        )
            .into_response();
    };
    let csrf = outcome.csrf_token(&s.auth);
    let body = views::shell(
        &format!(
            "Machine {}",
            if m.name.is_empty() {
                &m.id[..8]
            } else {
                &m.name
            }
        ),
        Section::Machines,
        true,
        views::machine_detail(&m, csrf.as_deref()),
    );
    Html(body.into_string()).into_response()
}

#[derive(Deserialize)]
struct CsrfForm {
    #[serde(default)]
    csrf: Option<String>,
}

async fn post_machine_expire(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    // Read form body manually so we can apply CSRF before mutating.
    let form: CsrfForm = match read_form(req).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if !check_csrf(&s, &outcome, form.csrf.as_deref()) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let _ = s.machines.expire(&id).await;
    Redirect::to(&format!("/admin/machines/{id}")).into_response()
}

async fn post_machine_delete(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let form: CsrfForm = match read_form(req).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if !check_csrf(&s, &outcome, form.csrf.as_deref()) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let _ = s.machines.delete(&id).await;
    Redirect::to("/admin/machines").into_response()
}

async fn page_users(State(s): State<AdminState>, RawQuery(q): RawQuery, req: Request) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let users = match s.users.all().await {
        Ok(users) => users,
        Err(e) => return user_store_html_error(&e),
    };
    let flash = q
        .as_deref()
        .and_then(|qs| qs.split('&').find_map(|kv| kv.strip_prefix("err=")))
        .map(urldecode);
    let csrf = outcome.csrf_token(&s.auth);
    let body = views::shell(
        "Users",
        Section::Users,
        true,
        views::users_page(&users, csrf.as_deref(), flash.as_deref()),
    );
    Html(body.into_string()).into_response()
}

#[derive(Deserialize)]
struct UserCreateForm {
    name: String,
    #[serde(default)]
    csrf: Option<String>,
}

async fn post_users_create(State(s): State<AdminState>, req: Request) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let form: UserCreateForm = match read_form(req).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if !check_csrf(&s, &outcome, form.csrf.as_deref()) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    match s.users.create(form.name.trim()).await {
        Ok(_) => {
            s.policy.refresh();
            Redirect::to("/admin/users").into_response()
        }
        Err(e) => {
            Redirect::to(&format!("/admin/users?err={}", urlencode(&e.to_string()))).into_response()
        }
    }
}

async fn post_users_delete(
    State(s): State<AdminState>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let form: CsrfForm = match read_form(req).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if !check_csrf(&s, &outcome, form.csrf.as_deref()) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    if s.users.delete(&name).await.is_ok() {
        s.policy.refresh();
    }
    Redirect::to("/admin/users").into_response()
}

async fn page_preauth(
    State(s): State<AdminState>,
    RawQuery(q): RawQuery,
    req: Request,
) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let keys = s.preauth.list().await;
    let mut err: Option<String> = None;
    let mut just_minted: Option<PreauthAdminKey> = None;
    if let Some(qs) = q.as_deref() {
        for kv in qs.split('&') {
            if let Some(raw) = kv.strip_prefix("err=") {
                err = Some(urldecode(raw));
            } else if let Some(raw) = kv.strip_prefix("minted=") {
                // Look up the key by prefix in the live list.
                let prefix = urldecode(raw);
                just_minted = keys.iter().find(|k| k.key.starts_with(&prefix)).cloned();
            }
        }
    }
    let csrf = outcome.csrf_token(&s.auth);
    let body = views::shell(
        "Pre-auth keys",
        Section::PreauthKeys,
        true,
        views::preauthkeys_page(&keys, csrf.as_deref(), just_minted.as_ref(), err.as_deref()),
    );
    Html(body.into_string()).into_response()
}

#[derive(Deserialize)]
struct PreauthForm {
    user: String,
    #[serde(default)]
    ttl_days: Option<u64>,
    #[serde(default)]
    reusable: Option<String>,
    #[serde(default)]
    ephemeral: Option<String>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    csrf: Option<String>,
}

async fn post_preauth_mint(State(s): State<AdminState>, req: Request) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let form: PreauthForm = match read_form(req).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if !check_csrf(&s, &outcome, form.csrf.as_deref()) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let req = PreauthMintRequest {
        user: form.user.trim().to_string(),
        ttl_secs: form.ttl_days.unwrap_or(1).saturating_mul(86400),
        reusable: form.reusable.is_some(),
        ephemeral: form.ephemeral.is_some(),
        tags: form
            .tags
            .unwrap_or_default()
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect(),
    };
    let user = req.user.clone();
    match s.preauth.mint(req).await {
        Ok(k) => {
            let _ = s.users.touch(&user).await;
            // Redirect with the key prefix so the page can splash the
            // full token from `s.preauth.list()` on render.
            let head_len = "hskey-auth-".len() + 12;
            let prefix = &k.key[..head_len.min(k.key.len())];
            Redirect::to(&format!("/admin/preauthkeys?minted={}", urlencode(prefix)))
                .into_response()
        }
        Err(e) => Redirect::to(&format!(
            "/admin/preauthkeys?err={}",
            urlencode(&e.to_string())
        ))
        .into_response(),
    }
}

async fn post_preauth_expire(
    State(s): State<AdminState>,
    Path(prefix): Path<String>,
    req: Request,
) -> Response {
    let outcome = match guard_html(&s, &req) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let form: CsrfForm = match read_form(req).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if !check_csrf(&s, &outcome, form.csrf.as_deref()) {
        return (StatusCode::FORBIDDEN, "bad csrf").into_response();
    }
    let _ = s.preauth.expire_by_prefix(&prefix).await;
    Redirect::to("/admin/preauthkeys").into_response()
}

async fn page_tailnet(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_html(&s, &req) {
        return r;
    }
    let body = views::shell(
        "Tailnet",
        Section::Tailnet,
        true,
        views::tailnet_page(s.derp_regions),
    );
    Html(body.into_string()).into_response()
}

async fn page_policy(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_html(&s, &req) {
        return r;
    }
    let body = views::shell("Policy", Section::Policy, true, views::policy_page(false));
    Html(body.into_string()).into_response()
}

async fn page_sessions(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_html(&s, &req) {
        return r;
    }
    let body = views::shell("Sessions", Section::Sessions, true, views::sessions_page());
    Html(body.into_string()).into_response()
}

// --- Login / logout --------------------------------------------------------

async fn page_login(RawQuery(q): RawQuery) -> Response {
    let err = q
        .as_deref()
        .and_then(|qs| qs.split('&').find_map(|kv| kv.strip_prefix("err=")))
        .map(urldecode);
    Html(views::login_page(err.as_deref()).into_string()).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn post_login(State(s): State<AdminState>, req: Request) -> Response {
    let form: LoginForm = match read_form(req).await {
        Ok(f) => f,
        Err(r) => return r,
    };
    if !s.auth.verify_bearer(form.token.trim()) {
        return Redirect::to(&format!("/admin/login?err={}", urlencode("Invalid token")))
            .into_response();
    }
    let expires = auth::now_unix().saturating_add(SESSION_TTL_SECS);
    let payload = s.auth.mint_session(expires);
    let cookie = AdminAuth::cookie_header(&payload, SESSION_TTL_SECS);
    let mut r = Redirect::to("/admin/").into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie ascii"),
    );
    r
}

async fn get_logout(State(_s): State<AdminState>) -> Response {
    let mut r = Redirect::to("/admin/login").into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&AdminAuth::cookie_clear_header()).expect("cookie ascii"),
    );
    r
}

// ---------------------------------------------------------------------------
// API handlers
// ---------------------------------------------------------------------------

async fn api_users_list(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    match s.users.all().await {
        Ok(users) => Json(users).into_response(),
        Err(e) => user_store_api_error(&e),
    }
}

#[derive(Deserialize)]
struct ApiUserCreate {
    name: String,
}

async fn api_users_create(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiUserCreate = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match s.users.create(body.name.trim()).await {
        Ok(rec) => {
            s.policy.refresh();
            (StatusCode::CREATED, Json(rec)).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_users_delete(
    State(s): State<AdminState>,
    Path(name): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    match s.users.delete(&name).await {
        Ok(()) => {
            s.policy.refresh();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_machines_list(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    Json(s.machines.list().await).into_response()
}

async fn api_machines_get(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    match s.machines.get(&id).await {
        Some(m) => Json(m).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct ApiExpireBody {
    /// Optional ISO-8601 timestamp. Absent ⇒ expire immediately.
    #[serde(default)]
    expiry: Option<String>,
}

async fn api_machines_expire(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    // Body is optional — empty body ⇒ expire immediately.
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 4096).await else {
        return (StatusCode::BAD_REQUEST, "body").into_response();
    };
    let body: ApiExpireBody = if bytes.is_empty() {
        ApiExpireBody::default()
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("json: {e}")})),
                )
                    .into_response();
            }
        }
    };
    let parsed_expiry = match body.expiry.as_deref() {
        None | Some("") => None,
        Some(s) => match chrono::DateTime::parse_from_rfc3339(s) {
            Ok(t) => Some(t.with_timezone(&chrono::Utc)),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": format!("invalid expiry: {e}")})),
                )
                    .into_response();
            }
        },
    };
    match s.machines.expire_at(&id, parsed_expiry).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_machines_logout(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    match s.machines.logout(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ApiRenameBody {
    hostname: String,
}

async fn api_machines_rename(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiRenameBody = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    match s.machines.rename(&id, &body.hostname).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(MachineAdminError::BadRequest(msg)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ApiTagsBody {
    #[serde(default)]
    tags: Vec<String>,
}

fn validate_api_tag(tag: &str) -> Result<(), String> {
    if !tag.starts_with("tag:") {
        return Err("tag must start with the string 'tag:'".to_string());
    }
    if tag.to_lowercase() != tag {
        return Err("tag should be lowercase".to_string());
    }
    if tag.split_whitespace().count() > 1 {
        return Err("tag should not contains space".to_string());
    }
    Ok(())
}

async fn api_machines_tags(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiTagsBody = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if body.tags.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "cannot remove all tags from a node - tagged nodes must have at least one tag"})),
        )
            .into_response();
    }
    for tag in &body.tags {
        if let Err(msg) = validate_api_tag(tag) {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response();
        }
    }
    let invalid_tags = body
        .tags
        .iter()
        .filter(|tag| !s.policy.tag_exists(tag))
        .cloned()
        .collect::<Vec<_>>();
    if !invalid_tags.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!(
                "requested tags [{}] are invalid or not permitted",
                invalid_tags.join(" ")
            )})),
        )
            .into_response();
    }
    match s.machines.set_tags(&id, body.tags).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(MachineAdminError::BadRequest(msg)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[derive(Deserialize)]
struct ApiRoutesBody {
    #[serde(default)]
    routes: Vec<String>,
}

async fn api_machines_routes(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiRoutesBody = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let routes = match normalize_routes(body.routes) {
        Ok(routes) => routes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("invalid route: {e}")})),
            )
                .into_response();
        }
    };
    match s.machines.set_approved_routes(&id, routes).await {
        Ok(()) => match s.machines.get(&id).await {
            Some(machine) => Json(machine).into_response(),
            None => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "machine not found after route update"})),
            )
                .into_response(),
        },
        Err(MachineAdminError::BadRequest(msg)) => {
            (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
        }
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_machines_delete(
    State(s): State<AdminState>,
    Path(id): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    match s.machines.delete(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_preauth_list(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    Json(s.preauth.list().await).into_response()
}

#[derive(Deserialize)]
struct ApiPreauthCreate {
    user: String,
    #[serde(default = "default_ttl_secs")]
    ttl_secs: u64,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    tags: Vec<String>,
}
fn default_ttl_secs() -> u64 {
    preauth::DEFAULT_TTL_SECS
}

async fn api_preauth_mint(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiPreauthCreate = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mint = PreauthMintRequest {
        user: body.user,
        ttl_secs: body.ttl_secs,
        reusable: body.reusable,
        ephemeral: body.ephemeral,
        tags: body.tags,
    };
    match s.preauth.mint(mint).await {
        Ok(k) => (StatusCode::CREATED, Json(k)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_preauth_expire(
    State(s): State<AdminState>,
    Path(prefix): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    match s.preauth.expire_by_prefix(&prefix).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_keys_list(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    Json(json!({ "api_keys": s.api_keys.list().await })).into_response()
}

#[derive(Deserialize)]
struct ApiKeyCreateBody {
    #[serde(default)]
    expiration: Option<ApiKeyExpiration>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ApiKeyExpiration {
    Unix(i64),
    Rfc3339(String),
}

impl ApiKeyExpiration {
    fn to_unix(&self) -> Result<i64, String> {
        match self {
            Self::Unix(v) => Ok(*v),
            Self::Rfc3339(s) => chrono::DateTime::parse_from_rfc3339(s)
                .map(|t| t.timestamp())
                .map_err(|e| format!("invalid expiration: {e}")),
        }
    }
}

async fn api_keys_mint(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiKeyCreateBody = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    let expiration = match body.expiration.as_ref().map(ApiKeyExpiration::to_unix) {
        Some(Ok(v)) => Some(v),
        Some(Err(e)) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response();
        }
        None => None,
    };
    match s.api_keys.mint(ApiKeyMintRequest { expiration }).await {
        Ok(k) => (StatusCode::CREATED, Json(k)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct ApiKeyIdentifyBody {
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    id: Option<u64>,
}

async fn api_keys_expire(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiKeyIdentifyBody = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if body.prefix.is_some() == body.id.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "provide exactly one of prefix or id"})),
        )
            .into_response();
    }
    let result = if let Some(id) = body.id {
        s.api_keys.expire_by_id(id).await
    } else {
        s.api_keys
            .expire_by_prefix(body.prefix.as_deref().unwrap_or_default())
            .await
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_keys_delete(
    State(s): State<AdminState>,
    Path(prefix): Path<String>,
    req: Request,
) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    match s.api_keys.delete_by_prefix(&prefix).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

async fn api_keys_delete_body(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let body: ApiKeyIdentifyBody = match read_json(req).await {
        Ok(v) => v,
        Err(r) => return r,
    };
    if body.prefix.is_some() == body.id.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "provide exactly one of prefix or id"})),
        )
            .into_response();
    }
    let result = if let Some(id) = body.id {
        s.api_keys.delete_by_id(id).await
    } else {
        s.api_keys
            .delete_by_prefix(body.prefix.as_deref().unwrap_or_default())
            .await
    };
    match result {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

/// `GET /api/v1/policy` — return the currently loaded policy.
///
/// Body shape (always JSON, even when no policy is loaded):
///
/// ```json
/// { "loaded": <bool>, "policy": <PolicyDoc | null>,
///   "raw": "<hujson source | null>" }
/// ```
///
/// `policy` is the canonicalised serde shape; `raw` preserves the
/// operator's exact source bytes (hujson comments + trailing commas
/// included) so the CLI can fetch + re-push without a re-serialise
/// round-trip.
async fn api_policy_get(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let doc = s.policy.doc();
    let raw = s.policy.raw();
    let loaded = doc.is_some();
    Json(json!({
        "loaded": loaded,
        "policy": doc,
        "raw": raw,
    }))
    .into_response()
}

/// `PUT /api/v1/policy` — replace the policy document.
///
/// Body is hujson (Tailscale's flavour of JSON with line/block
/// comments + trailing commas). On parse failure the response is
/// `400 Bad Request` with `{"error": "<diagnostic>"}` — the
/// existing policy stays intact. On success the new doc lands
/// atomically and every parked `/map` long-poller wakes within
/// ~1 ms.
async fn api_policy_put(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 1024 * 1024).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "policy body too large or unreadable"})),
        )
            .into_response();
    };
    let raw = match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_string(),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("policy body not UTF-8: {e}")})),
            )
                .into_response();
        }
    };
    match crate::policy::parse_hujson_policy(&raw) {
        Ok(doc) => {
            let n_rules = doc.rules.len();
            s.policy.set(doc, raw);
            let auto_approved_nodes =
                match machines::apply_policy_auto_approvals(&s.policy, s.machines.as_ref()).await {
                    Ok(count) => count,
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": e.to_string()})),
                        )
                            .into_response();
                    }
                };
            (
                StatusCode::OK,
                Json(json!({
                    "applied": true,
                    "rules": n_rules,
                    "autoApprovedNodes": auto_approved_nodes,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// `POST /api/v1/policy/validate` — parse the body as hujson + check
/// the schema without mutating the store. Returns `200 OK` with
/// `{"valid": true, "rules": <count>}` on success, `400` with
/// `{"error": "..."}` on failure. Operators wire this into pre-commit
/// hooks to catch typos before pushing.
async fn api_policy_validate(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 1024 * 1024).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "policy body too large or unreadable"})),
        )
            .into_response();
    };
    let raw = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("policy body not UTF-8: {e}")})),
            )
                .into_response();
        }
    };
    match crate::policy::parse_hujson_policy(raw) {
        Ok(doc) => (
            StatusCode::OK,
            Json(json!({"valid": true, "rules": doc.rules.len()})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn api_tailnet(State(s): State<AdminState>, req: Request) -> Response {
    if let Err(r) = guard_api(&s, req.headers().clone()).await {
        return r;
    }
    Json(json!({
        "derp_regions": s.derp_regions,
        "dns": { "magic_dns": false, "enabled": false },
        "policy_loaded": s.policy.is_loaded(),
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Body helpers
// ---------------------------------------------------------------------------

/// Buffer the request body and parse it as `application/x-www-form-urlencoded`.
#[allow(clippy::result_large_err)]
async fn read_form<T: serde::de::DeserializeOwned>(req: Request) -> Result<T, Response> {
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024).await else {
        return Err((StatusCode::BAD_REQUEST, "body").into_response());
    };
    serde_urlencoded::from_bytes(&bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("form: {e}")).into_response())
}

/// Buffer the request body and parse it as JSON.
#[allow(clippy::result_large_err)]
async fn read_json<T: serde::de::DeserializeOwned>(req: Request) -> Result<T, Response> {
    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 256 * 1024).await else {
        return Err((StatusCode::BAD_REQUEST, "body").into_response());
    };
    serde_json::from_slice(&bytes).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("json: {e}")})),
        )
            .into_response()
    })
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

/// Very small `application/x-www-form-urlencoded`-style escape — used
/// only for redirect targets. We don't need a general urlencoder.
fn urlencode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            // Write into the buffer directly — saves the intermediate `format!`
            // allocation. `String` writes never fail.
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Tiny urldecode, paired with [`urlencode`]. Plain `+` → space, `%XX`
/// → byte. Errors decode to a `?`.
fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => out.push(((h << 4) | l) as u8),
                    _ => out.push(b'?'),
                }
                i += 3;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
