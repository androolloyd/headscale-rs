//! Maud-rendered HTML views for every admin page.
//!
//! All user-supplied strings are interpolated through the standard
//! maud `{}` placeholder, which auto-escapes — so machine names, user
//! names, hostnames, tags etc. cannot break out of the document. The
//! one place we use `PreEscaped` is for the embedded CSS / JS files
//! (`include_str!`-ed at build time so there's no XSS surface).
//!
//! ## Layout shape
//!
//! Every page goes through [`shell`], which renders:
//!
//! ```text
//!   <header>             OctraVPN admin / nav links / signed-in user
//!   <div class=layout>
//!     <aside>            Sidebar with section links
//!     <main>             Page-specific content (passed in by handler)
//!   </div>
//!   <footer>             Build + version
//! ```
//!
//! Tailscale-admin's vibe is "boring, dense table on the right, slim
//! sidebar on the left, nothing animates". We mirror that. No
//! JavaScript framework is loaded — only the ~1 KB `app.js` for
//! confirm-on-delete + input hints.

use maud::{DOCTYPE, Markup, PreEscaped, html};

use super::machines::MachineAdminRecord;
use super::preauth::{MAX_TTL_DAYS, PreauthAdminKey, key_prefix};
use super::users::UserRecord;

// Inline assets, embedded at build time. ~5 KB combined.
const CSS: &str = include_str!("../admin_static/style.css");
const JS: &str = include_str!("../admin_static/app.js");

/// Identifier for the currently-active top-nav section. Used to set
/// the `class=active` flag on the right link.
///
/// `Settings` + `None` aren't yet routed from any page (they're listed
/// in the spec deliverable for the follow-up Settings page); kept here
/// so the variant set anchors the eventual route without churn. The
/// `dead_code` allow is therefore deliberate.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Section {
    Dashboard,
    Machines,
    Users,
    PreauthKeys,
    Tailnet,
    Policy,
    Sessions,
    Settings,
    None,
}

/// Page-shell wrapper. Renders the DOCTYPE + head + chrome + the
/// page-specific `inner`. `csrf` is plumbed through to forms via the
/// `csrf_input` helper, but the shell itself doesn't render forms —
/// per-page bodies do.
/// `inner` is taken by value (not `&Markup`) because every caller
/// builds it inline via `html!{}` and there's no reuse — borrowing
/// would just add a temporary, and changing the shape would ripple
/// through every page handler in `admin/mod.rs`.
#[allow(clippy::needless_pass_by_value)]
pub fn shell(title: &str, section: Section, signed_in: bool, inner: Markup) -> Markup {
    let nav_link = |label: &str, href: &str, sec: Section| -> Markup {
        let active = sec == section;
        html! {
            a href=(href) class=@if active { "active" } @else { "" } { (label) }
        }
    };
    let side_link = |label: &str, href: &str, sec: Section| -> Markup {
        let active = sec == section;
        html! {
            a href=(href) class=@if active { "active" } @else { "" } { (label) }
        }
    };
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " — OctraVPN admin" }
                style { (PreEscaped(CSS)) }
            }
            body {
                header class="topbar" {
                    span class="brand" { "OctraVPN" }
                    nav {
                        (nav_link("Dashboard", "/admin/", Section::Dashboard))
                        (nav_link("Machines", "/admin/machines", Section::Machines))
                        (nav_link("Users", "/admin/users", Section::Users))
                        (nav_link("Keys", "/admin/preauthkeys", Section::PreauthKeys))
                        (nav_link("Tailnet", "/admin/tailnet", Section::Tailnet))
                        (nav_link("Policy", "/admin/policy", Section::Policy))
                        (nav_link("Sessions", "/admin/sessions", Section::Sessions))
                    }
                    @if signed_in {
                        span class="user" { "admin · " a href="/admin/logout" style="color:inherit" { "Sign out" } }
                    } @else {
                        span class="user" { a href="/admin/login" { "Sign in" } }
                    }
                }
                div class="layout" {
                    aside class="sidebar" {
                        h3 { "Manage" }
                        (side_link("Dashboard", "/admin/", Section::Dashboard))
                        (side_link("Machines", "/admin/machines", Section::Machines))
                        (side_link("Users", "/admin/users", Section::Users))
                        (side_link("Pre-auth keys", "/admin/preauthkeys", Section::PreauthKeys))
                        h3 { "Network" }
                        (side_link("Tailnet", "/admin/tailnet", Section::Tailnet))
                        (side_link("Access policy", "/admin/policy", Section::Policy))
                        h3 { "Activity" }
                        (side_link("Sessions", "/admin/sessions", Section::Sessions))
                    }
                    main class="content" {
                        (inner)
                    }
                }
                footer { "OctraVPN admin v0 · " a href="https://github.com/golast/octra" { "source" } }
                script { (PreEscaped(JS)) }
            }
        }
    }
}

/// Login page, standalone (no sidebar / nav links).
pub fn login_page(error: Option<&str>) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Sign in — OctraVPN admin" }
                style { (PreEscaped(CSS)) }
            }
            body {
                header class="topbar" {
                    span class="brand" { "OctraVPN" }
                    nav {}
                    span class="user" {}
                }
                div class="center" {
                    div class="card" {
                        h1 { "Sign in" }
                        p class="subtitle" { "Enter the bearer token configured in " code { "HEADSCALE_ADMIN_TOKEN" } "." }
                        @if let Some(msg) = error {
                            div class="flash error" { (msg) }
                        }
                        form method="post" action="/admin/login" {
                            div class="row" {
                                label for="token" { "Bearer token" }
                                input type="password" id="token" name="token" data-required="" autocomplete="off";
                                div class="hint" { "Same value as " code { "Authorization: Bearer …" } " on the API." }
                            }
                            button type="submit" { "Sign in" }
                        }
                    }
                }
                script { (PreEscaped(JS)) }
            }
        }
    }
}

/// Hidden CSRF input. Bearer-token callers don't have CSRF (no cookie)
/// so this is a no-op for them.
fn csrf_input(csrf: Option<&str>) -> Markup {
    html! {
        @if let Some(t) = csrf {
            input type="hidden" name="csrf" value=(t);
        }
    }
}

/// Dashboard page.
pub fn dashboard(
    machine_count: usize,
    online_count: usize,
    user_count: usize,
    preauth_live: usize,
) -> Markup {
    html! {
        h1 { "Dashboard" }
        p class="subtitle" { "OctraVPN admin — quick view of the running tailnet." }

        div class="stats" {
            div class="stat" {
                div class="num" { (online_count) }
                div class="label" { "Machines online" }
            }
            div class="stat" {
                div class="num" { (machine_count) }
                div class="label" { "Machines registered" }
            }
            div class="stat" {
                div class="num" { (user_count) }
                div class="label" { "Users" }
            }
            div class="stat" {
                div class="num" { (preauth_live) }
                div class="label" { "Active pre-auth keys" }
            }
        }

        div class="card" {
            h2 { "Get started" }
            ul {
                li { a href="/admin/users" { "Create a user" } " — represents a person or service account." }
                li { a href="/admin/preauthkeys" { "Mint a pre-auth key" } " — hand to a node to register without OIDC." }
                li { a href="/admin/machines" { "View registered machines" } " — see live tailnet members." }
            }
        }

        div class="card" {
            h2 { "Network health" }
            p { "Live attestation stream and per-machine NodeMetrics land in a follow-up PR. The current snapshot reflects the in-memory wire registry only." }
        }
    }
}

/// Machines list view.
pub fn machines_list(machines: &[MachineAdminRecord], csrf: Option<&str>) -> Markup {
    html! {
        h1 { "Machines" }
        p class="subtitle" { "Registered devices on the tailnet." }
        div class="card" {
            @if machines.is_empty() {
                div class="empty" {
                    "No machines registered yet."
                    div class="cta" {
                        a class="btn" href="/admin/preauthkeys" { "Mint a pre-auth key" }
                    }
                }
            } @else {
                table {
                    thead { tr {
                        th { "Name" }
                        th { "User" }
                        th { "IPv4" }
                        th { "Status" }
                        th { "Version" }
                        th { "Actions" }
                    } }
                    tbody {
                        @for m in machines {
                            tr {
                                td {
                                    a href={ "/admin/machines/" (m.id) } {
                                        @if m.name.is_empty() { (key_prefix(&m.id)) } @else { (m.name) }
                                    }
                                }
                                td { (m.user) }
                                td { code { (m.ipv4) } }
                                td {
                                    @if m.online {
                                        span class="pill ok" { "online" }
                                    } @else {
                                        span class="pill warn" { "expired" }
                                    }
                                }
                                td { (m.version) }
                                td {
                                    @if !m.expired {
                                        form method="post" action={ "/admin/machines/" (m.id) "/expire" } style="display:inline" {
                                            (csrf_input(csrf))
                                            button type="submit" class="ghost" { "Expire" }
                                        }
                                    }
                                    form method="post"
                                         action={ "/admin/machines/" (m.id) "/delete" }
                                         style="display:inline"
                                         data-confirm={ "Delete machine '" (m.name) "'? This is not reversible." } {
                                        (csrf_input(csrf))
                                        button type="submit" class="danger" { "Delete" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Per-machine detail.
pub fn machine_detail(m: &MachineAdminRecord, csrf: Option<&str>) -> Markup {
    html! {
        h1 {
            @if m.name.is_empty() { (key_prefix(&m.id)) } @else { (m.name) }
        }
        p class="subtitle" { "Machine details for " code { (m.id) } "." }
        div class="card" {
            h2 { "Identity" }
            table {
                tbody {
                    tr { th { "User" } td { (m.user) } }
                    tr { th { "Hostname" } td { (m.name) } }
                    tr { th { "IPv4" } td { code { (m.ipv4) } } }
                    tr { th { "Node key" } td { code { (m.id) } } }
                    tr { th { "Machine key" } td { code { (m.machine_key_hex) } } }
                    tr { th { "OS" } td { (m.os) } }
                    tr { th { "Version" } td { (m.version) } }
                    tr { th { "Status" } td {
                        @if m.online { span class="pill ok" { "online" } }
                        @else        { span class="pill warn" { "expired" } }
                    } }
                }
            }
        }
        div class="card" {
            h2 { "Tags & routes" }
            p { "Tags: "
                @if m.tags.is_empty() { span class="pill muted" { "[none]" } }
                @else {
                    @for t in &m.tags {
                        span class="pill" { (t) }
                        " "
                    }
                }
            }
            p { "Advertised routes: "
                @if m.routes.is_empty() { span class="pill muted" { "[none]" } }
                @else {
                    @for r in &m.routes { code { (r) } " " }
                }
            }
        }
        div class="card" {
            h2 { "Actions" }
            @if !m.expired {
                form method="post" action={ "/admin/machines/" (m.id) "/expire" } style="display:inline-block;margin-right:8px" {
                    (csrf_input(csrf))
                    button type="submit" class="ghost" { "Expire" }
                }
            }
            form method="post"
                 action={ "/admin/machines/" (m.id) "/delete" }
                 style="display:inline-block"
                 data-confirm={ "Delete machine '" (m.name) "'?" } {
                (csrf_input(csrf))
                button type="submit" class="danger" { "Delete" }
            }
            p style="margin-top:14px" {
                a href="/admin/machines" { "← Back to machines" }
            }
        }
    }
}

/// Users list + create form.
pub fn users_page(users: &[UserRecord], csrf: Option<&str>, flash: Option<&str>) -> Markup {
    html! {
        h1 { "Users" }
        p class="subtitle" { "People or service accounts that own machines + pre-auth keys." }
        @if let Some(msg) = flash {
            div class="flash error" { (msg) }
        }
        div class="card" {
            h2 { "Create user" }
            form method="post" action="/admin/users" {
                (csrf_input(csrf))
                div class="row" {
                    label for="name" { "User name" }
                    input type="text" id="name" name="name"
                          data-required=""
                          data-pattern="^[a-z0-9_-]{1,32}$"
                          autocomplete="off"
                          placeholder="alice";
                    div class="hint" { "Lower-case letters, digits, " code { "-" } " or " code { "_" } ". 1–32 chars." }
                }
                button type="submit" { "Create" }
            }
        }
        div class="card" {
            h2 { "Existing" }
            @if users.is_empty() {
                div class="empty" { "No users yet." }
            } @else {
                table {
                    thead { tr {
                        th { "Name" }
                        th { "Created" }
                        th { "Last activity" }
                        th { "Actions" }
                    } }
                    tbody {
                        @for u in users {
                            tr {
                                td { (u.name) }
                                td { (u.created_at) }
                                td { (u.last_activity) }
                                td {
                                    form method="post"
                                         action={ "/admin/users/" (u.name) "/delete" }
                                         data-confirm={ "Delete user '" (u.name) "'?" }
                                         style="display:inline" {
                                        (csrf_input(csrf))
                                        button type="submit" class="danger" { "Delete" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Pre-auth keys list + create form + optional "key minted" flash.
pub fn preauthkeys_page(
    keys: &[PreauthAdminKey],
    csrf: Option<&str>,
    just_minted: Option<&PreauthAdminKey>,
    error: Option<&str>,
) -> Markup {
    html! {
        h1 { "Pre-auth keys" }
        p class="subtitle" { "Bearer tokens a Tailscale-style client redeems on first register." }

        @if let Some(k) = just_minted {
            div class="flash ok" {
                "Key minted for user " strong { (k.user) } ". Copy it now — the full value will not be shown again."
                pre { code { (k.key) } }
            }
        }
        @if let Some(e) = error {
            div class="flash error" { (e) }
        }

        div class="card" {
            h2 { "Mint key" }
            form method="post" action="/admin/preauthkeys" {
                (csrf_input(csrf))
                div class="row" {
                    label for="user" { "User" }
                    input type="text" id="user" name="user" data-required=""
                          data-pattern="^[a-z0-9_-]{1,32}$"
                          autocomplete="off";
                }
                div class="row" {
                    label for="ttl_days" { "Validity (days)" }
                    input type="number" id="ttl_days" name="ttl_days" value="1" min="1" max=(MAX_TTL_DAYS);
                    div class="hint" { "Capped at " (MAX_TTL_DAYS) " days." }
                }
                div class="row check" {
                    input type="checkbox" id="reusable" name="reusable" value="1";
                    label for="reusable" { "Reusable (multiple devices may redeem)" }
                }
                div class="row check" {
                    input type="checkbox" id="ephemeral" name="ephemeral" value="1";
                    label for="ephemeral" { "Ephemeral (auto-clean on disconnect)" }
                }
                div class="row" {
                    label for="tags" { "Tags" }
                    input type="text" id="tags" name="tags" placeholder="tag:dev,tag:ci";
                    div class="hint" { "Comma-separated. Optional in v0 — full ACL binding lands later." }
                }
                button type="submit" { "Mint" }
            }
        }

        div class="card" {
            h2 { "Live keys" }
            @if keys.is_empty() {
                div class="empty" { "No keys minted." }
            } @else {
                table {
                    thead { tr {
                        th { "Key" }
                        th { "User" }
                        th { "Reusable" }
                        th { "Ephemeral" }
                        th { "Tags" }
                        th { "Expires" }
                        th { "Used" }
                        th { "" }
                    } }
                    tbody {
                        @for k in keys {
                            tr {
                                td { code { (key_prefix(&k.key)) } }
                                td { (k.user) }
                                td { @if k.reusable { "yes" } @else { "no" } }
                                td { @if k.ephemeral { "yes" } @else { "no" } }
                                td {
                                    @if k.tags.is_empty() { span class="muted" { "—" } }
                                    @else {
                                        @for t in &k.tags { span class="pill" { (t) } " " }
                                    }
                                }
                                td { (k.expires_at) }
                                td { (k.redemptions) }
                                td {
                                    form method="post"
                                         action={ "/admin/preauthkeys/" (key_prefix(&k.key).trim_end_matches('…')) "/expire" }
                                         data-confirm="Expire this key now?"
                                         style="display:inline" {
                                        (csrf_input(csrf))
                                        button type="submit" class="ghost" { "Expire" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Read-only tailnet view (DERP + DNS + ACL placeholders).
pub fn tailnet_page(derp_region_count: usize) -> Markup {
    html! {
        h1 { "Tailnet" }
        p class="subtitle" { "Network-wide settings. Read-only in v0." }
        div class="card" {
            h2 { "DERP" }
            p { "Relay map regions configured: " strong { (derp_region_count) } "." }
            p class="subtitle" { "Configured via " code { "OCTRAVPN_DERP_MAP_PATH" } " at node startup. Live region editing arrives with the live tailnet view." }
        }
        div class="card" {
            h2 { "DNS" }
            p class="subtitle" { "MagicDNS / split-DNS configuration is a stub in v0 — the wire layer doesn't emit DNSConfig today." }
        }
        div class="card" {
            h2 { "Access policy" }
            p { a href="/admin/policy" { "→ View policy" } }
        }
    }
}

/// Read-only policy view.
pub fn policy_page(loaded: bool) -> Markup {
    html! {
        h1 { "Access policy" }
        p class="subtitle" { "HuJSON ACL policy — read-only in v0. The full editor + apply-preview ships in #230." }
        div class="card" {
            @if loaded {
                pre { "// policy not yet wired into the admin panel." }
            } @else {
                p { "No policy currently loaded — the embedding host has not registered one with the admin module." }
            }
        }
    }
}

/// Sessions placeholder.
pub fn sessions_page() -> Markup {
    html! {
        h1 { "Sessions" }
        p class="subtitle" { "Recent client sessions. Live analytics ship in #231 — this is a placeholder." }
        div class="card" {
            div class="empty" { "No sessions to display yet." }
        }
    }
}

/// Generic error page (404 / 5xx surface for the HTML routes).
pub fn error_page(code: u16, msg: &str) -> Markup {
    html! {
        h1 { (code) " — " (msg) }
        p { a href="/admin/" { "← Back to dashboard" } }
    }
}
