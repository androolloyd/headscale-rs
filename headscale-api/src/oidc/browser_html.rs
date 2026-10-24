// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Source-derived Headscale v0.29.5 registration and authentication pages.
//! Attribute/style order follows the pinned elem-go v0.31.0 renderer.

const STYLE: &str = include_str!("error_style.css");
const LOGO: &str = include_str!("error_logo.svg");

const SUCCESS_ICON: &str = r#"<svg id="checkbox" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 512 512" style="flex-shrink:0">
  <path fill="currentColor" d="M256 32C132.3 32 32 132.3 32 256s100.3 224 224 224 224-100.3 224-224S379.7 32 256 32zm114.9 149.1L231.8 359.6c-1.1 1.1-2.9 3.5-5.1 3.5-2.3 0-3.8-1.6-5.1-2.9-1.3-1.3-78.9-75.9-78.9-75.9l-1.5-1.5c-.6-.9-1.1-2-1.1-3.2 0-1.2.5-2.3 1.1-3.2.4-.4.7-.7 1.1-1.2 7.7-8.1 23.3-24.5 24.3-25.5 1.3-1.3 2.4-3 4.8-3 2.5 0 4.1 2.1 5.3 3.3 1.2 1.2 45 43.3 45 43.3l111.3-143c1-.8 2.2-1.4 3.5-1.4 1.3 0 2.5.5 3.5 1.3l30.6 24.1c.8 1 1.3 2.2 1.3 3.5.1 1.3-.4 2.4-1 3.3z"></path>
</svg>"#;

fn text(html: &mut String, value: &str) {
    // elem-go TextNode escapes only &, <, and >, retaining quotation marks.
    for character in value.chars() {
        match character {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            _ => html.push(character),
        }
    }
}

fn start(title: &str) -> String {
    let mut html = String::with_capacity(STYLE.len() + LOGO.len() + 4_000);
    html.push_str(concat!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">"#,
        r#"<meta content="IE=edge" http-equiv="X-UA-Compatible">"#,
        r#"<meta content="width=device-width, initial-scale=1.0" name="viewport">"#,
        r#"<link href="/favicon.ico" rel="icon">"#,
        r#"<link crossorigin="" href="https://fonts.gstatic.com" rel="preconnect">"#,
        r#"<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">"#,
        r#"<style type="text/css">"#,
    ));
    html.push_str(STYLE);
    html.push_str("</style><title>");
    text(&mut html, title);
    html.push_str(concat!(
        "</title></head>",
        r#"<body style="align-items: center; background-color: var(--hs-bg); display: flex; flex-direction: column; min-height: 100vh; padding: 3rem 1.5rem;" translate="no">"#,
        r#"<main class="md-typeset" style="max-width: min(800px, 90vw); width: 100%;">"#,
    ));
    html.push_str(LOGO);
    html
}

fn finish(mut html: String) -> String {
    html.push_str(concat!(
        r#"<footer style="color: var(--md-default-fg-color--light); font-size: 0.8em; line-height: 1.6; margin-top: 4rem; text-align: center;">Powered by "#,
        r#"<a href="https://github.com/juanfont/headscale" rel="noreferrer noopener" target="_blank">Headscale</a></footer>"#,
        "</main></body></html>",
    ));
    html
}

/// Device/user strings are escaped as text. Attribute values remain escaped
/// even for custom runtimes or malformed IDs: native length/prefix validation
/// does not establish that a value is safe inside a quoted HTML attribute.
pub(super) fn register_confirm(
    user: &str,
    hostname: &str,
    os: &str,
    machine_key: &str,
    form_action: &str,
    csrf_name: &str,
    csrf_value: &str,
) -> String {
    let mut html = start("Headscale - Confirm node registration");
    html.push_str(concat!(
        "<h2>Confirm node registration</h2>",
        "<p>A device is asking to be added to your tailnet. Please review the details below and confirm that this device is yours.</p>",
        r#"<table style="border-collapse: collapse; margin-bottom: 1.5em; margin-top: 1em; width: 100%;">"#,
    ));
    for (name, value) in [
        ("Hostname", hostname),
        ("OS", if os.is_empty() { "(unknown)" } else { os }),
        ("Machine key", machine_key),
        ("Registered to", user),
    ] {
        html.push_str(r#"<tr><td style="border-bottom: 1px solid var(--hs-border); color: var(--md-default-fg-color--light); font-weight: 600; padding: 0.5rem 1rem 0.5rem 0; white-space: nowrap;">"#);
        text(&mut html, name);
        html.push_str(
            r#"</td><td style="border-bottom: 1px solid var(--hs-border); padding: 0.5rem 0;">"#,
        );
        if name == "Machine key" {
            html.push_str("<code>");
        }
        text(&mut html, value);
        if name == "Machine key" {
            html.push_str("</code>");
        }
        html.push_str("</td></tr>");
    }
    html.push_str(r#"</table><form action=""#);
    html.push_str(&super::html_escape(form_action));
    html.push_str(r#"" method="POST"><input name=""#);
    html.push_str(&super::html_escape(csrf_name));
    html.push_str(r#"" type="hidden" value=""#);
    html.push_str(&super::html_escape(csrf_value));
    html.push_str(concat!(
        r#""><button type="submit">Confirm registration</button></form>"#,
        "<p>If you do not recognise this device, close this window. The registration request will expire automatically.</p>",
    ));
    finish(html)
}

/// AuthSuccess is shared by registration, reauthentication, and SSH checks.
/// Every supplied result field is rendered through elem-go's text rules.
pub(super) fn auth_success(
    title: &str,
    heading: &str,
    verb: &str,
    user: &str,
    message: &str,
) -> String {
    let mut html = start(title);
    html.push_str(r#"<div aria-live="polite" role="status" style="align-items: center; background-color: var(--hs-success-bg); border: 1px solid var(--hs-success); border-radius: 0.5rem; display: flex; gap: 1rem; margin-bottom: 2rem; padding: 1.5rem;">"#);
    html.push_str(SUCCESS_ICON);
    html.push_str(r#"<div><strong style="color: var(--hs-success); display: block; font-size: 1.25em; font-weight: 700; margin-bottom: 0.25rem;">"#);
    text(&mut html, heading);
    html.push_str("</strong>");
    text(&mut html, verb);
    html.push_str(" as <strong>");
    text(&mut html, user);
    html.push_str("</strong>. ");
    text(&mut html, message);
    html.push_str(concat!(
        "</div></div><h2>Getting started</h2>",
        "<p>Check out the documentation to learn more about headscale and Tailscale:</p><ul>",
        r#"<li><a href="https://headscale.net/stable/" rel="noreferrer noopener" target="_blank">Headscale documentation</a></li>"#,
        r#"<li><a href="https://tailscale.com/docs" rel="noreferrer noopener" target="_blank">Tailscale docs</a></li></ul>"#,
    ));
    finish(html)
}
