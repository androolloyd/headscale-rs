// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Headscale v0.29.5 browser errors, translated from httpUserError/AuthError.
//! The pinned elem-go v0.31.0 renderer sorts attributes and inline styles,
//! emits the HTML doctype, and preserves raw CSS/SVG bytes. Keep that layout
//! here while keeping technical errors separate from intentional user messages.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

const STYLE: &str = include_str!("error_style.css");
const LOGO: &str = include_str!("error_logo.svg");

const ERROR_ICON: &str = r#"<svg id="error-icon" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" style="flex-shrink:0">
  <circle cx="12" cy="12" r="10" fill="currentColor"/>
  <path d="M15 9l-6 6M9 9l6 6" stroke="var(--hs-error-bg, #fee2e2)" stroke-width="2" stroke-linecap="round"/>
</svg>"#;

fn heading(status: StatusCode) -> &'static str {
    // net/http retains these older reason phrases. The other pinned http
    // crate phrases agree with Go 1.26.9; unknown codes have an empty heading.
    match status.as_u16() {
        203 => "Non-Authoritative Information",
        413 => "Request Entity Too Large",
        414 => "Request URI Too Long",
        416 => "Requested Range Not Satisfiable",
        _ => status.canonical_reason().unwrap_or_default(),
    }
}

fn message(status: StatusCode) -> &'static str {
    match status.as_u16() {
        401 | 403 => "You are not authorized. Please contact your administrator.",
        410 => "Your session has expired. Please try again.",
        400..=499 => "The request could not be processed. Please try again.",
        _ => "Something went wrong. Please try again later.",
    }
}

pub(super) fn response(status: StatusCode) -> Response {
    response_with_message(status, "")
}

/// Render an intentional user-safe message, like upstream HTTPError.UserMsg.
/// An empty override falls back to the generic status message. The caller
/// retains technical error details for logging rather than page content.
pub(super) fn response_with_message(status: StatusCode, user_message: &str) -> Response {
    let mut html = String::with_capacity(STYLE.len() + LOGO.len() + 2_500);
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
    html.push_str(concat!(
        "</style><title>Headscale - Error</title></head>",
        r#"<body style="align-items: center; background-color: var(--hs-bg); display: flex; flex-direction: column; min-height: 100vh; padding: 3rem 1.5rem;" translate="no">"#,
        r#"<main class="md-typeset" style="max-width: min(800px, 90vw); width: 100%;">"#,
    ));
    html.push_str(LOGO);
    html.push_str(r#"<div aria-live="assertive" role="alert" style="align-items: center; background-color: var(--hs-error-bg); border: 1px solid var(--hs-error); border-radius: 0.5rem; display: flex; gap: 1rem; margin-bottom: 2rem; padding: 1.5rem;">"#);
    html.push_str(ERROR_ICON);
    html.push_str(r#"<div><strong style="color: var(--hs-error); display: block; font-size: 1.25em; font-weight: 700; margin-bottom: 0.25rem;">"#);
    text(&mut html, heading(status));
    html.push_str("</strong>");
    text(
        &mut html,
        if user_message.is_empty() {
            message(status)
        } else {
            user_message
        },
    );
    html.push_str(concat!(
        "</div></div>",
        r#"<footer style="color: var(--md-default-fg-color--light); font-size: 0.8em; line-height: 1.6; margin-top: 4rem; text-align: center;">Powered by "#,
        r#"<a href="https://github.com/juanfont/headscale" rel="noreferrer noopener" target="_blank">Headscale</a></footer>"#,
        "</main></body></html>",
    ));
    (
        status,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

/// elem-go TextNode escapes &, <, and >; quotation marks remain text.
fn text(html: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => html.push_str("&amp;"),
            '<' => html.push_str("&lt;"),
            '>' => html.push_str("&gt;"),
            _ => html.push(character),
        }
    }
}
