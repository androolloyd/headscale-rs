// Copyright (c) 2015-present Peter Kieltyka (https://github.com/pkieltyka),
// Google Inc. and contributors.
// Copyright 2009 The Go Authors. All rights reserved.
// chi v5.4.0 method admission and Go 1.26.9 net/http NotFound semantics;
// retained terms are in LICENSE-GO-CHI and LICENSE-GO-STDLIB.
//! Native chi method admission. Embedding routers keep Axum's implicit HEAD
//! fallback; native GET routes must reject it before invoking a GET handler.

use axum::{
    body::Body,
    extract::{MatchedPath, Request},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub(super) async fn admit(request: Request, next: Next) -> Response {
    let method = request.method().as_str();
    // chi's methodMap is checked before the routing path. HandleFunc accepts
    // every registered method, including QUERY, but not arbitrary method tokens.
    if !registered_method(method) {
        return method_not_allowed(&[]);
    }
    let allowed: &[&'static str] = match request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
    {
        Some("/ts2021" | "/register/confirm/:auth_id") => &["GET", "POST"],
        Some("/verify") => &["POST"],
        Some("/machine/ping-response") => &["HEAD"],
        Some(
            "/"
            | "/robots.txt"
            | "/health"
            | "/version"
            | "/windows"
            | "/apple"
            | "/apple/:platform"
            | "/swagger"
            | "/swagger/v1/openapiv2.json"
            | "/favicon.ico"
            | "/key"
            | "/register/:registration_id"
            | "/auth/:auth_id"
            | "/oidc/callback",
        ) => &["GET"],
        // DERP and bootstrap are HandleFunc routes. A route not mounted in
        // this configuration has no MatchedPath and reaches the 404 fallback.
        _ => return next.run(request).await,
    };
    if allowed.contains(&method) {
        next.run(request).await
    } else {
        method_not_allowed(allowed)
    }
}

fn registered_method(method: &str) -> bool {
    matches!(
        method,
        "CONNECT"
            | "DELETE"
            | "GET"
            | "HEAD"
            | "OPTIONS"
            | "PATCH"
            | "POST"
            | "PUT"
            | "QUERY"
            | "TRACE"
    )
}

pub(super) async fn finalize(request: Request, next: Next) -> Response {
    let unregistered = !registered_method(request.method().as_str());
    let mut response = next.run(request).await;
    // MethodRouter synthesizes Allow after its route-layer middleware.
    // The outer service wrapper removes it for chi's unsupported-method
    // branch, which rejects before route matching and has no Allow values.
    if unregistered {
        response.headers_mut().remove(header::ALLOW);
    }
    response
}

fn method_not_allowed(allowed: &[&'static str]) -> Response {
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    for method in allowed {
        // chi uses Header.Add, preserving distinct values. Its map traversal
        // makes their relative order unspecified when several methods exist.
        response
            .headers_mut()
            .append(header::ALLOW, HeaderValue::from_static(method));
    }
    response
}

pub(super) async fn not_found(request: Request) -> Response {
    const MESSAGE: &str = "404 page not found\n";
    let is_head = request.method() == Method::HEAD;
    let mut response = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(if is_head {
            Body::empty()
        } else {
            Body::from(MESSAGE)
        })
        .expect("static native 404 response is valid");
    if is_head {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("19"));
    }
    response
}
