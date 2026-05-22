//! HTTP client wrapper around the admin `/api/v1/*` surface.
//!
//! Legacy admin HTTP command groups route through [`AdminClient`]. Two things
//! live here that the per-subcommand modules don't want to repeat:
//!
//! 1. **URL composition.** All endpoints sit under `/api/v1/...` of a
//!    base URL the operator hands in via `--server` or
//!    `$HEADSCALE_URL`. The base may carry a trailing slash; we strip
//!    it once at construction so the rest of the code can just
//!    `format!("{base}/api/v1/users")`.
//! 2. **Auth + exit-code mapping.** The admin surface answers with
//!    `401` on bad bearer tokens, `404` on missing entities and `5xx`
//!    on server faults. The CLI promises a fixed exit-code contract
//!    (see `ExitCode` in [`crate::admin`]); we centralise the
//!    mapping in `send_and_check` so each subcommand only writes its
//!    happy-path JSON decode.

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::AdminError;

/// Connection + auth handle for the admin HTTP surface.
#[derive(Debug, Clone)]
pub struct AdminClient {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl AdminClient {
    /// Build a client. `base` is the operator's admin URL (e.g.
    /// `http://127.0.0.1:51822`); a trailing `/` is tolerated. `token`
    /// is the bearer secret the admin handler validates against.
    pub fn new(base: impl Into<String>, token: impl Into<String>) -> Self {
        let mut base = base.into();
        while base.ends_with('/') {
            base.pop();
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("headscale-cli/", env!("CARGO_PKG_VERSION")))
            // Operators run the admin surface on localhost most of the
            // time; a 10s ceiling is generous for that path and still
            // catches a hung remote.
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client builds with the static config above");
        Self {
            base,
            token: token.into(),
            http,
        }
    }

    /// Compose `<base>/api/v1/<path>`. `path` is taken verbatim — the
    /// caller is responsible for URL-encoding its components (the
    /// admin surface only routes on bare names today and the routes
    /// are simple enough that the per-command call sites encode their
    /// own segments if needed).
    pub fn url(&self, path: &str) -> String {
        debug_assert!(path.starts_with('/'), "admin paths must lead with '/'");
        format!("{}/api/v1{}", self.base, path)
    }

    /// `GET /api/v1<path>` → JSON body decoded as `T`.
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, AdminError> {
        let resp = self
            .http
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| map_send_err(&e))?;
        let resp = check_status(resp).await?;
        resp.json::<T>()
            .await
            .map_err(|e| AdminError::Decode(e.to_string()))
    }

    /// `POST /api/v1<path>` carrying a JSON body. Returns the decoded
    /// JSON response, or — for the `204 No Content` shape — calls
    /// [`AdminClient::post_no_content`] instead.
    pub async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, AdminError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| map_send_err(&e))?;
        let resp = check_status(resp).await?;
        resp.json::<T>()
            .await
            .map_err(|e| AdminError::Decode(e.to_string()))
    }

    /// `POST /api/v1<path>` expecting `204 No Content`. The body, if
    /// any, is drained and discarded.
    pub async fn post_no_content(&self, path: &str) -> Result<(), AdminError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| map_send_err(&e))?;
        check_status(resp).await?;
        Ok(())
    }

    /// `POST /api/v1<path>` carrying a JSON body and expecting
    /// `204 No Content`.
    pub async fn post_json_no_content<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(), AdminError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| map_send_err(&e))?;
        check_status(resp).await?;
        Ok(())
    }

    /// `PUT /api/v1<path>` carrying a raw string body (the policy
    /// endpoint accepts hujson; we never re-encode).
    pub async fn put_text(
        &self,
        path: &str,
        body: String,
    ) -> Result<serde_json::Value, AdminError> {
        let resp = self
            .http
            .put(self.url(path))
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| map_send_err(&e))?;
        let resp = check_status(resp).await?;
        // Admin returns `{applied, note}` on success — fall back to a
        // Null value if the response is empty (the `204 No Content`
        // future path).
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| AdminError::Decode(e.to_string()))?;
        if bytes.is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            serde_json::from_slice(&bytes).map_err(|e| AdminError::Decode(e.to_string()))
        }
    }

    /// `DELETE /api/v1<path>` expecting `204 No Content`.
    pub async fn delete_no_content(&self, path: &str) -> Result<(), AdminError> {
        let resp = self
            .http
            .delete(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| map_send_err(&e))?;
        check_status(resp).await?;
        Ok(())
    }

    /// `DELETE /api/v1<path>` carrying a JSON body and expecting
    /// `204 No Content`.
    pub async fn delete_json_no_content<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(), AdminError> {
        let resp = self
            .http
            .delete(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| map_send_err(&e))?;
        check_status(resp).await?;
        Ok(())
    }
}

/// Map a reqwest send-time failure (DNS / TCP / TLS) onto our
/// `Connection` variant. Decoded HTTP responses are handled by
/// [`check_status`].
fn map_send_err(e: &reqwest::Error) -> AdminError {
    AdminError::Connection(e.to_string())
}

/// Convert a non-2xx response into the matching [`AdminError`]
/// variant. The error body, if present, is captured verbatim for the
/// CLI to display.
async fn check_status(resp: reqwest::Response) -> Result<reqwest::Response, AdminError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    Err(match status.as_u16() {
        401 | 403 => AdminError::Auth(body),
        404 => AdminError::NotFound(body),
        400..=499 => AdminError::BadRequest {
            status: status.as_u16(),
            body,
        },
        // 5xx + any other unmapped status fall through to Server.
        _ => AdminError::Server {
            status: status.as_u16(),
            body,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_strips_trailing_slash() {
        let c = AdminClient::new("http://localhost:51822/", "tok");
        assert_eq!(c.url("/users"), "http://localhost:51822/api/v1/users");
        let c = AdminClient::new("http://localhost:51822///", "tok");
        assert_eq!(c.url("/users"), "http://localhost:51822/api/v1/users");
    }

    #[test]
    fn url_no_trailing_slash() {
        let c = AdminClient::new("http://localhost:51822", "tok");
        assert_eq!(
            c.url("/preauthkeys"),
            "http://localhost:51822/api/v1/preauthkeys"
        );
    }

    #[test]
    fn url_keeps_path_segments() {
        let c = AdminClient::new("http://example.com", "tok");
        assert_eq!(
            c.url("/users/alice"),
            "http://example.com/api/v1/users/alice"
        );
    }
}
