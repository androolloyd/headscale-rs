use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use headscale_api::tailscale_wire::acme::AcmeHttp01ChallengeStore;
use headscale_api::tailscale_wire::tls::{self, ReloadableServerConfig};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const ACCOUNT_CACHE_SUFFIX: &str = "instant-acme-account.json";
const ORDER_POLL_TIMEOUT: Duration = Duration::from_secs(90);
const CERTIFICATE_POLL_TIMEOUT: Duration = Duration::from_secs(90);
const CERTIFICATE_RENEWAL_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;
const CERTIFICATE_RENEWAL_CHECK_MIN: Duration = Duration::from_secs(30 * 60);
const CERTIFICATE_RENEWAL_CHECK_MAX: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone)]
pub(crate) struct AcmeHttp01IssuerConfig {
    pub directory_url: String,
    pub email: Option<String>,
    pub hostname: String,
    pub cache_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcmeHttp01CertificateOutcome {
    pub cache_path: PathBuf,
    pub issued: bool,
}

#[derive(Clone)]
pub(crate) struct AcmeTlsReloaders {
    pub public_tls: ReloadableServerConfig,
    pub remote_grpc_tls: Option<ReloadableServerConfig>,
}

pub(crate) async fn ensure_http01_certificate(
    config: &AcmeHttp01IssuerConfig,
    store: &AcmeHttp01ChallengeStore,
) -> Result<AcmeHttp01CertificateOutcome> {
    let cache_path = autocert_cache_path(&config.cache_dir, &config.hostname);
    match tls::load_from_autocert_cache(&config.cache_dir, &config.hostname) {
        Ok(material) if !certificate_is_expired(material.expires_at, Utc::now()) => {
            return Ok(AcmeHttp01CertificateOutcome {
                cache_path,
                issued: false,
            });
        }
        Ok(material) => {
            tracing::info!(
                hostname = %config.hostname,
                expires_at = %material.expires_at,
                "ACME HTTP-01 cached certificate is expired; starting online issuance"
            );
        }
        Err(err) => {
            tracing::info!(
                hostname = %config.hostname,
                cache_dir = %config.cache_dir.display(),
                error = %err,
                "ACME HTTP-01 cached certificate missing or invalid; starting online issuance"
            );
        }
    }

    tracing::info!(
        hostname = %config.hostname,
        cache_dir = %config.cache_dir.display(),
        directory_url = %config.directory_url,
        "ACME HTTP-01 online issuance started"
    );
    let (key_pem, certificate_pem) = issue_http01_certificate(config, store).await?;
    write_autocert_cache_entry(
        &config.cache_dir,
        &config.hostname,
        &key_pem,
        &certificate_pem,
    )
    .with_context(|| {
        format!(
            "write ACME cache entry {} for hostname {}",
            cache_path.display(),
            config.hostname
        )
    })?;
    tls::load_from_autocert_cache(&config.cache_dir, &config.hostname).with_context(|| {
        format!(
            "validate ACME cache entry {} after online issuance",
            cache_path.display()
        )
    })?;
    Ok(AcmeHttp01CertificateOutcome {
        cache_path,
        issued: true,
    })
}

pub(crate) fn spawn_http01_renewal_task(
    config: AcmeHttp01IssuerConfig,
    store: AcmeHttp01ChallengeStore,
    reloaders: AcmeTlsReloaders,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            hostname = %config.hostname,
            cache_dir = %config.cache_dir.display(),
            "ACME HTTP-01 live renewal and TLS reload task started"
        );
        loop {
            match renew_http01_certificate_once(&config, &store, &reloaders).await {
                Ok(outcome) if outcome.issued => {
                    tracing::info!(
                        path = %outcome.cache_path.display(),
                        hostname = %config.hostname,
                        "ACME HTTP-01 certificate renewed and TLS configs reloaded"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(
                        error = ?err,
                        hostname = %config.hostname,
                        "ACME HTTP-01 renewal failed; keeping existing TLS material"
                    );
                }
            }

            let expires_at = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname)
                .ok()
                .map(|material| material.expires_at);
            tokio::time::sleep(next_renewal_check_delay(expires_at, Utc::now())).await;
        }
    })
}

pub(crate) async fn renew_http01_certificate_once(
    config: &AcmeHttp01IssuerConfig,
    store: &AcmeHttp01ChallengeStore,
    reloaders: &AcmeTlsReloaders,
) -> Result<AcmeHttp01CertificateOutcome> {
    let cache_path = autocert_cache_path(&config.cache_dir, &config.hostname);
    let Ok(material) = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname) else {
        let outcome = ensure_http01_certificate(config, store).await?;
        if outcome.issued {
            reload_acme_tls_material(config, reloaders)?;
        }
        return Ok(outcome);
    };

    if !certificate_renewal_due(material.expires_at, Utc::now()) {
        return Ok(AcmeHttp01CertificateOutcome {
            cache_path,
            issued: false,
        });
    }

    tracing::info!(
        hostname = %config.hostname,
        expires_at = %material.expires_at,
        "ACME HTTP-01 cached certificate reached renewal window; starting online renewal"
    );
    let (key_pem, certificate_pem) = issue_http01_certificate(config, store).await?;
    write_autocert_cache_entry(
        &config.cache_dir,
        &config.hostname,
        &key_pem,
        &certificate_pem,
    )
    .with_context(|| {
        format!(
            "write renewed ACME cache entry {} for hostname {}",
            cache_path.display(),
            config.hostname
        )
    })?;
    reload_acme_tls_material(config, reloaders)?;
    Ok(AcmeHttp01CertificateOutcome {
        cache_path,
        issued: true,
    })
}

fn reload_acme_tls_material(
    config: &AcmeHttp01IssuerConfig,
    reloaders: &AcmeTlsReloaders,
) -> Result<tls::TlsMaterial> {
    let material = tls::load_from_autocert_cache(&config.cache_dir, &config.hostname)
        .with_context(|| {
            format!(
                "load renewed ACME cache entry for hostname {} from {}",
                config.hostname,
                config.cache_dir.display()
            )
        })?;
    reloaders
        .public_tls
        .replace(Arc::clone(&material.server_config));
    if let Some(remote_grpc_tls) = &reloaders.remote_grpc_tls {
        let grpc_tls = tls::build_grpc_server_config(&material.cert_pem, &material.key_pem)
            .context("build renewed remote gRPC TLS config")?;
        remote_grpc_tls.replace(Arc::new(grpc_tls));
    }
    Ok(material)
}

fn certificate_is_expired(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at <= now
}

fn certificate_renewal_due(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    expires_at <= now + chrono::Duration::seconds(CERTIFICATE_RENEWAL_WINDOW_SECS)
}

fn next_renewal_check_delay(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Duration {
    let Some(expires_at) = expires_at else {
        return CERTIFICATE_RENEWAL_CHECK_MIN;
    };
    let renewal_at = expires_at - chrono::Duration::seconds(CERTIFICATE_RENEWAL_WINDOW_SECS);
    let seconds_until_renewal = (renewal_at - now).num_seconds();
    if seconds_until_renewal <= 0 {
        return CERTIFICATE_RENEWAL_CHECK_MIN;
    }

    let candidate = Duration::from_secs(seconds_until_renewal as u64);
    candidate.clamp(CERTIFICATE_RENEWAL_CHECK_MIN, CERTIFICATE_RENEWAL_CHECK_MAX)
}

async fn issue_http01_certificate(
    config: &AcmeHttp01IssuerConfig,
    store: &AcmeHttp01ChallengeStore,
) -> Result<(String, String)> {
    let account = load_or_create_account(config).await?;
    let identifiers = [Identifier::Dns(config.hostname.clone())];
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .with_context(|| format!("create ACME order for {}", config.hostname))?;
    let mut cleanup = ChallengeCleanup::new(store.clone());

    {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization
                .with_context(|| format!("fetch ACME authorization for {}", config.hostname))?;
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            if authorization.status != AuthorizationStatus::Pending {
                bail!(
                    "ACME authorization for {} is {:?}, expected pending or valid",
                    config.hostname,
                    authorization.status
                );
            }

            let mut challenge =
                authorization
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| {
                        anyhow::anyhow!("ACME server did not offer HTTP-01 for {}", config.hostname)
                    })?;
            let token = challenge.token.clone();
            if token.is_empty() {
                bail!(
                    "ACME HTTP-01 challenge for {} did not include a token",
                    config.hostname
                );
            }
            let key_authorization = challenge.key_authorization().as_str().to_string();
            store.insert(token.clone(), key_authorization);
            cleanup.track(token);
            challenge.set_ready().await.with_context(|| {
                format!("mark ACME HTTP-01 challenge ready for {}", config.hostname)
            })?;
        }
    }

    match order
        .poll_ready(&RetryPolicy::new().timeout(ORDER_POLL_TIMEOUT))
        .await
        .with_context(|| format!("wait for ACME order readiness for {}", config.hostname))?
    {
        OrderStatus::Ready | OrderStatus::Valid => {}
        status => bail!(
            "ACME order for {} reached {:?}, expected ready",
            config.hostname,
            status
        ),
    }

    let key_pem = order
        .finalize()
        .await
        .with_context(|| format!("finalize ACME order for {}", config.hostname))?;
    let certificate_pem = order
        .poll_certificate(&RetryPolicy::new().timeout(CERTIFICATE_POLL_TIMEOUT))
        .await
        .with_context(|| format!("retrieve ACME certificate for {}", config.hostname))?;
    Ok((key_pem, certificate_pem))
}

async fn load_or_create_account(config: &AcmeHttp01IssuerConfig) -> Result<Account> {
    let account_path =
        account_cache_path(&config.cache_dir, &config.hostname, &config.directory_url);
    if let Ok(bytes) = fs::read(&account_path) {
        match serde_json::from_slice::<AccountCredentials>(&bytes) {
            Ok(credentials) => match Account::builder()
                .context("build ACME HTTP client")?
                .from_credentials(credentials)
                .await
            {
                Ok(account) => return Ok(account),
                Err(err) => {
                    tracing::warn!(
                        path = %account_path.display(),
                        error = %err,
                        "failed to restore cached ACME account credentials; creating a new account"
                    );
                }
            },
            Err(err) => {
                tracing::warn!(
                    path = %account_path.display(),
                    error = %err,
                    "failed to parse cached ACME account credentials; creating a new account"
                );
            }
        }
    }

    let contact = config.email.as_deref().and_then(acme_contact_uri);
    let contacts = contact.iter().map(String::as_str).collect::<Vec<_>>();
    let new_account = NewAccount {
        contact: &contacts,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, credentials) = Account::builder()
        .context("build ACME HTTP client")?
        .create(&new_account, config.directory_url.clone(), None)
        .await
        .with_context(|| format!("create ACME account at {}", config.directory_url))?;
    write_json_atomically(&account_path, &credentials).with_context(|| {
        format!(
            "write ACME account credentials cache {}",
            account_path.display()
        )
    })?;
    Ok(account)
}

fn acme_contact_uri(email: &str) -> Option<String> {
    let email = email.trim();
    if email.is_empty() {
        None
    } else if email.contains(':') {
        Some(email.to_string())
    } else {
        Some(format!("mailto:{email}"))
    }
}

fn write_autocert_cache_entry(
    cache_dir: &Path,
    hostname: &str,
    key_pem: &str,
    certificate_pem: &str,
) -> Result<()> {
    let cache_path = autocert_cache_path(cache_dir, hostname);
    let mut combined = String::with_capacity(key_pem.len() + certificate_pem.len() + 1);
    combined.push_str(key_pem.trim_end());
    combined.push('\n');
    combined.push_str(certificate_pem.trim_start());
    write_bytes_atomically(&cache_path, combined.as_bytes())
}

fn write_json_atomically<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes_atomically(path, &bytes)
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create cache directory {}", parent.display()))?;
    }
    let tmp_path = path.with_extension(format!("tmp-{:016x}", OsRng.next_u64()));
    {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| format!("create temporary cache file {}", tmp_path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write temporary cache file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync temporary cache file {}", tmp_path.display()))?;
    }
    #[cfg(unix)]
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod temporary cache file {}", tmp_path.display()))?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "rename temporary cache file {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn autocert_cache_path(cache_dir: &Path, hostname: &str) -> PathBuf {
    cache_dir.join(clean_autocert_name(hostname))
}

fn account_cache_path(cache_dir: &Path, hostname: &str, directory_url: &str) -> PathBuf {
    let digest = Sha256::digest(directory_url.as_bytes());
    let directory_hash = hex::encode(&digest[..8]);
    cache_dir.join(format!(
        "{}.{directory_hash}.{ACCOUNT_CACHE_SUFFIX}",
        clean_autocert_name(hostname)
    ))
}

fn clean_autocert_name(name: &str) -> String {
    let clean = name
        .trim()
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty() && *part != "." && *part != "..")
        .collect::<Vec<_>>()
        .join("/");
    if clean.is_empty() {
        "acme-empty-hostname".to_string()
    } else {
        clean
    }
}

struct ChallengeCleanup {
    store: AcmeHttp01ChallengeStore,
    tokens: Vec<String>,
}

impl ChallengeCleanup {
    fn new(store: AcmeHttp01ChallengeStore) -> Self {
        Self {
            store,
            tokens: Vec::new(),
        }
    }

    fn track(&mut self, token: String) {
        self.tokens.push(token);
    }
}

impl Drop for ChallengeCleanup {
    fn drop(&mut self) {
        for token in &self.tokens {
            self.store.remove(token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn acme_contact_uri_wraps_plain_email() {
        assert_eq!(
            acme_contact_uri("ops@example.com").as_deref(),
            Some("mailto:ops@example.com")
        );
        assert_eq!(
            acme_contact_uri("mailto:ops@example.com").as_deref(),
            Some("mailto:ops@example.com")
        );
        assert_eq!(acme_contact_uri("   "), None);
    }

    #[test]
    fn account_cache_path_depends_on_directory_url() {
        let cache_dir = Path::new("/tmp/acme");
        let production = account_cache_path(
            cache_dir,
            "headscale.example",
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        let staging = account_cache_path(
            cache_dir,
            "headscale.example",
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        );

        assert_ne!(production, staging);
        assert!(production.starts_with(cache_dir));
        assert!(
            production
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("headscale.example.")
                    && name.ends_with(ACCOUNT_CACHE_SUFFIX))
        );
    }

    #[test]
    fn write_autocert_cache_entry_matches_go_dircache_layout() {
        let dir = tempdir().unwrap();
        write_autocert_cache_entry(
            dir.path(),
            "headscale.example",
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
        )
        .unwrap();

        let path = dir.path().join("headscale.example");
        let bytes = fs::read_to_string(path).unwrap();
        assert_eq!(
            bytes,
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn challenge_cleanup_removes_tracked_tokens() {
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token", "token.thumbprint");
        {
            let mut cleanup = ChallengeCleanup::new(store.clone());
            cleanup.track("token".to_string());
        }

        assert_eq!(store.get("token"), None);
    }

    #[test]
    fn certificate_renewal_due_uses_thirty_day_window() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        assert!(certificate_is_expired(now, now));
        assert!(certificate_renewal_due(
            now + chrono::Duration::days(29),
            now
        ));
        assert!(certificate_renewal_due(
            now + chrono::Duration::days(30),
            now
        ));
        assert!(!certificate_renewal_due(
            now + chrono::Duration::days(31),
            now
        ));
    }

    #[test]
    fn next_renewal_check_delay_is_clamped() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();

        assert_eq!(
            next_renewal_check_delay(None, now),
            CERTIFICATE_RENEWAL_CHECK_MIN
        );
        assert_eq!(
            next_renewal_check_delay(Some(now + chrono::Duration::days(1)), now),
            CERTIFICATE_RENEWAL_CHECK_MIN
        );
        assert_eq!(
            next_renewal_check_delay(
                Some(now + chrono::Duration::days(30) + chrono::Duration::minutes(45)),
                now
            ),
            Duration::from_secs(45 * 60)
        );
        assert_eq!(
            next_renewal_check_delay(Some(now + chrono::Duration::days(90)), now),
            CERTIFICATE_RENEWAL_CHECK_MAX
        );
    }

    #[tokio::test]
    async fn ensure_http01_certificate_reuses_valid_cached_material() {
        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("source");
        let cache_dir = dir.path().join("cache");
        let generated = tls::load_or_generate(
            &source_dir,
            &tls::SanConfig::with_hostname("headscale.example"),
        )
        .unwrap();
        write_autocert_cache_entry(
            &cache_dir,
            "headscale.example",
            &generated.key_pem,
            &generated.cert_pem,
        )
        .unwrap();
        let config = AcmeHttp01IssuerConfig {
            directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            email: None,
            hostname: "headscale.example".into(),
            cache_dir: cache_dir.clone(),
        };

        let outcome = ensure_http01_certificate(&config, &AcmeHttp01ChallengeStore::new())
            .await
            .unwrap();

        assert_eq!(outcome.cache_path, cache_dir.join("headscale.example"));
        assert!(!outcome.issued);
    }
}
