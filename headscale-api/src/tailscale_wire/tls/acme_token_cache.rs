// Copyright 2016 The Go Authors. All rights reserved.
// Token cache adapts x/crypto/acme/autocert and DirCache; see LICENSE-GO-STDLIB.

//! Native-bound token persistence. Operations are synchronous because rustls'
//! resolver callback is synchronous; exact Go worker/context cancellation and
//! filesystem scheduling/resource behavior remain outside this adapter.

use std::{
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use rustls::sign::CertifiedKey;

use super::{WireError, acme_cache, certified_key_from_pem_without_webpki_checks, write_atomic};

#[derive(Debug)]
pub(super) struct TokenCache {
    directory: PathBuf,
}

impl TokenCache {
    pub(super) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }

    fn path(&self, normalized_domain: &str) -> Option<PathBuf> {
        // Lookup output cannot contain separators. Keep this private boundary
        // defensive: PathBuf::join must never replace the configured directory
        // with an absolute input or traverse it. No normal-key root-dot trim.
        if !normalized_domain.is_ascii()
            || normalized_domain.contains('/')
            || normalized_domain.contains('\\')
        {
            return None;
        }
        let filename = format!("{normalized_domain}+token");
        let mut components = Path::new(&filename).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return None;
        }
        Some(self.directory.join(filename))
    }

    pub(super) fn read(&self, normalized_domain: &str) -> Option<Arc<CertifiedKey>> {
        let bytes = fs::read(self.path(normalized_domain)?).ok()?;
        let (key_pem, cert_pem, _) = acme_cache::load_token(&bytes, normalized_domain).ok()?;
        // The ACME identifier extension is intentionally critical. Go does not
        // apply WebPKI verification here; shared cache eligibility already
        // checked dates, hostname, supported key type and public/private match.
        certified_key_from_pem_without_webpki_checks(&cert_pem, &key_pem)
            .ok()
            .map(Arc::new)
    }

    pub(super) fn put(
        &self,
        normalized_domain: &str,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), WireError> {
        let path = self
            .path(normalized_domain)
            .ok_or_else(|| WireError::Internal("invalid ACME token cache name".into()))?;
        let combined = acme_cache::encode_entry(key_pem, cert_pem)?;
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(&self.directory)?;
        // Existing helper uses random create_new 0600 temporary files and
        // rename in the same directory, with cleanup on a write/rename error.
        write_atomic(&path, combined.as_bytes(), 0o600)
    }

    pub(super) fn delete(&self, normalized_domain: &str) {
        if let Some(path) = self.path(normalized_domain) {
            // autocert.deleteCertToken ignores Cache.Delete errors, including
            // missing files; a failed cache operation does not retain memory.
            let _ = fs::remove_file(path);
        }
    }
}
