//! `derper` subprocess lifecycle.
//!
//! Spawns the upstream `tailscale.com/cmd/derper` Go binary and
//! manages its lifetime alongside the headscale-rs control plane.
//!
//! ## Process model
//!
//! - **Start** at boot via [`DerperSidecar::spawn`]. The child is
//!   left attached to the parent's stdout / stderr (no piping — the
//!   binary's own logging lands directly in the operator's terminal).
//! - **Watch** a background task polls `try_wait()` every 5 s. If the
//!   child exits unexpectedly the task records the exit status; the
//!   next `status()` call surfaces it. Auto-restart is **not** done
//!   in-process — the operator's systemd / docker supervisor is the
//!   right place for that.
//! - **Stop** on drop: try SIGTERM via `nix::sys::signal::kill` (Unix
//!   only), wait up to 5 s, then SIGKILL via
//!   [`std::process::Child::kill`]. Idempotent.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("derper binary not found at {0:?}")]
    BinaryMissing(PathBuf),
    #[error("failed to spawn derper: {0}")]
    Spawn(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub enum SidecarStatus {
    Running { pid: u32 },
    Exited { code: Option<i32> },
    NotStarted,
}

pub struct DerperSidecar {
    child: Arc<Mutex<Option<std::process::Child>>>,
    status: Arc<Mutex<SidecarStatus>>,
    binary: PathBuf,
}

impl DerperSidecar {
    /// Spawn the sidecar. Returns [`SidecarError::BinaryMissing`]
    /// without invoking the binary when `cfg.derper_binary` doesn't
    /// point at an existing file.
    pub fn spawn(cfg: &super::DerpConfig) -> Result<Self, SidecarError> {
        if !cfg.derper_binary.is_file() {
            return Err(SidecarError::BinaryMissing(cfg.derper_binary.clone()));
        }
        let mut cmd = Command::new(&cfg.derper_binary);
        cmd.arg("-a")
            .arg(cfg.sidecar_listen_addr.to_string())
            .arg("-hostname")
            .arg(&cfg.host_name)
            // We own STUN in Rust; turn off the binary's own listener.
            .arg("-stun=false")
            .arg("-certmode=manual")
            .arg("-c")
            .arg("/tmp/headscale-derp.key")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = cmd.spawn()?;
        let pid = child.id();
        let status = Arc::new(Mutex::new(SidecarStatus::Running { pid }));
        let child_mu = Arc::new(Mutex::new(Some(child)));

        let child_clone = Arc::clone(&child_mu);
        let status_clone = Arc::clone(&status);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut guard = child_clone.lock();
                let Some(child) = guard.as_mut() else {
                    return;
                };
                match child.try_wait() {
                    Ok(Some(exit)) => {
                        *status_clone.lock() = SidecarStatus::Exited { code: exit.code() };
                        *guard = None;
                        return;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("derper try_wait failed: {e}");
                    }
                }
            }
        });

        Ok(Self {
            child: child_mu,
            status,
            binary: cfg.derper_binary.clone(),
        })
    }

    pub fn status(&self) -> SidecarStatus {
        self.status.lock().clone()
    }

    pub fn binary_path(&self) -> &std::path::Path {
        &self.binary
    }

    /// Synchronous teardown. Tries SIGTERM via `nix::sys::signal::kill`
    /// on Unix, then SIGKILL on timeout. Idempotent.
    pub fn terminate(&self) {
        let mut guard = self.child.lock();
        let Some(child) = guard.as_mut() else {
            return;
        };
        #[cfg(unix)]
        {
            use nix::sys::signal::{Signal, kill};
            use nix::unistd::Pid;
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => {
                    *guard = None;
                    return;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        *guard = None;
    }
}

impl Drop for DerperSidecar {
    fn drop(&mut self) {
        self.terminate();
    }
}
