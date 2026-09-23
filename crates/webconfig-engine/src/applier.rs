//! The applier trait (spec §3).
//!
//! Define **exactly this shape**:
//!   synchronous `validate(&Config) -> Result`,
//!                `apply(&Config) -> Result`,
//!                `rollback() -> Result`.
//! Appliers run in a dedicated blocking task; the async HTTP layer
//! communicates with the engine over a channel. Every applier takes a
//! **sysroot path parameter** (default `/`) so CI can run the entire config
//! engine against a tempdir fake sysroot on x86 with no hardware.
//!
//! Where a real system interaction cannot be fully implemented (e.g. RAUC
//! D-Bus specifics), implement against a narrow trait and provide both the
//! real implementation and a mock — never silently stub with a TODO (spec §7).

use std::path::PathBuf;

use thiserror::Error;

use crate::store::Config;
use crate::sysroot::Sysroot;

/// Stage at which an applier failed, for diagnostics and for the rollback
/// decision (spec §3: rollback on apply failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyStage {
    Validate,
    Apply,
    Rollback,
}

/// What an applier produced. `Provisional` means the change could sever the
/// current connection and the caller must run the commit/confirm timer
/// (spec §4.2 flagship feature) and call `rollback()` if not confirmed.
#[derive(Debug, Clone)]
pub enum ApplyOutcome {
    Committed,
    Provisional { confirm_window_secs: u64 },
}

#[derive(Debug, Error)]
pub enum ApplyError {
    #[error("validation failed at {stage:?}: {message}")]
    Validation { stage: ApplyStage, message: String },
    #[error("apply failed at {stage:?}: {message}")]
    Apply { stage: ApplyStage, message: String },
    #[error("rollback failed: {0}")]
    Rollback(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dbus error: {0}")]
    Dbus(String),
    #[error("command `{cmd}` failed (exit {code:?}): {stderr}")]
    Command {
        cmd: String,
        code: Option<i32>,
        stderr: String,
    },
}

/// The applier trait, exactly as specified (spec §3). Synchronous; callers run
/// it on a blocking task. `sysroot` defaults to `/` in production and to a
/// tempdir in tests.
pub trait Applier: Send + Sync {
    /// Stable id for logging / audit (e.g. "hostname", "networkd").
    fn id(&self) -> &'static str;

    /// Validate the relevant slice of `config` without touching the system.
    fn validate(&self, sysroot: &Sysroot, config: &Config) -> Result<(), ApplyError>;

    /// Apply the relevant slice to the system. May return a provisional
    /// outcome requiring commit/confirm (spec §4.2).
    fn apply(&self, sysroot: &Sysroot, config: &Config) -> Result<ApplyOutcome, ApplyError>;

    /// Roll back the most recent apply. Default: no-op (appliers that produce
    /// side effects override).
    fn rollback(&self, _sysroot: &Sysroot) -> Result<(), ApplyError> {
        Ok(())
    }
}

/// Helper: run an external command, capturing stderr, mapping non-zero exit to
/// [`ApplyError::Command`]. Commands are only used by appliers that shell out
/// to well-known OS verbs (hostnamectl, timedatectl, ip, nft, wg, journalctl,
/// chpasswd). The sysroot parameter is *not* applied to the command here —
/// commands that honor a root (`--root=`) pass it themselves; tests use the
/// file-writing appliers instead. Kept as a shared helper to keep error shape
/// uniform.
pub fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, ApplyError> {
    // T-P02: on a flashed device (non-root + helper socket) every live verb
    // routes through the root helper's fixed allowlist; the direct path stays
    // for fake sysroots, root dev runs and any deployment without the helper.
    if crate::priv_client::active() {
        return match crate::priv_client::exec(cmd, args) {
            Ok((stdout, _stderr, 0)) => Ok(stdout),
            Ok((_, stderr, code)) => Err(ApplyError::Command {
                cmd: cmd.to_string(),
                code: Some(code),
                stderr,
            }),
            Err(e) => Err(ApplyError::Command {
                cmd: cmd.to_string(),
                code: None,
                stderr: e.to_string(),
            }),
        };
    }
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| ApplyError::Command {
            cmd: cmd.to_string(),
            code: None,
            stderr: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(ApplyError::Command {
            cmd: cmd.to_string(),
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// A captured backup of a file written by an applier, so `rollback()` can
/// restore it. Appliers keep the last backup in memory (single undo level).
/// T-P02: restores route through the privileged helper on a real device
/// (rollback rewrites the same /etc paths the apply wrote).
#[derive(Debug, Clone)]
pub struct FileBackup {
    pub path: PathBuf,
    pub prior: Option<Vec<u8>>,
}

impl FileBackup {
    pub fn capture(path: PathBuf) -> Result<Self, ApplyError> {
        let prior = if path.exists() {
            Some(std::fs::read(&path)?)
        } else {
            None
        };
        Ok(Self { path, prior })
    }

    pub fn restore(self) -> Result<(), ApplyError> {
        match self.prior {
            Some(bytes) => {
                crate::priv_client::write_file(&self.path, &bytes)?;
                Ok(())
            }
            None => {
                if self.path.exists() {
                    crate::priv_client::remove_file(&self.path)?;
                }
                Ok(())
            }
        }
    }
}
