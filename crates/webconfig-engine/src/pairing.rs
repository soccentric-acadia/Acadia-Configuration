//! HQ pairing agent (task 36).
//!
//! Implements the device side of the HQ/Configuration pairing contract
//! (`doc/hq-pairing-contract.md`): identity, enrollment, credentials,
//! revocation, retries, heartbeat, and offline behavior. This module is
//! deliberately free of HTTP/async code so it can be unit-tested against a
//! tempdir fake sysroot on x86 CI; the `webconfigd` HTTP layer wires the
//! transport and calls the state transitions here.
//!
//! The agent persists its pairing state durably so a device survives restart
//! and outage without re-enrolling, and applies **bounded, capped backoff** to
//! heartbeat/connect retries so it never hammers HQ (contract §Retries).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Maximum backoff before the next retry (cap), and the base per attempt.
pub const MAX_BACKOFF_SECS: u64 = 300;
const BASE_BACKOFF_SECS: u64 = 2;

/// Pairing lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairingState {
    /// No token yet — not enrolled.
    Unprovisioned,
    /// Token accepted, awaiting HQ enrollment confirmation.
    Pending,
    /// Enrolled and healthy.
    Enrolled,
    /// Enrollment or heartbeat rejected — token was revoked.
    Revoked,
}

/// Durable pairing state persisted to a JSON file on the data partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    /// Scheme/version so the record can be migrated.
    pub schema_version: u32,
    pub state: PairingState,
    /// The active credential token (held on-device; never in backups).
    pub credential_token: Option<String>,
    /// HQ endpoint the device enrolls/heartbeats against.
    pub hq_endpoint: String,
    /// Monotonic deadline (unix secs) until which the token is valid.
    pub token_expires_at_unix: Option<u64>,
    /// Expiry of the enrolled device credential, when HQ issues one.  This is
    /// deliberately separate from the one-time pairing-token deadline.
    #[serde(default)]
    pub credential_expires_at_unix: Option<u64>,
    /// Last successful heartbeat (unix secs).
    pub last_heartbeat_at: Option<u64>,
    /// Retry counter + next-backoff deadline for the retry loop.
    pub retry_count: u64,
    pub retry_after_unix: Option<u64>,
    /// Permanent device identity (UUID) assigned by HQ at enrollment
    /// (X5-001: needed for Heartbeat.device_id on every frame).
    #[serde(default)]
    pub device_id: Option<String>,
}

/// A rejected/revoked outcome carries a reason; a success carries the new state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingOutcome {
    Ok,
    Retry { after_secs: u64 },
    Revoked,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Default for PairingRecord {
    fn default() -> Self {
        Self {
            schema_version: 1,
            state: PairingState::Unprovisioned,
            credential_token: None,
            hq_endpoint: String::new(),
            token_expires_at_unix: None,
            credential_expires_at_unix: None,
            last_heartbeat_at: None,
            retry_count: 0,
            retry_after_unix: None,
            device_id: None,
        }
    }
}

/// The pairing agent: owns durable state and the retry/heartbeat transitions.
#[derive(Debug)]
pub struct PairingAgent {
    record: PairingRecord,
    path: PathBuf,
}

impl PairingAgent {
    /// Load (or initialize) the durable record at `data_dir/pairing.json`.
    pub fn load(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join("pairing.json");
        let record = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<PairingRecord>(&raw).ok())
            .unwrap_or_default();
        Self { record, path }
    }

    fn persist(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
            #[cfg(unix)]
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        if let Ok(raw) = serde_json::to_string(&self.record) {
            let temporary = self.path.with_extension("json.new");
            if std::fs::write(&temporary, raw).is_ok() {
                #[cfg(unix)]
                let _ =
                    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600));
                let _ = std::fs::rename(temporary, &self.path);
            }
        }
    }

    pub fn state(&self) -> PairingState {
        self.record.state
    }
    pub fn hq_endpoint(&self) -> &str {
        &self.record.hq_endpoint
    }

    /// The active pairing token or long-lived credential (may be None when
    /// unprovisioned).
    pub fn credential(&self) -> Option<&str> {
        self.record.credential_token.as_deref()
    }

    /// Store the permanent device identity assigned by HQ at enrollment.
    pub fn set_device_id(&mut self, device_id: String) {
        self.record.device_id = Some(device_id);
        self.persist();
    }
    pub fn device_id(&self) -> Option<&str> {
        self.record.device_id.as_deref()
    }

    /// Store the long-lived credential issued by HQ at enrollment
    /// (X5-001: replaces the single-use pairing token on the next connect).
    pub fn set_credential(&mut self, credential: String, expires_at_unix: Option<u64>) {
        self.record.credential_token = Some(credential);
        self.record.credential_expires_at_unix = expires_at_unix;
        // Pairing tokens are single-use and must never become a fallback
        // credential after enrollment.
        self.record.token_expires_at_unix = None;
        self.persist();
    }

    /// Provision with a fresh pairing token + HQ endpoint (enrollment start).
    pub fn provision(&mut self, token: String, hq_endpoint: String, ttl_secs: u64) {
        let now = now_unix();
        self.record.state = PairingState::Pending;
        self.record.credential_token = Some(token);
        self.record.hq_endpoint = hq_endpoint;
        self.record.token_expires_at_unix = Some(now + ttl_secs);
        self.record.credential_expires_at_unix = None;
        self.record.retry_count = 0;
        self.record.retry_after_unix = None;
        self.persist();
    }

    /// Call when HQ confirms enrollment.
    pub fn on_enrolled(&mut self) {
        self.record.state = PairingState::Enrolled;
        self.record.retry_count = 0;
        self.record.retry_after_unix = None;
        self.persist();
    }

    /// Called by the HTTP layer before attempting a heartbeat/connect. Decides
    /// whether a retry is allowed now.
    pub fn retry_allowed(&mut self) -> PairingOutcome {
        if self.record.state == PairingState::Revoked {
            return PairingOutcome::Revoked;
        }
        if let Some(after) = self.record.retry_after_unix {
            let now = now_unix();
            if now < after {
                return PairingOutcome::Retry {
                    after_secs: after - now,
                };
            }
        }
        PairingOutcome::Ok
    }

    /// Record a failed attempt and schedule the next retry with capped,
    /// exponential backoff (task 36: bounded backoff).
    pub fn on_failure(&mut self) -> PairingOutcome {
        let now = now_unix();
        self.record.retry_count += 1;
        let backoff = (BASE_BACKOFF_SECS
            * 2u64.pow(self.record.retry_count.saturating_sub(1) as u32))
        .min(MAX_BACKOFF_SECS);
        self.record.retry_after_unix = Some(now + backoff);
        self.persist();
        PairingOutcome::Retry {
            after_secs: backoff,
        }
    }

    /// Called when HQ reports the credential is revoked.
    pub fn on_revoked(&mut self) {
        self.record.state = PairingState::Revoked;
        self.record.retry_after_unix = None;
        self.persist();
    }

    /// Called on a successful heartbeat (survives restart by persisting).
    pub fn on_heartbeat(&mut self) {
        self.record.last_heartbeat_at = Some(now_unix());
        self.record.retry_count = 0;
        self.record.retry_after_unix = None;
        if self.record.state == PairingState::Pending {
            self.record.state = PairingState::Enrolled;
        }
        self.persist();
    }

    /// Returns true if the token has expired (needs re-enrollment).
    pub fn token_expired(&self) -> bool {
        match self.record.token_expires_at_unix {
            Some(exp) => now_unix() >= exp,
            None => false,
        }
    }

    /// Credentials are allowed a small bounded clock-skew window.  HQ remains
    /// authoritative (it validates expiry on every frame); this only prevents
    /// a target with a slightly fast clock from discarding a still-valid
    /// credential while it is offline.
    pub fn credential_expired(&self) -> bool {
        const CLOCK_SKEW_SECS: u64 = 300;
        self.record
            .credential_expires_at_unix
            .is_some_and(|expiry| now_unix() > expiry.saturating_add(CLOCK_SKEW_SECS))
    }

    /// Remove local enrollment material during factory reset. The immutable
    /// OS/factory serial is intentionally not owned by this record.
    pub fn clear_enrollment(data_dir: &std::path::Path) -> std::io::Result<()> {
        let path = data_dir.join("pairing.json");
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn record(&self) -> &PairingRecord {
        &self.record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_unprovisioned() {
        let dir = tempfile::tempdir().unwrap();
        let agent = PairingAgent::load(dir.path());
        assert_eq!(agent.state(), PairingState::Unprovisioned);
    }

    #[test]
    fn provision_persists_and_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut agent = PairingAgent::load(dir.path());
            agent.provision("tok".into(), "https://hq.example".into(), 900);
            assert_eq!(agent.state(), PairingState::Pending);
        }
        let reloaded = PairingAgent::load(dir.path());
        assert_eq!(reloaded.state(), PairingState::Pending);
        assert_eq!(reloaded.record().credential_token.as_deref(), Some("tok"));
        assert_eq!(reloaded.hq_endpoint(), "https://hq.example");
    }

    #[test]
    fn heartbeat_moves_pending_to_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = PairingAgent::load(dir.path());
        agent.provision("t".into(), "hq".into(), 600);
        agent.on_heartbeat();
        assert_eq!(agent.state(), PairingState::Enrolled);
    }

    #[test]
    fn failure_backoff_is_capped_and_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = PairingAgent::load(dir.path());
        agent.provision("t".into(), "hq".into(), 600);
        // Repeated failures must grow backoff but cap at MAX_BACKOFF_SECS.
        let mut last = 0u64;
        for _ in 0..20 {
            match agent.on_failure() {
                PairingOutcome::Retry { after_secs } => {
                    assert!(after_secs >= last);
                    assert!(after_secs <= MAX_BACKOFF_SECS);
                    last = after_secs;
                }
                _ => panic!("expected retry"),
            }
        }
        assert_eq!(last, MAX_BACKOFF_SECS);
    }

    #[test]
    fn revoked_blocks_retries() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = PairingAgent::load(dir.path());
        agent.provision("t".into(), "hq".into(), 600);
        agent.on_revoked();
        assert_eq!(agent.state(), PairingState::Revoked);
        assert_eq!(agent.retry_allowed(), PairingOutcome::Revoked);
    }

    #[test]
    fn success_resets_retry_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = PairingAgent::load(dir.path());
        agent.provision("t".into(), "hq".into(), 600);
        let _ = agent.on_failure();
        agent.on_heartbeat();
        assert_eq!(agent.record().retry_count, 0);
        assert_eq!(agent.retry_allowed(), PairingOutcome::Ok);
    }

    #[test]
    fn enrollment_uses_private_atomic_state_and_can_be_wiped() {
        let dir = tempfile::tempdir().unwrap();
        let mut agent = PairingAgent::load(dir.path());
        agent.provision("pairing-token".into(), "hq".into(), 600);
        agent.set_credential("device-credential".into(), Some(now_unix() - 301));
        assert!(agent.credential_expired());
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(dir.path().join("pairing.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        PairingAgent::clear_enrollment(dir.path()).unwrap();
        assert!(!dir.path().join("pairing.json").exists());
    }
}
