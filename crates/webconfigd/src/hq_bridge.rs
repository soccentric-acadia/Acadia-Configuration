//! HQ data-plane bridge + local execution of the `configuration`
//! pseudo-daemon ops (task 009, P2/P3).
//!
//! Two responsibilities live here:
//!
//! 1. **Local execution** ([`DeviceOps`]): the HQ operation catalog targets
//!    `daemon="configuration"` for verbs webconfigd itself owns (config
//!    read/write, backup, restore, factory reset, update install). These must
//!    never cross istate `Control` — istate only routes the nine spokes, so
//!    relaying them failed with "spoke not connected" and every HQ command
//!    died on-device (task 009 findings C3/H2). Spoke ops still cross istate.
//!
//! 2. **Data-plane bridge** ([`run_data_bridge`]): istate's spooled
//!    northbound records (telemetry, faults, log-bundle refs) are subscribed
//!    via `ConfigurationApi.StreamDeviceData` and mapped onto AgentLink
//!    frames, with uploads executed against the gateway's presigned URLs
//!    ([`UploadCoordinator`]/[`UploadExecutor`]). Before this bridge the
//!    gateway handled `TelemetryBatch`/`FaultEvent`/`LogUploadRequest` frames
//!    no device code ever sent, and istate's spool drained into an
//!    unimplemented `HqPeer` service (findings H6/H7).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use hq_agent::pb;
use hq_agent::{AgentMailbox, CommandOutcome};
use tokio::sync::watch;
use webconfig_engine::applier::ApplyOutcome;
use webconfig_engine::audit::{AuditEntry, AuditLog};
use webconfig_engine::store::ConfigFile;
use webconfig_engine::update::UpdateBackend;
use webconfig_engine::Sysroot;

use crate::engine_bridge::EngineBridge;
use crate::istate_client::SharedIstateClient;

/// HQ-initiated factory reset must carry this exact confirmation (the
/// AgentLink `Command.required_confirmation` field). istate enforces the same
/// gate for its own `factory-reset` op; the local path must not be weaker
/// (task 009, H4).
pub const REQUIRED_FACTORY_RESET_CONFIRMATION: &str = "FACTORY-RESET";
/// Confirmation an HQ `system.shutdown` must carry (T-P20): a remote
/// shutdown cannot be undone from HQ — someone must power-cycle the unit.
pub const REQUIRED_SHUTDOWN_CONFIRMATION: &str = "SHUTDOWN";
/// Confirmation an HQ `update.rollback` must carry (T-P20).
pub const REQUIRED_ROLLBACK_CONFIRMATION: &str = "ROLLBACK";
/// Delay between acknowledging a power-affecting command and executing it
/// (T-P20). The command outcome must reach HQ BEFORE the device goes down:
/// an unacknowledged reboot is re-delivered after the lease expires, and the
/// in-memory idempotency cache does not survive the reboot — the device
/// would reboot-loop.
pub const POWER_ACTION_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Service actions an HQ `service.control` may request (T-P20).
pub const SERVICE_ACTIONS: &[&str] = &["start", "stop", "restart", "enable", "disable"];

/// The HQ configuration-signing public key sources, in order (T-P13, F09):
/// 1. `WEBCONFIG_HQ_CONFIG_PUBKEY` — PEM ("-----BEGIN PUBLIC KEY-----", RFC
///    8410 Ed25519 SubjectPublicKeyInfo) or raw base64 of the 32-byte key,
/// 2. `/etc/acadia/hq-config-pub.pem` — provisioned with the fleet key.
pub const HQ_CONFIG_PUBKEY_ENV: &str = "WEBCONFIG_HQ_CONFIG_PUBKEY";
pub const HQ_CONFIG_PUBKEY_PATH: &str = "/etc/acadia/hq-config-pub.pem";

/// Extract the raw 32-byte Ed25519 verification key from PEM (RFC 8410 SPKI
/// DER: fixed 12-byte header + 32-byte key) or raw base64.
fn ed25519_pubkey_bytes(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.starts_with("-----BEGIN") {
        let b64: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----") && !l.contains(": "))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| "public key PEM body is not base64".to_string())?;
        // RFC 8410: 0x30 0x2a 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x03 0x21 0x00
        if der.len() == 44
            && der.starts_with(&[
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
            ])
        {
            return Ok(der[12..].to_vec());
        }
        return Err("public key PEM is not an Ed25519 SubjectPublicKeyInfo".into());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(trimmed.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed.as_bytes()))
        .map_err(|_| "public key is neither PEM nor base64".to_string())?;
    if raw.len() == 32 {
        return Ok(raw);
    }
    Err("raw public key must be exactly 32 bytes".into())
}

fn hq_config_pubkey() -> Option<Vec<u8>> {
    if let Ok(from_env) = std::env::var(HQ_CONFIG_PUBKEY_ENV) {
        if !from_env.trim().is_empty() {
            return ed25519_pubkey_bytes(&from_env).ok();
        }
    }
    std::fs::read_to_string(HQ_CONFIG_PUBKEY_PATH)
        .ok()
        .and_then(|pem| ed25519_pubkey_bytes(&pem).ok())
}

/// The exact bytes HQ signs and the device verifies (T-P13, F09): the
/// configuration contract fields ONLY — `{schema_version, origin, config}` —
/// canonical JSON. Transport metadata (`signature`, `signature_algorithm`,
/// `integration_status`) is excluded on both sides, so the signed bytes are
/// exactly the three contract fields, sorted-key/compact (byte-identical to
/// the HQ signer's `json.dumps(..., sort_keys=True, separators=(",", ":"),
/// ensure_ascii=False)`).
fn signed_document(envelope: &serde_json::Value) -> Result<Vec<u8>, String> {
    let doc = serde_json::json!({
        "schema_version": envelope.get("schema_version").ok_or("schema_version required")?,
        "origin": envelope.get("origin").ok_or("origin required")?,
        "config": envelope.get("config").ok_or("config required")?,
    });
    serde_json::to_vec(&doc).map_err(|e| e.to_string())
}

/// Envelope validation for `configuration.write` (task 009, H5; T-P13, F09).
///
/// Verification is MANDATORY: the HQ Ed25519 public key must be provisioned
/// (env or /etc/acadia/hq-config-pub.pem) and the signature must verify over
/// the canonical transport payload. Without a provisioned key the write is
/// rejected outright — the old length-check-only transitional policy is gone.
pub fn validate_write_envelope(envelope: &serde_json::Value) -> Result<(), String> {
    if envelope.get("schema_version").and_then(|v| v.as_u64())
        != Some(u64::from(webconfig_engine::CONFIG_SCHEMA_VERSION))
    {
        return Err("schema_version must equal the device configuration contract version".into());
    }
    if envelope.get("origin").and_then(|v| v.as_str()) != Some("hq") {
        return Err("origin must be \"hq\"".into());
    }
    if !envelope.get("config").is_some_and(|v| v.is_object()) {
        return Err("config must be an object".into());
    }
    let algorithm = envelope
        .get("signature_algorithm")
        .and_then(|v| v.as_str())
        .unwrap_or("ed25519");
    if algorithm != "ed25519" {
        return Err(format!(
            "signature_algorithm must be ed25519 (got {algorithm:?}) — the transitional \
             HMAC path is retired (T-P13)"
        ));
    }
    let raw = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("signature is required")?;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
        .map_err(|_| "signature is not base64".to_string())?;
    if sig.len() != 64 {
        return Err("signature must decode to 64 bytes".into());
    }
    let key = hq_config_pubkey().ok_or_else(|| {
        "FAILED_PRECONDITION: HQ verification key not provisioned — set          WEBCONFIG_HQ_CONFIG_PUBKEY or install /etc/acadia/hq-config-pub.pem"
            .to_string()
    })?;
    let verifier = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key);
    verifier
        .verify(signed_document(envelope)?.as_slice(), &sig)
        .map_err(|_| "signature verification failed".to_string())
}

/// The appliers owned by each config section (T-P18/SB-6d): a write to a
/// section runs exactly these, in this order.
fn section_appliers(section: &str) -> &'static [&'static str] {
    match section {
        "system" => &["hostname", "time", "ssh"],
        "network" => &["networkd", "wifi", "ap", "firewall", "wireguard"],
        "security" => &["firewall", "wireguard"],
        "logs" => &["journald"],
        "io" => &["gpio", "serial", "can"],
        _ => &[],
    }
}

/// The current value of one config section as JSON (for the T-P18
/// read-modify-write merge).
fn section_value(
    cfg: &webconfig_engine::store::Config,
    section: &str,
) -> Result<serde_json::Value, webconfig_engine::StoreError> {
    use webconfig_engine::StoreError;
    let v = match section {
        "system" => serde_json::to_value(&cfg.system),
        "network" => serde_json::to_value(&cfg.network),
        "services" => serde_json::to_value(&cfg.services),
        "updates" => serde_json::to_value(&cfg.updates),
        "monitoring" => serde_json::to_value(&cfg.monitoring),
        "logs" => serde_json::to_value(&cfg.logs),
        "alerts" => serde_json::to_value(&cfg.alerts),
        "security" => serde_json::to_value(&cfg.security),
        "io" => serde_json::to_value(&cfg.io),
        "app_settings" => serde_json::to_value(&cfg.app_settings),
        other => {
            return Err(StoreError::Validation(format!(
                "unknown config section {other}"
            )));
        }
    };
    v.map_err(|e| StoreError::Validation(format!("section serialize: {e}")))
}

/// Deep merge `incoming` over `current`: objects merge recursively, every
/// other type replaces. Absent fields keep their current value (T-P18).
fn deep_merge(current: serde_json::Value, incoming: serde_json::Value) -> serde_json::Value {
    match (current, incoming) {
        (serde_json::Value::Object(mut a), serde_json::Value::Object(b)) => {
            for (k, v) in b {
                let merged = match a.remove(&k) {
                    Some(existing) => deep_merge(existing, v),
                    None => v,
                };
                a.insert(k, merged);
            }
            serde_json::Value::Object(a)
        }
        (_, incoming) => incoming,
    }
}

/// One queued device→HQ upload blob.
#[derive(Debug)]
pub struct PendingUpload {
    pub kind: pb::log_upload_request::Kind,
    pub path: PathBuf,
    pub size_bytes: u64,
    /// T-P22: correlation id sent in `LogUploadRequest.client_ref` and echoed
    /// in `SignedUploadUrl`; assigned by [`UploadCoordinator::register`].
    pub client_ref: String,
}

/// The `LogUploadRequest` frame announcing a registered upload (T-P22).
pub fn upload_request_frame(
    upload_kind: pb::log_upload_request::Kind,
    size: u64,
    client_ref: &str,
) -> pb::AgentFrame {
    pb::AgentFrame {
        body: Some(pb::agent_frame::Body::LogUploadRequest(
            pb::LogUploadRequest {
                kind: upload_kind.into(),
                time_range_start_unix_ms: 0,
                time_range_end_unix_ms: 0,
                size_bytes_estimate: size as i64,
                client_ref: client_ref.to_string(),
            },
        )),
    }
}

/// Registry of uploads created by the device that await a presigned URL.
///
/// T-P22: each upload gets a `client_ref` the gateway echoes in its
/// `SignedUploadUrl`, so a URL is matched to exactly its blob. A pre-T-P22
/// gateway echoes nothing; then the oldest upload of the URL's kind (else
/// the oldest of any kind) is taken, as before.
#[derive(Default)]
pub struct UploadCoordinator {
    pending: Mutex<VecDeque<PendingUpload>>,
    next_ref: std::sync::atomic::AtomicU64,
}

impl UploadCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an upload awaiting its presigned URL; returns its client_ref.
    pub fn register(&self, mut upload: PendingUpload) -> String {
        if upload.client_ref.is_empty() {
            let n = self
                .next_ref
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            upload.client_ref = format!("{}-{n}", now_unix_ms());
        }
        let client_ref = upload.client_ref.clone();
        self.pending
            .lock()
            .expect("upload queue lock")
            .push_back(upload);
        client_ref
    }

    /// Pop the upload a `SignedUploadUrl` answers: by client_ref when the
    /// gateway echoed one, else positionally by kind (pre-T-P22 gateway).
    pub fn take_for(
        &self,
        client_ref: &str,
        kind: pb::log_upload_request::Kind,
    ) -> Option<PendingUpload> {
        if !client_ref.is_empty() {
            let mut q = self.pending.lock().expect("upload queue lock");
            if let Some(i) = q.iter().position(|p| p.client_ref == client_ref) {
                return q.remove(i);
            }
            return None;
        }
        self.take(kind)
    }

    /// Pop the oldest pending upload of @p kind, falling back to the oldest
    /// of any kind (the URL correlation is positional, see struct docs).
    pub fn take(&self, kind: pb::log_upload_request::Kind) -> Option<PendingUpload> {
        let mut q = self.pending.lock().expect("upload queue lock");
        let idx = q
            .iter()
            .position(|p| p.kind == kind)
            .or_else(|| q.iter().position(|_| true));
        idx.map(|i| q.remove(i).expect("index from position"))
    }

    /// Pending upload count (diagnostics).
    #[allow(dead_code)] // surfaced for monitoring/diagnostics consumers
    pub fn pending_count(&self) -> usize {
        self.pending.lock().expect("upload queue lock").len()
    }
}

/// Executes the gateway's `SignedUploadUrl`: PUTs the matched pending upload
/// to the presigned URL with curl (the same tool the web API's backup flows
/// use — no new rootfs dependency). Upload completion is not reportable in
/// this proto version (the gateway creates its row on `LogUploadRequest`
/// optimistically; see gateway/handlers.py).
pub struct UploadExecutor {
    pub coordinator: Arc<UploadCoordinator>,
    pub audit: Arc<AuditLog>,
    /// T-P22: publishes the `UploadComplete` report after each PUT.
    pub mailbox: AgentMailbox,
}

#[async_trait::async_trait]
impl hq_agent::ServerFrameHooks for UploadExecutor {
    async fn on_signed_upload_url(&self, url: pb::SignedUploadUrl) {
        let kind = pb::log_upload_request::Kind::try_from(url.kind)
            .unwrap_or(pb::log_upload_request::Kind::LogBundle);
        let pending = match self.coordinator.take_for(&url.client_ref, kind) {
            Some(p) => p,
            None => {
                tracing::warn!(request_ref = %url.request_ref, "signed upload url with no pending upload");
                return;
            }
        };
        tracing::info!(request_ref = %url.request_ref, size = pending.size_bytes, "uploading pending blob");
        // T-P22: digest of exactly the bytes being uploaded, for the report.
        let digest_path = pending.path.clone();
        let (size, sha256) = tokio::task::spawn_blocking(move || {
            webconfig_engine::applier::sha256_file(&digest_path)
                .map(|(n, d)| (n as i64, d))
                .unwrap_or((0, String::new()))
        })
        .await
        .unwrap_or((0, String::new()));
        let path = pending.path.clone();
        let upload_url = url.upload_url.clone();
        let audit = self.audit.clone();
        let request_ref = url.request_ref.clone();
        let result = tokio::task::spawn_blocking(move || {
            webconfig_engine::applier::run_local(
                "curl",
                &[
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "300",
                    "--upload-file",
                    &path.to_string_lossy(),
                    &upload_url,
                ],
            )
        })
        .await;
        let ok = matches!(&result, Ok(Ok(_)));
        let error = match &result {
            Ok(Ok(_)) => String::new(),
            Ok(Err(e)) => e.to_string(),
            Err(e) => e.to_string(),
        };
        // T-P22: report the outcome so HQ finalises (or fails) the row
        // instead of trusting its optimistic record.
        let reported = self.mailbox.try_publish(pb::AgentFrame {
            body: Some(pb::agent_frame::Body::UploadComplete(pb::UploadComplete {
                request_ref: request_ref.clone(),
                success: ok,
                size_bytes: if ok { size } else { 0 },
                sha256: if ok { sha256 } else { String::new() },
                error,
            })),
        });
        if !reported {
            tracing::warn!(request_ref = %request_ref, "upload_complete dropped (agent offline or saturated)");
        }
        let _ = audit.append(&AuditEntry {
            ts: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            user: "hq".into(),
            action: "upload".into(),
            detail: Some(format!(
                "{request_ref}: {}",
                if ok { "uploaded" } else { "failed" }
            )),
        });
        if ok {
            tracing::info!(request_ref = %request_ref, "upload complete");
            // Temp blob consumed; remove it (best effort).
            let _ = std::fs::remove_file(&pending.path);
        } else {
            tracing::warn!(request_ref = %request_ref, "upload failed; blob retained for retry");
        }
    }
}

/// Executes the `configuration` pseudo-daemon verbs locally (config engine,
/// update backend, factory reset) and hands spoke verbs to istate.
pub struct DeviceOps {
    pub engine: EngineBridge,
    pub update_backend: Arc<dyn UpdateBackend>,
    pub schema: Arc<webconfig_engine::schema::Schema>,
    pub istate: SharedIstateClient,
    pub coordinator: Arc<UploadCoordinator>,
    pub sysroot: Arc<Sysroot>,
    /// T-P20: service control + status for `service.control`.
    pub systemd: Arc<dyn crate::systemd::SystemdClient>,
    /// T-P20: the board manifest's service allowlist — HQ may drive exactly
    /// the units the local Services page may.
    pub service_allowlist: Vec<String>,
    /// T-P20: the local web-UI account store (`users.*` commands).
    pub users_path: PathBuf,
}

impl DeviceOps {
    /// Redacted configuration document — the same document the web UI's
    /// `GET /updates/backup` returns: secrets never leave the device
    /// unencrypted, and HQ never receives them (spec §4.4).
    fn backup_document(&self) -> Result<serde_json::Value, String> {
        let mut cfg = self
            .engine
            .load()
            .map_err(|e| format!("config load failed: {e}"))?;
        crate::api::updates::redact_secrets(&mut cfg, &self.schema);
        Ok(serde_json::json!({
            "schema_version": webconfig_engine::CONFIG_SCHEMA_VERSION,
            "config": cfg,
            "secrets_included": false,
        }))
    }

    /// `configuration.read` (task 009, H5): returns the device configuration
    /// contract document (schema_version + config tree, secrets redacted).
    pub async fn read_configuration(&self) -> CommandOutcome {
        match self.backup_document() {
            Ok(doc) => {
                CommandOutcome::ok_json("OK", serde_json::to_string(&doc).unwrap_or_default())
            }
            Err(e) => CommandOutcome::failure("INTERNAL", e),
        }
    }

    /// `configuration.write` (task 009, H5): a signed, origin=hq envelope.
    ///
    /// Sections present in `config` replace the device value; absent sections
    /// are untouched (a partial merge, not a blind replace).
    /// `configuration.write` (task 009, H5; T-P18/SB-6d): a signed, origin=hq
    /// envelope. Sections present in `config` are MERGED over the device
    /// value (read-modify-write: absent fields keep their current value —
    /// this is what makes the HQ-side "[redacted]" drop safe), then the
    /// touched sections' appliers RUN, and the outcome reports one result per
    /// applier. Provisional outcomes arm the commit/confirm window with
    /// auto-confirm while HQ stays reachable.
    pub async fn write_configuration(&self, envelope: &serde_json::Value) -> CommandOutcome {
        if let Err(e) = validate_write_envelope(envelope) {
            return CommandOutcome::failure("INVALID_ARGUMENT", e);
        }
        let incoming = match envelope.get("config").and_then(|v| v.as_object()) {
            Some(m) => m.clone(),
            None => return CommandOutcome::failure("INVALID_ARGUMENT", "config must be an object"),
        };
        let touched: Vec<String> = incoming.keys().cloned().collect();
        let engine = self.engine.clone();
        let applied = engine.update(move |cfg: &mut webconfig_engine::store::Config| {
            for (key, value) in &incoming {
                // T-P18: section merge — overlay the incoming section JSON on
                // the current section so absent fields keep their values.
                let current = section_value(cfg, key)?;
                let merged = deep_merge(current, value.clone());
                let parsed: Result<(), webconfig_engine::StoreError> = match key.as_str() {
                    "system" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::system::SystemConfig| cfg.system = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "network" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::network::NetworkConfig| cfg.network = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "services" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::services::ServicesConfig| {
                            cfg.services = v
                        })
                        .map_err(webconfig_engine::StoreError::Parse),
                    "updates" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::updates::UpdatesConfig| cfg.updates = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "monitoring" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::monitoring::MonitoringConfig| {
                            cfg.monitoring = v
                        })
                        .map_err(webconfig_engine::StoreError::Parse),
                    "logs" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::logs::LogsConfig| cfg.logs = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "alerts" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::alerts::AlertsConfig| cfg.alerts = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "security" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::security::SecurityConfig| {
                            cfg.security = v
                        })
                        .map_err(webconfig_engine::StoreError::Parse),
                    "io" => serde_json::from_value(merged)
                        .map(|v: webconfig_engine::store::io::IoConfig| cfg.io = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "app_settings" => {
                        serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(merged)
                            .map(|v| cfg.app_settings = v)
                            .map_err(webconfig_engine::StoreError::Parse)
                    }
                    other => Err(webconfig_engine::StoreError::Validation(format!(
                        "unknown config section {other}"
                    ))),
                };
                parsed?;
            }
            Ok(())
        });
        match applied {
            Ok(_) => {
                // T-P18 (SB-6d): run the appliers for the touched sections and
                // report one outcome per applier.
                let results = self.apply_sections(&touched).await;
                let any_failed = results.iter().any(|r| r.1.is_err());
                let any_provisional = results.iter().any(|r| {
                    matches!(
                        r.1,
                        Ok(webconfig_engine::applier::ApplyOutcome::Provisional { .. })
                    )
                });
                let appliers_json: Vec<serde_json::Value> = results
                    .iter()
                    .map(|(id, r)| match r {
                        Ok(webconfig_engine::applier::ApplyOutcome::Committed) => {
                            serde_json::json!({"id": id, "ok": true, "outcome": "committed"})
                        }
                        Ok(webconfig_engine::applier::ApplyOutcome::Provisional {
                            confirm_window_secs,
                        }) => serde_json::json!({"id": id, "ok": true, "outcome": "provisional", "confirm_window_secs": confirm_window_secs}),
                        Err(e) => serde_json::json!({"id": id, "ok": false, "error": e}),
                    })
                    .collect();
                let payload = serde_json::json!({
                    "applied": !any_failed,
                    "origin": "hq",
                    "schema_version": webconfig_engine::CONFIG_SCHEMA_VERSION,
                    "sections": touched,
                    "appliers": appliers_json,
                    "confirm_armed": any_provisional,
                });
                if any_failed {
                    CommandOutcome::ok_json("PARTIAL", payload.to_string())
                } else {
                    CommandOutcome::ok_json("OK", payload.to_string())
                }
            }
            Err(e) => CommandOutcome::failure("INVALID_ARGUMENT", e.to_string()),
        }
    }

    /// Apply the appliers owned by the touched config sections (T-P18).
    async fn apply_sections(
        &self,
        sections: &[String],
    ) -> Vec<(String, Result<ApplyOutcome, String>)> {
        let mut ids: Vec<&str> = Vec::new();
        for s in sections {
            for id in section_appliers(s) {
                if !ids.contains(id) {
                    ids.push(id);
                }
            }
        }
        let mut out = Vec::new();
        for id in ids {
            match self.engine.apply(id).await {
                Ok(o) => out.push((id.to_string(), Ok(o))),
                Err(e) => out.push((id.to_string(), Err(e.to_string()))),
            }
        }
        out
    }

    /// T-P11 (B05): provision the operator account's authorized_keys from an
    /// HQ command. Stores the keys in the config store and runs the ssh
    /// applier immediately — the outcome reports the apply result (the keys
    /// must be ON the device, not merely stored).
    pub async fn set_ssh_keys(&self, keys: &str) -> CommandOutcome {
        let engine = self.engine.clone();
        let keys = keys.to_string();
        let stored = engine.update(move |cfg: &mut webconfig_engine::store::Config| {
            cfg.system.ssh.authorized_keys = keys;
            Ok(())
        });
        if let Err(e) = stored {
            return CommandOutcome::failure("INVALID_ARGUMENT", e.to_string());
        }
        match self.engine.apply("ssh").await {
            Ok(outcome) => CommandOutcome::ok_json(
                "OK",
                serde_json::json!({
                    "applied": true,
                    "applier": "ssh",
                    "outcome": match outcome {
                        webconfig_engine::applier::ApplyOutcome::Committed => "committed",
                        webconfig_engine::applier::ApplyOutcome::Provisional { .. } => "provisional",
                    },
                })
                .to_string(),
            ),
            Err(e) => CommandOutcome::failure("INTERNAL", e.to_string()),
        }
    }

    /// `take_backup_now` (task 009, H7): build the redacted backup document,
    /// register it for upload, and publish a `LogUploadRequest(BACKUP)`; the
    /// gateway answers with a presigned URL and [`UploadExecutor`] PUTs it.
    pub async fn backup_now(&self, mailbox: &AgentMailbox) -> CommandOutcome {
        let doc = match self.backup_document() {
            Ok(d) => d,
            Err(e) => return CommandOutcome::failure("INTERNAL", e),
        };
        let body = serde_json::to_vec_pretty(&doc).unwrap_or_default();
        let dir = self.sysroot.webconfig_dir().join("hq-uploads");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return CommandOutcome::failure("INTERNAL", format!("upload dir: {e}"));
        }
        let stamp = time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string();
        let path = dir.join(format!("backup-{stamp}.json"));
        if let Err(e) = std::fs::write(&path, &body) {
            return CommandOutcome::failure("INTERNAL", format!("backup write: {e}"));
        }
        let client_ref = self.coordinator.register(PendingUpload {
            kind: pb::log_upload_request::Kind::Backup,
            path: path.clone(),
            size_bytes: body.len() as u64,
            client_ref: String::new(),
        });
        let sent = mailbox.try_publish(upload_request_frame(
            pb::log_upload_request::Kind::Backup,
            body.len() as u64,
            &client_ref,
        ));
        CommandOutcome::ok_json(
            "OK",
            serde_json::json!({
                "status": if sent { "upload_pending" } else { "upload_deferred" },
                "size_bytes": body.len(),
                "secrets_included": false,
            })
            .to_string(),
        )
    }

    /// `restore` from an HQ-provided download URL (task 009, H3): the blob is
    /// a redacted device backup document; secrets were never in it.
    pub async fn restore_from_url(&self, url: &str) -> CommandOutcome {
        if url.is_empty() {
            return CommandOutcome::failure("INVALID_ARGUMENT", "backup_download_url is required");
        }
        let dir = self.sysroot.webconfig_dir().join("hq-uploads");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return CommandOutcome::failure("INTERNAL", format!("download dir: {e}"));
        }
        let stamp = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        let path = dir.join(format!("restore-{stamp}.json"));
        let target = path.clone();
        let url = url.to_string();
        let download = tokio::task::spawn_blocking(move || {
            webconfig_engine::applier::run_local(
                "curl",
                &[
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "300",
                    "--output",
                    &target.to_string_lossy(),
                    &url,
                ],
            )
        })
        .await;
        if let Err(e) = download {
            let _ = std::fs::remove_file(&path);
            return CommandOutcome::failure("INTERNAL", format!("restore download: {e}"));
        }
        let raw = match std::fs::read(&path) {
            Ok(r) => r,
            Err(e) => return CommandOutcome::failure("INTERNAL", format!("restore read: {e}")),
        };
        let _ = std::fs::remove_file(&path);
        let file: ConfigFile = match serde_json::from_slice(&raw) {
            Ok(f) => f,
            Err(e) => {
                return CommandOutcome::failure(
                    "INVALID_ARGUMENT",
                    format!("downloaded backup is not a device backup document: {e}"),
                )
            }
        };
        if file.schema_version > webconfig_engine::CONFIG_SCHEMA_VERSION {
            return CommandOutcome::failure(
                "FAILED_PRECONDITION",
                format!(
                    "backup schema_version {} > engine {}",
                    file.schema_version,
                    webconfig_engine::CONFIG_SCHEMA_VERSION
                ),
            );
        }
        match self.engine.store.commit(&file) {
            Ok(()) => CommandOutcome::ok_json("OK", r#"{"restored": true}"#),
            Err(e) => CommandOutcome::failure("INTERNAL", e.to_string()),
        }
    }

    /// `apply_update` (task 009, H3): download the artifact, verify the
    /// declared SHA-256, verify the bundle, install to the inactive slot.
    /// Reboot-to-apply is deliberately NOT automatic: the commit/confirm
    /// rollback window stays operator-controlled (spec §4.2/§4.4).
    pub async fn apply_update(&self, args: &serde_json::Value) -> CommandOutcome {
        let url = args
            .get("artifact_download_url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let expected = args
            .get("checksum_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if url.is_empty() {
            return CommandOutcome::failure(
                "INVALID_ARGUMENT",
                "artifact_download_url is required",
            );
        }
        if expected.len() != 64 {
            return CommandOutcome::failure(
                "INVALID_ARGUMENT",
                "checksum_sha256 must be a SHA-256 hex digest",
            );
        }
        // Staged outside /pst (1 GiB, shared): see Sysroot::ota_staging_dir.
        let dir = self.sysroot.ota_staging_dir().join("hq-uploads");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return CommandOutcome::failure("INTERNAL", format!("download dir: {e}"));
        }
        let path = dir.join("hq-artifact.bundle");
        let target = path.clone();
        let url = url.to_string();
        let download = tokio::task::spawn_blocking(move || {
            webconfig_engine::applier::run_local(
                "curl",
                &[
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "1800",
                    "--output",
                    &target.to_string_lossy(),
                    &url,
                ],
            )
        })
        .await;
        if let Err(e) = download {
            let _ = std::fs::remove_file(&path);
            return CommandOutcome::failure("INTERNAL", format!("artifact download: {e}"));
        }
        // Streaming digest: the daemon is capped at 32 MiB and a bundle is
        // hundreds of MB (reading it whole OOM-killed webconfigd).
        let hash_path = path.clone();
        let digest = match tokio::task::spawn_blocking(move || {
            webconfig_engine::applier::sha256_file(&hash_path)
        })
        .await
        {
            Ok(Ok((_, d))) => d,
            Ok(Err(e)) => {
                return CommandOutcome::failure("INTERNAL", format!("artifact read: {e}"))
            }
            Err(e) => return CommandOutcome::failure("INTERNAL", e.to_string()),
        };
        if digest != expected.to_ascii_lowercase() {
            let _ = std::fs::remove_file(&path);
            return CommandOutcome::failure("FAILED_PRECONDITION", "artifact checksum mismatch");
        }
        let bundle_path = path.to_string_lossy().to_string();
        let backend = self.update_backend.clone();
        let verified =
            tokio::task::spawn_blocking(move || backend.verify_bundle(&bundle_path)).await;
        let manifest = match verified {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                let _ = std::fs::remove_file(&path);
                return CommandOutcome::failure("FAILED_PRECONDITION", e.to_string());
            }
            Err(e) => return CommandOutcome::failure("INTERNAL", e.to_string()),
        };
        let backend = self.update_backend.clone();
        let install_path = path.clone();
        let installed = tokio::task::spawn_blocking(move || {
            let mut progress = |_p: webconfig_engine::update::InstallProgress| {};
            backend.install(&install_path.to_string_lossy(), &mut progress)
        })
        .await;
        let _ = std::fs::remove_file(&path);
        match installed {
            Ok(Ok(())) => CommandOutcome::ok_json(
                "OK",
                serde_json::json!({
                    "installed": true,
                    "reboot_required": true,
                    "artifact_version": manifest.version,
                })
                .to_string(),
            ),
            Ok(Err(e)) => CommandOutcome::failure("INTERNAL", e.to_string()),
            Err(e) => CommandOutcome::failure("INTERNAL", e.to_string()),
        }
    }

    /// `factory_reset` (task 009, H4): the HQ path must carry the same
    /// confirmation istate demands for its own `factory-reset` op.
    pub fn factory_reset(&self) -> CommandOutcome {
        let failures = crate::api::system::factory_reset_core(&self.sysroot, "settings");
        if failures.is_empty() {
            // T-P20: acknowledge first, reboot after POWER_ACTION_DELAY (an
            // unacknowledged reset would be re-delivered after the reboot).
            self.schedule_power_action("factory_reset", || {
                webconfig_engine::applier::run_cmd("systemctl", &["reboot"])
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            });
            CommandOutcome::ok_json("OK", r#"{"factory_reset": true, "mode": "settings"}"#)
        } else {
            CommandOutcome::failure(
                "INTERNAL",
                format!("factory reset partial failures: {}", failures.join("; ")),
            )
        }
    }

    /// Run a power-affecting action after [`POWER_ACTION_DELAY`] on a
    /// blocking thread (T-P20), so the command outcome is acknowledged first.
    /// A no-op outside the real root (fake-sysroot tests must never reboot
    /// the host). Returns whether the action was scheduled.
    fn schedule_power_action<F>(&self, label: &'static str, action: F) -> bool
    where
        F: FnOnce() -> Result<(), String> + Send + 'static,
    {
        if !self.sysroot.is_real_root() {
            tracing::info!(action = label, "power action skipped (not the real root)");
            return false;
        }
        tokio::spawn(async move {
            tokio::time::sleep(POWER_ACTION_DELAY).await;
            match tokio::task::spawn_blocking(action).await {
                Ok(Ok(())) => tracing::info!(action = label, "power action executed"),
                Ok(Err(e)) => tracing::error!(action = label, error = %e, "power action failed"),
                Err(e) => tracing::error!(action = label, error = %e, "power action panicked"),
            }
        });
        true
    }

    fn scheduled(&self, what: &str, scheduled: bool) -> CommandOutcome {
        CommandOutcome::ok_json(
            "OK",
            serde_json::json!({
                "action": what,
                "scheduled": scheduled,
                "delay_s": POWER_ACTION_DELAY.as_secs(),
            })
            .to_string(),
        )
    }

    /// `system.reboot` (T-P20, C04).
    pub fn reboot(&self) -> CommandOutcome {
        let s = self.schedule_power_action("system.reboot", || {
            webconfig_engine::applier::run_cmd("systemctl", &["reboot"])
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        self.scheduled("reboot", s)
    }

    /// `system.shutdown` (T-P20, C05). Confirmation-gated in the handler.
    pub fn shutdown(&self) -> CommandOutcome {
        let s = self.schedule_power_action("system.shutdown", || {
            webconfig_engine::applier::run_cmd("systemctl", &["poweroff"])
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        self.scheduled("shutdown", s)
    }

    /// `update.reboot_to_apply` (T-P20, K10): tryboot into the freshly
    /// installed slot; firmware rollback protects a slot that never boots.
    pub fn reboot_to_apply(&self) -> CommandOutcome {
        let backend = self.update_backend.clone();
        let s = self.schedule_power_action("update.reboot_to_apply", move || {
            backend.reboot_to_apply().map_err(|e| e.to_string())
        });
        self.scheduled("reboot_to_apply", s)
    }

    /// `update.rollback` (T-P20, K10): re-arm the previous slot and reboot.
    /// Confirmation-gated in the handler.
    pub fn rollback_update(&self) -> CommandOutcome {
        let backend = self.update_backend.clone();
        let s = self.schedule_power_action("update.rollback", move || {
            backend.rollback().map_err(|e| e.to_string())
        });
        self.scheduled("rollback", s)
    }

    /// `update.confirm` (T-P20, K05/K10): mark the running slot good. No
    /// reboot, so it runs synchronously and reports the real result.
    pub async fn confirm_update(&self) -> CommandOutcome {
        let backend = self.update_backend.clone();
        match tokio::task::spawn_blocking(move || backend.mark_good()).await {
            Ok(Ok(())) => CommandOutcome::ok_json("OK", r#"{"confirmed": true}"#),
            Ok(Err(e)) => CommandOutcome::failure("FAILED_PRECONDITION", e.to_string()),
            Err(e) => CommandOutcome::failure("INTERNAL", e.to_string()),
        }
    }

    /// `service.control` (T-P20, G02): start/stop/restart/enable/disable one
    /// unit from the board manifest's service allowlist, then report its
    /// state.
    pub async fn service_control(&self, unit: &str, action: &str) -> CommandOutcome {
        if !self.service_allowlist.iter().any(|u| u == unit) {
            return CommandOutcome::failure(
                "PERMISSION_DENIED",
                format!("unit {unit:?} is not in the service allowlist"),
            );
        }
        let result = match action {
            "start" => self.systemd.start(unit).await,
            "stop" => self.systemd.stop(unit).await,
            "restart" => self.systemd.restart(unit).await,
            "enable" => self.systemd.enable(unit).await,
            "disable" => self.systemd.disable(unit).await,
            other => {
                return CommandOutcome::failure(
                    "INVALID_ARGUMENT",
                    format!("unsupported service action {other:?}"),
                )
            }
        };
        if let Err(e) = result {
            return CommandOutcome::failure("INTERNAL", e.to_string());
        }
        let state = self.systemd.status(unit).await.ok();
        CommandOutcome::ok_json(
            "OK",
            serde_json::json!({ "unit": unit, "action": action, "state": state }).to_string(),
        )
    }

    /// `log_bundle.request` (T-P20, J04): ask logmanager for a support
    /// bundle, fetch its bytes and publish a `LogUploadRequest(LOG_BUNDLE)`;
    /// the gateway answers with a presigned URL and the upload executor PUTs
    /// it — the same path istate-originated bundles take.
    pub async fn request_log_bundle(&self, mailbox: &AgentMailbox) -> CommandOutcome {
        let created = match self
            .istate
            .relay_command("logmanager".into(), "bundle-create".into(), "{}".into())
            .await
        {
            Ok(v) => v,
            Err(e) => return CommandOutcome::failure("UNAVAILABLE", format!("bundle-create: {e}")),
        };
        let handle = match created.get("handle").and_then(|v| v.as_str()) {
            Some(h) if !h.is_empty() => h.to_string(),
            _ => return CommandOutcome::failure("INTERNAL", "bundle-create returned no handle"),
        };
        let upload = match self.fetch_bundle(&handle).await {
            Ok(u) => u,
            Err(e) => return CommandOutcome::failure("INTERNAL", e),
        };
        let size = upload.size_bytes;
        let client_ref = self.coordinator.register(upload);
        let sent = mailbox.try_publish(upload_request_frame(
            pb::log_upload_request::Kind::LogBundle,
            size,
            &client_ref,
        ));
        CommandOutcome::ok_json(
            "OK",
            serde_json::json!({
                "handle": handle,
                "size_bytes": size,
                "status": if sent { "upload_pending" } else { "upload_deferred" },
            })
            .to_string(),
        )
    }

    /// `users.*` (T-P20, B02): the local web-UI account store, driven from
    /// HQ with the same rules as the admin-only local endpoints (last-admin
    /// guard, argon2, role parsing). Password hashes never leave the device.
    pub fn users(&self, op: &str, args: &serde_json::Value) -> CommandOutcome {
        use webconfig_engine::users::{Role, UserStore};
        let str_arg = |k: &str| {
            args.get(k)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        };
        let mut store = match UserStore::load(&self.users_path) {
            Ok(s) => s,
            Err(e) => return CommandOutcome::failure("INTERNAL", e.to_string()),
        };
        let listing = |store: &UserStore| {
            serde_json::json!({
                "users": store.users.iter().map(|u| serde_json::json!({
                    "username": u.username,
                    "role": u.role.as_str(),
                    "groups": u.groups,
                })).collect::<Vec<_>>()
            })
        };
        let mutated = match op {
            "users.list" => return CommandOutcome::ok_json("OK", listing(&store).to_string()),
            "users.create" => {
                let password = str_arg("password");
                if password.len() < 8 {
                    return CommandOutcome::failure("INVALID_ARGUMENT", "password >= 8 chars");
                }
                Role::parse(&str_arg("role"))
                    .and_then(|role| store.add(&str_arg("username"), &password, role))
            }
            "users.delete" => store.remove(&str_arg("username")),
            "users.set_role" => Role::parse(&str_arg("role"))
                .and_then(|role| store.set_role(&str_arg("username"), role)),
            other => {
                return CommandOutcome::failure(
                    "INVALID_ARGUMENT",
                    format!("unsupported users operation {other:?}"),
                )
            }
        };
        if let Err(e) = mutated {
            return CommandOutcome::failure("FAILED_PRECONDITION", e.to_string());
        }
        if let Err(e) = store.save(&self.users_path) {
            return CommandOutcome::failure("INTERNAL", e.to_string());
        }
        CommandOutcome::ok_json("OK", listing(&store).to_string())
    }

    /// Fetch a logmanager bundle by handle over istate (RelayCommand →
    /// bundle-fetch) and read its bytes from the bulk socket (§7.7: payload
    /// bytes never traverse the control path).
    pub async fn fetch_bundle(&self, handle: &str) -> Result<PendingUpload, String> {
        let payload = self
            .istate
            .relay_command(
                "logmanager".into(),
                "bundle-fetch".into(),
                format!("{{\"handle\":\"{handle}\"}}"),
            )
            .await
            .map_err(|e| format!("bundle-fetch relay: {e}"))?;
        let bulk_socket = payload
            .get("bulk_socket")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "bundle-fetch reply missing bulk_socket".to_string())?
            .to_string();
        let handle_for_path = handle.to_string();
        let handle = handle.to_string();
        let bytes = tokio::task::spawn_blocking(move || read_bulk(&bulk_socket, &handle))
            .await
            .map_err(|e| format!("bulk fetch join: {e}"))?
            .map_err(|e| format!("bulk fetch: {e}"))?;
        let dir = self.sysroot.webconfig_dir().join("hq-uploads");
        std::fs::create_dir_all(&dir).map_err(|e| format!("upload dir: {e}"))?;
        let path = dir.join(format!(
            "bundle-{}",
            handle_for_path.trim_start_matches('/')
        ));
        std::fs::write(&path, &bytes).map_err(|e| format!("bundle write: {e}"))?;
        Ok(PendingUpload {
            kind: pb::log_upload_request::Kind::LogBundle,
            path,
            size_bytes: bytes.len() as u64,
            client_ref: String::new(),
        })
    }
}

/// Read the logmanager bulk socket: 4-byte LE length frame carrying the
/// handle, then the payload bytes until EOF (Instrumentation §7.7).
fn read_bulk(socket_path: &str, handle: &str) -> std::io::Result<Vec<u8>> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket_path)?;
    let mut framed = Vec::with_capacity(4 + handle.len());
    framed.extend_from_slice(&(handle.len() as u32).to_le_bytes());
    framed.extend_from_slice(handle.as_bytes());
    stream.write_all(&framed)?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn now_unix_ms() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp() * 1000
}

/// istate telemetry batch → AgentLink `TelemetryBatch` frame.
fn forward_telemetry(mailbox: &AgentMailbox, payload: &str) {
    let parsed: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => return,
    };
    let wall_ms = parsed
        .get("wall_unix_ms")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let recorded_at = if wall_ms > 0 { wall_ms } else { now_unix_ms() };
    let firmware = parsed
        .get("firmware_version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let serial = parsed
        .get("device_serial")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut samples = Vec::new();
    if let Some(records) = parsed.get("records").and_then(|v| v.as_array()) {
        for r in records {
            let metric = r
                .get("metric")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if metric.is_empty() {
                continue;
            }
            let mut tags: std::collections::HashMap<String, String> = r
                .get("tags")
                .and_then(|v| v.as_object())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default();
            tags.insert("device_serial".into(), serial.clone());
            tags.insert("firmware_version".into(), firmware.clone());
            if let Some(unit) = r.get("unit").and_then(|v| v.as_str()) {
                tags.insert("unit".into(), unit.to_string());
            }
            samples.push(pb::TelemetrySample {
                metric,
                value: r.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0),
                recorded_at_unix_ms: recorded_at,
                tags,
            });
        }
    }
    if samples.is_empty() {
        return;
    }
    let frame = pb::AgentFrame {
        body: Some(pb::agent_frame::Body::TelemetryBatch(pb::TelemetryBatch {
            samples,
            location: None,
        })),
    };
    if !mailbox.try_publish(frame) {
        tracing::debug!("telemetry frame dropped (mailbox saturated or agent offline)");
    }
}

/// istate fault severity (X.733 scale) → AgentLink FaultEvent severity.
fn map_severity(sev: i64) -> i32 {
    match sev {
        0 => pb::fault_event::Severity::Info as i32,
        1 | 2 => pb::fault_event::Severity::Warn as i32,
        _ => pb::fault_event::Severity::Critical as i32,
    }
}

/// istate fault record → AgentLink `FaultEvent` frame (raise).
fn forward_fault(mailbox: &AgentMailbox, payload: &str) {
    let parsed: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => return,
    };
    let at_unix_ms = parsed
        .get("wall_unix_ms")
        .and_then(|v| v.as_i64())
        .unwrap_or_else(now_unix_ms);
    let event = pb::FaultEvent {
        code: parsed
            .get("rule")
            .and_then(|v| v.as_str())
            .or_else(|| parsed.get("device_key").and_then(|v| v.as_str()))
            .unwrap_or("UNKNOWN")
            .to_string(),
        severity: map_severity(parsed.get("severity").and_then(|v| v.as_i64()).unwrap_or(0)),
        message: parsed
            .get("raw_line")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        kind: pb::fault_event::Kind::Raised.into(),
        at_unix_ms,
        fault_code_ref: String::new(),
    };
    let frame = pb::AgentFrame {
        body: Some(pb::agent_frame::Body::FaultEvent(event)),
    };
    if !mailbox.try_publish(frame) {
        tracing::debug!("fault frame dropped (agent offline or saturated)");
    }
}

/// istate log_ref (bundle handle) → bulk fetch + `LogUploadRequest` publish.
async fn forward_bundle(ops: &DeviceOps, mailbox: &AgentMailbox, payload: &str) {
    let parsed: serde_json::Value = match serde_json::from_str(payload) {
        Ok(v) => v,
        Err(_) => return,
    };
    let handle = match parsed.get("handle").and_then(|v| v.as_str()) {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => return,
    };
    // Fetch the bytes first: a bundle we cannot read must not consume a
    // presigned URL at HQ.
    let upload = match ops.fetch_bundle(&handle).await {
        Ok(u) => u,
        Err(e) => {
            tracing::debug!(handle = %handle, error = %e, "bundle fetch failed; no upload requested");
            return;
        }
    };
    let size = upload.size_bytes;
    let client_ref = ops.coordinator.register(upload);
    let frame = upload_request_frame(pb::log_upload_request::Kind::LogBundle, size, &client_ref);
    if !mailbox.try_publish(frame) {
        tracing::debug!("log upload request dropped (agent offline or saturated)");
    }
}

/// The istate → AgentLink data bridge (task 009, P3.3).
///
/// Subscribes to istate's `StreamDeviceData` while the pairing state is
/// Enrolled, maps spool records to AgentLink frames, and publishes them via
/// the agent mailbox. A monotonic `since` watermark makes reconnects replay
/// only what was missed (no duplicate telemetry at HQ).
pub async fn run_data_bridge(
    ops: Arc<DeviceOps>,
    pairing: Arc<std::sync::Mutex<webconfig_engine::pairing::PairingAgent>>,
    mailbox: AgentMailbox,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut since: u64 = 0;
    loop {
        if *shutdown.borrow() {
            return;
        }
        let enrolled = {
            let a = pairing.lock().expect("pairing agent lock");
            a.state() == webconfig_engine::pairing::PairingState::Enrolled
        };
        if !enrolled {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => continue,
                _ = shutdown.changed() => return,
            }
        }
        let mut stream = match ops
            .istate
            .stream_device_data(
                vec!["telemetry".into(), "fault".into(), "log_ref".into()],
                since,
            )
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(error = %e, "device data bridge: istate stream unavailable");
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => continue,
                    _ = shutdown.changed() => return,
                }
            }
        };
        loop {
            let next = tokio::select! {
                _ = shutdown.changed() => return,
                item = stream.message() => item,
            };
            match next {
                Ok(Some(record)) => {
                    let mono_ns = record.ts.as_ref().map(|t| t.mono_ns).unwrap_or(0);
                    if mono_ns > since {
                        since = mono_ns;
                    }
                    match record.r#type.as_str() {
                        "telemetry" => forward_telemetry(&mailbox, &record.payload_json),
                        "fault" => forward_fault(&mailbox, &record.payload_json),
                        "log_ref" => forward_bundle(&ops, &mailbox, &record.payload_json).await,
                        other => tracing::trace!(class = other, "unmapped data record"),
                    }
                }
                Ok(None) => break, // stream closed; reconnect loop re-subscribes
                Err(status) => {
                    tracing::debug!(%status, "device data bridge: stream error");
                    break;
                }
            }
        }
    }
}

// ── T-P24: device status snapshot for the HQ heartbeat ────────────────────

/// How often the heartbeat snapshot is refreshed.
pub const STATUS_SNAPSHOT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// `VERSION` from os-release (quotes stripped).
fn os_release_version(sysroot: &Sysroot) -> String {
    std::fs::read_to_string(sysroot.join("/etc/os-release"))
        .ok()
        .and_then(|raw| {
            raw.lines()
                .find_map(|l| l.strip_prefix("VERSION="))
                .map(|v| v.trim_matches('"').to_string())
        })
        .unwrap_or_default()
}

/// systemd's view of clock synchronisation (timesyncd/chrony via timedated).
fn time_synchronized(sysroot: &Sysroot) -> bool {
    if !sysroot.is_real_root() {
        return false;
    }
    std::process::Command::new("timedatectl")
        .args(["show", "--property=NTPSynchronized", "--value"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "yes")
        .unwrap_or(false)
}

impl DeviceOps {
    /// Build one heartbeat snapshot from what the device already knows
    /// (update backend, istate, systemd, os-release). Every source is
    /// best-effort: an unreachable source leaves its fields empty.
    pub async fn status_snapshot(&self) -> pb::DeviceStatus {
        let mut status = pb::DeviceStatus {
            image_version: os_release_version(&self.sysroot),
            collected_at_unix_ms: now_unix_ms(),
            ..Default::default()
        };
        status
            .component_versions
            .insert("webconfigd".into(), env!("CARGO_PKG_VERSION").into());
        let backend = self.update_backend.clone();
        if let Ok(Ok(slots)) = tokio::task::spawn_blocking(move || backend.slots()).await {
            if let Some(running) = slots.iter().find(|s| s.running) {
                status.running_slot = running.slot.clone();
                status.slot_confirmed = running.confirmed;
            }
        }
        if let Ok(snap) = self.istate.system_snapshot().await {
            status.health_known = true;
            status.health_score = snap.health_score;
            status.serial = snap.serial;
            status.hardware_revision = snap.hw_revision;
            status.istate_state = snap.istate_state;
            if !snap.suite_version.is_empty() {
                status
                    .component_versions
                    .insert("instrumentation".into(), snap.suite_version);
            }
        }
        for unit in &self.service_allowlist {
            let active = match self.systemd.status(unit).await {
                Ok(s) => s.active,
                Err(_) => "unknown".into(),
            };
            status.services.push(pb::ServiceState {
                unit: unit.clone(),
                active,
            });
        }
        let sysroot = self.sysroot.clone();
        status.time_synchronized = tokio::task::spawn_blocking(move || time_synchronized(&sysroot))
            .await
            .unwrap_or(false);
        status
    }
}

/// Refresh the heartbeat snapshot forever (T-P24).
pub async fn run_status_snapshot(ops: Arc<DeviceOps>) {
    loop {
        let status = ops.status_snapshot().await;
        hq_agent::set_device_status(status);
        tokio::time::sleep(STATUS_SNAPSHOT_INTERVAL).await;
    }
}

#[cfg(test)]
mod upload_coordinator_tests {
    use super::*;

    fn upload(kind: pb::log_upload_request::Kind, name: &str) -> PendingUpload {
        PendingUpload {
            kind,
            path: PathBuf::from(name),
            size_bytes: 1,
            client_ref: String::new(),
        }
    }

    /// T-P22: an echoed client_ref selects exactly its blob, even when
    /// uploads of both kinds interleave (positional matching could PUT a
    /// backup into a log-bundle object).
    #[test]
    fn client_ref_selects_the_matching_upload() {
        let c = UploadCoordinator::new();
        let bundle = c.register(upload(pb::log_upload_request::Kind::LogBundle, "bundle"));
        let backup = c.register(upload(pb::log_upload_request::Kind::Backup, "backup"));
        assert_ne!(bundle, backup);
        let got = c
            .take_for(&backup, pb::log_upload_request::Kind::LogBundle)
            .unwrap();
        assert_eq!(got.path, PathBuf::from("backup"));
        assert!(c
            .take_for(&backup, pb::log_upload_request::Kind::Backup)
            .is_none());
        assert_eq!(c.pending_count(), 1);
    }

    /// Pre-T-P22 gateway (no echo): positional by kind, as before.
    #[test]
    fn empty_client_ref_falls_back_to_kind() {
        let c = UploadCoordinator::new();
        c.register(upload(pb::log_upload_request::Kind::LogBundle, "bundle"));
        c.register(upload(pb::log_upload_request::Kind::Backup, "backup"));
        let got = c
            .take_for("", pb::log_upload_request::Kind::Backup)
            .unwrap();
        assert_eq!(got.path, PathBuf::from("backup"));
    }
}
