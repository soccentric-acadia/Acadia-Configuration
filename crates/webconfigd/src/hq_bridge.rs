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

/// Base64-standard or hex decode of a signature field.
fn decode_signature(algorithm: &str, raw: &str) -> Result<Vec<u8>, String> {
    match algorithm {
        "ed25519" => base64::engine::general_purpose::STANDARD
            .decode(raw)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
            .map_err(|_| "signature is not base64".to_string()),
        "HMAC-SHA256" => {
            let hex = raw.trim();
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("HMAC-SHA256 signature must be 64 hex chars".into());
            }
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|e| e.to_string())
        }
        other => Err(format!("unsupported signature_algorithm {other}")),
    }
}

/// Envelope validation for `configuration.write` (task 009, H5).
///
/// Transitional verification policy (mirrors istate `SignedConfig`): Ed25519
/// is the target; while no HQ signing key is provisioned the signature is
/// length-checked only, and the unverified use is recorded in the audit
/// trail. Verification becomes mandatory when key provisioning lands.
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
    let raw = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("signature is required")?;
    let bytes = decode_signature(algorithm, raw).map_err(|e| format!("signature rejected: {e}"))?;
    let expected_len = match algorithm {
        // Ed25519 signature; HMAC-SHA256 is a 32-byte digest (transitional).
        "ed25519" => 64,
        "HMAC-SHA256" => 32,
        _ => return Err("unsupported signature_algorithm".into()),
    };
    if bytes.len() != expected_len {
        return Err(format!("signature must decode to {expected_len} bytes"));
    }
    Ok(())
}

/// One queued device→HQ upload blob.
#[derive(Debug)]
pub struct PendingUpload {
    pub kind: pb::log_upload_request::Kind,
    pub path: PathBuf,
    pub size_bytes: u64,
}

/// Registry of uploads created by the device that await a presigned URL.
///
/// `LogUploadRequest` carries no client-side request id (the gateway's
/// `request_ref` is its own object id), so a URL is matched to the oldest
/// pending upload, in order. Overlapping requests queue in FIFO order.
#[derive(Default)]
pub struct UploadCoordinator {
    pending: Mutex<VecDeque<PendingUpload>>,
}

impl UploadCoordinator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an upload awaiting its presigned URL.
    pub fn register(&self, upload: PendingUpload) {
        self.pending.lock().expect("upload queue lock").push_back(upload);
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
}

#[async_trait::async_trait]
impl hq_agent::ServerFrameHooks for UploadExecutor {
    async fn on_signed_upload_url(&self, url: pb::SignedUploadUrl) {
        let kind = pb::log_upload_request::Kind::LogBundle;
        let pending = match self.coordinator.take(kind) {
            Some(p) => p,
            None => {
                tracing::warn!(request_ref = %url.request_ref, "signed upload url with no pending upload");
                return;
            }
        };
        tracing::info!(request_ref = %url.request_ref, size = pending.size_bytes, "uploading pending blob");
        let path = pending.path.clone();
        let upload_url = url.upload_url.clone();
        let audit = self.audit.clone();
        let request_ref = url.request_ref.clone();
        let result = tokio::task::spawn_blocking(move || {
            webconfig_engine::applier::run_cmd(
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
        let _ = audit.append(&AuditEntry {
            ts: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            user: "hq".into(),
            action: "upload".into(),
            detail: Some(format!("{request_ref}: {}", if ok { "uploaded" } else { "failed" })),
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
}

impl DeviceOps {
    /// Redacted configuration document — the same document the web UI's
    /// `GET /updates/backup` returns: secrets never leave the device
    /// unencrypted, and HQ never receives them (spec §4.4).
    fn backup_document(&self) -> Result<serde_json::Value, String> {
        let mut cfg = self.engine.load().map_err(|e| format!("config load failed: {e}"))?;
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
            Ok(doc) => CommandOutcome::ok_json("OK", serde_json::to_string(&doc).unwrap_or_default()),
            Err(e) => CommandOutcome::failure("INTERNAL", e),
        }
    }

    /// `configuration.write` (task 009, H5): a signed, origin=hq envelope.
    ///
    /// Sections present in `config` replace the device value; absent sections
    /// are untouched (a partial merge, not a blind replace).
    pub async fn write_configuration(&self, envelope: &serde_json::Value) -> CommandOutcome {
        if let Err(e) = validate_write_envelope(envelope) {
            return CommandOutcome::failure("INVALID_ARGUMENT", e);
        }
        let incoming = match envelope.get("config").and_then(|v| v.as_object()) {
            Some(m) => m.clone(),
            None => return CommandOutcome::failure("INVALID_ARGUMENT", "config must be an object"),
        };
        let engine = self.engine.clone();
        let applied = engine.update(move |cfg: &mut webconfig_engine::store::Config| {
            for (key, value) in &incoming {
                let parsed: Result<(), webconfig_engine::StoreError> = match key.as_str() {
                    "system" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::system::SystemConfig| cfg.system = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "network" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::network::NetworkConfig| cfg.network = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "services" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::services::ServicesConfig| cfg.services = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "updates" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::updates::UpdatesConfig| cfg.updates = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "monitoring" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::monitoring::MonitoringConfig| cfg.monitoring = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "logs" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::logs::LogsConfig| cfg.logs = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "alerts" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::alerts::AlertsConfig| cfg.alerts = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "security" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::security::SecurityConfig| cfg.security = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "io" => serde_json::from_value(value.clone())
                        .map(|v: webconfig_engine::store::io::IoConfig| cfg.io = v)
                        .map_err(webconfig_engine::StoreError::Parse),
                    "app_settings" => serde_json::from_value::<
                        serde_json::Map<String, serde_json::Value>,
                    >(value.clone())
                    .map(|map| {
                        for (sk, sv) in map {
                            cfg.app_settings.insert(sk, sv);
                        }
                    })
                    .map_err(webconfig_engine::StoreError::Parse),
                    other => Err(webconfig_engine::StoreError::Validation(format!(
                        "unknown config section {other}"
                    ))),
                };
                parsed?;
            }
            Ok(())
        });
        match applied {
            Ok(_) => CommandOutcome::ok_json(
                "OK",
                serde_json::json!({
                    "applied": true,
                    "origin": "hq",
                    "schema_version": webconfig_engine::CONFIG_SCHEMA_VERSION,
                    "signature_verification": "transitional-unverified",
                })
                .to_string(),
            ),
            Err(e) => CommandOutcome::failure("INVALID_ARGUMENT", e.to_string()),
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
        self.coordinator.register(PendingUpload {
            kind: pb::log_upload_request::Kind::Backup.into(),
            path: path.clone(),
            size_bytes: body.len() as u64,
        });
        let sent = mailbox.try_publish(pb::AgentFrame {
            body: Some(pb::agent_frame::Body::LogUploadRequest(pb::LogUploadRequest {
                kind: pb::log_upload_request::Kind::Backup.into(),
                time_range_start_unix_ms: 0,
                time_range_end_unix_ms: 0,
                size_bytes_estimate: body.len() as i64,
            })),
        });
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
            webconfig_engine::applier::run_cmd(
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
            return CommandOutcome::failure("INVALID_ARGUMENT", "artifact_download_url is required");
        }
        if expected.len() != 64 {
            return CommandOutcome::failure(
                "INVALID_ARGUMENT",
                "checksum_sha256 must be a SHA-256 hex digest",
            );
        }
        let dir = self.sysroot.webconfig_dir().join("hq-uploads");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return CommandOutcome::failure("INTERNAL", format!("download dir: {e}"));
        }
        let path = dir.join("hq-artifact.bundle");
        let target = path.clone();
        let url = url.to_string();
        let download = tokio::task::spawn_blocking(move || {
            webconfig_engine::applier::run_cmd(
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
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => return CommandOutcome::failure("INTERNAL", format!("artifact read: {e}")),
        };
        use sha2::Digest;
        let digest = format!("{:x}", sha2::Sha256::digest(&bytes));
        if digest != expected.to_ascii_lowercase() {
            let _ = std::fs::remove_file(&path);
            return CommandOutcome::failure("FAILED_PRECONDITION", "artifact checksum mismatch");
        }
        let bundle_path = path.to_string_lossy().to_string();
        let backend = self.update_backend.clone();
        let verified = tokio::task::spawn_blocking(move || backend.verify_bundle(&bundle_path)).await;
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
            if self.sysroot.is_real_root() {
                let _ = webconfig_engine::applier::run_cmd("systemctl", &["reboot"]);
            }
            CommandOutcome::ok_json("OK", r#"{"factory_reset": true, "mode": "settings"}"#)
        } else {
            CommandOutcome::failure(
                "INTERNAL",
                format!("factory reset partial failures: {}", failures.join("; ")),
            )
        }
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
        let path = dir.join(format!("bundle-{}", handle_for_path.trim_start_matches('/')));
        std::fs::write(&path, &bytes).map_err(|e| format!("bundle write: {e}"))?;
        Ok(PendingUpload {
            kind: pb::log_upload_request::Kind::LogBundle.into(),
            path,
            size_bytes: bytes.len() as u64,
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
    let size = upload.size_bytes as i64;
    ops.coordinator.register(upload);
    let frame = pb::AgentFrame {
        body: Some(pb::agent_frame::Body::LogUploadRequest(pb::LogUploadRequest {
            kind: pb::log_upload_request::Kind::LogBundle.into(),
            time_range_start_unix_ms: 0,
            time_range_end_unix_ms: 0,
            size_bytes_estimate: size,
        })),
    };
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