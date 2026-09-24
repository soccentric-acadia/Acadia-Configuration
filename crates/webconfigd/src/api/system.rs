//! System section handlers (spec §4.1): hostname + asset tag, timezone/NTP/
//! manual time, web-UI user management, sshd/serial-getty toggles + authorized
//! keys, factory reset, reboot/shutdown, read-only device info, root password.

use axum::extract::{Path, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
use webconfig_engine::store::system::SystemConfig;
use webconfig_engine::users::Role;

use crate::api::{apply_and_audit, audit, username};
use crate::auth::AuthRole;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// `GET /api/v1/system` — the system section (spec §4.1).
pub async fn get(State(app): State<AppState>) -> ApiResult<Json<SystemConfig>> {
    Ok(Json(app.engine.load()?.system))
}

/// `PUT /api/v1/system` — update hostname/time/ssh/ntp. Admin only (spec §4.1).
pub async fn put(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Json(req): Json<SystemConfig>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("system.put")?;
    validate_system_config(&req)?;
    let user = username(&session).await;
    let cfg = app.engine.update(move |c| {
        c.system = req.clone();
        Ok(())
    })?;
    audit(&app, &user, "system.put", None);
    Ok(Json(serde_json::to_value(&cfg.system).unwrap_or_default()))
}

/// Validate the system section at save time (spec §4.1). The time applier
/// re-checks all of this at apply (defense in depth), but rejecting here gives
/// the operator immediate feedback instead of a failure only when they press
/// Apply — the same "reject at save" rationale as PUT /alerts. Mirrors the
/// applier's time-sync mutex exactly: NTP, PTP, and GPS are mutually exclusive,
/// a manual date/time requires every sync source off, PTP needs a valid
/// interface + domain, and GPS needs a device path. Timezone tzdata existence
/// is left to the applier (it needs a real root).
fn validate_system_config(cfg: &SystemConfig) -> ApiResult<()> {
    let t = &cfg.time;
    let sync_sources = [t.ntp_enabled, t.ptp_enabled, t.gps_enabled]
        .into_iter()
        .filter(|enabled| *enabled)
        .count();
    if sync_sources > 1 {
        return Err(ApiError::BadRequest(
            "NTP, PTP, and GPS cannot be enabled together".into(),
        ));
    }
    if t.manual_datetime.is_some() && (t.ntp_enabled || t.ptp_enabled || t.gps_enabled) {
        return Err(ApiError::BadRequest(
            "manual_datetime requires NTP, PTP, and GPS synchronization to be disabled".into(),
        ));
    }
    if let Some(tz) = &t.timezone {
        if tz.is_empty()
            || tz
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '/' || c == '_' || c == '-'))
        {
            return Err(ApiError::BadRequest(format!(
                "invalid timezone characters: {tz}"
            )));
        }
    }
    if let Some(manual) = &t.manual_datetime {
        let stripped = manual.trim();
        let bad = stripped.len() < 19
            || !stripped[4..5].contains('-')
            || !stripped[7..8].contains('-')
            || !stripped[10..11].contains(' ')
            || !stripped[13..14].contains(':')
            || !stripped[16..17].contains(':');
        if bad {
            return Err(ApiError::BadRequest(format!(
                "manual_datetime must be 'YYYY-MM-DD HH:MM:SS', got {manual:?}"
            )));
        }
    }
    if t.ptp_enabled {
        let interface = t.ptp_interface.as_deref().unwrap_or("");
        if interface.is_empty()
            || interface
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
        {
            return Err(ApiError::BadRequest(
                "PTP requires a valid network interface".into(),
            ));
        }
        if t.ptp_domain.is_some_and(|domain| domain > 127) {
            return Err(ApiError::BadRequest(
                "PTP domain must be between 0 and 127".into(),
            ));
        }
    }
    if t.gps_enabled {
        for (label, device) in [
            ("GPS", t.gps_device.as_deref()),
            ("GPS PPS", t.gps_pps_device.as_deref()),
        ] {
            if let Some(path) = device {
                if path.is_empty()
                    || path
                        .chars()
                        .any(|c| !(c.is_ascii_alphanumeric() || "/_-.:".contains(c)))
                {
                    return Err(ApiError::BadRequest(format!(
                        "{label} device path is invalid"
                    )));
                }
            }
        }
        if t.gps_device.is_none() {
            return Err(ApiError::BadRequest("GPS requires a device path".into()));
        }
    }
    Ok(())
}

/// `POST /api/v1/system/apply` — apply hostname + time + ssh appliers (spec
/// §4.1). The ssh applier writes authorized_keys and toggles sshd /
/// serial-getty units.
pub async fn apply(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("system.apply")?;
    let user = username(&session).await;
    app.engine.validate("hostname").await?;
    app.engine.validate("time").await?;
    app.engine.validate("ssh").await?;
    let _ = apply_and_audit(&app, &user, "hostname").await?;
    let _ = apply_and_audit(&app, &user, "time").await?;
    let _ = apply_and_audit(&app, &user, "ssh").await?;
    Ok(Json(
        serde_json::json!({ "applied": ["hostname","time","ssh"] }),
    ))
}

/// `POST /api/v1/system/apply-all` — apply **every** registered applier
/// (task 39). Returns one result per applier so the operator (and tests) can
/// prove no applier was skipped, even when one fails. Routes that persist a
/// setting should use this so a newly registered applier is never silently
/// left out.
pub async fn apply_all(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("system.apply_all")?;
    let user = username(&session).await;
    let results = app.engine.apply_all().await?;
    let failed = results.iter().filter(|(_, r)| r.is_err()).count();
    let payload: Vec<serde_json::Value> = results
        .iter()
        .map(|(id, r)| {
            serde_json::json!({
                "applier": id,
                "ok": r.is_ok(),
                "error": r.as_ref().err(),
            })
        })
        .collect();
    audit(
        &app,
        &user,
        "system.apply_all",
        Some(format!("appliers={} failed={failed}", results.len())),
    );
    Ok(Json(serde_json::json!({
        "applied": results.len(),
        "failed": failed,
        "results": payload,
    })))
}

/// `GET /api/v1/system/info` — read-only device info (spec §4.1).
pub async fn info(State(app): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let m = &app.manifest;
    let configured = app.engine.load()?.system;
    let sysroot = &app.engine.sysroot;
    let os_release = std::fs::read_to_string(sysroot.join("/etc/os-release")).unwrap_or_default();
    let mut kv = std::collections::BTreeMap::new();
    for line in os_release.lines() {
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.to_string(), v.trim_matches('"').to_string());
        }
    }
    let unknown = || "unknown".to_string();
    let read_first = |paths: &[&str]| {
        paths
            .iter()
            .find_map(|path| {
                std::fs::read_to_string(sysroot.join(path))
                    .ok()
                    .map(|value| value.trim_matches('\0').trim().to_string())
                    .filter(|value| !value.is_empty())
            })
            .unwrap_or_else(unknown)
    };
    // Per-interface MAC addresses (spec §4.1: "uptime, MACs"). Read from the
    // sysroot's `/sys/class/net/*/address`, skipping the loopback. The loopback
    // has no usable MAC and would only clutter the map.
    let mut macs = std::collections::BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(sysroot.join("/sys/class/net")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "lo" {
                continue;
            }
            if let Ok(addr) =
                std::fs::read_to_string(sysroot.join(format!("/sys/class/net/{name}/address")))
            {
                let addr = addr.trim().to_string();
                if !addr.is_empty() {
                    macs.insert(name, addr);
                }
            }
        }
    }
    let os_version = kv
        .get("PRETTY_NAME")
        .or_else(|| kv.get("VERSION"))
        .cloned()
        .unwrap_or_else(unknown);
    let os_revision = kv
        .get("BUILD_ID")
        .or_else(|| kv.get("VERSION_ID"))
        .cloned()
        .unwrap_or_else(unknown);
    Ok(Json(serde_json::json!({
        "platform": m.platform,
        "model": m.model,
        "board_name": m.board_name,
        "hardware_revision": configured.hardware_revision.or_else(|| Some(read_first(&[
            "/etc/hardware-revision",
            "/etc/board-revision",
            "/proc/device-tree/chosen/board-revision",
        ]))),
        "serial_number": configured.serial_number,
        "has_rtc": m.has_rtc,
        "os_name": kv.get("NAME").cloned().unwrap_or_else(unknown),
        "os_version": os_version,
        "os_revision": os_revision,
        "kernel_version": read_first(&["/proc/sys/kernel/osrelease"]),
        "bootloader_version": read_first(&[
            "/etc/bootloader-version",
            "/etc/bootloader_version",
            "/proc/device-tree/chosen/bootloader-version",
        ]),
        "software_name": "WebConfig",
        "software_version": env!("CARGO_PKG_VERSION"),
        "software_revision": std::env::var("WEBCONFIG_REVISION").unwrap_or_else(|_| unknown()),
        "os_release": kv,
        "macs": macs,
        "uptime_secs": webconfig_engine::monitoring::read_vitals(sysroot).uptime_secs,
    })))
}

/// `POST /api/v1/system/reboot` / `/shutdown` (spec §4.1). The frontend shows a
/// "rebooting, reconnecting…" page that polls until the device returns.
pub async fn reboot(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("system.reboot")?;
    let user = username(&session).await;
    audit(&app, &user, "system.reboot", None);
    if app.engine.sysroot.is_real_root() {
        let _ = webconfig_engine::applier::run_cmd("systemctl", &["reboot"]);
    }
    Ok(Json(serde_json::json!({ "rebooting": true })))
}

pub async fn shutdown(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("system.shutdown")?;
    let user = username(&session).await;
    audit(&app, &user, "system.shutdown", None);
    if app.engine.sysroot.is_real_root() {
        let _ = webconfig_engine::applier::run_cmd("systemctl", &["poweroff"]);
    }
    Ok(Json(serde_json::json!({ "shutting_down": true })))
}

/// `POST /api/v1/system/factory-reset` — the local factory reset (spec §4.1,
/// T-P33 contract, meta-acadia docs/factory-reset.md):
///
/// * `settings` (C06) — configuration back to image defaults, accounts kept;
/// * `settings+users` — also removes every WebConfig account (first-boot
///   reopens, gated by the label claim code);
/// * `full` (C07 / RMA) — everything customer- or site-specific: the whole
///   persistent store except the factory identity, home directories (SSH
///   keys, Acadia-Client/HQ credentials), OTA staging and the journal.
///
/// WebConfig resets its own store in-process for the two settings modes,
/// then every mode writes a boot-time request
/// ([`FACTORY_WIPE_REQUEST`]) that `acadia-factory-wipe.service` carries out
/// before any service starts (Instrumentation config/state for the settings
/// modes, everything for `full`), and reboots. Typed confirmation: `RESET`
/// for the settings modes, `WIPE` for `full`.
#[derive(Deserialize)]
pub struct FactoryResetRequest {
    pub confirm: String,
    pub mode: String, // "settings" | "settings+users" | "full"
}

/// The boot-time reset request consumed by `acadia-factory-wipe.service`
/// (meta-acadia, T-P33), relative to the WebConfig data dir (`/pst/webconfig`).
pub const FACTORY_WIPE_REQUEST: &str = "factory-wipe.request";

/// Write the boot-time reset request for `level` ("settings" | "full").
pub(crate) fn request_boot_wipe(
    sysroot: &webconfig_engine::Sysroot,
    level: &str,
    requested_by: &str,
) -> Result<(), String> {
    let dir = sysroot.webconfig_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let body = serde_json::json!({
        "level": level,
        "requested_by": requested_by,
        "requested_at": crate::api::now_iso(),
    });
    let path = dir.join(FACTORY_WIPE_REQUEST);
    let tmp = dir.join(format!("{FACTORY_WIPE_REQUEST}.tmp"));
    std::fs::write(&tmp, format!("{body}\n"))
        .and_then(|_| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("write {}: {e}", path.display()))
}

pub async fn factory_reset(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Json(req): Json<FactoryResetRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("system.factory-reset")?;
    let expected_confirm = match req.mode.as_str() {
        "settings" | "settings+users" => "RESET",
        "full" => "WIPE",
        _ => {
            return Err(ApiError::BadRequest(
                "mode must be settings|settings+users|full".into(),
            ))
        }
    };
    if req.confirm != expected_confirm {
        return Err(ApiError::BadRequest(format!(
            "type {expected_confirm} to confirm"
        )));
    }
    let user = username(&session).await;
    audit(&app, &user, "system.factory-reset", Some(req.mode.clone()));
    let failures = if req.mode == "full" {
        // Nothing is removed in-process: the boot-time wipe takes the whole
        // store (this daemon's included) before anything reopens it.
        request_boot_wipe(&app.engine.sysroot, "full", &user)
            .err()
            .into_iter()
            .collect()
    } else {
        factory_reset_core(&app.engine.sysroot, &req.mode)
    };

    // A partial failure means the device is in an unknown, possibly
    // inconsistent state — rebooting it now would present that as a clean
    // reset. Skip the reboot and report the failure explicitly instead
    // (Checkpoint 1.6).
    if !failures.is_empty() {
        tracing::error!(
            failures = failures.join("; "),
            "factory reset completed with errors — reboot skipped"
        );
        return Ok(Json(serde_json::json!({
            "factory_reset": false,
            "mode": req.mode,
            "partial": true,
            "errors": failures,
        })));
    }

    if app.engine.sysroot.is_real_root() {
        let _ = webconfig_engine::applier::run_cmd("systemctl", &["reboot"]);
    }
    Ok(Json(
        serde_json::json!({ "factory_reset": true, "mode": req.mode }),
    ))
}

/// The wipe itself, shared by the web API handler and the HQ command
/// executor (task 009: one implementation, one behavior). Returns the real
/// failures encountered; an empty list means the wipe completed cleanly.
/// Rebooting and audit are the caller's concern.
pub(crate) fn factory_reset_core(sysroot: &webconfig_engine::Sysroot, mode: &str) -> Vec<String> {
    let dir = sysroot.webconfig_dir();
    let mut failures: Vec<String> = Vec::new();
    if dir.exists() {
        // Settings only: reset the SQLite config and audit tables but keep users.
        let database = dir.join("config.db");
        match rusqlite::Connection::open(&database) {
            Ok(conn) => {
                exec_best_effort(&conn, "DELETE FROM config_state", &mut failures);
                exec_best_effort(&conn, "DELETE FROM audit_entries", &mut failures);
                // The alert history ring buffer lives in config.db when the
                // history path ends in .db (it does in production). The
                // legacy alert.jsonl file is removed below; the SQLite table
                // must be cleared too or fired/cleared events survive a
                // factory reset (spec §4.1: "wipe data partition").
                exec_best_effort(&conn, "DELETE FROM alert_history", &mut failures);
            }
            Err(e) => {
                tracing::error!(error = %e, db = %database.display(), "factory reset: failed to open config.db");
                failures.push(format!("could not open config.db: {e}"));
            }
        }
        remove_file_best_effort(&dir.join("config.json"), &mut failures);
        remove_file_best_effort(&dir.join("config.json.bak"), &mut failures);
        remove_file_best_effort(&dir.join("audit.jsonl"), &mut failures);
        remove_file_best_effort(&dir.join("alert.jsonl"), &mut failures);
        // Device identity + cert store (spec §4.8): a factory reset returns the
        // device to a clean provisioning state, so drop the TLS cert/key (the
        // next boot regenerates a fresh self-signed identity via
        // tls::ensure_self_signed) and any uploaded CA/client certs in the
        // device cert store. Both modes wipe these — the settings/settings+users
        // distinction is about user accounts, not security material. The cert
        // store directory is created on demand by the upload route, so its
        // absence here is normal.
        remove_file_best_effort(&dir.join("cert.pem"), &mut failures);
        remove_file_best_effort(&dir.join("key.pem"), &mut failures);
        remove_dir_best_effort(&dir.join("certs"), &mut failures);
        if mode == "settings+users" {
            match rusqlite::Connection::open(&database) {
                Ok(conn) => {
                    exec_best_effort(&conn, "DELETE FROM group_members", &mut failures);
                    exec_best_effort(&conn, "DELETE FROM groups", &mut failures);
                    exec_best_effort(&conn, "DELETE FROM users", &mut failures);
                }
                Err(e) => {
                    tracing::error!(error = %e, db = %database.display(), "factory reset: failed to open config.db for user wipe");
                    failures.push(format!("could not open config.db for user wipe: {e}"));
                }
            }
            remove_file_best_effort(&dir.join("users.json"), &mut failures);
        }
    }
    // T-P33: the Instrumentation config/state half of a settings reset runs
    // at next boot, before istate starts (acadia-factory-wipe.service). Only
    // requested after a clean in-process wipe — a partial failure skips the
    // reboot, and a stale request must not fire on some later boot.
    if failures.is_empty() {
        if let Err(e) = request_boot_wipe(sysroot, "settings", "factory-reset") {
            failures.push(e);
        }
    }
    failures
}

/// Run a best-effort `DELETE`, logging and recording a real failure — but
/// tolerating "no such table" (the table genuinely may not exist yet on a
/// freshly-provisioned device, which is not a failure).
fn exec_best_effort(conn: &rusqlite::Connection, sql: &str, failures: &mut Vec<String>) {
    if let Err(e) = conn.execute(sql, []) {
        let msg = e.to_string();
        if msg.contains("no such table") {
            return;
        }
        tracing::error!(error = %e, sql, "factory reset: SQL delete failed");
        failures.push(format!("{sql}: {e}"));
    }
}

/// Remove a file, logging and recording a real failure — but tolerating
/// "not found" (the file may legitimately never have existed, e.g. a device
/// that was never provisioned with an uploaded cert store).
fn remove_file_best_effort(path: &std::path::Path, failures: &mut Vec<String>) {
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        tracing::error!(error = %e, path = %path.display(), "factory reset: failed to remove file");
        failures.push(format!("remove {}: {e}", path.display()));
    }
}

/// Same as [`remove_file_best_effort`] for a directory tree.
fn remove_dir_best_effort(path: &std::path::Path, failures: &mut Vec<String>) {
    if let Err(e) = std::fs::remove_dir_all(path) {
        if e.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        tracing::error!(error = %e, path = %path.display(), "factory reset: failed to remove directory");
        failures.push(format!("remove {}: {e}", path.display()));
    }
}

// --- User management (spec §4.1) ------------------------------------------

/// `GET /api/v1/system/users` — list users (no hashes).
pub async fn list_users(
    State(app): State<AppState>,
    _role: AuthRole,
) -> ApiResult<Json<Vec<UserPublic>>> {
    let store = app.load_users().map_err(|_| ApiError::Internal)?;
    Ok(Json(
        store
            .users
            .iter()
            .map(|u| UserPublic {
                username: u.username.clone(),
                role: u.role.as_str().to_string(),
                groups: u.groups.clone(),
            })
            .collect(),
    ))
}

#[derive(Serialize)]
pub struct UserPublic {
    pub username: String,
    pub role: String,
    pub groups: Vec<String>,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role: String,
}

/// `POST /api/v1/system/users` — create a user (admin only).
pub async fn create_user(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Json(req): Json<CreateUserRequest>,
) -> ApiResult<Json<UserPublic>> {
    role.require_admin("users.create")?;
    let parsed = Role::parse(&req.role).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    webconfig_engine::users::check_password_policy(&req.username, &req.password)
        .map_err(ApiError::BadRequest)?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store
        .add(&req.username, &req.password, parsed)
        .map_err(|e| ApiError::Conflict(e.to_string()))?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "users.create",
        Some(req.username.clone()),
    );
    Ok(Json(UserPublic {
        username: req.username,
        role: parsed.as_str().to_string(),
        groups: Vec::new(),
    }))
}

#[derive(Serialize)]
pub struct GroupPublic {
    pub name: String,
    pub members: Vec<String>,
}

/// `GET /api/v1/system/groups` — list groups and their members.
pub async fn list_groups(
    State(app): State<AppState>,
    _role: AuthRole,
) -> ApiResult<Json<Vec<GroupPublic>>> {
    let store = app.load_users().map_err(|_| ApiError::Internal)?;
    Ok(Json(
        store
            .groups
            .into_iter()
            .map(|group| GroupPublic {
                name: group.name,
                members: group.members,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

/// `POST /api/v1/system/groups` — create a group (admin only).
pub async fn create_group(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Json(req): Json<CreateGroupRequest>,
) -> ApiResult<Json<GroupPublic>> {
    role.require_admin("groups.create")?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store.add_group(&req.name)?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "groups.create",
        Some(req.name.clone()),
    );
    Ok(Json(GroupPublic {
        name: req.name,
        members: Vec::new(),
    }))
}

/// `DELETE /api/v1/system/groups/:name` — delete a group (admin only).
pub async fn delete_group(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("groups.delete")?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store.remove_group(&name)?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "groups.delete",
        Some(name.clone()),
    );
    Ok(Json(serde_json::json!({ "deleted": name })))
}

/// `PUT/DELETE /api/v1/system/groups/:name/members/:user` — assign or remove
/// a user from a group (admin only).
pub async fn add_group_member(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Path((group, user)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("groups.members.put")?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store.add_member(&group, &user)?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "groups.members.put",
        Some(format!("{group}:{user}")),
    );
    Ok(Json(
        serde_json::json!({ "group": group, "user": user, "member": true }),
    ))
}

pub async fn remove_group_member(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Path((group, user)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("groups.members.delete")?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store.remove_member(&group, &user)?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "groups.members.delete",
        Some(format!("{group}:{user}")),
    );
    Ok(Json(
        serde_json::json!({ "group": group, "user": user, "member": false }),
    ))
}

/// `DELETE /api/v1/system/users/:name` (admin only; last-admin guarded).
pub async fn delete_user(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("users.delete")?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store
        .remove(&name)
        .map_err(|e| ApiError::Conflict(e.to_string()))?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "users.delete",
        Some(name.clone()),
    );
    Ok(Json(serde_json::json!({ "deleted": name })))
}

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

/// `PUT /api/v1/system/users/:name/role` (admin only).
pub async fn set_role(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Path(name): Path<String>,
    Json(req): Json<SetRoleRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("users.set_role")?;
    let parsed = Role::parse(&req.role).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store
        .set_role(&name, parsed)
        .map_err(|e| ApiError::Conflict(e.to_string()))?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "users.set_role",
        Some(name.clone()),
    );
    Ok(Json(serde_json::json!({ "user": name, "role": req.role })))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub password: String,
}

/// `PUT /api/v1/system/users/:name/password` (admin only).
pub async fn change_password(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Path(name): Path<String>,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("users.change_password")?;
    webconfig_engine::users::check_password_policy(&name, &req.password)
        .map_err(ApiError::BadRequest)?;
    let mut store = app.load_users().map_err(|_| ApiError::Internal)?;
    store.set_password(&name, &req.password)?;
    app.save_users(&store).map_err(|_| ApiError::Internal)?;
    audit(
        &app,
        &username(&session).await,
        "users.change_password",
        Some(name.clone()),
    );
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use webconfig_engine::store::system::{SshConfig, TimeConfig};

    fn cfg() -> SystemConfig {
        SystemConfig {
            hostname: None,
            asset_tag: None,
            hardware_revision: None,
            serial_number: None,
            time: TimeConfig::default(),
            ssh: SshConfig::default(),
            ntp_servers: Vec::new(),
        }
    }

    #[test]
    fn accepts_a_single_sync_source() {
        let mut c = cfg();
        c.time.ntp_enabled = true;
        assert!(validate_system_config(&c).is_ok());
        let mut c = cfg();
        c.time.ptp_enabled = true;
        c.time.ptp_interface = Some("eth0".into());
        assert!(validate_system_config(&c).is_ok());
        let mut c = cfg();
        c.time.gps_enabled = true;
        c.time.gps_device = Some("/dev/ttyUSB0".into());
        assert!(validate_system_config(&c).is_ok());
    }

    #[test]
    fn rejects_ntp_and_ptp_together() {
        let mut c = cfg();
        c.time.ntp_enabled = true;
        c.time.ptp_enabled = true;
        c.time.ptp_interface = Some("eth0".into());
        assert!(validate_system_config(&c).is_err());
    }

    #[test]
    fn rejects_manual_time_with_any_sync_on() {
        let mut c = cfg();
        c.time.manual_datetime = Some("2026-01-02 03:04:05".into());
        c.time.ntp_enabled = true;
        assert!(validate_system_config(&c).is_err());
        let mut c = cfg();
        c.time.manual_datetime = Some("2026-01-02 03:04:05".into());
        c.time.ptp_enabled = true;
        c.time.ptp_interface = Some("eth0".into());
        assert!(validate_system_config(&c).is_err());
    }

    #[test]
    fn accepts_manual_time_with_all_sync_off() {
        let mut c = cfg();
        c.time.manual_datetime = Some("2026-01-02 03:04:05".into());
        assert!(validate_system_config(&c).is_ok());
    }

    #[test]
    fn rejects_ptp_without_interface() {
        let mut c = cfg();
        c.time.ptp_enabled = true;
        assert!(validate_system_config(&c).is_err());
    }

    #[test]
    fn rejects_gps_without_device() {
        let mut c = cfg();
        c.time.gps_enabled = true;
        assert!(validate_system_config(&c).is_err());
    }
}
