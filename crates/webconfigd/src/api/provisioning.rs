//! First-use provisioning (P-A10, OS-071, T-P00d): the trust material and
//! endpoints a device needs before HQ or the IV&V server can talk to it.
//!
//! * **HQ trust** — the HQ CA the AgentLink client pins (F10) and the HQ
//!   configuration-signing public key every signed `configuration.write` is
//!   verified against (F09). Written to the persistent WebConfig store
//!   (`/pst/webconfig/hq-ca.pem`, `/pst/webconfig/hq-config-pub.pem`), which
//!   survives OTA slot switches and a settings reset, and is wiped by the full
//!   (RMA) reset. Lookup order everywhere: environment → the persistent store →
//!   `/etc/acadia/` (a fleet default baked into the image at build time).
//! * **IV&V client** — the Acadia-Server address the acadia-client daemon
//!   streams to. Rendered to `/var/lib/acadia/client.conf` (the client's own
//!   persistent directory, owner acadia) through the privileged helper; the
//!   client unit only starts once that file exists.
//!
//! The HQ endpoint and pairing token themselves are provisioned by the
//! pairing flow (`/pairing/provision`).

use std::path::{Path, PathBuf};

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use sha2::Digest;
use tower_sessions::Session;

use crate::api::{audit, username};
use crate::auth::AuthRole;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// File names inside the WebConfig data dir.
pub const HQ_CA_FILE: &str = "hq-ca.pem";
pub const HQ_CONFIG_PUBKEY_FILE: &str = "hq-config-pub.pem";
pub const HQ_CONFIG_KEY_ID_FILE: &str = "hq-config-key-id";
const IVV_CLIENT_FILE: &str = "ivv-client.json";

/// Image-baked fleet defaults (optional `acadia-hq-trust` recipe).
pub const IMAGE_HQ_CA: &str = "/etc/acadia/hq-ca.pem";
pub const IMAGE_HQ_CONFIG_PUBKEY: &str = "/etc/acadia/hq-config-pub.pem";

/// acadia-client's configuration, in its own persistent directory.
pub const IVV_CLIENT_CONF: &str = "/var/lib/acadia/client.conf";
pub const IVV_CLIENT_CA: &str = "/var/lib/acadia/ivv-ca.pem";
const IVV_CLIENT_UNIT: &str = "acadia-client.service";

/// The first existing file among the device-provisioned and image paths.
pub fn resolve(webconfig_dir: &Path, file: &str, image_default: &str) -> Option<PathBuf> {
    [webconfig_dir.join(file), PathBuf::from(image_default)]
        .into_iter()
        .find(|p| p.is_file())
}

fn fingerprint(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hex::encode(sha2::Sha256::digest(&bytes))[..16].to_string())
}

fn source(webconfig_dir: &Path, file: &str, image_default: &str) -> serde_json::Value {
    match resolve(webconfig_dir, file, image_default) {
        Some(p) => serde_json::json!({
            "provisioned": true,
            "source": if p.starts_with(webconfig_dir) { "device" } else { "image" },
            "sha256_prefix": fingerprint(&p),
        }),
        None => serde_json::json!({ "provisioned": false }),
    }
}

/// `GET /api/v1/provisioning` — what is provisioned (never the material).
pub async fn get(
    State(app): State<AppState>,
    _role: AuthRole,
) -> ApiResult<Json<serde_json::Value>> {
    let dir = app.engine.sysroot.webconfig_dir();
    let ivv: Option<serde_json::Value> = std::fs::read(dir.join(IVV_CLIENT_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    Ok(Json(serde_json::json!({
        "hq_ca": source(&dir, HQ_CA_FILE, IMAGE_HQ_CA),
        "hq_config_key": if std::env::var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV)
            .is_ok_and(|v| !v.trim().is_empty())
        {
            // The environment wins over every file (hq_bridge lookup order).
            serde_json::json!({ "provisioned": true, "source": "environment" })
        } else {
            source(&dir, HQ_CONFIG_PUBKEY_FILE, IMAGE_HQ_CONFIG_PUBKEY)
        },
        "ivv_client": ivv,
    })))
}

#[derive(Debug, Deserialize)]
pub struct HqTrustRequest {
    /// PEM certificate(s) of the CA that issued the HQ gateway's certificate.
    #[serde(default)]
    pub hq_ca_pem: Option<String>,
    /// Ed25519 public key (PEM SubjectPublicKeyInfo or raw base64) HQ signs
    /// configuration writes with.
    #[serde(default)]
    pub hq_config_pubkey_pem: Option<String>,
    /// Stable identifier of the public key. Required when replacing the key
    /// so a replay signed by a revoked predecessor cannot be accepted.
    #[serde(default)]
    pub hq_config_key_id: Option<String>,
}

fn valid_cert_pem(pem: &str) -> bool {
    let t = pem.trim();
    t.len() <= 64 * 1024
        && t.starts_with("-----BEGIN CERTIFICATE-----")
        && t.ends_with("-----END CERTIFICATE-----")
        && !t.contains("PRIVATE KEY")
}

/// The WebConfig data dir is the daemon's own — written directly, no helper.
fn write_private(path: &Path, body: &str) -> ApiResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{}\n", body.trim()))
        .and_then(|_| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o640)))
        .and_then(|_| std::fs::rename(&tmp, path))
        .map_err(|e| {
            tracing::error!(error = %e, path = %path.display(), "provisioning write failed");
            ApiError::Internal
        })
}

/// `PUT /api/v1/provisioning/hq-trust` (admin) — provision the HQ CA and/or
/// the HQ configuration-signing key.
pub async fn put_hq_trust(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Json(req): Json<HqTrustRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("provisioning.hq_trust")?;
    if req.hq_ca_pem.is_none() && req.hq_config_pubkey_pem.is_none() {
        return Err(ApiError::BadRequest(
            "provide hq_ca_pem and/or hq_config_pubkey_pem".into(),
        ));
    }
    if let Some(ca) = &req.hq_ca_pem {
        if !valid_cert_pem(ca) {
            return Err(ApiError::BadRequest(
                "hq_ca_pem must be PEM certificate(s) (-----BEGIN CERTIFICATE-----)".into(),
            ));
        }
    }
    if let Some(key) = &req.hq_config_pubkey_pem {
        crate::hq_bridge::ed25519_pubkey_bytes(key).map_err(ApiError::BadRequest)?;
        let key_id = req.hq_config_key_id.as_deref().unwrap_or("default");
        if key_id.is_empty()
            || key_id.len() > 128
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(ApiError::BadRequest("hq_config_key_id is invalid".into()));
        }
    }
    let dir = app.engine.sysroot.webconfig_dir();
    std::fs::create_dir_all(&dir).map_err(|_| ApiError::Internal)?;
    let mut changed = Vec::new();
    if let Some(ca) = &req.hq_ca_pem {
        write_private(&dir.join(HQ_CA_FILE), ca)?;
        changed.push("hq_ca");
    }
    if let Some(key) = &req.hq_config_pubkey_pem {
        write_private(&dir.join(HQ_CONFIG_PUBKEY_FILE), key)?;
        write_private(
            &dir.join(HQ_CONFIG_KEY_ID_FILE),
            req.hq_config_key_id.as_deref().unwrap_or("default"),
        )?;
        changed.push("hq_config_key");
    }
    audit(
        &app,
        &username(&session).await,
        "provisioning.hq_trust",
        Some(changed.join(",")),
    );
    get(State(app), role).await
}

#[derive(Debug, Deserialize)]
pub struct IvvClientRequest {
    /// Acadia-Server host name or IP address.
    pub server_address: String,
    #[serde(default = "default_port")]
    pub server_port: u16,
    /// Shared stream token (must match the server's ACADIA_STREAM_TOKEN when
    /// it requires one). Write-only: never returned.
    #[serde(default)]
    pub server_stream_token: Option<String>,
    /// CA for a TLS-serving Acadia-Server. Empty = plaintext (lab subnet).
    #[serde(default)]
    pub tls_ca_pem: Option<String>,
}

fn default_port() -> u16 {
    50051
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}

fn valid_token(token: &str) -> bool {
    token.len() <= 512
        && token
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

/// Render acadia-client's TOML. Every interpolated value is validated to a
/// character set that needs no TOML escaping.
fn render_client_conf(req: &IvvClientRequest, tls_ca: Option<&str>) -> String {
    let mut conf = String::from(
        "# Written by WebConfig first-use provisioning (P-A10). Edits here are\n\
         # replaced the next time the IV&V client is provisioned.\n",
    );
    conf.push_str(&format!("server_address = \"{}\"\n", req.server_address));
    conf.push_str(&format!("server_port = {}\n", req.server_port));
    conf.push_str(&format!(
        "server_stream_token = \"{}\"\n",
        req.server_stream_token.as_deref().unwrap_or("")
    ));
    conf.push_str("spool_path = \"/var/lib/acadia/spool/spool.db\"\n");
    if let Some(ca) = tls_ca {
        conf.push_str(&format!("tls_ca = \"{ca}\"\n"));
    }
    conf
}

/// `PUT /api/v1/provisioning/ivv-client` (admin) — point acadia-client at the
/// IV&V server and (re)start it.
pub async fn put_ivv_client(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Json(req): Json<IvvClientRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("provisioning.ivv_client")?;
    if !valid_host(&req.server_address) {
        return Err(ApiError::BadRequest(
            "server_address must be a host name or IP address".into(),
        ));
    }
    if req.server_port == 0 {
        return Err(ApiError::BadRequest("server_port must be 1..65535".into()));
    }
    if let Some(token) = &req.server_stream_token {
        if !valid_token(token) {
            return Err(ApiError::BadRequest(
                "server_stream_token must be printable ASCII without quotes or backslashes".into(),
            ));
        }
    }
    let tls_ca = match req.tls_ca_pem.as_deref().map(str::trim) {
        Some(ca) if !ca.is_empty() => {
            if !valid_cert_pem(ca) {
                return Err(ApiError::BadRequest(
                    "tls_ca_pem must be PEM certificate(s)".into(),
                ));
            }
            Some(ca)
        }
        _ => None,
    };
    let sysroot = &app.engine.sysroot;
    let conf_path = sysroot.join(IVV_CLIENT_CONF);
    if let Some(parent) = conf_path.parent() {
        if !sysroot.is_real_root() {
            std::fs::create_dir_all(parent).map_err(|_| ApiError::Internal)?;
        }
    }
    let write = |path: PathBuf, body: String| {
        webconfig_engine::priv_client::write_file_owner(&path, body, 0o640, "acadia:acadia").map_err(
            |e| {
                tracing::error!(error = %e, path = %path.display(), "IV&V client provisioning failed");
                ApiError::Internal
            },
        )
    };
    if let Some(ca) = tls_ca {
        write(sysroot.join(IVV_CLIENT_CA), format!("{ca}\n"))?;
    }
    write(
        conf_path,
        render_client_conf(&req, tls_ca.map(|_| IVV_CLIENT_CA)),
    )?;
    // Non-secret mirror for GET (the client's directory is not readable by
    // the webconfig user).
    let mirror = serde_json::json!({
        "server_address": req.server_address,
        "server_port": req.server_port,
        "stream_token_set": req.server_stream_token.as_deref().is_some_and(|t| !t.is_empty()),
        "tls": tls_ca.is_some(),
    });
    let dir = sysroot.webconfig_dir();
    std::fs::create_dir_all(&dir).map_err(|_| ApiError::Internal)?;
    std::fs::write(dir.join(IVV_CLIENT_FILE), mirror.to_string())
        .map_err(|_| ApiError::Internal)?;
    let restarted = app.systemd.restart(IVV_CLIENT_UNIT).await.is_ok();
    audit(
        &app,
        &username(&session).await,
        "provisioning.ivv_client",
        Some(format!("{}:{}", req.server_address, req.server_port)),
    );
    Ok(Json(
        serde_json::json!({ "ivv_client": mirror, "restarted": restarted }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_conf_renders_only_validated_values() {
        let req = IvvClientRequest {
            server_address: "10.0.0.5".into(),
            server_port: 50051,
            server_stream_token: Some("tok-123".into()),
            tls_ca_pem: None,
        };
        let conf = render_client_conf(&req, Some(IVV_CLIENT_CA));
        assert!(conf.contains("server_address = \"10.0.0.5\"\n"));
        assert!(conf.contains("server_port = 50051\n"));
        assert!(conf.contains("server_stream_token = \"tok-123\"\n"));
        assert!(conf.contains("tls_ca = \"/var/lib/acadia/ivv-ca.pem\"\n"));
        assert!(!valid_host("evil\"\nx = 1"));
        assert!(!valid_token("a\"b"));
        assert!(valid_host("ivv-server.lab.local"));
    }
}
