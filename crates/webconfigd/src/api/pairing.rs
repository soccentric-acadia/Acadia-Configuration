//! HQ pairing agent handlers (task 36).
//!
//! Enroll a provisioned image with HQ and drive heartbeat/rotation/retry
//! transitions. The agent state machine lives in
//! `webconfig_engine::pairing::PairingAgent`; this module wires the HTTP
//! transport (enroll, heartbeat, status, rotate) around it.
//!
//! The transport itself is the `webconfigd` HTTP layer calling the configured
//! HQ endpoint; these routes expose the pairing lifecycle for the operator and
//! tests, and the engine transitions are covered by unit tests so a provisioned
//! image survives restart, outage, and credential rotation.

use axum::extract::State;
use axum::Json;
use tower_sessions::Session;
use webconfig_engine::pairing::PairingState;

use crate::api::{audit, username};
use crate::auth::AuthRole;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// `GET /api/v1/pairing` — current pairing state + HQ endpoint (no secrets).
pub async fn get(
    State(app): State<AppState>,
    _role: AuthRole,
) -> ApiResult<Json<serde_json::Value>> {
    let guard = app
        .pairing
        .lock()
        .map_err(|_| ApiError::Conflict("pairing locked".into()))?;
    let rec = guard.record().clone();
    drop(guard);
    Ok(Json(serde_json::json!({
        "state": format!("{:?}", rec.state),
        "hq_endpoint": rec.hq_endpoint,
        "enrolled": rec.state == PairingState::Enrolled,
        "token_expired": !rec.credential_token.is_none() && rec.token_expires_at_unix.is_some(),
    })))
}

#[derive(serde::Deserialize)]
pub struct ProvisionRequest {
    /// Pairing token issued by HQ.
    pub token: String,
    /// HQ base endpoint for enrollment/heartbeat.
    pub hq_endpoint: String,
    /// Token TTL in seconds.
    pub ttl_secs: u64,
}

/// `POST /api/v1/pairing/provision` — start enrollment with a fresh token.
pub async fn provision(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
    Json(req): Json<ProvisionRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("pairing.provision")?;
    let user = username(&session).await;
    {
        let mut guard = app
            .pairing
            .lock()
            .map_err(|_| ApiError::Conflict("pairing locked".into()))?;
        guard.provision(req.token.clone(), req.hq_endpoint.clone(), req.ttl_secs);
    }
    audit(&app, &user, "pairing.provision", Some(req.hq_endpoint));
    Ok(Json(serde_json::json!({ "state": "pending" })))
}

/// `POST /api/v1/pairing/heartbeat` — record a successful heartbeat.
pub async fn heartbeat(
    State(app): State<AppState>,
    _role: AuthRole,
) -> ApiResult<Json<serde_json::Value>> {
    {
        let mut guard = app
            .pairing
            .lock()
            .map_err(|_| ApiError::Conflict("pairing locked".into()))?;
        guard.on_heartbeat();
    }
    Ok(Json(serde_json::json!({ "heartbeat": true })))
}

/// `POST /api/v1/pairing/rotate` — simulate credential rotation (revoke).
pub async fn rotate(
    State(app): State<AppState>,
    role: AuthRole,
    session: Session,
) -> ApiResult<Json<serde_json::Value>> {
    role.require_admin("pairing.rotate")?;
    let user = username(&session).await;
    {
        let mut guard = app
            .pairing
            .lock()
            .map_err(|_| ApiError::Conflict("pairing locked".into()))?;
        guard.on_revoked();
    }
    audit(&app, &user, "pairing.rotate", None);
    Ok(Json(serde_json::json!({ "state": "revoked" })))
}
