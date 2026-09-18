use crate::{
    auth::AuthRole,
    error::{ApiError, ApiResult},
    state::AppState,
};
use axum::{extract::State, Json};

/// Return the local control-plane view. istate is authoritative for peer
/// health; HQ pairing state remains local because HQ may be offline.
pub async fn status(
    State(app): State<AppState>,
    _role: AuthRole,
) -> ApiResult<Json<serde_json::Value>> {
    let istate = app.istate.status().await.unwrap_or_else(
        |error| serde_json::json!({"reachable": false, "error": error.to_string()}),
    );
    let pairing = app
        .pairing
        .lock()
        .map_err(|_| ApiError::Conflict("pairing locked".into()))?;
    let record = pairing.record();
    Ok(Json(serde_json::json!({
        "istate": istate,
        "hq": {
            "state": format!("{:?}", record.state),
            "device_id": record.device_id,
            "last_heartbeat_at": record.last_heartbeat_at
        }
    })))
}
