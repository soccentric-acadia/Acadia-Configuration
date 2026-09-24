//! `GET /api/v1/operations` — the operation catalog (T-P25, N04).
//!
//! Both lists are contract files instead of hand copies:
//! `contracts/configuration-operations.json` (owned here — the verbs
//! `hq_command_handler.rs` executes) and the vendored Instrumentation
//! `contracts/instrumentation-operation-catalog.json` (generated from the
//! spokes' command tables).

use axum::Json;

use crate::auth::AuthRole;
use crate::error::ApiResult;

pub const CONFIGURATION_OPERATIONS: &str =
    include_str!("../../../../contracts/configuration-operations.json");
pub const INSTRUMENTATION_CATALOG: &str =
    include_str!("../../../../contracts/instrumentation-operation-catalog.json");

/// The configuration verbs as parsed JSON (tests + the handler check).
pub fn configuration_operations() -> Vec<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(CONFIGURATION_OPERATIONS)
        .ok()
        .and_then(|v| v.get("operations").and_then(|o| o.as_array()).cloned())
        .unwrap_or_default()
}

pub async fn list(_role: AuthRole) -> ApiResult<Json<serde_json::Value>> {
    let spokes = serde_json::from_str::<serde_json::Value>(INSTRUMENTATION_CATALOG)
        .ok()
        .and_then(|v| v.get("spokes").cloned())
        .unwrap_or_default();
    Ok(Json(serde_json::json!({
        "items": configuration_operations(),
        "spokes": spokes,
    })))
}
