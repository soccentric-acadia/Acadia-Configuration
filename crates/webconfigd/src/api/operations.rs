use axum::Json;
use serde::Serialize;

use crate::auth::AuthRole;
use crate::error::ApiResult;

#[derive(Debug, Serialize)]
pub struct OperationDescription {
    pub name: &'static str,
    pub daemon: &'static str,
    pub command_kind: &'static str,
    pub description: &'static str,
}

const OPERATIONS: &[OperationDescription] = &[
    OperationDescription {
        name: "backup",
        daemon: "configuration",
        command_kind: "take_backup_now",
        description: "Capture and upload a device backup.",
    },
    OperationDescription {
        name: "restore",
        daemon: "configuration",
        command_kind: "restore",
        description: "Restore a previously uploaded device backup.",
    },
    OperationDescription {
        name: "factory_reset",
        daemon: "configuration",
        command_kind: "factory_reset",
        description: "Reset the device to factory configuration.",
    },
    OperationDescription {
        name: "apply_update",
        daemon: "configuration",
        command_kind: "apply_update",
        description: "Install a signed device update artifact.",
    },
];

pub async fn list(_role: AuthRole) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({ "items": OPERATIONS })))
}
