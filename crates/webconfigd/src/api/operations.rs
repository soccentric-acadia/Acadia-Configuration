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
    OperationDescription {
        name: "configuration.read",
        daemon: "configuration",
        command_kind: "configuration_read",
        description: "Read the device configuration document (contract v1).",
    },
    OperationDescription {
        name: "configuration.write",
        daemon: "configuration",
        command_kind: "configuration_write",
        description: "Signed configuration write; merges, applies and reports per-applier outcomes.",
    },
    OperationDescription {
        name: "ssh_keys.set",
        daemon: "configuration",
        command_kind: "ssh_keys_set",
        description: "Provision the operator account's authorized_keys (T-P11).",
    },
    OperationDescription {
        name: "system.reboot",
        daemon: "configuration",
        command_kind: "reboot",
        description: "Reboot the device (executed after the outcome is acknowledged; T-P20).",
    },
    OperationDescription {
        name: "system.shutdown",
        daemon: "configuration",
        command_kind: "shutdown",
        description: "Power the device off; requires required_confirmation = SHUTDOWN (T-P20).",
    },
    OperationDescription {
        name: "update.reboot_to_apply",
        daemon: "configuration",
        command_kind: "reboot_to_apply",
        description: "Tryboot into the freshly installed slot (T-P20).",
    },
    OperationDescription {
        name: "update.confirm",
        daemon: "configuration",
        command_kind: "confirm_update",
        description: "Mark the running slot good (T-P20).",
    },
    OperationDescription {
        name: "update.rollback",
        daemon: "configuration",
        command_kind: "rollback_update",
        description: "Re-arm the previous slot and reboot; requires required_confirmation = ROLLBACK (T-P20).",
    },
    OperationDescription {
        name: "service.control",
        daemon: "configuration",
        command_kind: "service_control",
        description: "Start/stop/restart/enable/disable one allowlisted unit (T-P20).",
    },
    OperationDescription {
        name: "log_bundle.request",
        daemon: "configuration",
        command_kind: "log_bundle_request",
        description: "Create a logmanager support bundle and upload it to HQ (T-P20).",
    },
    OperationDescription {
        name: "users.list",
        daemon: "configuration",
        command_kind: "users_list",
        description: "List local web-UI accounts (no hashes; T-P20).",
    },
    OperationDescription {
        name: "users.create",
        daemon: "configuration",
        command_kind: "users_create",
        description: "Create a local web-UI account (T-P20).",
    },
    OperationDescription {
        name: "users.delete",
        daemon: "configuration",
        command_kind: "users_delete",
        description: "Delete a local web-UI account (last-admin guarded; T-P20).",
    },
    OperationDescription {
        name: "users.set_role",
        daemon: "configuration",
        command_kind: "users_set_role",
        description: "Change a local web-UI account's role (T-P20).",
    },
];

pub async fn list(_role: AuthRole) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(serde_json::json!({ "items": OPERATIONS })))
}
