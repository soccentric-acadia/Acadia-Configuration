use base64::Engine;
use hq_agent::pb;

use crate::istate_client::{ControlRequest, IstateClient, SharedIstateClient};
use std::sync::Arc;
use webconfig_engine::audit::{AuditEntry, AuditLog};

pub struct IstateCommandHandler {
    client: SharedIstateClient,
    audit: Arc<AuditLog>,
}

impl IstateCommandHandler {
    pub fn new(client: Arc<dyn IstateClient>, audit: Arc<AuditLog>) -> Self {
        Self { client, audit }
    }

    fn normalize(command: &pb::Command) -> Result<(String, String, String), String> {
        if command.command_id.is_empty() {
            return Err("INVALID_ARGUMENT: command_id is required".into());
        }
        if !command.operation.is_empty() {
            if command.operation == "configuration.read"
                || command.operation == "configuration.write"
            {
                let args = if command.json_args.is_empty() {
                    "{}".to_owned()
                } else {
                    command.json_args.clone()
                };
                validate_configuration_envelope(&command.operation, &args)?;
                return Ok(("configuration".into(), command.operation.clone(), args));
            }
            return Ok((
                command.daemon.clone(),
                command.operation.clone(),
                if command.json_args.is_empty() {
                    "{}".into()
                } else {
                    command.json_args.clone()
                },
            ));
        }

        /// Validate the device configuration contract before it crosses the istate
        /// boundary. Cryptographic verification remains istate's responsibility; this
        /// layer rejects malformed/ambiguous envelopes rather than acknowledging them.
        fn validate_configuration_envelope(operation: &str, raw: &str) -> Result<(), String> {
            if raw.len() > 256 * 1024 {
                return Err("INVALID_ARGUMENT: configuration envelope exceeds 256 KiB".into());
            }
            let value: serde_json::Value = serde_json::from_str(raw)
                .map_err(|e| format!("INVALID_ARGUMENT: envelope is not valid JSON: {e}"))?;
            let object = value.as_object().ok_or_else(|| {
                "INVALID_ARGUMENT: configuration envelope must be an object".to_owned()
            })?;
            let version = object
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "INVALID_ARGUMENT: schema_version is required".to_owned())?;
            if version != u64::from(webconfig_engine::CONFIG_SCHEMA_VERSION) {
                return Err(format!(
                    "FAILED_PRECONDITION: unsupported configuration schema_version {version}"
                ));
            }
            if operation == "configuration.write" {
                if object.get("origin").and_then(serde_json::Value::as_str) != Some("hq") {
                    return Err("PERMISSION_DENIED: configuration.write origin must be hq".into());
                }
                if !object
                    .get("config")
                    .is_some_and(serde_json::Value::is_object)
                {
                    return Err(
                        "INVALID_ARGUMENT: configuration.write config must be an object".into(),
                    );
                }
                let algorithm = object
                    .get("signature_algorithm")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("ed25519");
                if algorithm != "ed25519" {
                    return Err(
                        "INVALID_ARGUMENT: unsupported configuration signature_algorithm".into(),
                    );
                }
                let signature = object
                    .get("signature")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        "UNAUTHENTICATED: configuration.write signature is required".to_owned()
                    })?;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(signature)
                    .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(signature))
                    .map_err(|_| {
                        "UNAUTHENTICATED: configuration.write signature is not base64".to_owned()
                    })?;
                if decoded.len() != 64 {
                    return Err(
                        "UNAUTHENTICATED: configuration.write signature must be 64 bytes".into(),
                    );
                }
            }
            Ok(())
        }
        let (operation, args) = match command.kind.as_ref() {
            Some(pb::command::Kind::TakeBackupNow(_)) => ("backup".into(), "{}".into()),
            Some(pb::command::Kind::Restore(value)) => (
                "restore".into(),
                serde_json::json!({"backup_download_url": value.backup_download_url}).to_string(),
            ),
            Some(pb::command::Kind::FactoryReset(_)) => ("factory_reset".into(), "{}".into()),
            Some(pb::command::Kind::ApplyUpdate(value)) => (
                "apply_update".into(),
                serde_json::json!({
                    "artifact_id": value.artifact_id,
                    "artifact_download_url": value.artifact_download_url,
                    "checksum_sha256": value.checksum_sha256,
                })
                .to_string(),
            ),
            None => return Err("INVALID_ARGUMENT: operation is required".into()),
        };
        Ok((command.daemon.clone(), operation, args))
    }
}

#[async_trait::async_trait]
impl hq_agent::CommandHandler for IstateCommandHandler {
    async fn handle(&self, command: pb::Command) -> (bool, String) {
        let (daemon, operation, json_args) = match Self::normalize(&command) {
            Ok(value) => value,
            Err(error) => return (false, error),
        };
        let audit_operation = format!("{daemon}:{operation}");
        let request = ControlRequest {
            daemon,
            operation,
            json_args,
            actor: if command.actor.is_empty() {
                "hq".into()
            } else {
                command.actor
            },
            request_id: if command.correlation_id.is_empty() {
                command.command_id
            } else {
                command.correlation_id
            },
            deadline_ms: command.deadline_ms,
        };
        let result = match self.client.control(request).await {
            Ok(reply) if reply.ok => (
                true,
                serde_json::json!({
                    "ok": true, "code": reply.code, "message": reply.message,
                    "payload": serde_json::from_str::<serde_json::Value>(&reply.json_payload)
                        .unwrap_or_else(|_| serde_json::json!({"raw": reply.json_payload}))
                })
                .to_string(),
            ),
            Ok(reply) => (
                false,
                serde_json::json!({"ok": false, "code": reply.code, "message": reply.message})
                    .to_string(),
            ),
            Err(error) => {
                let text = error.to_string();
                let (code, message) = text.split_once(": ").unwrap_or(("INTERNAL", text.as_str()));
                (
                    false,
                    serde_json::json!({"ok": false, "code": code, "message": message}).to_string(),
                )
            }
        };
        let _ = self.audit.append(&AuditEntry {
            ts: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            user: "hq".into(),
            action: "command".into(),
            detail: Some(format!(
                "{audit_operation}: {}",
                if result.0 { "succeeded" } else { "failed" }
            )),
        });
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(operation: &str, args: &str) -> pb::Command {
        pb::Command {
            command_id: "cmd-1".into(),
            operation: operation.into(),
            json_args: args.into(),
            ..Default::default()
        }
    }

    #[test]
    fn configuration_read_requires_current_schema() {
        let err = IstateCommandHandler::normalize(&command(
            "configuration.read",
            r#"{"schema_version":99}"#,
        ))
        .unwrap_err();
        assert!(err.starts_with("FAILED_PRECONDITION:"));
    }

    #[test]
    fn configuration_write_requires_signed_hq_envelope() {
        let err = IstateCommandHandler::normalize(&command(
            "configuration.write",
            r#"{"schema_version":1,"origin":"hq","config":{}}"#,
        ))
        .unwrap_err();
        assert!(err.starts_with("UNAUTHENTICATED:"));
    }
}
