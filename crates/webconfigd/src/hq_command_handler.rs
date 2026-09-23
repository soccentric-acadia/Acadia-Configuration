//! Dispatch of HQ commands to the device (task 009, P2).
//!
//! The HQ operation catalog (and the gateway's dispatcher) sends every
//! command with `daemon="configuration"` — the pseudo-daemon whose verbs
//! webconfigd itself owns. Relaying those through istate `Control` failed
//! with "spoke not connected": istate only routes the nine spokes, and no
//! component ever executed the `configuration` ops (findings C3/H2). This
//! handler now splits:
//!
//! - `configuration.read`/`write`, `take_backup_now`, `restore`,
//!   `factory_reset`, `apply_update` → executed **locally** by
//!   [`crate::hq_bridge::DeviceOps`] (config engine / update backend / wipe);
//! - anything targeting a real spoke (`daemon="networkd"` …) → istate
//!   `Control`, the only sanctioned route to a spoke (R1).
//!
//! The handler is idempotent by `command_id` via the wrapping
//! [`hq_agent::IdempotentCommandHandler`]; the factory-reset gate here
//! mirrors istate's own gate (`required_confirmation == "FACTORY-RESET"`),
//! so the local path is not weaker than the relayed one (finding H4).

use hq_agent::pb;

use crate::hq_bridge::{DeviceOps, REQUIRED_FACTORY_RESET_CONFIRMATION};
use crate::istate_client::{ControlRequest, IstateClient, SharedIstateClient};
use std::sync::Arc;
use webconfig_engine::audit::{AuditEntry, AuditLog};

/// What to do with one normalized HQ command.
#[derive(Debug)]
enum Action {
    /// Execute on-device: the `configuration` pseudo-daemon verbs.
    Local(LocalOp),
    /// Relay to a spoke through istate Control.
    Spoke { daemon: String, operation: String, json_args: String },
}

#[derive(Debug)]
enum LocalOp {
    ReadConfiguration,
    WriteConfiguration(serde_json::Value),
    /// T-P11 (B05): provision the operator account's authorized_keys.
    SetSshKeys(String),
    BackupNow,
    Restore(String),
    ApplyUpdate(serde_json::Value),
    FactoryReset,
}

pub struct IstateCommandHandler {
    client: SharedIstateClient,
    audit: Arc<AuditLog>,
    ops: Arc<DeviceOps>,
    /// The agent's data-plane mailbox: backup uploads publish a
    /// `LogUploadRequest` through it (task 009, H7).
    mailbox: hq_agent::AgentMailbox,
}

impl IstateCommandHandler {
    pub fn new(
        client: Arc<dyn IstateClient>,
        audit: Arc<AuditLog>,
        ops: Arc<DeviceOps>,
        mailbox: hq_agent::AgentMailbox,
    ) -> Self {
        Self { client, audit, ops, mailbox }
    }

    /// Map one HQ command onto a device action. Envelope validation and the
    /// destructive-operation gate live here so malformed or unsafe commands
    /// are refused before anything executes.
    fn normalize(command: &pb::Command) -> Result<Action, String> {
        if command.command_id.is_empty() {
            return Err("INVALID_ARGUMENT: command_id is required".into());
        }
        if !command.operation.is_empty() {
            if command.operation == "configuration.read" || command.operation == "configuration.write"
            {
                let args = if command.json_args.is_empty() {
                    "{}".to_owned()
                } else {
                    command.json_args.clone()
                };
                let value: serde_json::Value = serde_json::from_str(&args)
                    .map_err(|e| format!("INVALID_ARGUMENT: envelope is not valid JSON: {e}"))?;
                if command.operation == "configuration.read" {
                    // Read needs no signature; only the current contract version.
                    if value.get("schema_version").and_then(|v| v.as_u64())
                        != Some(u64::from(webconfig_engine::CONFIG_SCHEMA_VERSION))
                    {
                        return Err(format!(
                            "FAILED_PRECONDITION: unsupported configuration schema_version {}",
                            value
                                .get("schema_version")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0)
                        ));
                    }
                    return Ok(Action::Local(LocalOp::ReadConfiguration));
                }
                validate_write_envelope(&value).map_err(|e| format!("INVALID_ARGUMENT: {e}"))?;
                return Ok(Action::Local(LocalOp::WriteConfiguration(value)));
            }
            // T-P11 (B05): HQ-driven SSH key provisioning for the operator
            // account. The keys are applied immediately (ssh applier) and the
            // outcome reports the apply result, not just the store write.
            if command.operation == "ssh_keys.set" {
                let args = if command.json_args.is_empty() {
                    "{}".to_owned()
                } else {
                    command.json_args.clone()
                };
                let value: serde_json::Value = serde_json::from_str(&args)
                    .map_err(|e| format!("INVALID_ARGUMENT: envelope is not valid JSON: {e}"))?;
                let keys = value
                    .get("authorized_keys")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                return Ok(Action::Local(LocalOp::SetSshKeys(keys.to_string())));
            }
            // Generic pass-through to a real spoke.
            if command.daemon.is_empty() {
                return Err("INVALID_ARGUMENT: daemon is required for spoke operations".into());
            }
            return Ok(Action::Spoke {
                daemon: command.daemon.clone(),
                operation: command.operation.clone(),
                json_args: if command.json_args.is_empty() {
                    "{}".into()
                } else {
                    command.json_args.clone()
                },
            });
        }

        // Typed legacy commands (normalized fields absent).
        let args = match command.kind.as_ref() {
            Some(pb::command::Kind::TakeBackupNow(_)) => LocalOp::BackupNow,
            Some(pb::command::Kind::Restore(value)) => {
                LocalOp::Restore(value.backup_download_url.clone())
            }
            Some(pb::command::Kind::FactoryReset(_)) => {
                if command.required_confirmation != REQUIRED_FACTORY_RESET_CONFIRMATION {
                    return Err(format!(
                        "PERMISSION_DENIED: factory reset requires required_confirmation = {REQUIRED_FACTORY_RESET_CONFIRMATION}"
                    ));
                }
                LocalOp::FactoryReset
            }
            Some(pb::command::Kind::ApplyUpdate(value)) => {
                LocalOp::ApplyUpdate(
                    serde_json::json!({
                        "artifact_id": value.artifact_id,
                        "artifact_download_url": value.artifact_download_url,
                        "checksum_sha256": value.checksum_sha256,
                    }),
                )
            }
            None => return Err("INVALID_ARGUMENT: operation is required".into()),
        };
        Ok(Action::Local(args))
    }

    async fn execute_local(&self, op: LocalOp) -> hq_agent::CommandOutcome {
        match op {
            LocalOp::ReadConfiguration => self.ops.read_configuration().await,
            LocalOp::WriteConfiguration(envelope) => self.ops.write_configuration(&envelope).await,
            LocalOp::SetSshKeys(keys) => self.ops.set_ssh_keys(&keys).await,
            LocalOp::BackupNow => {
                let mailbox = self.mailbox.clone();
                self.ops.backup_now(&mailbox).await
            }
            LocalOp::Restore(url) => self.ops.restore_from_url(&url).await,
            LocalOp::ApplyUpdate(args) => self.ops.apply_update(&args).await,
            LocalOp::FactoryReset => self.ops.factory_reset(),
        }
    }
}

/// Validate the device configuration write contract before it is applied.
/// Cryptographic verification is transitional (see hq_bridge docs); this
/// layer rejects malformed/ambiguous envelopes rather than acknowledging them.
fn validate_write_envelope(value: &serde_json::Value) -> Result<(), String> {
    let raw = serde_json::to_string(value).unwrap_or_default();
    if raw.len() > 256 * 1024 {
        return Err("INVALID_ARGUMENT: configuration envelope exceeds 256 KiB".into());
    }
    crate::hq_bridge::validate_write_envelope(value)
}

#[async_trait::async_trait]
impl hq_agent::CommandHandler for IstateCommandHandler {
    async fn handle(&self, command: pb::Command) -> hq_agent::CommandOutcome {
        let actor = if command.actor.is_empty() {
            "hq".to_string()
        } else {
            command.actor.clone()
        };
        let action = match Self::normalize(&command) {
            Ok(value) => value,
            Err(error) => {
                let (code, message) = match error.split_once(": ") {
                    Some((c, _)) => (c.to_string(), message_tail(&error)),
                    None => ("INTERNAL".to_string(), error.clone()),
                };
                self.record_audit(&action_label(&command), false, &code);
                return hq_agent::CommandOutcome::failure(code, message);
            }
        };
        let label = action_label(&command);
        let outcome = match action {
            Action::Local(op) => self.execute_local(op).await,
            Action::Spoke {
                daemon,
                operation,
                json_args,
            } => self.relay_spoke(&daemon, &operation, &json_args, &actor, &command).await,
        };
        self.record_audit(&label, outcome.success, &outcome.code);
        outcome
    }
}

impl IstateCommandHandler {
    fn record_audit(&self, action: &str, ok: bool, code: &str) {
        let _ = self.audit.append(&AuditEntry {
            ts: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            user: "hq".into(),
            action: "command".into(),
            detail: Some(format!(
                "{action}: {}",
                if ok { "succeeded".to_owned() } else { format!("failed ({code})") }
            )),
        });
    }

    async fn relay_spoke(
        &self,
        daemon: &str,
        operation: &str,
        json_args: &str,
        actor: &str,
        command: &pb::Command,
    ) -> hq_agent::CommandOutcome {
        let request = ControlRequest {
            daemon: daemon.to_string(),
            operation: operation.to_string(),
            json_args: json_args.to_string(),
            actor: actor.to_string(),
            request_id: if command.correlation_id.is_empty() {
                command.command_id.clone()
            } else {
                command.correlation_id.clone()
            },
            deadline_ms: command.deadline_ms,
        };
        match self.client.control(request).await {
            Ok(reply) if reply.ok => hq_agent::CommandOutcome::ok_json(
                if reply.code.is_empty() { "OK".into() } else { reply.code.clone() },
                reply.json_payload,
            ),
            Ok(reply) => {
                hq_agent::CommandOutcome::failure(reply.code, reply.message)
            }
            Err(error) => {
                let text = error.to_string();
                let (code, message) = text
                    .split_once(": ")
                    .map(|(c, m)| (c.to_string(), m.to_string()))
                    .unwrap_or(("INTERNAL".into(), text.clone()));
                hq_agent::CommandOutcome::failure(code, message)
            }
        }
    }
}

/// Stable audit label for a command.
fn action_label(command: &pb::Command) -> String {
    let op = if command.operation.is_empty() {
        match command.kind.as_ref() {
            Some(pb::command::Kind::TakeBackupNow(_)) => "take_backup_now".to_string(),
            Some(pb::command::Kind::Restore(_)) => "restore".to_string(),
            Some(pb::command::Kind::FactoryReset(_)) => "factory_reset".to_string(),
            Some(pb::command::Kind::ApplyUpdate(_)) => "apply_update".to_string(),
            None => "unknown".to_string(),
        }
    } else {
        command.operation.clone()
    };
    format!("{}:{op}", command.daemon)
}

/// The message part of "CODE: message".
fn message_tail(error: &str) -> String {
    error.split_once(": ").map(|(_, m)| m.to_string()).unwrap_or_else(|| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

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
    fn configuration_read_with_current_schema_is_local() {
        let action = IstateCommandHandler::normalize(&command(
            "configuration.read",
            r#"{"schema_version":1}"#,
        ))
        .expect("read is executable locally");
        assert!(matches!(action, Action::Local(LocalOp::ReadConfiguration)));
    }

    /// T-P11 (B05): ssh_keys.set is a local op carrying the authorized_keys
    /// blob; empty args mean "clear the keys" and stay valid.
    #[test]
    fn ssh_keys_set_is_local_with_keys() {
        let action = IstateCommandHandler::normalize(&command(
            "ssh_keys.set",
            r#"{"authorized_keys":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… op@laptop"}"#,
        ))
        .expect("ssh_keys.set is executable locally");
        match action {
            Action::Local(LocalOp::SetSshKeys(keys)) => {
                assert!(keys.starts_with("ssh-ed25519 "));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn ssh_keys_set_with_empty_args_clears() {
        let action = IstateCommandHandler::normalize(&command("ssh_keys.set", "{}"))
            .expect("clearing is a valid set");
        assert!(matches!(action, Action::Local(LocalOp::SetSshKeys(_))));
    }

    #[test]
    fn configuration_write_requires_signed_hq_envelope() {
        let err = IstateCommandHandler::normalize(&command(
            "configuration.write",
            r#"{"schema_version":1,"origin":"hq","config":{}}"#,
        ))
        .unwrap_err();
        assert!(err.starts_with("INVALID_ARGUMENT") || err.starts_with("UNAUTHENTICATED"));
    }

    #[test]
    fn configuration_write_rejects_hmac_envelope() {
        // The pre-alignment HQ envelope (config_version/values) must not apply.
        let err = IstateCommandHandler::normalize(&command(
            "configuration.write",
            r#"{"config_version":1,"values":{},"signature":"00","signature_algorithm":"HMAC-SHA256"}"#,
        ))
        .unwrap_err();
        assert!(err.starts_with("INVALID_ARGUMENT:"));
    }

    #[test]
    fn factory_reset_requires_confirmation() {
        let mut cmd = pb::Command {
            command_id: "cmd-9".into(),
            ..Default::default()
        };
        cmd.kind = Some(pb::command::Kind::FactoryReset(pb::FactoryReset {}));
        let err = IstateCommandHandler::normalize(&cmd).unwrap_err();
        assert!(err.starts_with("PERMISSION_DENIED: factory reset requires"));
        cmd.required_confirmation = REQUIRED_FACTORY_RESET_CONFIRMATION.into();
        assert!(IstateCommandHandler::normalize(&cmd).is_ok());
    }

    #[test]
    fn spoke_ops_relay_through_istate() {
        let mut cmd = command("status", "{}");
        cmd.daemon = "networkd".into();
        match IstateCommandHandler::normalize(&cmd) {
            Ok(Action::Spoke { daemon, .. }) => assert_eq!(daemon, "networkd"),
            other => panic!("expected spoke relay, got {other:?}"),
        }
    }

    #[test]
    fn typed_commands_are_local() {
        let mut cmd = pb::Command {
            command_id: "cmd-2".into(),
            ..Default::default()
        };
        cmd.kind = Some(pb::command::Kind::TakeBackupNow(pb::TakeBackupNow {}));
        assert!(matches!(
            IstateCommandHandler::normalize(&cmd).unwrap(),
            Action::Local(LocalOp::BackupNow)
        ));
    }

    #[test]
    fn base64_signature_is_length_checked() {
        let sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        assert!(crate::hq_bridge::validate_write_envelope(&serde_json::json!({
            "schema_version": 1,
            "origin": "hq",
            "config": {},
            "signature_algorithm": "ed25519",
            "signature": sig,
        }))
        .is_ok());
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        assert!(crate::hq_bridge::validate_write_envelope(&serde_json::json!({
            "schema_version": 1,
            "origin": "hq",
            "config": {},
            "signature_algorithm": "ed25519",
            "signature": short,
        }))
        .is_err());
    }
}