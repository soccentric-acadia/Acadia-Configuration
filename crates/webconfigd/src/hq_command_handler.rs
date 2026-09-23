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

use crate::hq_bridge::{
    DeviceOps, REQUIRED_FACTORY_RESET_CONFIRMATION, REQUIRED_ROLLBACK_CONFIRMATION,
    REQUIRED_SHUTDOWN_CONFIRMATION, SERVICE_ACTIONS,
};
use crate::istate_client::{ControlRequest, IstateClient, SharedIstateClient};
use std::sync::Arc;
use webconfig_engine::audit::{AuditEntry, AuditLog};

/// What to do with one normalized HQ command.
#[derive(Debug)]
enum Action {
    /// Execute on-device: the `configuration` pseudo-daemon verbs.
    Local(LocalOp),
    /// Relay to a spoke through istate Control.
    Spoke {
        daemon: String,
        operation: String,
        json_args: String,
    },
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
    /// T-P20 (C04/C05): power control, executed after the outcome is acked.
    Reboot,
    Shutdown,
    /// T-P20 (K10): the remote OTA activation/confirm/rollback verbs.
    RebootToApply,
    ConfirmUpdate,
    RollbackUpdate,
    /// T-P20 (G02): one allowlisted unit, one action.
    ServiceControl {
        unit: String,
        action: String,
    },
    /// T-P20 (J04): create + upload a logmanager support bundle.
    LogBundleRequest,
    /// T-P20 (B02): `users.list|create|delete|set_role` + its JSON args.
    Users(String, serde_json::Value),
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
        Self {
            client,
            audit,
            ops,
            mailbox,
        }
    }

    /// Map one HQ command onto a device action. Envelope validation and the
    /// destructive-operation gate live here so malformed or unsafe commands
    /// are refused before anything executes.
    fn normalize(command: &pb::Command) -> Result<Action, String> {
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
            // T-P20: device-local verbs of the `configuration` pseudo-daemon.
            if let Some(op) = Self::normalize_tp20(command)? {
                return Ok(Action::Local(op));
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
                LocalOp::ApplyUpdate(serde_json::json!({
                    "artifact_id": value.artifact_id,
                    "artifact_download_url": value.artifact_download_url,
                    "checksum_sha256": value.checksum_sha256,
                }))
            }
            None => return Err("INVALID_ARGUMENT: operation is required".into()),
        };
        Ok(Action::Local(args))
    }

    /// T-P20 verbs. `Ok(None)` = not a T-P20 operation.
    fn normalize_tp20(command: &pb::Command) -> Result<Option<LocalOp>, String> {
        let args = || -> Result<serde_json::Value, String> {
            let raw = if command.json_args.is_empty() {
                "{}"
            } else {
                command.json_args.as_str()
            };
            serde_json::from_str(raw)
                .map_err(|e| format!("INVALID_ARGUMENT: json_args is not valid JSON: {e}"))
        };
        let confirm = |required: &str| -> Result<(), String> {
            if command.required_confirmation == required {
                Ok(())
            } else {
                Err(format!(
                    "PERMISSION_DENIED: {} requires required_confirmation = {required}",
                    command.operation
                ))
            }
        };
        let op = match command.operation.as_str() {
            "system.reboot" => LocalOp::Reboot,
            "system.shutdown" => {
                confirm(REQUIRED_SHUTDOWN_CONFIRMATION)?;
                LocalOp::Shutdown
            }
            "update.reboot_to_apply" => LocalOp::RebootToApply,
            "update.confirm" => LocalOp::ConfirmUpdate,
            "update.rollback" => {
                confirm(REQUIRED_ROLLBACK_CONFIRMATION)?;
                LocalOp::RollbackUpdate
            }
            "service.control" => {
                let v = args()?;
                let unit = v.get("unit").and_then(|x| x.as_str()).unwrap_or("");
                let action = v.get("action").and_then(|x| x.as_str()).unwrap_or("");
                if unit.is_empty() || !SERVICE_ACTIONS.contains(&action) {
                    return Err(format!(
                        "INVALID_ARGUMENT: service.control needs unit and action in {SERVICE_ACTIONS:?}"
                    ));
                }
                LocalOp::ServiceControl {
                    unit: unit.to_string(),
                    action: action.to_string(),
                }
            }
            "log_bundle.request" => LocalOp::LogBundleRequest,
            "users.list" | "users.create" | "users.delete" | "users.set_role" => {
                let v = args()?;
                if command.operation != "users.list"
                    && v.get("username")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .is_empty()
                {
                    return Err("INVALID_ARGUMENT: username is required".into());
                }
                LocalOp::Users(command.operation.clone(), v)
            }
            _ => return Ok(None),
        };
        Ok(Some(op))
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
            LocalOp::Reboot => self.ops.reboot(),
            LocalOp::Shutdown => self.ops.shutdown(),
            LocalOp::RebootToApply => self.ops.reboot_to_apply(),
            LocalOp::ConfirmUpdate => self.ops.confirm_update().await,
            LocalOp::RollbackUpdate => self.ops.rollback_update(),
            LocalOp::ServiceControl { unit, action } => {
                self.ops.service_control(&unit, &action).await
            }
            LocalOp::LogBundleRequest => {
                let mailbox = self.mailbox.clone();
                self.ops.request_log_bundle(&mailbox).await
            }
            LocalOp::Users(op, args) => self.ops.users(&op, &args),
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
            } => {
                self.relay_spoke(&daemon, &operation, &json_args, &actor, &command)
                    .await
            }
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
                if ok {
                    "succeeded".to_owned()
                } else {
                    format!("failed ({code})")
                }
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
                if reply.code.is_empty() {
                    "OK".into()
                } else {
                    reply.code.clone()
                },
                reply.json_payload,
            ),
            Ok(reply) => hq_agent::CommandOutcome::failure(reply.code, reply.message),
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
    error
        .split_once(": ")
        .map(|(_, m)| m.to_string())
        .unwrap_or_else(|| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// Serialise the WEBCONFIG_HQ_CONFIG_PUBKEY env manipulation — tests run
    /// on threads sharing one process environment.
    static PUBKEY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    /// T-P13 (F09): the transitional HMAC path is retired — HMAC envelopes
    /// are rejected outright.
    #[test]
    fn configuration_write_rejects_hmac_envelope() {
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

    /// T-P20: power/update/service/log/users verbs are device-local.
    #[test]
    fn tp20_verbs_are_local() {
        for (op, args) in [
            ("system.reboot", "{}"),
            ("update.reboot_to_apply", "{}"),
            ("update.confirm", "{}"),
            ("log_bundle.request", "{}"),
            (
                "service.control",
                r#"{"unit":"sshd.service","action":"restart"}"#,
            ),
            ("users.list", "{}"),
            ("users.delete", r#"{"username":"bob"}"#),
        ] {
            let action = IstateCommandHandler::normalize(&command(op, args))
                .unwrap_or_else(|e| panic!("{op}: {e}"));
            assert!(matches!(action, Action::Local(_)), "{op} must be local");
        }
    }

    #[test]
    fn tp20_destructive_verbs_need_confirmation() {
        for (op, word) in [
            ("system.shutdown", REQUIRED_SHUTDOWN_CONFIRMATION),
            ("update.rollback", REQUIRED_ROLLBACK_CONFIRMATION),
        ] {
            let mut cmd = command(op, "{}");
            let err = IstateCommandHandler::normalize(&cmd).unwrap_err();
            assert!(err.starts_with("PERMISSION_DENIED"), "{op}: {err}");
            cmd.required_confirmation = word.into();
            assert!(IstateCommandHandler::normalize(&cmd).is_ok(), "{op}");
        }
    }

    #[test]
    fn tp20_argument_validation() {
        let err = IstateCommandHandler::normalize(&command(
            "service.control",
            r#"{"unit":"sshd.service","action":"mask"}"#,
        ))
        .unwrap_err();
        assert!(err.starts_with("INVALID_ARGUMENT"));
        let err = IstateCommandHandler::normalize(&command("users.create", r#"{"role":"admin"}"#))
            .unwrap_err();
        assert!(err.starts_with("INVALID_ARGUMENT"));
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

    /// T-P13: without a provisioned HQ verification key, ANY write is
    /// rejected (fail closed) — the old length-check-only policy is gone.
    #[test]
    fn write_is_rejected_without_provisioned_verification_key() {
        let _guard = PUBKEY_ENV_LOCK.lock().unwrap();
        // The test harness never provisions WEBCONFIG_HQ_CONFIG_PUBKEY.
        std::env::remove_var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV);
        let sig = base64::engine::general_purpose::STANDARD.encode([0u8; 64]);
        let err = IstateCommandHandler::normalize(&command(
            "configuration.write",
            &format!(
                r#"{{"schema_version":1,"origin":"hq","config":{{}},"signature_algorithm":"ed25519","signature":"{sig}"}}"#
            ),
        ))
        .unwrap_err();
        assert!(err.contains("verification key not provisioned"), "{err}");
    }

    /// T-P13: an envelope signed by the HQ Ed25519 key verifies against the
    /// provisioned key, over the canonical transport payload (envelope minus
    /// the signature fields).
    #[test]
    fn write_verifies_ed25519_signature_against_provisioned_key() {
        let _guard = PUBKEY_ENV_LOCK.lock().unwrap();
        use base64::Engine;
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let envelope = serde_json::json!({
            "schema_version": 1,
            "origin": "hq",
            "config": {"system": {"hostname": "signed-by-hq"}},
            "signature_algorithm": "ed25519",
        });
        // Canonical bytes = the contract fields ONLY (schema_version/origin/
        // config) — the same subset canonicalization hq_bridge::signed_document
        // performs.
        let doc = serde_json::json!({
            "schema_version": 1,
            "origin": "hq",
            "config": {"system": {"hostname": "signed-by-hq"}},
        });
        let sig = pair.sign(serde_json::to_vec(&doc).unwrap().as_slice());
        let envelope = {
            let mut e = envelope.clone();
            e["signature"] = serde_json::Value::String(
                base64::engine::general_purpose::STANDARD.encode(sig.as_ref()),
            );
            e
        };
        let pub_raw = pair.public_key().as_ref();
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_raw);
        std::env::set_var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV, &pub_b64);
        let res = crate::hq_bridge::validate_write_envelope(&envelope);
        std::env::remove_var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV);
        assert!(res.is_ok(), "{res:?}");

        // A tampered config fails verification.
        let mut tampered = envelope.clone();
        tampered["config"]["system"]["hostname"] = "tampered".into();
        std::env::set_var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV, &pub_b64);
        let res = crate::hq_bridge::validate_write_envelope(&tampered);
        std::env::remove_var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV);
        assert!(res.is_err());
    }

    /// T-P13: a PEM (RFC 8410 SPKI) provisioned key verifies too — the
    /// deployment runbook provisions PEM files.
    #[test]
    fn pem_provisioned_verification_key_is_accepted() {
        let _guard = PUBKEY_ENV_LOCK.lock().unwrap();
        use base64::Engine;
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let envelope = serde_json::json!({
            "schema_version": 1,
            "origin": "hq",
            "config": {},
            "signature_algorithm": "ed25519",
        });
        let doc = serde_json::json!({
            "schema_version": 1,
            "origin": "hq",
            "config": {},
        });
        let sig = pair.sign(serde_json::to_vec(&doc).unwrap().as_slice());
        let mut envelope = envelope.clone();
        envelope["signature"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(sig.as_ref()),
        );
        // Build the RFC 8410 SPKI PEM from the raw public key.
        let mut der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        der.extend_from_slice(pair.public_key().as_ref());
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        std::env::set_var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV, &pem);
        let res = crate::hq_bridge::validate_write_envelope(&envelope);
        std::env::remove_var(crate::hq_bridge::HQ_CONFIG_PUBKEY_ENV);
        assert!(res.is_ok(), "{res:?}");
    }
}
