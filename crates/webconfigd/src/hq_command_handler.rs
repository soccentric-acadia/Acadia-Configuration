use std::sync::Arc;

use hq_agent::pb;

use crate::istate_client::{ControlRequest, IstateClient, SharedIstateClient};

pub struct IstateCommandHandler {
    client: SharedIstateClient,
}

impl IstateCommandHandler {
    pub fn new(client: Arc<dyn IstateClient>) -> Self {
        Self { client }
    }

    fn normalize(command: &pb::Command) -> Result<(String, String, String), String> {
        if command.command_id.is_empty() {
            return Err("INVALID_ARGUMENT: command_id is required".into());
        }
        if !command.operation.is_empty() {
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
        match self.client.control(request).await {
            Ok(reply) if reply.ok => (true, reply.json_payload),
            Ok(reply) => (false, format!("{}: {}", reply.code, reply.message)),
            Err(error) => (false, error.to_string()),
        }
    }
}
