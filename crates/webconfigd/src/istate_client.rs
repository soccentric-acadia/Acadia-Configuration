use futures_util::TryFutureExt;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

// Generated tonic/prost code: the full Instrumentation contract is mounted
// (cross-references need every package), but webconfigd uses only part of it.
#[allow(dead_code, clippy::all)]
pub mod pb {
    /// The full Instrumentation contract tree: istate.proto references
    /// telemetry/faults/logmanager types (DeviceFrame payloads, StreamLogs
    /// TailLine), so all five packages must be generated and mounted as
    /// siblings under `instr` for the cross-references to resolve.
    pub mod common {
        tonic::include_proto!("instr.common");
    }
    pub mod telemetry {
        tonic::include_proto!("instr.telemetry");
    }
    pub mod faults {
        tonic::include_proto!("instr.faults");
    }
    pub mod logmanager {
        tonic::include_proto!("instr.logmanager");
    }
    pub mod istate {
        tonic::include_proto!("instr.istate");
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRequest {
    pub daemon: String,
    pub operation: String,
    pub json_args: String,
    pub actor: String,
    pub request_id: String,
    pub deadline_ms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlReply {
    pub ok: bool,
    pub code: String,
    pub message: String,
    pub json_payload: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IstateError {
    #[error("UNAVAILABLE: istate client transport is not configured")]
    Unavailable,
    #[error("INVALID_ARGUMENT: {0}")]
    InvalidArgument(String),
    #[error("DEADLINE_EXCEEDED: istate operation timed out")]
    DeadlineExceeded,
    #[error("{code}: {message}")]
    Remote { code: String, message: String },
    #[error("INTERNAL: istate transport failure")]
    Transport,
}

#[async_trait::async_trait]
pub trait IstateClient: Send + Sync + 'static {
    async fn control(&self, request: ControlRequest) -> Result<ControlReply, IstateError>;
    /// Peer heartbeat to istate (Instrumentation §3.1): proves this daemon's
    /// event loop is turning so the hub reports the configuration peer as
    /// connected. Implementations without a live channel report Unavailable.
    async fn heartbeat(
        &self,
        hb: pb::common::Heartbeat,
    ) -> Result<pb::common::HeartbeatAck, IstateError> {
        let _ = hb;
        Err(IstateError::Unavailable)
    }
    async fn status(&self) -> Result<serde_json::Value, IstateError> {
        Err(IstateError::Unavailable)
    }
    /// Subscribe to istate's spooled northbound data (Instrumentation
    /// `ConfigurationApi.StreamDeviceData`): the device→HQ data plane. The
    /// returned stream yields replayed-then-live records; the caller maps
    /// them onto AgentLink frames (task 009, H6).
    async fn stream_device_data(
        &self,
        classes: Vec<String>,
        since_mono_ns: u64,
    ) -> Result<tonic::codec::Streaming<pb::common::RelayedData>, IstateError> {
        let _ = (classes, since_mono_ns);
        Err(IstateError::Unavailable)
    }
    /// Full-coverage relay to a spoke (istate `RelayCommand`): used by the
    /// log-bundle upload path to fetch bundle metadata/handles (task 009, H7).
    async fn relay_command(
        &self,
        daemon: String,
        op: String,
        json_args: String,
    ) -> Result<serde_json::Value, IstateError> {
        let _ = (daemon, op, json_args);
        Err(IstateError::Unavailable)
    }
}

pub type SharedIstateClient = Arc<dyn IstateClient>;

/// Explicit failure implementation used until the pinned Instrumentation
/// contract is selected for this image. It prevents commands from being
/// acknowledged as "not implemented" or silently dropped.
pub struct UnavailableIstateClient;

#[async_trait::async_trait]
impl IstateClient for UnavailableIstateClient {
    async fn control(&self, _request: ControlRequest) -> Result<ControlReply, IstateError> {
        Err(IstateError::Unavailable)
    }
}

pub struct GrpcIstateClient {
    client:
        tokio::sync::Mutex<pb::istate::configuration_api_client::ConfigurationApiClient<Channel>>,
}

impl GrpcIstateClient {
    pub async fn connect(path: impl Into<String>) -> Result<Self, IstateError> {
        let path = path.into();
        let endpoint =
            Endpoint::from_shared("http://istate.invalid").map_err(|_| IstateError::Transport)?;
        let channel = endpoint
            .connect_with_connector(service_fn(move |_: Uri| {
                UnixStream::connect(path.clone()).map_ok(TokioIo::new)
            }))
            .await
            .map_err(|_| IstateError::Unavailable)?;
        Ok(Self {
            client: tokio::sync::Mutex::new(
                pb::istate::configuration_api_client::ConfigurationApiClient::new(channel),
            ),
        })
    }

    pub async fn from_env() -> Arc<dyn IstateClient> {
        let path = std::env::var("ISTATE_SOCKET")
            .unwrap_or_else(|_| "/run/instrumentation/configuration.sock".into());
        match Self::connect(path).await {
            Ok(client) => Arc::new(client),
            Err(error) => {
                tracing::warn!(%error, "istate UDS unavailable at startup");
                Arc::new(UnavailableIstateClient)
            }
        }
    }
}

fn validate(request: &ControlRequest) -> Result<serde_json::Value, IstateError> {
    if request.daemon.len() > 128 || request.operation.len() > 128 {
        return Err(IstateError::InvalidArgument(
            "daemon or operation too long".into(),
        ));
    }
    if request.json_args.len() > 64 * 1024 {
        return Err(IstateError::InvalidArgument(
            "json_args exceeds 64 KiB".into(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(&request.json_args)
        .map_err(|e| IstateError::InvalidArgument(format!("json_args is invalid JSON: {e}")))?;
    if !value.is_object() {
        return Err(IstateError::InvalidArgument(
            "json_args must be an object".into(),
        ));
    }
    Ok(value)
}

#[async_trait::async_trait]
impl IstateClient for GrpcIstateClient {
    async fn control(&self, request: ControlRequest) -> Result<ControlReply, IstateError> {
        validate(&request)?;
        let timeout = Duration::from_millis(u64::from(request.deadline_ms.clamp(1, 120_000)));
        let rpc = pb::common::ControlRequest {
            daemon: request.daemon,
            op: request.operation,
            json_args: request.json_args,
            actor: request.actor,
            request_id: request.request_id.parse().unwrap_or(0),
            deadline_ms: request.deadline_ms,
        };
        let reply = tokio::time::timeout(timeout, async {
            self.client.lock().await.control(rpc).await
        })
        .await
        .map_err(|_| IstateError::DeadlineExceeded)?
        .map_err(|_| IstateError::Transport)?
        .into_inner();
        if !reply.ok {
            return Err(IstateError::Remote {
                code: reply.code,
                message: reply.message,
            });
        }
        Ok(ControlReply {
            ok: true,
            code: reply.code,
            message: reply.message,
            json_payload: reply.json_payload,
        })
    }

    async fn status(&self) -> Result<serde_json::Value, IstateError> {
        let peers = self
            .client
            .lock()
            .await
            .get_peer_status(pb::istate::ListSpokesRequest {})
            .await
            .map_err(|_| IstateError::Transport)?
            .into_inner();
        Ok(
            serde_json::json!({"reachable": true, "peers": peers.peers.into_iter().map(|p| serde_json::json!({
                "peer": p.peer, "kind": peer_kind_name(p.kind), "connected": p.connected, "operational": p.operational,
                "state": p.state, "detail": p.detail
            })).collect::<Vec<_>>() }),
        )
    }

    async fn stream_device_data(
        &self,
        classes: Vec<String>,
        since_mono_ns: u64,
    ) -> Result<tonic::codec::Streaming<pb::common::RelayedData>, IstateError> {
        let rpc = pb::istate::DataStreamSpec {
            classes,
            since_mono_ns,
        };
        let stream = self
            .client
            .lock()
            .await
            .stream_device_data(rpc)
            .await
            .map_err(|_| IstateError::Transport)?
            .into_inner();
        Ok(stream)
    }

    async fn relay_command(
        &self,
        daemon: String,
        op: String,
        json_args: String,
    ) -> Result<serde_json::Value, IstateError> {
        let rpc = pb::istate::RelayRequest {
            daemon,
            command: Some(pb::common::Command {
                op,
                json_args,
                issued_by: "configuration".into(),
                ..Default::default()
            }),
        };
        let reply = self
            .client
            .lock()
            .await
            .relay_command(rpc)
            .await
            .map_err(|_| IstateError::Transport)?
            .into_inner();
        if !reply.ok {
            return Err(IstateError::Remote {
                code: reply.code,
                message: reply.message,
            });
        }
        Ok(
            serde_json::from_str::<serde_json::Value>(&reply.json_payload)
                .unwrap_or_else(|_| serde_json::json!({})),
        )
    }

    async fn heartbeat(
        &self,
        hb: pb::common::Heartbeat,
    ) -> Result<pb::common::HeartbeatAck, IstateError> {
        Ok(self
            .client
            .lock()
            .await
            .heartbeat(hb)
            .await
            .map_err(|_| IstateError::Transport)?
            .into_inner())
    }
}

/// @brief Human-readable name for a `common.PeerKind` value (proto enum as i32).
fn peer_kind_name(kind: i32) -> &'static str {
    match kind {
        0 => "spoke",
        1 => "configuration",
        2 => "hq",
        _ => "unknown",
    }
}

#[cfg(test)]
pub struct MockIstateClient {
    pub reply: std::sync::Mutex<Option<Result<ControlReply, IstateError>>>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl IstateClient for MockIstateClient {
    async fn control(&self, _request: ControlRequest) -> Result<ControlReply, IstateError> {
        self.reply
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Err(IstateError::Unavailable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_arguments_are_bounded_json_objects() {
        let valid = ControlRequest {
            daemon: "networkd".into(),
            operation: "status".into(),
            json_args: "{}".into(),
            actor: "test".into(),
            request_id: "req-1".into(),
            deadline_ms: 1000,
        };
        assert!(validate(&valid).is_ok());
        let mut scalar = valid.clone();
        scalar.json_args = "[]".into();
        assert!(matches!(
            validate(&scalar),
            Err(IstateError::InvalidArgument(_))
        ));
        scalar.json_args = "{".into();
        assert!(matches!(
            validate(&scalar),
            Err(IstateError::InvalidArgument(_))
        ));
    }

    #[tokio::test]
    async fn mock_returns_a_structured_control_reply() {
        let client = MockIstateClient {
            reply: std::sync::Mutex::new(Some(Ok(ControlReply {
                ok: true,
                code: "OK".into(),
                message: String::new(),
                json_payload: "{}".into(),
            }))),
        };
        let reply = client
            .control(ControlRequest {
                daemon: "networkd".into(),
                operation: "status".into(),
                json_args: "{}".into(),
                actor: "test".into(),
                request_id: "req-1".into(),
                deadline_ms: 1000,
            })
            .await
            .unwrap();
        assert!(reply.ok);
        assert_eq!(reply.code, "OK");
    }
}
