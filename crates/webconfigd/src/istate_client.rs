use std::sync::Arc;

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
}

#[async_trait::async_trait]
pub trait IstateClient: Send + Sync + 'static {
    async fn control(&self, request: ControlRequest) -> Result<ControlReply, IstateError>;
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
