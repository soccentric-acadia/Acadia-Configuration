//! Device-side Acadia-HQ AgentLink client (X5-001..005).
//!
//! Implements the device side of `doc/hq-pairing-contract.md` on the
//! `acadiahq.agent.AgentLink` gRPC service, matching the gateway semantics in
//! `Acadia-HQ/agent-gateway/gateway/servicer.py`:
//!
//! - state `Pending`: connect → `PairingHandshake` → await `PairingResult`.
//!   On success the long-lived credential + permanent `device_id` are stored
//!   and the device reconnects as `Enrolled` (the pairing stream ends after
//!   the result). On failure: bounded, capped, jittered backoff — the same
//!   token is retried until it expires.
//! - state `Enrolled`: connect → `Heartbeat` (credential on every frame, per
//!   the contract) → `HeartbeatAck` keeps the stream alive; commands are
//!   dispatched to a [`CommandHandler`] and acknowledged.
//! - An `UNAUTHENTICATED` abort while enrolled means the credential was
//!   revoked → agent enters `Revoked` (degraded state, prompts re-enroll).
//!   Any other stream failure is a plain retry with backoff.
//!
//! The loop is transport-agnostic: [`AgentConnector`] + [`AgentSession`] are
//! object-safe traits so unit tests drive the state machine against an
//! in-memory mock with no network. [`GrpcConnector`] is the tonic client.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::{mpsc, watch};

use webconfig_engine::pairing::{PairingAgent, PairingOutcome, PairingState};

pub mod pb {
    tonic::include_proto!("acadiahq.agent");
}

/// Contract default (doc/hq-pairing-contract.md §Heartbeat). The gateway may
/// override per-device via `HeartbeatAck.next_heartbeat_interval_s`.
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: i64 = 30;
pub const AGENT_PROTOCOL_VERSION: u32 = 1;

/// Wait used when the device has nothing to authenticate with yet.
const IDLE_POLL_SECS: u64 = 5;

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("send failed: {0}")]
    Send(String),
    /// The gateway rejected the credential (revoked / disabled device).
    #[error("unauthenticated: {0}")]
    Unauthenticated(String),
}

/// One live AgentLink stream (send + receive halves are independent).
#[async_trait::async_trait]
pub trait AgentSession: Send {
    async fn send(&mut self, frame: pb::AgentFrame) -> Result<(), AgentError>;
    /// None = the server closed the stream.
    async fn next_frame(&mut self) -> Option<Result<pb::ServerFrame, AgentError>>;
}

#[async_trait::async_trait]
pub trait AgentConnector: Send + Sync + 'static {
    async fn connect(&self, endpoint: &str) -> Result<Box<dyn AgentSession>, AgentError>;
}

/// Executes a Command pushed by HQ; the result becomes the `CommandAck`.
/// Handlers must be idempotent on `command_id` and gate destructive
/// operations (factory reset etc.) — X5-027/028.
#[async_trait::async_trait]
pub trait CommandHandler: Send + Sync + 'static {
    async fn handle(&self, command: pb::Command) -> CommandOutcome;
}

/// Hooks for server frames the agent loop does not interpret itself.
///
/// `SignedUploadUrl` answers a device-issued `LogUploadRequest` (log bundle /
/// backup blob upload, X5-024): the device fetches bulk bytes itself and PUTs
/// them to the presigned URL. The agent stays transport-only; the device
/// implements the actual upload (task 009, H7).
#[async_trait::async_trait]
pub trait ServerFrameHooks: Send + Sync + 'static {
    async fn on_signed_upload_url(&self, url: pb::SignedUploadUrl) {
        let _ = url;
    }
}

/// No-op hooks for callers/tests that do not implement uploads.
#[async_trait::async_trait]
impl ServerFrameHooks for () {
    async fn on_signed_upload_url(&self, _url: pb::SignedUploadUrl) {}
}

/// The full result of executing one HQ command (task 009, H1).
///
/// The gateway reads `json_payload` into the durable command record's
/// `result_payload` and keeps `error` only on failure — a handler that
/// collapses everything into the old `(bool, String)` pair lost successful
/// results (e.g. a `configuration.read` answer) entirely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutcome {
    pub success: bool,
    /// Machine-readable status code ("OK" on success).
    pub code: String,
    /// Human-readable failure detail; empty on success.
    pub message: String,
    /// JSON result data (stringified) returned to HQ on success.
    pub json_payload: String,
}

impl CommandOutcome {
    /// Successful outcome with a JSON payload.
    pub fn ok_json(code: impl Into<String>, json_payload: impl Into<String>) -> Self {
        Self {
            success: true,
            code: code.into(),
            message: String::new(),
            json_payload: json_payload.into(),
        }
    }
    /// Structured failure.
    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            success: false,
            code: code.into(),
            message: message.into(),
            json_payload: String::new(),
        }
    }
}

/// Adds device-side at-most-once behavior to any command implementation.
/// The cache is intentionally bounded so a compromised gateway cannot make
/// the agent retain unbounded command history.
pub struct IdempotentCommandHandler<H> {
    inner: H,
    completed: Mutex<HashMap<String, CommandOutcome>>,
    capacity: usize,
}

impl<H> IdempotentCommandHandler<H> {
    pub fn new(inner: H) -> Self {
        Self::with_capacity(inner, 256)
    }

    pub fn with_capacity(inner: H, capacity: usize) -> Self {
        assert!(capacity > 0, "idempotency cache capacity must be positive");
        Self {
            inner,
            completed: Mutex::new(HashMap::new()),
            capacity,
        }
    }
}

#[async_trait::async_trait]
impl<H: CommandHandler> CommandHandler for IdempotentCommandHandler<H> {
    async fn handle(&self, command: pb::Command) -> CommandOutcome {
        let key = if command.idempotency_key.is_empty() {
            command.command_id.clone()
        } else {
            command.idempotency_key.clone()
        };
        if let Some(result) = self.completed.lock().unwrap().get(&key).cloned() {
            return result;
        }

        let result = self.inner.handle(command).await;
        let mut completed = self.completed.lock().unwrap();
        if completed.len() >= self.capacity {
            if let Some(oldest) = completed.keys().next().cloned() {
                completed.remove(&oldest);
            }
        }
        completed.insert(key, result.clone());
        result
    }
}

/// Refuses every command with a well-formed ack until the per-daemon
/// handlers land (X5-021+).
pub struct NullCommandHandler;

#[async_trait::async_trait]
impl CommandHandler for NullCommandHandler {
    async fn handle(&self, command: pb::Command) -> CommandOutcome {
        CommandOutcome::failure(
            "NOT_IMPLEMENTED",
            format!(
                "command {} not implemented on this agent",
                command.command_id
            ),
        )
    }
}

/// ±20% jitter so fleets do not reconnect in lockstep after an HQ outage.
fn jittered(secs: u64) -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let pct = nanos % 41; // 0..=40 → ±20%
    let delta = secs * pct / 100;
    if pct >= 20 {
        secs + (secs * (pct - 20) / 100)
    } else {
        secs.saturating_sub(secs * (20 - pct) / 100)
    }
    .max(1)
    .saturating_add(0)
    .max(if delta == 0 { 1 } else { delta })
}

/// T-P24: the latest device snapshot attached to every heartbeat. The
/// embedding daemon refreshes it (webconfigd: every 30 s); `None` until the
/// first snapshot, in which case heartbeats carry no status.
fn device_status_slot() -> &'static Mutex<Option<pb::DeviceStatus>> {
    static STATUS: OnceLock<Mutex<Option<pb::DeviceStatus>>> = OnceLock::new();
    STATUS.get_or_init(|| Mutex::new(None))
}

/// Replace the device snapshot sent with the next heartbeats (T-P24).
pub fn set_device_status(status: pb::DeviceStatus) {
    if let Ok(mut slot) = device_status_slot().lock() {
        *slot = Some(status);
    }
}

fn current_device_status() -> Option<pb::DeviceStatus> {
    device_status_slot().lock().ok().and_then(|s| s.clone())
}

fn heartbeat_frame(agent: &PairingAgent, credential: &str) -> pb::Heartbeat {
    static HEARTBEAT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    pb::Heartbeat {
        device_id: agent.device_id().unwrap_or_default().to_string(),
        credential_token: credential.to_string(),
        sent_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: AGENT_PROTOCOL_VERSION,
        boot_id: boot_id(),
        heartbeat_sequence: HEARTBEAT_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1,
        sent_at_mono_ns: monotonic_now_ns(),
        capabilities: Vec::new(),
        status: current_device_status(),
    }
}

fn boot_id() -> String {
    static BOOT_ID: OnceLock<String> = OnceLock::new();
    BOOT_ID
        .get_or_init(|| {
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map(|value| value.trim().to_string())
                .unwrap_or_else(|_| "unknown".into())
        })
        .clone()
}

fn heartbeat_frame_msg(agent: &PairingAgent, credential: &str) -> pb::AgentFrame {
    pb::AgentFrame {
        body: Some(pb::agent_frame::Body::Heartbeat(heartbeat_frame(
            agent, credential,
        ))),
    }
}

/// The frame to open a session with for the current state. `Ok(None)` means
/// the device has nothing to authenticate with.
fn first_frame(agent: &PairingAgent) -> Result<Option<pb::AgentFrame>, AgentError> {
    match agent.state() {
        PairingState::Pending => {
            if agent.token_expired() {
                return Err(AgentError::Connect(
                    "pairing token expired — re-provision required".into(),
                ));
            }
            let token = agent
                .credential()
                .ok_or_else(|| AgentError::Connect("pending state without token".into()))?
                .to_string();
            Ok(Some(pb::AgentFrame {
                body: Some(pb::agent_frame::Body::PairingHandshake(
                    pb::PairingHandshake {
                        pairing_token: token,
                    },
                )),
            }))
        }
        PairingState::Enrolled => {
            let credential = agent
                .credential()
                .ok_or_else(|| AgentError::Connect("enrolled state without credential".into()))?
                .to_string();
            Ok(Some(heartbeat_frame_msg(agent, &credential)))
        }
        PairingState::Unprovisioned | PairingState::Revoked => Ok(None),
    }
}

/// Handle one ServerFrame. Returns true when the caller should close this
/// session (pairing complete → reconnect as Enrolled).
async fn handle_server_frame<H, S, U>(
    agent: &Arc<std::sync::Mutex<PairingAgent>>,
    session: &mut S,
    frame: pb::ServerFrame,
    handler: &H,
    hooks: &U,
    heartbeat_interval: &mut i64,
) -> bool
where
    H: CommandHandler,
    U: ServerFrameHooks,
    S: AgentSession + ?Sized,
{
    match frame.body {
        Some(pb::server_frame::Body::PairingResult(result)) => {
            if result.success {
                {
                    let mut a = agent.lock().unwrap();
                    a.set_credential(result.credential_token.clone());
                    if !result.device_id.is_empty() {
                        a.set_device_id(result.device_id.clone());
                    }
                    a.on_enrolled();
                }
                tracing::info!("pairing: enrolled with HQ");
                // Complete enrollment: answer the new credential with a
                // Heartbeat on this same session before it is torn down.
                let frame = {
                    let a = agent.lock().unwrap();
                    match a.credential() {
                        Some(cred) => heartbeat_frame_msg(&a, cred),
                        None => return true,
                    }
                };
                if let Err(e) = session.send(frame).await {
                    tracing::warn!("failed to send post-enrollment heartbeat: {e}");
                }
                true
            } else {
                tracing::warn!("pairing rejected by HQ: {}", result.error);
                let mut a = agent.lock().unwrap();
                a.on_failure(); // retry the same token until it expires
                false
            }
        }
        Some(pb::server_frame::Body::HeartbeatAck(ack)) => {
            {
                let mut a = agent.lock().unwrap();
                a.on_heartbeat();
                if ack.next_heartbeat_interval_s > 0
                    && ack.next_heartbeat_interval_s as i64 != *heartbeat_interval
                {
                    tracing::info!(
                        "gateway adjusted heartbeat interval: {}s",
                        ack.next_heartbeat_interval_s
                    );
                    *heartbeat_interval = ack.next_heartbeat_interval_s as i64;
                }
            }
            false
        }
        Some(pb::server_frame::Body::Command(command)) => {
            let accepted_at_mono_ns = monotonic_now_ns();
            let outcome = handler.handle(command.clone()).await;
            let correlation_id = if command.correlation_id.is_empty() {
                command.command_id.clone()
            } else {
                command.correlation_id.clone()
            };
            let ack = pb::AgentFrame {
                body: Some(pb::agent_frame::Body::CommandAck(pb::CommandAck {
                    command_id: command.command_id,
                    success: outcome.success,
                    // Failure detail only: the gateway stores json_payload as
                    // the durable result; a payload smuggled through `error`
                    // was discarded on success (task 009, H1).
                    error: if outcome.success {
                        String::new()
                    } else {
                        outcome.message.clone()
                    },
                    daemon: command.daemon,
                    operation: command.operation,
                    code: outcome.code,
                    json_payload: outcome.json_payload,
                    correlation_id,
                    accepted_at_mono_ns,
                    completed_at_mono_ns: monotonic_now_ns(),
                    retryable: false,
                })),
            };
            if let Err(e) = session.send(ack).await {
                tracing::warn!("failed to send CommandAck: {e}");
            }

            false
        }
        Some(pb::server_frame::Body::SignedUploadUrl(url)) => {
            // Forwarded to the device's upload executor (task 009, H7); the
            // agent itself never interprets the URL.
            hooks.on_signed_upload_url(url).await;
            false
        }
        None => false,
    }
}

fn monotonic_now_ns() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

/// The real transport: a thin tonic client for the one streaming RPC. The
/// generated client is disabled because the RPC is named `Connect`, which
/// collides with tonic's generated `AgentLinkClient::connect(dst)`
/// constructor — the hand-written wrapper keeps the wire path
/// `/acadiahq.agent.AgentLink/Connect` exact.
pub struct GrpcConnector {
    /// Per-connect timeout; the loop's backoff governs retry pacing overall.
    pub connect_timeout: Duration,
}

impl Default for GrpcConnector {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
        }
    }
}

fn to_agent_error(status: tonic::Status) -> AgentError {
    match status.code() {
        tonic::Code::Unauthenticated => AgentError::Unauthenticated(status.message().into()),
        tonic::Code::InvalidArgument => AgentError::Connect(format!("invalid frame: {status}")),
        _ => AgentError::Connect(format!("{status}")),
    }
}

/// One live gRPC bidi stream. The request-half sender is held for the
/// session's lifetime so the gateway keeps receiving our frames.
///
/// X5-012 deadlock note: tonic's `Grpc::streaming` future only resolves once
/// the server sends response headers, and this gateway sends headers lazily
/// — AFTER the first client frame. So the streaming call is spawned and the
/// receive half is handed back via a oneshot, while `send()` queues frames
/// immediately (the h2 connection task flushes them as the stream opens).
pub struct GrpcSession {
    tx: mpsc::Sender<pb::AgentFrame>,
    ready: Option<
        tokio::sync::oneshot::Receiver<
            Result<tonic::codec::Streaming<pb::ServerFrame>, AgentError>,
        >,
    >,
    rx: Option<tonic::codec::Streaming<pb::ServerFrame>>,
}

#[async_trait::async_trait]
impl AgentSession for GrpcSession {
    async fn send(&mut self, frame: pb::AgentFrame) -> Result<(), AgentError> {
        self.tx
            .send(frame)
            .await
            .map_err(|_| AgentError::Send("request stream closed".into()))
    }

    async fn next_frame(&mut self) -> Option<Result<pb::ServerFrame, AgentError>> {
        if self.rx.is_none() {
            let ready = self.ready.take()?;
            match ready.await {
                Ok(Ok(streaming)) => self.rx = Some(streaming),
                Ok(Err(e)) => return Some(Err(e)),
                Err(_) => return Some(Err(AgentError::Connect("stream task dropped".into()))),
            }
        }
        match self.rx.as_mut().unwrap().message().await {
            Ok(Some(f)) => Some(Ok(f)),
            Ok(None) => None,
            Err(status) => Some(Err(to_agent_error(status))),
        }
    }
}

impl GrpcConnector {
    /// Resolve the dial URI for an AgentLink endpoint (T-P12, F10).
    ///
    /// Secure by default: a bare `host:port` (the pairing-UI provisioning
    /// shape) dials `https://` — the gateway serves TLS (gateway/server.py)
    /// with the HQ CA pinned at `/etc/acadia/hq-ca.pem` (provisioned with the
    /// endpoint, P-A10). An explicit scheme is honored: `http://` stays
    /// available for plaintext dev deployments, `https://` is explicit TLS.
    ///
    /// Optional mTLS: when the device carries an AgentLink client identity
    /// (`/pst/webconfig/hq-client-{cert,key}.pem`), it presents it — paired
    /// with the gateway's `tls_client_ca_path`.
    pub fn normalize_endpoint(endpoint: &str) -> String {
        if endpoint.contains("://") {
            endpoint.to_string()
        } else {
            format!("https://{endpoint}")
        }
    }

    async fn dial(
        endpoint: &str,
        connect_timeout: std::time::Duration,
    ) -> Result<tonic::transport::Channel, AgentError> {
        let uri = Self::normalize_endpoint(endpoint);
        let mut ep = tonic::transport::Endpoint::from_shared(uri.clone())
            .map_err(|e| AgentError::Connect(e.to_string()))?
            .connect_timeout(connect_timeout);
        if uri.starts_with("https://") {
            // Pinned HQ CA first (provisioned, P-A10); the native root store
            // (tls-roots feature) covers publicly-trusted gateway certs.
            let mut tls = tonic::transport::ClientTlsConfig::new().with_enabled_roots();
            if let Some(ca) = hq_ca_pem() {
                tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(ca));
            }
            // Optional mTLS identity (factory-issued client certificate).
            if let (Ok(cert), Ok(key)) = (
                std::fs::read(HQ_CLIENT_CERT_PATH),
                std::fs::read(HQ_CLIENT_KEY_PATH),
            ) {
                tls = tls.identity(tonic::transport::Identity::from_pem(cert, key));
            }
            ep = ep
                .tls_config(tls)
                .map_err(|e| AgentError::Connect(e.to_string()))?;
        }
        ep.connect()
            .await
            .map_err(|e| AgentError::Connect(e.to_string()))
    }
}

/// Pinned HQ CA for AgentLink TLS verification (P-A10): first-use
/// provisioning writes it to the persistent WebConfig store
/// (`$WEBCONFIG_DATA_DIR/webconfig/hq-ca.pem`, default `/pst/webconfig/`);
/// `/etc/acadia/hq-ca.pem` is an optional fleet CA baked into the image.
const HQ_CA_IMAGE_PATH: &str = "/etc/acadia/hq-ca.pem";

fn hq_ca_pem() -> Option<Vec<u8>> {
    let data = std::env::var("WEBCONFIG_DATA_DIR").unwrap_or_else(|_| "/pst".into());
    let provisioned = std::path::Path::new(&data).join("webconfig/hq-ca.pem");
    std::fs::read(provisioned)
        .or_else(|_| std::fs::read(HQ_CA_IMAGE_PATH))
        .ok()
}
/// Optional mTLS device identity for AgentLink (factory-issued, T-P12).
const HQ_CLIENT_CERT_PATH: &str = "/pst/webconfig/hq-client-cert.pem";
const HQ_CLIENT_KEY_PATH: &str = "/pst/webconfig/hq-client-key.pem";

#[async_trait::async_trait]
impl AgentConnector for GrpcConnector {
    async fn connect(&self, endpoint: &str) -> Result<Box<dyn AgentSession>, AgentError> {
        let channel = Self::dial(endpoint, self.connect_timeout).await?;

        // The request half of the bidi stream: frames we send upstream.
        // ReceiverStream bridges tokio's channel to the futures Stream the
        // gRPC codec expects.
        let (tx, rx) = mpsc::channel::<pb::AgentFrame>(16);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let mut grpc = tonic::client::Grpc::new(channel);
            if let Err(e) = grpc.ready().await {
                let _ = ready_tx.send(Err(AgentError::Connect(e.to_string())));
                return;
            }
            let path = http::uri::PathAndQuery::from_static("/acadiahq.agent.AgentLink/Connect");
            let request = tonic::Request::new(tokio_stream::wrappers::ReceiverStream::new(rx));
            let response: tonic::Response<tonic::codec::Streaming<pb::ServerFrame>> = match grpc
                .streaming(
                    request,
                    path,
                    tonic::codec::ProstCodec::<pb::AgentFrame, pb::ServerFrame>::default(),
                )
                .await
            {
                Ok(r) => r,
                Err(status) => {
                    let _ = ready_tx.send(Err(to_agent_error(status)));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(response.into_inner()));
        });

        Ok(Box::new(GrpcSession {
            tx,
            ready: Some(ready_rx),
            rx: None,
        }))
    }
}

/// Handle for other components (the device→HQ data-plane bridge) to enqueue
/// frames on the agent's live AgentLink session (task 009, P3.2).
///
/// Bounded buffer: while the agent is offline or saturated, `try_publish`
/// reports rejection instead of blocking — the istate northbound spool stays
/// the durability layer, and the gateway tolerates telemetry gaps.
/// Frames buffered between sessions are flushed on the next connect.
#[derive(Clone)]
pub struct AgentMailbox {
    tx: mpsc::Sender<pb::AgentFrame>,
}

impl AgentMailbox {
    /// Enqueue a frame for the current/next enrolled session. Non-blocking;
    /// returns false when the agent has no capacity (offline or saturated).
    /// Callers must only publish while the pairing state is Enrolled — the
    /// agent re-checks the state before sending.
    pub fn try_publish(&self, frame: pb::AgentFrame) -> bool {
        self.tx.try_send(frame).is_ok()
    }
}

/// Create the data-plane mailbox pair: the caller keeps the
/// [`AgentMailbox`], and passes the receiver to [`run_agent`]. Created outside
/// the loop so other components can hold the mailbox before the agent's first
/// session opens.
pub fn mailbox_channel() -> (AgentMailbox, mpsc::Receiver<pb::AgentFrame>) {
    let (tx, rx) = mpsc::channel::<pb::AgentFrame>(256);
    (AgentMailbox { tx }, rx)
}

/// Run the connect/heartbeat/retry loop until `shutdown` fires. Never returns
/// early on transport errors — every failure goes through the pairing agent's
/// bounded backoff and the loop reconnects. Returns the mailbox other
/// components publish data-plane frames through.
///
/// Lock discipline: `agent` is a std mutex shared with the HTTP layer; the
/// loop only holds it for state reads/writes, never across an await.
pub async fn run_agent<C, H, U>(
    agent: Arc<std::sync::Mutex<PairingAgent>>,
    connector: C,
    handler: H,
    hooks: U,
    mut pub_rx: mpsc::Receiver<pb::AgentFrame>,
    mut shutdown: watch::Receiver<bool>,
) where
    C: AgentConnector,
    H: CommandHandler,
    U: ServerFrameHooks,
{
    #[derive(Debug)]
    enum Next {
        /// Nothing to do yet — poll again shortly.
        Idle,
        /// Backoff window of `secs` (already jittered); then re-check.
        Wait(u64),
        /// Open a session with this endpoint and first frame.
        Attempt(String, Box<pb::AgentFrame>),
    }

    let mut heartbeat_interval = DEFAULT_HEARTBEAT_INTERVAL_SECS;
    loop {
        if *shutdown.borrow() {
            return;
        }

        // ── Decide what to do next (short lock, no awaits inside) ───────────
        let next = {
            let mut a = agent.lock().expect("pairing agent lock");
            match a.state() {
                PairingState::Unprovisioned | PairingState::Revoked => Next::Idle,
                PairingState::Pending | PairingState::Enrolled => match a.retry_allowed() {
                    PairingOutcome::Revoked => Next::Idle,
                    PairingOutcome::Retry { after_secs } => Next::Wait(jittered(after_secs)),
                    PairingOutcome::Ok => match first_frame(&a) {
                        Ok(Some(frame)) => {
                            Next::Attempt(a.hq_endpoint().to_string(), Box::new(frame))
                        }
                        Ok(None) => Next::Idle,
                        Err(e) => {
                            tracing::warn!("agent: cannot authenticate: {e}");
                            a.on_failure();
                            Next::Idle
                        }
                    },
                },
            }
        };

        match next {
            Next::Idle => {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(IDLE_POLL_SECS)) => continue,
                    _ = shutdown.changed() => return,
                }
            }
            Next::Wait(secs) => {
                tracing::info!("agent: backing off {secs}s before next attempt");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(secs)) => continue,
                    _ = shutdown.changed() => return,
                }
            }
            Next::Attempt(endpoint, first) => {
                tracing::info!(state = ?first.body, "agent: connecting to {endpoint}");
                let mut session = match connector.connect(&endpoint).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("agent: connect to {endpoint} failed: {e}");
                        agent.lock().unwrap().on_failure();
                        continue;
                    }
                };

                if let Err(e) = session.send(*first).await {
                    tracing::warn!("agent: first frame failed: {e}");
                    agent.lock().unwrap().on_failure();
                    continue;
                }

                let mut ticker =
                    tokio::time::interval(Duration::from_secs(heartbeat_interval.max(1) as u64));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // the first tick completes immediately

                loop {
                    tokio::select! {
                        _ = shutdown.changed() => return,

                        maybe_frame = pub_rx.recv() => {
                            // Data-plane frame from the bridge. Only enrolled
                            // sessions carry data frames: the gateway drops a
                            // session whose device row it cannot resolve, so
                            // publishing during pairing/revocation would kill
                            // the stream. Dropped here, retried by the spool
                            // replay on the next subscription.
                            if let Some(frame) = maybe_frame {
                                let enrolled = agent.lock().unwrap().state() == PairingState::Enrolled;
                                if !enrolled {
                                    tracing::debug!("agent: dropping published frame while not enrolled");
                                } else if let Err(e) = session.send(frame).await {
                                    tracing::warn!("agent: published frame send failed: {e}");
                                    break;
                                }
                            }
                            // None = mailbox closed: the agent outlives it; keep polling.
                        }

                        _ = ticker.tick() => {
                            // Credential on every frame (contract §Enrollment).
                            let frame = {
                                let a = agent.lock().unwrap();
                                match a.credential() {
                                    Some(cred)
                                        if a.state() == PairingState::Enrolled =>
                                    {
                                        Some(heartbeat_frame_msg(&a, cred))
                                    }
                                    _ => None,
                                }
                            };
                            if let Some(frame) = frame {
                                if let Err(e) = session.send(frame).await {
                                    tracing::warn!("agent: heartbeat send failed: {e}");
                                    break;
                                }
                            }
                        }

                        frame = session.next_frame() => {
                            match frame {
                                None => break, // server closed the stream
                                Some(Err(e)) => {
                                    // UNAUTHENTICATED while enrolled = revoked
                                    // credential (contract §Revocation): enter
                                    // the degraded state, prompt re-enroll.
                                    let revoked =
                                        matches!(e, AgentError::Unauthenticated(_));
                                    let mut a = agent.lock().unwrap();
                                    if revoked && a.state() == PairingState::Enrolled {
                                        tracing::warn!(
                                            "agent: credential rejected — entering revoked state"
                                        );
                                        a.on_revoked();
                                    } else {
                                        a.on_failure();
                                    }
                                    break;
                                }
                                Some(Ok(frame)) => {
                                    let reconnect = handle_server_frame(
                                        &agent,
                                        &mut *session,
                                        frame,
                                        &handler,
                                        &hooks,
                                        &mut heartbeat_interval,
                                    )
                                    .await;
                                    // Re-arm the ticker (interval may have changed).
                                    ticker = tokio::time::interval(Duration::from_secs(
                                        heartbeat_interval.max(1) as u64,
                                    ));
                                    ticker.set_missed_tick_behavior(
                                        tokio::time::MissedTickBehavior::Delay,
                                    );
                                    ticker.tick().await;
                                    if reconnect {
                                        break; // pairing done → reconnect as Enrolled
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Session ended → bounded backoff, then reconnect.
        tracing::info!("agent: session ended; scheduling reconnect");
        agent.lock().unwrap().on_failure();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T-P12 (F10): secure by default — bare host:port dials https://; an
    /// explicit scheme is honored (http:// dev, https:// prod).
    #[test]
    fn normalize_endpoint_is_secure_by_default() {
        assert_eq!(
            GrpcConnector::normalize_endpoint("hq.example:50051"),
            "https://hq.example:50051"
        );
        assert_eq!(
            GrpcConnector::normalize_endpoint("https://hq.example:50051"),
            "https://hq.example:50051"
        );
        assert_eq!(
            GrpcConnector::normalize_endpoint("http://hq-dev:50051"),
            "http://hq-dev:50051"
        );
    }
    use std::collections::VecDeque;
    use tokio::sync::Mutex as AsyncMutex;

    /// Scripted session: sends are recorded, replies are pre-queued.
    struct MockSession {
        sent: Arc<AsyncMutex<Vec<pb::AgentFrame>>>,
        responses: Arc<AsyncMutex<VecDeque<Result<pb::ServerFrame, AgentError>>>>,
    }

    #[async_trait::async_trait]
    impl AgentSession for MockSession {
        async fn send(&mut self, frame: pb::AgentFrame) -> Result<(), AgentError> {
            self.sent.lock().await.push(frame);
            Ok(())
        }
        async fn next_frame(&mut self) -> Option<Result<pb::ServerFrame, AgentError>> {
            self.responses.lock().await.pop_front()
        }
    }

    /// Serves one scripted session per connect() call, then errors.
    struct MockConnector {
        sessions: AsyncMutex<VecDeque<Result<Arc<AsyncMutex<MockSession>>, AgentError>>>,
    }

    impl MockConnector {
        fn with_session(
            responses: VecDeque<Result<pb::ServerFrame, AgentError>>,
        ) -> (Self, Arc<AsyncMutex<MockSession>>) {
            let session = Arc::new(AsyncMutex::new(MockSession {
                sent: Arc::new(AsyncMutex::new(Vec::new())),
                responses: Arc::new(AsyncMutex::new(responses)),
            }));
            (
                Self {
                    sessions: AsyncMutex::new(VecDeque::from([Ok(session.clone())])),
                },
                session,
            )
        }
    }

    #[async_trait::async_trait]
    impl AgentConnector for MockConnector {
        async fn connect(&self, _endpoint: &str) -> Result<Box<dyn AgentSession>, AgentError> {
            match self.sessions.lock().await.pop_front() {
                Some(Ok(s)) => {
                    let inner = s.lock().await;
                    Ok(Box::new(MockSession {
                        sent: inner.sent.clone(),
                        responses: inner.responses.clone(),
                    }))
                }
                Some(Err(e)) => Err(e),
                None => Err(AgentError::Connect("no scripted session".into())),
            }
        }
    }

    fn pairing_result(success: bool) -> pb::ServerFrame {
        pb::ServerFrame {
            body: Some(pb::server_frame::Body::PairingResult(pb::PairingResult {
                success,
                error: if success {
                    String::new()
                } else {
                    "token invalid".into()
                },
                device_id: if success {
                    "dev-123".into()
                } else {
                    String::new()
                },
                credential_token: if success {
                    "long-lived-cred".into()
                } else {
                    String::new()
                },
            })),
        }
    }

    fn heartbeat_ack(interval: i32) -> pb::ServerFrame {
        pb::ServerFrame {
            body: Some(pb::server_frame::Body::HeartbeatAck(pb::HeartbeatAck {
                server_time_unix_ms: 0,
                next_heartbeat_interval_s: interval,
                protocol_version: AGENT_PROTOCOL_VERSION,
            })),
        }
    }

    fn provisioned(dir: &std::path::Path) -> Arc<std::sync::Mutex<PairingAgent>> {
        let mut a = PairingAgent::load(dir);
        a.provision("token-1".into(), "hq.example:50051".into(), 900);
        Arc::new(std::sync::Mutex::new(a))
    }

    fn enrolled(dir: &std::path::Path) -> Arc<std::sync::Mutex<PairingAgent>> {
        let mut a = PairingAgent::load(dir);
        a.provision("token-1".into(), "hq.example:50051".into(), 900);
        a.set_credential("cred-1".into());
        a.set_device_id("dev-42".into());
        a.on_enrolled();
        Arc::new(std::sync::Mutex::new(a))
    }

    #[tokio::test]
    async fn pairing_success_stores_credential_and_device_id() {
        let dir = tempfile::tempdir().unwrap();
        let agent = provisioned(dir.path());
        // Gateway: handshake → PairingResult(success) → stream ends.
        let (conn, _session) =
            MockConnector::with_session(VecDeque::from([Ok(pairing_result(true))]));
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(run_agent(
            agent.clone(),
            conn,
            NullCommandHandler,
            (),
            mailbox_channel().1,
            rx,
        ));
        tokio::time::sleep(Duration::from_millis(400)).await;
        tx.send(true).unwrap();
        handle.abort();

        let a = agent.lock().unwrap();
        assert_eq!(a.state(), PairingState::Enrolled);
        assert_eq!(a.credential(), Some("long-lived-cred"));
        assert_eq!(a.device_id(), Some("dev-123"));
    }

    #[tokio::test]
    async fn pairing_failure_backs_off_keeps_pending() {
        let dir = tempfile::tempdir().unwrap();
        let agent = provisioned(dir.path());
        let (conn, _session) =
            MockConnector::with_session(VecDeque::from([Ok(pairing_result(false))]));
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(run_agent(
            agent.clone(),
            conn,
            NullCommandHandler,
            (),
            mailbox_channel().1,
            rx,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx.send(true).unwrap();
        handle.abort();

        let a = agent.lock().unwrap();
        assert_eq!(a.state(), PairingState::Pending);
        assert_eq!(a.credential(), Some("token-1"));
        assert!(a.record().retry_count >= 1, "failure must schedule a retry");
        assert!(a.record().retry_after_unix.is_some());
    }

    #[tokio::test]
    async fn enrolled_sends_heartbeat_and_records_ack() {
        let dir = tempfile::tempdir().unwrap();
        let agent = enrolled(dir.path());
        // Gateway: HeartbeatAck with a 1s heartbeat interval, then keep the
        // stream open (no more frames) so the ticker fires at least once.
        let (conn, session) = MockConnector::with_session(VecDeque::from([Ok(heartbeat_ack(1))]));
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(run_agent(
            agent.clone(),
            conn,
            NullCommandHandler,
            (),
            mailbox_channel().1,
            rx,
        ));
        tokio::time::sleep(Duration::from_millis(1700)).await;
        tx.send(true).unwrap();
        handle.abort();

        {
            let a = agent.lock().unwrap();
            assert!(
                a.record().last_heartbeat_at.is_some(),
                "ack must record heartbeat"
            );
        }
        let sent = {
            let binding = session.lock().await;
            binding.sent.clone()
        };
        let sent = sent.lock().await;
        let mut cred_ok = false;
        for f in sent.iter() {
            if let Some(pb::agent_frame::Body::Heartbeat(hb)) = &f.body {
                assert_eq!(hb.credential_token, "cred-1", "credential on every frame");
                assert_eq!(hb.device_id, "dev-42");
                cred_ok = true;
            }
        }
        assert!(cred_ok, "expected at least one heartbeat frame");
    }

    #[tokio::test]
    async fn commands_are_acked() {
        let dir = tempfile::tempdir().unwrap();
        let agent = enrolled(dir.path());
        let command = pb::ServerFrame {
            body: Some(pb::server_frame::Body::Command(pb::Command {
                command_id: "cmd-7".into(),
                kind: Some(pb::command::Kind::FactoryReset(pb::FactoryReset {})),
                ..Default::default()
            })),
        };
        let (conn, session) =
            MockConnector::with_session(VecDeque::from([Ok(command), Ok(heartbeat_ack(30))]));
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(run_agent(
            agent.clone(),
            conn,
            NullCommandHandler,
            (),
            mailbox_channel().1,
            rx,
        ));
        tokio::time::sleep(Duration::from_millis(300)).await;
        tx.send(true).unwrap();
        handle.abort();

        let sent = {
            let binding = session.lock().await;
            binding.sent.clone()
        };
        let sent = sent.lock().await;
        let acks: Vec<_> = sent
            .iter()
            .filter_map(|f| match &f.body {
                Some(pb::agent_frame::Body::CommandAck(a)) => Some(a.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(acks.len(), 1);
        assert_eq!(acks[0].command_id, "cmd-7");
        assert!(!acks[0].success, "NullCommandHandler must refuse");
    }

    #[test]
    fn jitter_keeps_wait_positive_and_bounded() {
        // Any wait > 0 must stay within ±20%.
        for base in [1u64, 2, 7, 60, 300] {
            for _ in 0..50 {
                let j = jittered(base);
                assert!(j >= 1);
                assert!(
                    j <= base + base / 2 + 1,
                    "jitter {j} out of range for {base}"
                );
            }
        }
    }
}
