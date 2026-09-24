//! webconfigd — on-device WebConfig daemon (spec §2: exactly one daemon, tokio
//! `current_thread` runtime, non-root, TLS, rustls, no OpenSSL).
//!
//! Layers (spec §3): HTTP (here) → config engine (webconfig-engine) → platform
//! (board manifest). The async HTTP layer talks to the synchronous engine over
//! the [`engine_bridge`] and runs appliers on blocking tasks.

#![forbid(unsafe_code)]

mod alert_dispatch;
mod api;
mod auth;
mod bootstrap;
mod csrf;
mod engine_bridge;
mod error;
mod hq_bridge;
mod hq_command_handler;
mod istate_client;
mod jobs;
mod routes;
mod server;
mod sse;
mod state;
mod systemd;
mod tls;
mod update_backend;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use tracing_subscriber::EnvFilter;
use webconfig_engine::Sysroot;

/// One daemon, current-thread runtime (spec §2).
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .compact()
        .init();

    let sysroot = resolve_sysroot();
    let application = bootstrap::build(sysroot).await;
    let bootstrap::Application {
        state,
        engine,
        manifest,
        alert_engine,
    } = application;

    let static_dir = resolve_static_dir();
    let telemetry = state.telemetry.clone();
    let pairing = state.pairing.clone();
    let app = routes::build_router(state.clone(), static_dir);

    // Commit/confirm rollback timer (spec §4.2 flagship feature).
    tokio::spawn(Arc::new(engine.clone()).run_confirm_timer());

    // Alert evaluation timer (spec §4.7): rule evaluation on the same data the
    // dashboard reads, on a timer inside the daemon — no extra process.
    tokio::spawn(jobs::run_alert_timer(
        engine.clone(),
        manifest.clone(),
        alert_engine.clone(),
        telemetry,
    ));

    // HQ AgentLink client (X5-001..005): pairing handshake, heartbeats with
    // bounded backoff, command acks. Idle (5s poll) until the operator
    // provisions a pairing token via the web UI; a revoked credential parks
    // the agent until re-provisioning. Runs on this daemon's runtime — no
    // extra process (spec §2: exactly one daemon).
    let (agent_stop, agent_stop_rx) = tokio::sync::watch::channel(false);
    // Data-plane plumbing (task 009 P2/P3): local execution of the
    // `configuration` pseudo-daemon verbs, the upload coordinator/executor,
    // and the istate→AgentLink data bridge.
    let (mailbox, pub_rx) = hq_agent::mailbox_channel();
    let uploads = Arc::new(hq_bridge::UploadCoordinator::new());
    let ops = Arc::new(hq_bridge::DeviceOps {
        engine: engine.clone(),
        update_backend: state.update_backend.clone(),
        schema: state.schema.clone(),
        istate: state.istate.clone(),
        coordinator: uploads.clone(),
        sysroot: state.engine.sysroot.clone(),
        systemd: state.systemd.clone(),
        service_allowlist: state.manifest.service_allowlist.clone(),
        users_path: state.users_path.clone(),
    });
    let mailbox_for_agent = mailbox.clone();
    let bridge_stop = agent_stop_rx.clone();
    tokio::spawn(hq_agent::run_agent(
        pairing.clone(),
        hq_agent::GrpcConnector::default(),
        hq_agent::IdempotentCommandHandler::new(hq_command_handler::IstateCommandHandler::new(
            state.istate.clone(),
            state.audit.clone(),
            ops.clone(),
            mailbox_for_agent,
        )),
        hq_bridge::UploadExecutor {
            coordinator: uploads,
            audit: state.audit.clone(),
            mailbox: mailbox.clone(),
        },
        pub_rx,
        agent_stop_rx,
    ));
    // T-P24: periodic device snapshot carried by every heartbeat.
    tokio::spawn(hq_bridge::run_status_snapshot(ops.clone()));
    // Device→HQ data bridge: istate spooled records → AgentLink frames.
    tokio::spawn(hq_bridge::run_data_bridge(
        ops,
        pairing,
        mailbox,
        bridge_stop,
    ));
    // Ensure the loop stops cleanly when main exits (process death covers the
    // daemon case; the watch is for tests and future graceful shutdown).
    tokio::spawn(async move {
        let _ = agent_stop; // held for the process lifetime
    });

    // Peer heartbeat to istate (Instrumentation §3.1): istate reports the
    // configuration peer as connected from this cadence. Degrade, don't block
    // (R10): a quiet hub logs and retries, it never stops the web UI.
    tokio::spawn(jobs::run_istate_heartbeat(state.istate.clone()));

    let webconfig_dir = engine.sysroot.webconfig_dir();
    server::serve(app, engine, &webconfig_dir, &manifest).await
}

/// Resolve the sysroot from `WEBCONFIG_SYSROOT` (dev/CI fake sysroot) or `/`.
fn resolve_sysroot() -> Sysroot {
    match std::env::var("WEBCONFIG_SYSROOT") {
        Ok(dir) => Sysroot::at(dir),
        Err(_) => Sysroot::new(),
    }
}

/// Resolve the frontend static dir from `WEBCONFIG_STATIC_DIR`, else the
/// install default `/usr/share/webconfig/static`, else `frontend/` (dev).
fn resolve_static_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("WEBCONFIG_STATIC_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let prod = std::path::PathBuf::from("/usr/share/webconfig/static");
    if prod.exists() {
        return prod;
    }
    std::path::PathBuf::from("frontend")
}
