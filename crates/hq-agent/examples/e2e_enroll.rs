//! E2E driver (X5-012): enroll this device against a REAL Acadia-HQ gateway.
//!
//! Reads the pairing token + HQ endpoint from the environment, runs the
//! production `run_agent` loop, and exits 0 once the device is Enrolled
//! (credential stored, state persisted to the given data dir).
//!
//! Usage (see agent-gateway/tests/e2e_device_enroll.sh):
//!   AGENT_TOKEN=… AGENT_ENDPOINT=127.0.0.1:50051 AGENT_DATA_DIR=/tmp/… \
//!   cargo run -p hq-agent --example e2e_enroll
//!
//! Exit codes: 0 = enrolled; 1 = timed out / failed.

use std::time::{Duration, Instant};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .compact()
        .init();

    let token = std::env::var("AGENT_TOKEN").expect("AGENT_TOKEN not set");
    let endpoint = std::env::var("AGENT_ENDPOINT").expect("AGENT_ENDPOINT not set");
    let data_dir = std::env::var("AGENT_DATA_DIR").unwrap_or_else(|_| "/tmp/agent-e2e".into());
    let timeout_secs: u64 = std::env::var("AGENT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);

    std::fs::create_dir_all(&data_dir).expect("data dir");

    // Provision (idempotent): only if not already provisioned with this token.
    let agent = {
        let mut a = webconfig_engine::pairing::PairingAgent::load(std::path::Path::new(&data_dir));
        if a.credential().is_none() {
            a.provision(token.clone(), endpoint.clone(), 900);
        }
        std::sync::Arc::new(std::sync::Mutex::new(a))
    };

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let runner = tokio::spawn(hq_agent::run_agent(
        agent.clone(),
        hq_agent::GrpcConnector::default(),
        hq_agent::NullCommandHandler,
        (),
        hq_agent::mailbox_channel().1,
        stop_rx,
    ));

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let state = agent.lock().unwrap().state();
        let enrolled = state == webconfig_engine::pairing::PairingState::Enrolled;
        if enrolled {
            // Drop the guard BEFORE the grace sleep — run_agent needs the lock
            // to reconnect and send the first Enrolled heartbeat (X5-012).
            {
                let a = agent.lock().unwrap();
                println!(
                    "e2e: ENROLLED device_id={:?} credential_present={}",
                    a.device_id(),
                    a.credential().is_some()
                );
            }
            tokio::time::sleep(Duration::from_millis(4000)).await;
            let _ = stop_tx.send(true);
            runner.abort();
            std::process::exit(0);
        }
        if Instant::now() > deadline {
            eprintln!("e2e: timed out waiting for enrollment (state={state:?})");
            let _ = stop_tx.send(true);
            runner.abort();
            std::process::exit(1);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
