//! Background feature workers owned by the daemon process.

use std::sync::Arc;
use std::time::Duration;

use webconfig_engine::alert::{merge_defaults, AlertEngine};
use webconfig_engine::manifest::BoardManifest;
use webconfig_engine::telemetry::TelemetryQueue;

use crate::alert_dispatch::dispatch_event;
use crate::bootstrap;
use crate::engine_bridge::EngineBridge;

/// Heartbeat to istate on the shared peer cadence (Instrumentation §3.1).
///
/// istate records the last heartbeat of every peer and Configuration's peer
/// row reads "connected" from it; without this loop the Configuration peer
/// would always render as unresponsive even while serving traffic. Failures
/// are logged and retried on the next tick — a quiet hub must never stop the
/// web UI (R10 degrade, don't block).
pub(crate) async fn run_istate_heartbeat(client: crate::istate_client::SharedIstateClient) {
    let mut sequence: u64 = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        sequence = sequence.wrapping_add(1);
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // HEALTH_PASS = 0 in instr.common.proto; the generated type is the raw
        // enum integer, so pass the constant directly.
        let hb = crate::istate_client::pb::common::Heartbeat {
            peer: "configuration".to_string(),
            sequence,
            mono_ns: now_ns,
            ready: true,
            health: 0, // HEALTH_PASS
            ..Default::default()
        };
        if let Err(error) = client.heartbeat(hb).await {
            tracing::debug!(%error, "istate heartbeat not acknowledged");
        }
    }
}

/// Periodically evaluate configured alert rules against current vitals.
pub(crate) async fn run_alert_timer(
    engine: EngineBridge,
    manifest: Arc<BoardManifest>,
    alert_engine: Arc<tokio::sync::Mutex<AlertEngine>>,
    telemetry: Arc<std::sync::Mutex<TelemetryQueue>>,
) {
    let history = bootstrap::alert_history(&engine);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        // Real wall-clock epoch seconds (spec §4.7): alert history `ts` must be
        // an ISO-8601 UTC stamp, so the engine receives the actual time rather
        // than a monotonic tick counter. The HTTP layer owns the clock; the
        // engine stays deterministic (it only formats what we pass).
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let config = match engine.load() {
            Ok(config) => config,
            Err(_) => continue,
        };
        let vitals = {
            let mut v = webconfig_engine::monitoring::read_vitals(&engine.sysroot);
            // spec §4.8: cert expiry feeds the alert engine. The HTTP layer owns
            // the wall clock, so days-until-expiry is computed here from each
            // cert's operator-supplied ISO-8601 not_after and injected into the
            // vitals snapshot the engine evaluates (the engine stays pure).
            v.cert_expiries = webconfig_engine::monitoring::cert_expiries(
                &config.security.certificates,
                now_secs,
            );
            v
        };
        // Global alert switch (spec §4.7). When the engine is disabled, do not
        // evaluate rules — instead flush any firing state with clear events so
        // the dashboard red-state resets. This makes `alerts.enabled` actually
        // gate the engine (previously it was ignored).
        if !config.alerts.enabled {
            let clears = alert_engine.lock().await.clear_all(now_secs);
            for event in clears {
                tracing::info!(rule = %event.rule_id, state = ?event.state, "alert (engine disabled)");
                if let Err(error) = history.record(&event) {
                    tracing::warn!(error = %error, "alert history write failed");
                }
            }
            continue;
        }
        // Merge per-platform default rule packs with the user-configured rules
        // (spec §4.7). User rules override defaults by id; defaults ship in the
        // board manifest (Acadia: throttling; all: disk-full, watchdog-reset).
        let rules = merge_defaults(&manifest.default_alert_rules, &config.alerts.rules);
        let events = alert_engine
            .lock()
            .await
            .evaluate(&rules, &vitals, now_secs);
        for event in events {
            tracing::info!(rule = %event.rule_id, state = ?event.state, "alert");
            // Event log (always) — append to the ring-buffer history.
            if let Err(error) = history.record(&event) {
                tracing::warn!(error = %error, "alert history write failed");
            }
            // Push actions (spec §4.7): webhook POST + MQTT event topic. UI
            // red-state is derived by the dashboard from this history. Look up
            // the effective rule (merged set) to read its actions.
            if let Some(rule) = rules.iter().find(|r| r.id == event.rule_id) {
                dispatch_event(
                    &engine.sysroot,
                    &config.alerts,
                    &config.services.mqtt,
                    rule,
                    &event,
                    Some(&telemetry),
                );
            }
        }
    }
}
