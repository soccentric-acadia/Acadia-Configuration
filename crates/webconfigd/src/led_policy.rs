//! Board-LED policy loop + log-level relay (T-P28: M04, G07).
//!
//! * LED policy: every 5 s the status LEDs named in `io.board_leds` are
//!   driven from live state — OS (allowlisted units), hardware (thermal
//!   throttling / temperature), system (the worse of the two) and an optional
//!   application LED that follows one service. good → on, warning → slow
//!   blink, error → fast blink. Only changes are written.
//! * Log levels: `services.log_levels` (source → level) is relayed to
//!   Instrumentation's logmanager (`level-set`) through istate whenever an
//!   entry changes — it used to be stored and never applied.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use webconfig_engine::leds::{self, LedState};
use webconfig_engine::monitoring::Vitals;

use crate::engine_bridge::EngineBridge;
use crate::istate_client::SharedIstateClient;
use crate::systemd::SystemdClient;

/// Severity order for combining states (higher = worse).
fn rank(s: LedState) -> u8 {
    match s {
        LedState::Off => 0,
        LedState::On => 1,
        LedState::SlowBlink => 2,
        LedState::FastBlink => 3,
    }
}

fn worse(a: LedState, b: LedState) -> LedState {
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// OS status from unit ActiveStates: failed → error, not active → warning.
pub fn os_state(unit_states: &[String]) -> LedState {
    if unit_states.iter().any(|s| s == "failed") {
        LedState::FastBlink
    } else if unit_states.iter().any(|s| s != "active") {
        LedState::SlowBlink
    } else {
        LedState::On
    }
}

/// Hardware status: >= 85 °C → error; throttling → warning.
pub fn hardware_state(vitals: &Vitals) -> LedState {
    if vitals
        .temperatures
        .iter()
        .any(|t| t.temp_millideg_c >= 85_000)
    {
        LedState::FastBlink
    } else if vitals.temperatures.iter().any(|t| t.throttled) {
        LedState::SlowBlink
    } else {
        LedState::On
    }
}

/// Application LED from one unit's ActiveState.
pub fn app_state(active: &str) -> LedState {
    match active {
        "active" => LedState::On,
        "failed" => LedState::FastBlink,
        "activating" | "reloading" | "deactivating" => LedState::SlowBlink,
        _ => LedState::Off,
    }
}

/// The LED policy loop.
pub async fn run_led_policy(
    engine: EngineBridge,
    systemd: Arc<dyn SystemdClient>,
    allowlist: Vec<String>,
) {
    let mut shown: HashMap<String, LedState> = HashMap::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if !engine.sysroot.is_real_root() {
            continue;
        }
        let Ok(cfg) = engine.load() else { continue };
        let b = cfg.io.board_leds;
        if !b.enabled {
            shown.clear();
            continue;
        }
        let mut units = Vec::with_capacity(allowlist.len());
        for unit in &allowlist {
            units.push(match systemd.status(unit).await {
                Ok(s) => s.active,
                Err(_) => "unknown".into(),
            });
        }
        let os = os_state(&units);
        let vitals = webconfig_engine::monitoring::read_vitals(&engine.sysroot);
        let hw = hardware_state(&vitals);
        let mut wanted: Vec<(String, LedState)> = Vec::new();
        if let Some(led) = b.system_led {
            wanted.push((led, worse(os, hw)));
        }
        if let Some(led) = b.os_led {
            wanted.push((led, os));
        }
        if let Some(led) = b.hardware_led {
            wanted.push((led, hw));
        }
        if b.app.enabled {
            if let (Some(led), Some(service)) = (b.app.led, b.app.service) {
                let active = systemd
                    .status(&service)
                    .await
                    .map(|s| s.active)
                    .unwrap_or_else(|_| "unknown".into());
                wanted.push((led, app_state(&active)));
            }
        }
        for (led, state) in wanted {
            if shown.get(&led) == Some(&state) {
                continue;
            }
            let sysroot = engine.sysroot.clone();
            let name = led.clone();
            let result =
                tokio::task::spawn_blocking(move || leds::set_led(&sysroot, &name, state)).await;
            match result {
                Ok(Ok(())) => {
                    shown.insert(led, state);
                }
                Ok(Err(e)) => tracing::warn!(led = %led, error = %e, "LED update failed"),
                Err(e) => tracing::warn!(led = %led, error = %e, "LED update panicked"),
            }
        }
    }
}

/// Entries of `desired` that differ from what was last applied.
pub fn changed_levels(
    desired: &BTreeMap<String, String>,
    applied: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    desired
        .iter()
        .filter(|(k, v)| applied.get(*k) != Some(*v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Relay `services.log_levels` changes to logmanager (G07).
pub async fn run_log_level_relay(engine: EngineBridge, istate: SharedIstateClient) {
    let mut applied: BTreeMap<String, String> = BTreeMap::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let Ok(cfg) = engine.load() else { continue };
        for (source, level) in changed_levels(&cfg.services.log_levels, &applied) {
            let args = serde_json::json!({ "source": source, "level": level }).to_string();
            match istate
                .relay_command("logmanager".into(), "level-set".into(), args)
                .await
            {
                Ok(_) => {
                    applied.insert(source, level);
                }
                Err(e) => tracing::debug!(%source, error = %e, "log level relay deferred"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webconfig_engine::monitoring::TempZone;

    #[test]
    fn os_and_app_states() {
        assert_eq!(os_state(&["active".into(), "active".into()]), LedState::On);
        assert_eq!(
            os_state(&["active".into(), "inactive".into()]),
            LedState::SlowBlink
        );
        assert_eq!(
            os_state(&["failed".into(), "inactive".into()]),
            LedState::FastBlink
        );
        assert_eq!(app_state("active"), LedState::On);
        assert_eq!(app_state("failed"), LedState::FastBlink);
        assert_eq!(app_state("inactive"), LedState::Off);
    }

    #[test]
    fn hardware_state_from_thermal() {
        let mut v = Vitals::default();
        assert_eq!(hardware_state(&v), LedState::On);
        v.temperatures.push(TempZone {
            zone: "cpu".into(),
            temp_millideg_c: 70_000,
            throttled: true,
        });
        assert_eq!(hardware_state(&v), LedState::SlowBlink);
        v.temperatures.push(TempZone {
            zone: "gpu".into(),
            temp_millideg_c: 90_000,
            throttled: false,
        });
        assert_eq!(hardware_state(&v), LedState::FastBlink);
        assert_eq!(
            worse(LedState::On, LedState::SlowBlink),
            LedState::SlowBlink
        );
    }

    #[test]
    fn only_changed_levels_are_relayed() {
        let mut desired = BTreeMap::new();
        desired.insert("kernel".into(), "WARNING".into());
        desired.insert("app".into(), "DEBUG".into());
        let mut applied = BTreeMap::new();
        applied.insert("kernel".into(), "WARNING".into());
        assert_eq!(
            changed_levels(&desired, &applied),
            vec![("app".into(), "DEBUG".into())]
        );
    }
}
