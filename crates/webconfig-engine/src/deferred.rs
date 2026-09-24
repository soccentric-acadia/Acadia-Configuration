//! Features a product defers from its release (T-P00e, X-013).
//!
//! The board manifest lists them in `deferred_features`; the UI hides them
//! and every configuration write (local API or HQ) is refused if it would
//! enable one — hidden must also mean unreachable, not merely invisible.

use crate::store::Config;

/// Known feature ids and whether `config` enables each.
pub fn enabled_features(config: &Config) -> Vec<&'static str> {
    let mut on = Vec::new();
    if config.system.time.ptp_enabled {
        on.push("ptp");
    }
    if config.network.ap_mode.enabled {
        on.push("ap_mode");
    }
    if config.security.wireguard.enabled {
        on.push("wireguard");
    }
    let five_g_on = config
        .network
        .cellular_5g
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !config.network.cellular.is_empty() || five_g_on {
        on.push("cellular");
    }
    on
}

/// Refuse a configuration that enables a deferred feature.
pub fn check(config: &Config, deferred: &[String]) -> Result<(), String> {
    let hits: Vec<&str> = enabled_features(config)
        .into_iter()
        .filter(|f| deferred.iter().any(|d| d == f))
        .collect();
    if hits.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "deferred in this release (board manifest): {}",
            hits.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabling_a_deferred_feature_is_refused() {
        let deferred = vec!["ptp".to_string(), "wireguard".to_string()];
        let mut c = Config::default();
        assert!(check(&c, &deferred).is_ok());
        c.system.time.ptp_enabled = true;
        assert!(check(&c, &deferred).unwrap_err().contains("ptp"));
        c.system.time.ptp_enabled = false;
        c.network.ap_mode.enabled = true; // not deferred in this list
        assert!(check(&c, &deferred).is_ok());
        c.security.wireguard.enabled = true;
        assert!(check(&c, &deferred).unwrap_err().contains("wireguard"));
    }

    #[test]
    fn cellular_counts_when_configured() {
        let mut c = Config::default();
        c.network.cellular_5g = serde_json::json!({"enabled": true});
        assert!(enabled_features(&c).contains(&"cellular"));
    }
}
