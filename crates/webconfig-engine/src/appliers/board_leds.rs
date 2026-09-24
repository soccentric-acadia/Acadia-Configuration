//! Board-LED policy applier (T-P28, M04).
//!
//! `io.board_leds` names which kernel LED shows system / OS / hardware status
//! and optionally one LED that follows an application service. The status is
//! live, so the LEDs are driven by webconfigd's LED policy loop; this applier
//! validates the policy and, when it is disabled, releases the LEDs it named
//! (off) so a stale blink does not linger.

use crate::applier::{Applier, ApplyError, ApplyOutcome, ApplyStage};
use crate::leds;
use crate::store::Config;
use crate::sysroot::Sysroot;

#[derive(Debug, Default)]
pub struct BoardLedApplier;

impl BoardLedApplier {
    pub fn new() -> Self {
        Self
    }

    /// Every LED name the policy assigns.
    pub fn assigned(config: &Config) -> Vec<String> {
        let b = &config.io.board_leds;
        let mut out: Vec<String> = [&b.system_led, &b.os_led, &b.hardware_led]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        if b.app.enabled {
            if let Some(led) = &b.app.led {
                out.push(led.clone());
            }
        }
        out
    }
}

impl Applier for BoardLedApplier {
    fn id(&self) -> &'static str {
        "board_leds"
    }

    fn validate(&self, sysroot: &Sysroot, config: &Config) -> Result<(), ApplyError> {
        let names = Self::assigned(config);
        for name in &names {
            if !leds::led_name_valid(name) {
                return Err(ApplyError::Validation {
                    stage: ApplyStage::Validate,
                    message: format!("invalid LED name {name:?}"),
                });
            }
            if sysroot.is_real_root() && !leds::led_exists(sysroot, name) {
                return Err(ApplyError::Validation {
                    stage: ApplyStage::Validate,
                    message: format!("LED {name:?} does not exist under /sys/class/leds"),
                });
            }
        }
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        if sorted.len() != names.len() {
            return Err(ApplyError::Validation {
                stage: ApplyStage::Validate,
                message: "one LED cannot show two statuses".into(),
            });
        }
        Ok(())
    }

    fn apply(&self, sysroot: &Sysroot, config: &Config) -> Result<ApplyOutcome, ApplyError> {
        self.validate(sysroot, config)?;
        if !config.io.board_leds.enabled && sysroot.is_real_root() {
            for name in Self::assigned(config) {
                leds::set_led(sysroot, &name, leds::LedState::Off)?;
            }
        }
        Ok(ApplyOutcome::Committed)
    }
}
