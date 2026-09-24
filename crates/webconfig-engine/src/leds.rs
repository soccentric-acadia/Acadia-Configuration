//! Kernel LED control for the board-LED policy (T-P28, M04).
//!
//! A board LED is a `/sys/class/leds/<name>` class device. The policy maps a
//! status onto a trigger: good → steady on, warning → slow blink, error →
//! fast blink, none → off. Writes go through `priv_client` (the root helper
//! on a device; its allowlist admits only these four LED attributes).

use crate::sysroot::Sysroot;

/// The status an LED shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedState {
    Off,
    On,
    SlowBlink,
    FastBlink,
}

/// The LED attributes the policy writes (also the helper's allowlist).
pub const LED_ATTRIBUTES: &[&str] = &["trigger", "brightness", "delay_on", "delay_off"];

/// A kernel LED name as it appears under `/sys/class/leds` (e.g. `ACT`,
/// `PWR`, `led0`, `rpi:green:status`): no path separators, no `..`.
pub fn led_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.'))
}

/// Whether the LED exists on this system.
pub fn led_exists(sysroot: &Sysroot, name: &str) -> bool {
    led_name_valid(name) && sysroot.join(format!("/sys/class/leds/{name}")).exists()
}

/// The attribute writes that realise `state`, in order.
pub fn writes_for(state: LedState) -> Vec<(&'static str, &'static str)> {
    match state {
        LedState::Off => vec![("trigger", "none"), ("brightness", "0")],
        LedState::On => vec![("trigger", "default-on")],
        LedState::SlowBlink => vec![
            ("trigger", "timer"),
            ("delay_on", "500"),
            ("delay_off", "500"),
        ],
        LedState::FastBlink => vec![
            ("trigger", "timer"),
            ("delay_on", "100"),
            ("delay_off", "100"),
        ],
    }
}

/// Drive one LED to `state`.
pub fn set_led(sysroot: &Sysroot, name: &str, state: LedState) -> std::io::Result<()> {
    if !led_name_valid(name) {
        return Err(std::io::Error::other(format!("invalid LED name {name:?}")));
    }
    for (attr, value) in writes_for(state) {
        let path = sysroot.join(format!("/sys/class/leds/{name}/{attr}"));
        crate::priv_client::write_file(&path, value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(led_name_valid("ACT"));
        assert!(led_name_valid("rpi:green:status"));
        assert!(!led_name_valid("../x"));
        assert!(!led_name_valid("a/b"));
        assert!(!led_name_valid(""));
    }

    #[test]
    fn set_led_writes_the_trigger_files() {
        let tmp = tempfile::tempdir().unwrap();
        let sys = Sysroot::at(tmp.path());
        std::fs::create_dir_all(tmp.path().join("sys/class/leds/ACT")).unwrap();
        set_led(&sys, "ACT", LedState::FastBlink).unwrap();
        let read = |a: &str| {
            std::fs::read_to_string(tmp.path().join(format!("sys/class/leds/ACT/{a}"))).unwrap()
        };
        assert_eq!(read("trigger"), "timer");
        assert_eq!(read("delay_on"), "100");
        set_led(&sys, "ACT", LedState::Off).unwrap();
        assert_eq!(read("trigger"), "none");
        assert_eq!(read("brightness"), "0");
    }
}
