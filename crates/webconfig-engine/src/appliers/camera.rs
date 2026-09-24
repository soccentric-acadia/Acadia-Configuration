//! Camera capture applier (T-P28, M08).
//!
//! Drives the Acadia-OS `acadia-camera-capture` service: `io.cameras_enabled`
//! plus the first enabled `io.cameras[]` entry set `ENABLED` and
//! `CAMERA_DEVICE` in `/etc/acadia/camera-capture.conf` (every other key —
//! mode, resolution, sink — is preserved) and enable/start or disable/stop
//! the unit.

use std::sync::Mutex;

use crate::applier::{run_cmd, Applier, ApplyError, ApplyOutcome, ApplyStage, FileBackup};
use crate::store::Config;
use crate::sysroot::Sysroot;

pub const CAPTURE_CONF: &str = "/etc/acadia/camera-capture.conf";
pub const CAPTURE_UNIT: &str = "acadia-camera-capture.service";

#[derive(Debug, Default)]
pub struct CameraApplier {
    last_backup: Mutex<Option<FileBackup>>,
}

impl CameraApplier {
    pub fn new() -> Self {
        Self::default()
    }

    /// `/dev/videoN` for a camera name given as `videoN` or `/dev/videoN`.
    pub fn device_path(name: &str) -> Option<String> {
        let n = name.strip_prefix("/dev/").unwrap_or(name);
        let idx = n.strip_prefix("video")?;
        (!idx.is_empty() && idx.bytes().all(|b| b.is_ascii_digit())).then(|| format!("/dev/{n}"))
    }

    /// The desired (enabled, device) from the config.
    fn desired(config: &Config) -> Result<(bool, Option<String>), ApplyError> {
        let io = &config.io;
        let camera = io.cameras.iter().find(|c| c.enabled);
        if !io.cameras_enabled || camera.is_none() {
            return Ok((false, None));
        }
        let name = &camera.expect("checked").name;
        let dev = Self::device_path(name).ok_or_else(|| ApplyError::Validation {
            stage: ApplyStage::Validate,
            message: format!("camera {name:?} is not a V4L2 device name (videoN)"),
        })?;
        Ok((true, Some(dev)))
    }

    /// Rewrite ENABLED / CAMERA_DEVICE, preserving every other line.
    pub fn render(existing: &str, enabled: bool, device: Option<&str>) -> String {
        let mut out = Vec::new();
        let (mut saw_enabled, mut saw_device) = (false, false);
        for line in existing.lines() {
            if line.trim_start().starts_with("ENABLED=") {
                out.push(format!("ENABLED={}", u8::from(enabled)));
                saw_enabled = true;
            } else if line.trim_start().starts_with("CAMERA_DEVICE=") && device.is_some() {
                out.push(format!("CAMERA_DEVICE={}", device.expect("checked")));
                saw_device = true;
            } else {
                out.push(line.to_string());
            }
        }
        if !saw_enabled {
            out.push(format!("ENABLED={}", u8::from(enabled)));
        }
        if let (false, Some(d)) = (saw_device, device) {
            out.push(format!("CAMERA_DEVICE={d}"));
        }
        out.join("\n") + "\n"
    }
}

impl Applier for CameraApplier {
    fn id(&self) -> &'static str {
        "camera"
    }

    fn validate(&self, _sysroot: &Sysroot, config: &Config) -> Result<(), ApplyError> {
        Self::desired(config).map(|_| ())
    }

    fn apply(&self, sysroot: &Sysroot, config: &Config) -> Result<ApplyOutcome, ApplyError> {
        let (enabled, device) = Self::desired(config)?;
        let path = sysroot.join(CAPTURE_CONF);
        if !path.exists() && !enabled {
            return Ok(ApplyOutcome::Committed); // no capture package, nothing to stop
        }
        let prior = FileBackup::capture(path.clone())?;
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if let Some(parent) = path.parent().filter(|p| !p.exists()) {
            crate::priv_client::create_dir_all(parent)?;
        }
        crate::priv_client::write_file(&path, Self::render(&existing, enabled, device.as_deref()))?;
        *self.last_backup.lock().expect("backup lock") = Some(prior);
        if sysroot.is_real_root() {
            let verb = if enabled { "enable" } else { "disable" };
            run_cmd("systemctl", &[verb, "--now", CAPTURE_UNIT])?;
        }
        Ok(ApplyOutcome::Committed)
    }

    fn rollback(&self, sysroot: &Sysroot) -> Result<(), ApplyError> {
        if let Some(backup) = self.last_backup.lock().expect("backup lock").take() {
            backup.restore()?;
            if sysroot.is_real_root() {
                let _ = run_cmd("systemctl", &["try-restart", CAPTURE_UNIT]);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names() {
        assert_eq!(
            CameraApplier::device_path("video0").as_deref(),
            Some("/dev/video0")
        );
        assert_eq!(
            CameraApplier::device_path("/dev/video12").as_deref(),
            Some("/dev/video12")
        );
        assert_eq!(CameraApplier::device_path("videoX"), None);
        assert_eq!(CameraApplier::device_path("../video0"), None);
    }

    #[test]
    fn render_preserves_other_keys() {
        let conf = "# c\nENABLED=0\nMODE=udp\nCAMERA_DEVICE=/dev/video0\nSTREAM_PORT=5000\n";
        let out = CameraApplier::render(conf, true, Some("/dev/video2"));
        assert_eq!(
            out,
            "# c\nENABLED=1\nMODE=udp\nCAMERA_DEVICE=/dev/video2\nSTREAM_PORT=5000\n"
        );
        let off = CameraApplier::render(conf, false, None);
        assert!(off.contains("ENABLED=0") && off.contains("CAMERA_DEVICE=/dev/video0"));
    }
}
