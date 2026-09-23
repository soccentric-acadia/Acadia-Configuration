//! Sysroot path resolution.
//!
//! Every applier takes a sysroot path parameter (default `/`) so CI can run
//! the entire config engine against a tempdir fake sysroot on x86 with no
//! hardware (spec §3, applier trait). All filesystem reads/writes done by
//! appliers must go through [`Sysroot`]; nothing in the engine hardcodes `/`.

use std::path::{Path, PathBuf};

/// A rooted view of the target filesystem. In production this wraps `/`; in
/// tests it wraps a `tempfile` directory. Construct with [`Sysroot::new`] for
/// the real root or [`Sysroot::at`] for a tempdir.
#[derive(Debug, Clone)]
pub struct Sysroot {
    root: PathBuf,
}

impl Sysroot {
    /// The real root filesystem.
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/"),
        }
    }

    /// A sysroot rooted at `root` (used by tests and CI's fake sysroot).
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Raw root path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether this is the real root filesystem (`/`). Appliers use this to
    /// decide whether to invoke live system verbs (hostnamectl, timedatectl,
    /// …) — a tempdir sysroot skips them so tests run with no hardware and no
    /// host side effects.
    pub fn is_real_root(&self) -> bool {
        self.root == Path::new("/")
    }

    /// Join an absolute guest path (e.g. `/etc/hostname`) onto this sysroot.
    /// `guest` must be absolute; passing a relative path is a programmer error
    /// and panics, since every applier deals in absolute system paths.
    pub fn join(&self, guest: impl AsRef<Path>) -> PathBuf {
        let guest = guest.as_ref();
        assert!(
            guest.is_absolute(),
            "sysroot guest paths must be absolute, got {:?}",
            guest
        );
        // Strip the leading `/` so `join` produces `<root>/etc/hostname`
        // rather than replacing `root` entirely.
        let rel = guest.strip_prefix("/").expect("absolute after assert");
        self.root.join(rel)
    }

    /// The writable data partition root. Resolution order:
    ///
    /// 1. `WEBCONFIG_DATA_DIR` — dev `make run` and tests redirect it to a
    ///    tempdir; the override always wins.
    /// 2. The persistent `/pst` store partition (task 003, T-P01) when it
    ///    exists under this sysroot — mutable state (config store, web-UI
    ///    users, HQ pairing credential, TLS identity) must survive OTA slot
    ///    switches, so it lives on `/pst`, never on the A/B rootfs. On real
    ///    devices `/pst` is either the mounted p4 partition (pst.mount) or
    ///    the plain rootfs fallback directory the acadia-pst-init recipe
    ///    ships — the same convention istate uses.
    /// 3. `/data` — the pre-T-P01 default, kept for fake sysroots and
    ///    deployments without the `/pst` partition.
    pub fn data_dir(&self) -> PathBuf {
        if let Ok(dir) = std::env::var("WEBCONFIG_DATA_DIR") {
            return PathBuf::from(dir);
        }
        if self.join("/pst").is_dir() {
            self.join("/pst")
        } else {
            self.join("/data")
        }
    }

    /// `/data/webconfig` — the canonical mutable state directory.
    pub fn webconfig_dir(&self) -> PathBuf {
        self.data_dir().join("webconfig")
    }

    /// `/usr/share/webconfig` — BSP-provided, read-only manifests & schemas.
    pub fn share_dir(&self) -> PathBuf {
        self.join("/usr/share/webconfig")
    }
}

impl Default for Sysroot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_strips_leading_slash_for_tempdir_root() {
        let s = Sysroot::at("/tmp/fake");
        assert_eq!(
            s.join("/etc/hostname"),
            PathBuf::from("/tmp/fake/etc/hostname")
        );
    }

    #[test]
    fn real_root_resolves_to_absolute_paths() {
        let s = Sysroot::new();
        assert_eq!(s.join("/etc/hostname"), PathBuf::from("/etc/hostname"));
    }

    #[test]
    #[should_panic(expected = "must be absolute")]
    fn relative_guest_path_panics() {
        let s = Sysroot::at("/tmp/fake");
        let _ = s.join("etc/hostname");
    }

    /// Serialise the WEBCONFIG_DATA_DIR env manipulation (tests run on
    /// threads sharing one process environment).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// T-P01: the mutable store lives on the persistent /pst partition when
    /// the sysroot carries it (real device or simulated fake root).
    #[test]
    fn data_dir_uses_pst_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("pst")).unwrap();
        let s = Sysroot::at(tmp.path());
        assert_eq!(s.data_dir(), tmp.path().join("pst"));
        // The whole WebConfig state tree hangs off it (config.db, users,
        // pairing.json, TLS identity) — one redirect point covers all.
        assert_eq!(s.webconfig_dir(), tmp.path().join("pst").join("webconfig"));
    }

    #[test]
    fn data_dir_falls_back_to_data_without_pst() {
        let tmp = tempfile::tempdir().unwrap();
        let s = Sysroot::at(tmp.path());
        assert_eq!(s.data_dir(), tmp.path().join("data"));
        assert_eq!(s.webconfig_dir(), tmp.path().join("data").join("webconfig"));
    }

    /// T-P01: the env override still wins over the /pst detection — the dev
    /// `make run` target must keep redirecting to ./data even though the
    /// workspace happens to contain a data/ directory.
    #[test]
    fn env_override_wins_over_pst() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("pst")).unwrap();
        let s = Sysroot::at(tmp.path());
        let redirect = tempfile::tempdir().unwrap();
        std::env::set_var("WEBCONFIG_DATA_DIR", redirect.path());
        let dir = s.data_dir();
        std::env::remove_var("WEBCONFIG_DATA_DIR");
        assert_eq!(dir, redirect.path());
    }
}
