//! The applyd allowlist — the daemon's sandbox.
//!
//! Three tables, each traceable to the applier that needs it (T-P02):
//!
//! * [`EXEC_PROGRAMS`] — the only programs a request may run;
//! * [`SYSTEMCTL_*`] — the exact systemctl verbs/units the appliers drive;
//! * [`WRITE_PREFIXES`]/[`WRITE_FILES`] — the exact filesystem paths the
//!   appliers write;
//! * [`PASSWORD_USERS`] — the accounts `chpasswd` may touch.
//!
//! Anything else is rejected. Keep every entry annotated with the applier
//! that needs it so the next reviewer can trace each line back to a feature.

/// Programs a request may execute. Everything else is rejected outright.
pub const EXEC_PROGRAMS: &[&str] = &[
    "systemctl",       // unit control (systemd-manager verbs, allowlisted below)
    "hostnamectl",     // appliers/hostname.rs
    "timedatectl",     // appliers/time.rs
    "networkctl",      // appliers/networkd.rs, ap.rs
    "nft",             // appliers/firewall.rs
    "iw",              // appliers/wifi.rs (regulatory domain)
    "wpa_cli",         // appliers/wifi.rs (reconfigure)
    "wg",              // appliers/wireguard.rs (genkey)
    "wg-quick",        // appliers/wireguard.rs (up/down)
    "rauc",            // engine/update.rs (RAUC backend)
    "swupdate-client", // engine/update.rs SWUpdate backend: daemon IPC install (T-P26)
    "swupdate",        // engine/update.rs SWUpdate backend: one-shot `-i` fallback (T-P26)
    "gpioget",         // webconfigd api/io.rs (device access via the helper)
    "gpioset",         // webconfigd api/io.rs
    "i2cdetect",       // webconfigd api/io.rs (bus scan + listing, CFG-040)
    "mmc",             // engine/monitoring.rs eMMC wear fallback (read-only, CFG-041)
    "pico-flash",      // board manifest flash_command (MCU firmware flash)
    "journalctl",      // webconfigd Logs page read queries (fixed flag set)
];

/// systemctl verbs that take no unit argument.
const SYSTEMCTL_NO_UNIT: &[&str] = &["daemon-reload", "reboot", "poweroff", "is-active"];

/// systemctl verbs that take exactly one unit argument (plus optional flags).
const SYSTEMCTL_UNIT_VERBS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "reload",
    "try-restart",
    "enable",
    "disable",
];

/// Fixed units any applier may drive (appliers/ssh, time, networkd, ap,
/// journald, wifi).
pub const SYSTEMCTL_FIXED_UNITS: &[&str] = &[
    "sshd.service",
    "systemd-networkd.service",
    "systemd-resolved.service",
    "systemd-timesyncd.service",
    "systemd-journald.service",
    "wpa_supplicant.service",
    "hostapd.service",
    "dnsmasq.service",
    "phc2sys.service",
    "gpsd.service",
    "chrony.service",
    "chronyd.service",
    "webconfig-syslog-forward.service",
    "webconfigd.service",
    "swupdate.service",
    "swupdate.socket",
];

/// Unit-name prefixes that expand dynamically per interface/device (appliers/
/// can.rs, serial.rs, gpio.rs, time.rs). `can-<name>.service`,
/// `webconfig-serial-<dev>.service`, `webconfig-gpio-<name>.service`,
/// `serial-getty@<tty>.service`, `ptp4l@<if>.service`.
pub const SYSTEMCTL_DYNAMIC_PREFIXES: &[&str] = &[
    "can-",
    "webconfig-serial-",
    "webconfig-gpio-",
    "serial-getty@",
    "ptp4l@",
];

/// Units a request may READ state of via `systemctl show` (read-only).
fn unit_allowed(unit: &str) -> bool {
    if !unit.is_ascii() {
        return false;
    }
    if SYSTEMCTL_FIXED_UNITS.contains(&unit) {
        return true;
    }
    for prefix in SYSTEMCTL_DYNAMIC_PREFIXES {
        if let Some(rest) = unit.strip_prefix(prefix) {
            // The dynamic part must be a sane device/unit token: alphanumerics,
            // '-' '@' '.' '_' '+' — never '/' or whitespace.
            if !rest.is_empty()
                && rest.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'@' | b'.' | b'_' | b'+')
                })
            {
                return true;
            }
        }
    }
    false
}

/// File paths the appliers write. Prefixes match directories (recursively),
/// `WRITE_FILES` exact files. The generated-unit tree (`/etc/systemd/system/`)
/// is additionally name-filtered by [`generated_unit_name`] so an allowlisted
/// write can never overwrite a real system unit (e.g. sshd.service).
pub const WRITE_PREFIXES: &[&str] = &[
    // networkd per-interface config + AP bridge network (networkd.rs, ap.rs)
    "/etc/systemd/network/",
    // NTP server drop-in (time.rs)
    "/etc/systemd/timesyncd.conf.d/",
    // DNS upstream drop-in (networkd.rs)
    "/etc/systemd/resolved.conf.d/",
    // journald storage/retention drop-in (journald.rs)
    "/etc/systemd/journald.conf.d/",
    // generated units: can-*, webconfig-serial-*, webconfig-gpio-*,
    // webconfig-syslog-forward (can.rs, serial.rs, gpio.rs, journald.rs) —
    // name-filtered in path_allowed, the whole tree is NOT writable
    "/etc/systemd/system/",
    // firewall ruleset (firewall.rs)
    "/etc/nftables.d/",
    // hostapd AP config (ap.rs)
    "/etc/hostapd/",
    // dnsmasq AP config (ap.rs)
    "/etc/dnsmasq.d/",
    // wpa_supplicant client config (wifi.rs)
    "/etc/wpa_supplicant/",
    // wireguard tunnel config (wireguard.rs)
    "/etc/wireguard/",
    // sshd_config.d drop-ins (ssh.rs)
    "/etc/ssh/sshd_config.d/",
    // operator account authorized_keys (ssh.rs, T-P11/B05: keys live for the
    // operator user, never root — PermitRootLogin is no in the image)
    "/home/operator/.ssh/",
];

/// Exact files the appliers write outside the prefix trees.
pub const WRITE_FILES: &[&str] = &["/etc/hostname"];

/// Accounts `chpasswd` may be pointed at (B04: root password from the UI).
pub const PASSWORD_USERS: &[&str] = &["root", "rpi"];

/// User:group pairs a write/mkdir may be chown'ed to (T-P11: the operator's
/// authorized_keys must be operator-owned). Root keeps root ownership.
pub const OWNER_ALLOWED: &[&str] = &["operator:operator", "root:root", "webconfig:webconfig"];

/// Whether a write/mkdir may carry this owner.
pub fn owner_allowed(owner: &str) -> bool {
    owner.is_empty() || OWNER_ALLOWED.contains(&owner)
}

/// Whether this (program, args) pair is allowed to run.
pub fn exec_allowed(program: &str, args: &[String]) -> bool {
    // The Acadia board manifest's flash_command names the helper by absolute
    // path (/usr/local/bin/pico-flash); it is the only non-bare program name
    // accepted and is treated as "pico-flash" below.
    let canonical = if program == "/usr/local/bin/pico-flash" {
        "pico-flash"
    } else {
        program
    };
    if !EXEC_PROGRAMS.contains(&canonical) {
        return false;
    }
    match canonical {
        "systemctl" => systemctl_args_allowed(args),
        "hostnamectl" => {
            args.len() == 2
                && args[0] == "set-hostname"
                && !args[1].is_empty()
                && args[1].len() <= 63
                && args[1]
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }
        "timedatectl" => timedatectl_args_allowed(args),
        "networkctl" => args == ["reload"],
        "nft" => nft_args_allowed(args),
        "iw" => args.len() == 3 && args[0] == "reg" && args[1] == "set",
        "wpa_cli" => args == ["reconfigure"],
        "wg" => args == ["genkey"],
        "wg-quick" => args == ["up", "wg0"] || args == ["down", "wg0"],
        "rauc" => rauc_args_allowed(args),
        // T-P26 (K06): hand a staged bundle to the running SWUpdate daemon.
        "swupdate-client" => args.len() == 1 && bundle_path_allowed(&args[0]),
        // T-P26 (K06, CFG-038): one-shot LOCAL install — exactly
        // `-f <cfg> -k <pubkey> -i <bundle>` (`-i` installs a local file;
        // `-u` was the wrong flag). The key is mandatory, so a one-shot
        // install can never skip signature verification.
        "swupdate" => {
            args.len() == 6
                && args[0] == "-f"
                && args[1] == SWUPDATE_CFG
                && args[2] == "-k"
                && args[3] == SWUPDATE_PUBKEY
                && args[4] == "-i"
                && bundle_path_allowed(&args[5])
        }
        // Read-only journal queries from the Logs page: -u <unit> | -b | -n<N>
        // | -o <fmt> | --no-pager | --since/--until — a fixed flag set, never
        // an open passthrough (a stray --vacuum-size would delete logs).
        "journalctl" => journalctl_args_allowed(args),
        // Hardware toggles/scans: positional args plus i2cdetect's -y flag.
        // Hardware toggles/scans: positional args plus i2cdetect's -y flag.
        "gpioget" | "gpioset" => {
            !args.is_empty()
                && args.len() <= 3
                && args.iter().all(|a| {
                    !a.starts_with('-')
                        && a.bytes().all(|b| {
                            b.is_ascii_alphanumeric()
                                || matches!(b, b'-' | b'_' | b'.' | b'=' | b'@' | b'/' | b'+')
                        })
                })
        }
        // CFG-041: read-only EXT_CSD dump of one eMMC block device.
        "mmc" => {
            args.len() == 3
                && args[0] == "extcsd"
                && args[1] == "read"
                && args[2]
                    .strip_prefix("/dev/mmcblk")
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        }
        "i2cdetect" => {
            args.len() == 2 && args[0] == "-y" && args[1].bytes().all(|b| b.is_ascii_digit())
        }
        // pico-flash <fw-path>: the Acadia board manifest's flash_command
        // (board-manifests/acadia.json); the argument is the staged firmware
        // file the daemon wrote under its own data dir.
        "pico-flash" => args.len() == 1 && !args[0].starts_with('-') && !args[0].contains(".."),
        // Passwords only via the dedicated verb (never argv).
        "chpasswd" => false,
        _ => false,
    }
}

fn systemctl_args_allowed(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }
    let head = args[0].as_str();
    if SYSTEMCTL_NO_UNIT.contains(&head) {
        // Only known flag shapes after the verb (e.g. reboot --reboot-argument=…).
        return args[1..]
            .iter()
            .all(|a| a.starts_with("--") && !a.contains("..") && a.len() < 128);
    }
    // systemctl show <unit> [flags] — read-only status for the Services page.
    if head == "show" {
        return args.len() >= 2 && unit_allowed(&args[1]);
    }
    if SYSTEMCTL_UNIT_VERBS.contains(&head) {
        // Optional "--now"-style flags may precede the single unit argument.
        let rest = &args[1..];
        let flags_end = rest.iter().take_while(|a| a.starts_with("--")).count();
        if rest.len() - flags_end != 1 {
            return false;
        }
        let flags = &rest[..flags_end];
        let unit = &rest[flags_end];
        return flags
            .iter()
            .all(|f| *f == "--now" || *f == "--no-block" || *f == "--quiet")
            && unit_allowed(unit);
    }
    false
}

fn timedatectl_args_allowed(args: &[String]) -> bool {
    if args.len() == 2 && args[0] == "set-timezone" {
        // IANA zone: letters, digits, '/', '_', '-'.
        return args[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'+'));
    }
    if args.len() == 2 && args[0] == "set-ntp" {
        return args[1] == "true" || args[1] == "false";
    }
    if args.len() == 2 && args[0] == "set-time" {
        // ISO-8601-ish: digits and separators only.
        return args[1].bytes().all(|b| {
            b.is_ascii_digit() || matches!(b, b'-' | b':' | b'T' | b' ' | b'.' | b'Z' | b'+')
        });
    }
    false
}

fn nft_args_allowed(args: &[String]) -> bool {
    // firewall.rs: `nft delete table inet webconfig` (rollback) and
    // `nft -f /etc/nftables.d/webconfig.nft`.
    if args == ["delete", "table", "inet", "webconfig"] {
        return true;
    }
    if args.len() == 2 && args[0] == "-f" {
        let path = &args[1];
        return path.starts_with("/etc/nftables.d/") && !path.contains("..");
    }
    false
}

/// SWUpdate configuration and signing key the one-shot install must use
/// (installed by meta-acadia's rpi5-swupdate-config).
pub const SWUPDATE_CFG: &str = "/etc/swupdate/swupdate.cfg";
pub const SWUPDATE_PUBKEY: &str = "/etc/swupdate/swupdate-public.pem";

/// Directories an update bundle may be installed from: webconfigd's own data
/// dir (upload staging, HQ downloads) — `/pst/webconfig` on A/B boards
/// (T-P01), the legacy/non-A/B locations otherwise.
pub const BUNDLE_DIRS: &[&str] = &[
    "/pst/webconfig/",
    "/var/lib/webconfig/",
    "/data/webconfig/",
    // Rootfs staging for full-image bundles (WEBCONFIG_OTA_STAGING_DIR).
    "/var/lib/webconfig-ota/",
];

/// Whether a bundle path is a plain file path inside [`BUNDLE_DIRS`].
pub fn bundle_path_allowed(path: &str) -> bool {
    !path.starts_with('-')
        && !path.contains("..")
        && !path.contains('\0')
        && BUNDLE_DIRS
            .iter()
            .any(|d| path.starts_with(d) && path.len() > d.len())
}

/// Boot slots `boot_select` may point `/boot/autoboot.txt` at (OS-016
/// tryboot layout: per-slot boot dirs `/boot/A`, `/boot/B`).
pub const BOOT_SLOTS: &[&str] = &["A", "B"];

/// Whether `slot` is a valid tryboot slot directory name.
pub fn boot_slot_allowed(slot: &str) -> bool {
    BOOT_SLOTS.contains(&slot)
}

fn rauc_args_allowed(args: &[String]) -> bool {
    if args == ["status", "--output-format=json"] || args == ["status", "mark-good"] {
        return true;
    }
    // rauc install <bundle-path>
    if args.len() == 2 && args[0] == "install" {
        let p = &args[1];
        return p.starts_with('/') && !p.contains("..");
    }
    // rauc info <bundle-path>
    if args.len() == 2 && args[0] == "info" {
        let p = &args[1];
        return p.starts_with('/') && !p.contains("..");
    }
    false
}

fn journalctl_args_allowed(args: &[String]) -> bool {
    // Read-only journal queries from the Logs page — a fixed flag set (a
    // stray --vacuum-size=0 would destroy logs, so no open passthrough).
    let mut expect_unit = false;
    for a in args {
        if expect_unit {
            if !unit_allowed(a) {
                return false;
            }
            expect_unit = false;
            continue;
        }
        if a == "-u" {
            expect_unit = true;
        } else if !(a == "--no-pager"
            || a == "--quiet"
            || a == "-b"
            || (a.starts_with("-u") && a.len() > 2 && unit_allowed(&a[2..]))
            || (a.starts_with("-n") && a.len() > 2 && a[2..].bytes().all(|b| b.is_ascii_digit()))
            || (a.starts_with("--since=") && !a.contains(".."))
            || (a.starts_with("--until=") && !a.contains(".."))
            || (a.starts_with("-o") && a.len() > 2))
        {
            return false;
        }
    }
    !expect_unit
}

/// Whether a user may be passed to `chpasswd`.
pub fn user_allowed(user: &str) -> bool {
    PASSWORD_USERS.contains(&user)
}

/// Whether a file path may be written/removed/chmod'ed.
pub fn path_allowed(path: &std::path::Path) -> bool {
    let p = path.to_string_lossy();
    if p.contains("..") || !p.starts_with('/') {
        return false;
    }
    if WRITE_FILES.contains(&p.as_ref()) {
        return true;
    }
    WRITE_PREFIXES.iter().any(|prefix| {
        if !p.starts_with(prefix) || p[prefix.len()..].contains("..") {
            return false;
        }
        // The generated-unit tree is name-filtered: only the appliers' own
        // unit names (can-*, webconfig-*) may ever be created there.
        if *prefix == "/etc/systemd/system/" {
            let name = p[prefix.len()..]
                .trim_start_matches('/')
                .split('/')
                .next()
                .unwrap_or("");
            return name.starts_with("can-") || name.starts_with("webconfig-");
        }
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn exec_program_allowlist() {
        assert!(EXEC_PROGRAMS.contains(&"systemctl"));
        assert!(!EXEC_PROGRAMS.contains(&"sh"));
        assert!(!exec_allowed("sh", &s(&["-c", "evil"])));
        assert!(!exec_allowed("bash", &[]));
        assert!(!exec_allowed("curl", &s(&["http://x"]))); // network egress stays local
    }

    #[test]
    fn systemctl_unit_allowlist() {
        assert!(exec_allowed("systemctl", &s(&["restart", "sshd.service"])));
        assert!(exec_allowed(
            "systemctl",
            &s(&["enable", "--now", "hostapd.service"])
        ));
        assert!(exec_allowed("systemctl", &s(&["daemon-reload"])));
        assert!(exec_allowed(
            "systemctl",
            &s(&["reboot", "--reboot-argument=0 tryboot"])
        ));
        assert!(exec_allowed(
            "systemctl",
            &s(&["enable", "can-can0.service"])
        ));
        assert!(exec_allowed(
            "systemctl",
            &s(&["start", "webconfig-serial-ttyAMA10.service"])
        ));
        assert!(exec_allowed(
            "systemctl",
            &s(&["restart", "webconfig-gpio-led0.service"])
        ));
        assert!(exec_allowed(
            "systemctl",
            &s(&["start", "serial-getty@ttyS0.service"])
        ));
        assert!(exec_allowed(
            "systemctl",
            &s(&["restart", "ptp4l@eth0.service"])
        ));
        assert!(exec_allowed(
            "systemctl",
            &s(&["restart", "chrony.service"])
        ));
        assert!(exec_allowed(
            "systemctl",
            &s(&["show", "webconfigd.service", "--property=LoadState"])
        ));
        assert!(!exec_allowed("systemctl", &s(&["start", "sshd"])));
        assert!(!exec_allowed(
            "systemctl",
            &s(&["start", "../../evil.service"])
        ));
        assert!(!exec_allowed("systemctl", &s(&["start", "evil.service"])));
        assert!(!exec_allowed("systemctl", &s(&["mask", "sshd.service"])));
        assert!(!exec_allowed(
            "systemctl",
            &s(&["enable", "a.service", "b.service"])
        ));
    }

    #[test]
    fn time_and_network_verbs() {
        assert!(exec_allowed(
            "hostnamectl",
            &s(&["set-hostname", "acadia-01"])
        ));
        assert!(!exec_allowed("hostnamectl", &s(&["set-hostname", "a b"])));
        assert!(exec_allowed(
            "timedatectl",
            &s(&["set-timezone", "Europe/Oslo"])
        ));
        assert!(exec_allowed("timedatectl", &s(&["set-ntp", "false"])));
        assert!(exec_allowed(
            "timedatectl",
            &s(&["set-time", "2026-09-23 10:00:00"])
        ));
        assert!(!exec_allowed(
            "timedatectl",
            &s(&["set-timezone", "../../etc"])
        ));
        assert!(exec_allowed("networkctl", &s(&["reload"])));
        assert!(!exec_allowed("networkctl", &s(&["delete", "eth0"])));
        assert!(exec_allowed(
            "nft",
            &s(&["-f", "/etc/nftables.d/webconfig.nft"])
        ));
        assert!(exec_allowed(
            "nft",
            &s(&["delete", "table", "inet", "webconfig"])
        ));
        assert!(!exec_allowed("nft", &s(&["-f", "/tmp/evil.nft"])));
        assert!(exec_allowed("iw", &s(&["reg", "set", "NO"])));
        assert!(exec_allowed("wpa_cli", &s(&["reconfigure"])));
        assert!(exec_allowed("wg", &s(&["genkey"])));
        assert!(exec_allowed("wg-quick", &s(&["up", "wg0"])));
        assert!(!exec_allowed("wg-quick", &s(&["up", "wg1"])));
    }

    #[test]
    fn journalctl_read_only() {
        assert!(exec_allowed(
            "journalctl",
            &s(&["-u", "sshd.service", "-n100", "--no-pager"])
        ));
        assert!(!exec_allowed("journalctl", &s(&["--vacuum-size=0"])));
    }

    #[test]
    fn write_path_allowlist() {
        for p in [
            "/etc/hostname",
            "/etc/systemd/network/10-eth0.network",
            "/etc/systemd/timesyncd.conf.d/webconfig.conf",
            "/etc/systemd/resolved.conf.d/webconfig.conf",
            "/etc/systemd/journald.conf.d/webconfig.conf",
            "/etc/systemd/system/can-can0.service",
            "/etc/systemd/system/webconfig-syslog-forward.service",
            "/etc/nftables.d/webconfig.nft",
            "/etc/hostapd/hostapd.conf",
            "/etc/dnsmasq.d/webconfig-ap.conf",
            "/etc/wpa_supplicant/wpa_supplicant.conf",
            "/etc/wireguard/wg0.conf",
            "/home/operator/.ssh/authorized_keys",
        ] {
            assert!(path_allowed(std::path::Path::new(p)), "must allow {p}");
        }
        for p in [
            "/etc/shadow",
            "/etc/passwd",
            // name-filtered generated-unit tree: real units are untouchable
            "/etc/systemd/system/sshd.service",
            "/etc/systemd/system/swupdate.service",
            "/var/lib/webconfig/config.db",
            "/etc/systemd/system/../../etc/shadow",
            "relative/path",
        ] {
            assert!(!path_allowed(std::path::Path::new(p)), "must reject {p}");
        }
    }

    #[test]
    fn swupdate_install_verbs() {
        assert!(exec_allowed(
            "swupdate-client",
            &s(&["/pst/webconfig/uploads/x.swu"])
        ));
        assert!(!exec_allowed("swupdate-client", &s(&["/tmp/x.swu"])));
        assert!(exec_allowed(
            "swupdate-client",
            &s(&["/var/lib/webconfig-ota/hq-uploads/hq-artifact.bundle"])
        ));
        assert!(!exec_allowed(
            "swupdate-client",
            &s(&["/pst/webconfig/../../etc/shadow"])
        ));
        assert!(!exec_allowed("swupdate-client", &s(&["-h"])));
        let ok = s(&[
            "-f",
            SWUPDATE_CFG,
            "-k",
            SWUPDATE_PUBKEY,
            "-i",
            "/pst/webconfig/hq/u.swu",
        ]);
        assert!(exec_allowed("swupdate", &ok));
        // CFG-038: -u is not a local install and never passes
        assert!(!exec_allowed(
            "swupdate",
            &s(&["-u", "/pst/webconfig/u.swu"])
        ));
        // signature key is mandatory
        assert!(!exec_allowed(
            "swupdate",
            &s(&["-f", SWUPDATE_CFG, "-i", "/pst/webconfig/u.swu"])
        ));
        assert!(!exec_allowed(
            "swupdate",
            &s(&[
                "-f",
                SWUPDATE_CFG,
                "-k",
                "/tmp/evil.pem",
                "-i",
                "/pst/webconfig/u.swu"
            ])
        ));
    }

    #[test]
    fn mmc_extcsd_read_only() {
        assert!(exec_allowed("mmc", &s(&["extcsd", "read", "/dev/mmcblk0"])));
        assert!(!exec_allowed(
            "mmc",
            &s(&["extcsd", "write", "/dev/mmcblk0"])
        ));
        assert!(!exec_allowed("mmc", &s(&["extcsd", "read", "/dev/sda"])));
        assert!(!exec_allowed(
            "mmc",
            &s(&["extcsd", "read", "/dev/mmcblk0p1"])
        ));
        assert!(!exec_allowed(
            "mmc",
            &s(&["bkops", "enable", "/dev/mmcblk0"])
        ));
    }

    #[test]
    fn boot_slots() {
        assert!(boot_slot_allowed("A"));
        assert!(boot_slot_allowed("B"));
        assert!(!boot_slot_allowed("a"));
        assert!(!boot_slot_allowed("../A"));
        assert!(!boot_slot_allowed(""));
    }

    #[test]
    fn password_users() {
        assert!(user_allowed("root"));
        assert!(user_allowed("rpi"));
        assert!(!user_allowed("acaida"));
        assert!(!user_allowed("nobody"));
    }
}
