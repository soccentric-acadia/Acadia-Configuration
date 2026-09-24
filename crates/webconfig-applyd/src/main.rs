//! webconfig-applyd — root privileged-apply helper (T-P00b option (a), T-P02).
//!
//! The hardened `webconfigd.service` sandbox (ProtectSystem=strict, empty
//! capability bounding set, PrivateDevices) cannot itself apply operator
//! configuration: every applier writes /etc and drives systemctl/nft/… . This
//! daemon closes that gap with a **fixed verb set** over a Unix socket — never
//! a generic shell:
//!
//! * listens on `/run/webconfig/apply.sock` (0660, webconfig:webconfig) inside
//!   the root-owned 0750 `/run/webconfig` runtime directory,
//! * enforces a program allowlist (systemctl, hostnamectl, timedatectl,
//!   networkctl, nft, iw, wpa_cli, wg, wg-quick, rauc, gpioget, gpioset,
//!   i2cdetect, pico-flash), a systemctl unit allowlist (exactly the units the
//!   appliers manage) and a file-path allowlist (exactly the paths the
//!   appliers write),
//! * answers newline-delimited JSON requests.
//!
//! webconfigd (as `webconfig`) routes through the helper whenever the socket
//! exists and the process is not root; the fake-sysroot test path and root
//! dev runs keep the direct `std::fs`/`std::process` behaviour (see
//! webconfig-engine's `priv` module).
//!
//! The daemon is deliberately std-only: no async runtime, no D-Bus, one
//! auditable allowlist module (`allow.rs`) — it is the single root-owned
//! process in the stack, so it stays reviewable. Peer identity is enforced by
//! the transport gate (socket 0660 webconfig:webconfig inside a 0750
//! root:webconfig runtime dir): only root and the webconfig daemon can open
//! it; safe std cannot read SO_PEERCRED and this daemon forbids unsafe code.
//!
//! The daemon is intentionally NOT sandboxed with ProtectSystem=strict: its
//! entire purpose is to write the operator-configuration allowlist and drive
//! system units. The allowlist module IS its sandbox.

#![forbid(unsafe_code)]

pub mod allow;

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// Default listen path. Overridable for tests and unusual deployments.
pub const DEFAULT_SOCK: &str = "/run/webconfig/apply.sock";

/// Environment override for the socket path (tests / CI).
pub const ENV_SOCK: &str = "WEBCONFIG_APPLYD_SOCK";
/// Environment override for the allowed peer uid — reserved for CI images
/// where the `webconfig` account does not exist; on a device it always does.
pub const ENV_ALLOWED_UID: &str = "WEBCONFIG_APPLYD_ALLOWED_UID";

/// One privileged request (newline-delimited JSON over the UDS).
#[derive(Debug, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum Request {
    /// Run one allowlisted program with validated arguments.
    Exec { program: String, args: Vec<String> },
    /// Write (create/replace) one allowlisted file. `mode` defaults to 0644;
    /// `owner` ("user:group") is optional and allowlisted (T-P11).
    WriteFile {
        path: String,
        #[serde(default = "default_file_mode")]
        mode: u32,
        /// base64 of the file contents (binary-safe).
        content: String,
        #[serde(default)]
        owner: String,
    },
    /// Create a directory (and parents) inside an allowlisted tree.
    Mkdir {
        path: String,
        #[serde(default = "default_dir_mode")]
        mode: u32,
        #[serde(default)]
        owner: String,
    },
    /// Remove one allowlisted file (applier cleanup paths).
    RemoveFile { path: String },
    /// chmod one allowlisted path (e.g. 0600 on secret-bearing files).
    SetMode { path: String, mode: u32 },
    /// Point the firmware at a tryboot slot permanently (T-P26, CFG-039):
    /// atomically rewrite `/boot/autoboot.txt` to `boot_prefix=<slot>/` and,
    /// when `clear_state` is set, drop `/boot/boot_state`. Used by the
    /// SWUpdate backend's `mark_good` (confirm the running slot) and
    /// `rollback` (re-arm the previous slot). `/boot` is otherwise never
    /// writable through the helper.
    BootSelect {
        slot: String,
        #[serde(default)]
        clear_state: bool,
    },
}

fn default_file_mode() -> u32 {
    0o644
}

fn default_dir_mode() -> u32 {
    0o755
}

/// One privileged-apply reply.
#[derive(Debug, Serialize)]
pub struct Reply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
}

impl Reply {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            stdout: None,
            stderr: None,
            code: None,
        }
    }

    fn exec(stdout: String, stderr: String, code: i32) -> Self {
        Self {
            ok: code == 0,
            error: None,
            stdout: Some(stdout),
            stderr: Some(stderr),
            code: Some(code),
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(message.into()),
            stdout: None,
            stderr: None,
            code: None,
        }
    }
}

/// The account's uid, resolved from `/etc/passwd` (std-only; the daemon must
/// not depend on NSS tooling at runtime).
pub fn user_uid(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut f = line.split(':');
        let user = f.next()?;
        if user == name {
            return f.nth(1)?.parse().ok();
        }
    }
    None
}

/// The effective uid this process runs as (Linux: `/proc/self/status`).
pub fn euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            // Real, effective, saved, fs — the second field is euid.
            return rest.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

/// Handle one newline-delimited JSON request.
pub fn handle(request: &str) -> Reply {
    let req: Request = match serde_json::from_str(request) {
        Ok(r) => r,
        Err(e) => return Reply::err(format!("bad request: {e}")),
    };
    match req {
        Request::Exec { program, args } => handle_exec(&program, &args),
        Request::WriteFile {
            path,
            mode,
            content,
            owner,
        } => handle_write(&path, mode, &content, &owner),
        Request::Mkdir { path, mode, owner } => handle_mkdir(&path, mode, &owner),
        Request::RemoveFile { path } => handle_remove(&path),
        Request::SetMode { path, mode } => handle_set_mode(&path, mode),
        Request::BootSelect { slot, clear_state } => {
            handle_boot_select(Path::new(BOOT_DIR), &slot, clear_state)
        }
    }
}

fn handle_exec(program: &str, args: &[String]) -> Reply {
    if !allow::exec_allowed(program, args) {
        return Reply::err(format!(
            "program/arguments rejected by allowlist: {program} {args:?}"
        ));
    }
    match std::process::Command::new(program).args(args).output() {
        Ok(out) => Reply::exec(
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code().unwrap_or(-1),
        ),
        Err(e) => Reply::err(format!("spawn {program} failed: {e}")),
    }
}

fn checked_path(raw: &str) -> Result<&Path, String> {
    if raw.contains("..") || raw.contains('\0') {
        return Err("path rejected".into());
    }
    if !allow::path_allowed(Path::new(raw)) {
        return Err(format!("path rejected by allowlist: {raw}"));
    }
    Ok(Path::new(raw))
}

fn handle_write(path: &str, mode: u32, content_b64: &str, owner: &str) -> Reply {
    if !allow::owner_allowed(owner) {
        return Reply::err(format!("owner rejected by allowlist: {owner:?}"));
    }
    let bytes = match base64::engine::general_purpose::STANDARD.decode(content_b64) {
        Ok(b) => b,
        Err(e) => return Reply::err(format!("bad content encoding: {e}")),
    };
    let path = match checked_path(path) {
        Ok(p) => p,
        Err(e) => return Reply::err(e),
    };
    // Symlink-safe parent check: the parent must exist and resolve inside the
    // allowlist, so a symlink planted in an allowlisted directory cannot
    // redirect the write outside it.
    let parent = match path.parent() {
        Some(p) => p,
        None => return Reply::err("path has no parent"),
    };
    let real_parent = match std::fs::canonicalize(parent) {
        Ok(p) => p,
        Err(e) => return Reply::err(format!("parent missing: {e}")),
    };
    if !allow::path_allowed(&real_parent) {
        return Reply::err("resolved parent outside allowlist (symlink?)");
    }
    match std::fs::write(path, &bytes) {
        Ok(()) => {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
            if !owner.is_empty() {
                chown_name(path, owner);
            }
            Reply::ok()
        }
        Err(e) => Reply::err(format!("write {path:?}: {e}")),
    }
}

fn handle_mkdir(path: &str, mode: u32, owner: &str) -> Reply {
    if !allow::owner_allowed(owner) {
        return Reply::err(format!("owner rejected by allowlist: {owner:?}"));
    }
    let path = match checked_path(path) {
        Ok(p) => p,
        Err(e) => return Reply::err(e),
    };
    match std::fs::create_dir_all(path) {
        Ok(()) => {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
            if !owner.is_empty() {
                chown_name(path, owner);
            }
            Reply::ok()
        }
        Err(e) => Reply::err(format!("mkdir {path:?}: {e}")),
    }
}

fn handle_remove(path: &str) -> Reply {
    let path = match checked_path(path) {
        Ok(p) => p,
        Err(e) => return Reply::err(e),
    };
    match std::fs::remove_file(path) {
        Ok(()) => Reply::ok(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Reply::ok(),
        Err(e) => Reply::err(format!("remove {path:?}: {e}")),
    }
}

fn handle_set_mode(path: &str, mode: u32) -> Reply {
    let path = match checked_path(path) {
        Ok(p) => p,
        Err(e) => return Reply::err(e),
    };
    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        Ok(()) => Reply::ok(),
        Err(e) => Reply::err(format!("chmod {path:?}: {e}")),
    }
}

/// The firmware boot partition (OS-016 tryboot layout).
pub const BOOT_DIR: &str = "/boot";

/// `boot_select` against an explicit boot dir (tests use a temp dir).
pub fn handle_boot_select(boot: &Path, slot: &str, clear_state: bool) -> Reply {
    if !allow::boot_slot_allowed(slot) {
        return Reply::err(format!("boot slot rejected by allowlist: {slot:?}"));
    }
    // Only a tryboot-managed /boot with the target slot present may be
    // re-pointed; anything else would leave the firmware without a kernel.
    if !boot.join(slot).is_dir() {
        return Reply::err(format!("boot slot directory {slot}/ missing"));
    }
    let autoboot = boot.join("autoboot.txt");
    let tmp = boot.join("autoboot.txt.tmp");
    let body = format!("[all]\nboot_prefix={slot}/\n");
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &autoboot)
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Reply::err(format!("write autoboot.txt: {e}"));
    }
    if clear_state {
        match std::fs::remove_file(boot.join("boot_state")) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Reply::err(format!("remove boot_state: {e}")),
        }
    }
    Reply::ok()
}

/// Serve one connection: read newline-delimited requests, answer each.
pub fn serve_stream(stream: UnixStream) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.is_empty() {
            continue;
        }
        let body = serve_once(trimmed);
        let mut stream = &stream;
        if writeln!(stream, "{body}").is_err() {
            return;
        }
    }
}

/// Bind the UDS and serve forever. The socket drops to webconfig:webconfig
/// 0660 when the account exists — the transport gate for all connections.
pub fn run() -> Result<(), String> {
    let sock = std::env::var(ENV_SOCK).unwrap_or_else(|_| DEFAULT_SOCK.into());
    if euid() != Some(0) {
        return Err("webconfig-applyd must run as root".into());
    }
    if std::env::var(ENV_ALLOWED_UID).is_err() && user_uid("webconfig").is_none() {
        // Fail closed: without the account the transport gate cannot be set
        // to a non-root identity, so nothing would ever be allowed to connect.
        return Err(
            "the webconfig account does not exist — refusing to start (fail closed)".to_string(),
        );
    }

    let path = PathBuf::from(&sock);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {dir:?}: {e}"))?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| format!("bind {sock:?}: {e}"))?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
    if let Some(uid) = user_uid("webconfig") {
        chown_path(&path, uid, uid);
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || serve_stream(stream));
            }
            Err(e) => eprintln!("webconfig-applyd: accept: {e}"),
        }
    }
    Ok(())
}

/// chown by name ("user:group") for write/mkdir owner requests. The name is
/// allowlist-checked by allow::owner_allowed before we get here.
fn chown_name(path: &Path, owner: &str) {
    let _ = std::process::Command::new("chown")
        .arg(owner)
        .arg(path)
        .status();
}

/// chown without libc: this root daemon shells out to coreutils chown.
fn chown_path(path: &Path, uid: u32, gid: u32) {
    let _ = std::process::Command::new("chown")
        .arg(format!("{uid}:{gid}"))
        .arg(path)
        .status();
}

/// Serve a single request string (tests / one-shot embedding).
pub fn serve_once(request: &str) -> String {
    let reply = handle(request);
    serde_json::to_string(&reply)
        .unwrap_or_else(|_| r#"{"ok":false,"error":"reply serialization failed"}"#.to_string())
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        // --selftest <request-json>: answer one request on stdout (allowlist
        // unit tests run this binary; no root/no socket needed).
        Some("--selftest") => {
            let req = args.next().unwrap_or_default();
            println!("{}", serve_once(&req));
        }
        _ => {
            if let Err(e) = run() {
                eprintln!("webconfig-applyd: {e}");
                std::process::exit(1);
            }
        }
    }
}
#[cfg(test)]
mod boot_select_tests {
    use super::*;

    #[test]
    fn boot_select_rewrites_autoboot_and_clears_state() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("B")).unwrap();
        std::fs::write(
            tmp.path().join("autoboot.txt"),
            "[all]\nboot_prefix=A/\nboot_prefix_try=B/\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("boot_state"), "slot=b\n").unwrap();
        let r = handle_boot_select(tmp.path(), "B", true);
        assert!(r.ok, "{:?}", r.error);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("autoboot.txt")).unwrap(),
            "[all]\nboot_prefix=B/\n"
        );
        assert!(!tmp.path().join("boot_state").exists());
    }

    #[test]
    fn boot_select_keeps_state_unless_asked() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("A")).unwrap();
        std::fs::write(tmp.path().join("boot_state"), "slot=b\n").unwrap();
        assert!(handle_boot_select(tmp.path(), "A", false).ok);
        assert!(tmp.path().join("boot_state").exists());
    }

    #[test]
    fn boot_select_rejects_bad_slots() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!handle_boot_select(tmp.path(), "C", false).ok);
        assert!(!handle_boot_select(tmp.path(), "../A", false).ok);
        // allowlisted but absent slot dir: refuse rather than brick
        assert!(!handle_boot_select(tmp.path(), "A", false).ok);
    }

    #[test]
    fn boot_select_request_parses() {
        let req: Request =
            serde_json::from_str(r#"{"verb":"boot_select","slot":"A","clear_state":true}"#)
                .unwrap();
        assert!(matches!(req, Request::BootSelect { ref slot, clear_state: true } if slot == "A"));
    }
}
