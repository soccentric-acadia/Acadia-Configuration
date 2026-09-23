//! The privileged-apply channel (T-P02, T-P00b option (a)).
//!
//! On a flashed device webconfigd runs as the non-root `webconfig` user inside
//! a hardened sandbox; the appliers' file writes and live system verbs fail
//! there with EROFS/EPERM. `webconfig-applyd` (root, fixed-verb UDS daemon) is
//! the sanctioned privileged writer:
//!
//! * `active()` — the helper is used whenever the process is not root AND its
//!   socket exists; everything else keeps the direct `std::fs` /
//!   `std::process` path so CI's fake sysroots and root dev runs behave
//!   exactly as before this module.
//! * File ops ([`write_file`], [`create_dir_all`], [`remove_file`],
//!   [`set_mode`]) mirror the std equivalents (same `io::Result` shape) and
//!   route to the helper transparently.
//! * [`exec`] runs one allowlisted program through the helper and returns
//!   stdout/stderr/exit-code in the shape `run_cmd` already maps onto
//!   [`ApplyError::Command`].
//!
//! The helper's request/allowlist types live in `webconfig-applyd` (the
//! daemon); this module only depends on the JSON shapes, so the engine keeps
//! compiling for every cross target without pulling in the daemon binary.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Default helper socket, matching webconfig-applyd's DEFAULT_SOCK.
pub const DEFAULT_SOCK: &str = "/run/webconfig/apply.sock";
/// Env override for the socket path (tests / CI).
pub const ENV_SOCK: &str = "WEBCONFIG_APPLY_SOCK";
/// Per-request deadline (applies are short; a hung helper must not wedge the
/// engine bridge forever).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// The helper socket path for this process.
pub fn socket_path() -> std::path::PathBuf {
    std::env::var(ENV_SOCK)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(DEFAULT_SOCK))
}

/// Effective uid of this process (Linux `/proc/self/status`, std-only).
fn euid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

/// Whether the privileged helper should be used for file ops and live verbs:
/// only when running as a non-root process against the real root and the
/// helper socket exists.
pub fn active() -> bool {
    // Root does not need the helper; non-root processes outside the real root
    // (fake sysroots) keep local behaviour.
    if euid() == Some(0) {
        return false;
    }
    socket_path().exists()
}

/// One request/response exchange with the helper.
fn request(payload: String) -> Result<serde_json::Value, std::io::Error> {
    request_at(&socket_path(), payload)
}

/// One exchange against an explicit socket (tests use this to talk to a stub
/// server without touching process-global env).
fn request_at(
    socket: &std::path::Path,
    payload: String,
) -> Result<serde_json::Value, std::io::Error> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
    stream.set_write_timeout(Some(REQUEST_TIMEOUT))?;
    writeln!(stream, "{payload}")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let reply: serde_json::Value = serde_json::from_str(line.trim())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(reply)
}

fn io_err(context: &str, message: &str) -> std::io::Error {
    std::io::Error::other(format!("{context}: {message}"))
}

/// Run one program through the helper. Returns (stdout, stderr, exit code);
/// the caller maps a non-zero code onto its own error type.
pub fn exec(program: &str, args: &[&str]) -> Result<(String, String, i32), std::io::Error> {
    exec_at(&socket_path(), program, args)
}

fn exec_at(
    socket: &std::path::Path,
    program: &str,
    args: &[&str],
) -> Result<(String, String, i32), std::io::Error> {
    let payload = serde_json::json!({
        "verb": "exec",
        "program": program,
        "args": args,
    })
    .to_string();
    let reply = request_at(socket, payload)?;
    if reply.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = reply
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("rejected");
        return Err(io_err(&format!("helper rejected {program}"), message));
    }
    Ok((
        reply
            .get("stdout")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        reply
            .get("stderr")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        reply
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(-1) as i32,
    ))
}

/// Write one allowlisted file with mode + owner (`"user:group"`). Local
/// fallback: chmod only (ownership applies on-device via the helper; the
/// fake-sysroot tests don't assert ownership).
pub fn write_file_owner(
    path: &Path,
    bytes: impl AsRef<[u8]>,
    mode: u32,
    owner: &str,
) -> std::io::Result<()> {
    if !active() {
        write_file_mode(path, bytes, mode)?;
        Ok(())
    } else {
        write_file_owner_at(&socket_path(), path, bytes, mode, owner)
    }
}

/// mkdir -p with mode + owner (`"user:group"`).
pub fn create_dir_all_mode(path: &Path, mode: u32, owner: &str) -> std::io::Result<()> {
    if !active() {
        std::fs::create_dir_all(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
        Ok(())
    } else {
        create_dir_all_mode_at(&socket_path(), path, mode, owner)
    }
}

/// Write one allowlisted file through the helper (default mode 0644).
/// Accepts anything `std::fs::write` accepts (`impl AsRef<[u8]>`) so the
/// appliers' call sites only change their function prefix.
pub fn write_file(path: &Path, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    write_file_mode(path, bytes, 0o644)
}

/// Write one allowlisted file with an explicit mode (e.g. 0600 secrets).
pub fn write_file_mode(path: &Path, bytes: impl AsRef<[u8]>, mode: u32) -> std::io::Result<()> {
    if !active() {
        let r = std::fs::write(path, bytes.as_ref());
        #[cfg(unix)]
        if r.is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }
        return r;
    }
    write_file_mode_at(&socket_path(), path, bytes, mode)
}

fn write_file_mode_at(
    socket: &std::path::Path,
    path: &Path,
    bytes: impl AsRef<[u8]>,
    mode: u32,
) -> std::io::Result<()> {
    write_file_owner_at(socket, path, bytes, mode, "")
}

fn write_file_owner_at(
    socket: &std::path::Path,
    path: &Path,
    bytes: impl AsRef<[u8]>,
    mode: u32,
    owner: &str,
) -> std::io::Result<()> {
    use base64::Engine;
    let payload = serde_json::json!({
        "verb": "write_file",
        "path": path.to_string_lossy(),
        "mode": mode,
        "content": base64::engine::general_purpose::STANDARD.encode(bytes.as_ref()),
        "owner": owner,
    })
    .to_string();
    check(request_at(socket, payload)?, "write_file")
}

fn create_dir_all_mode_at(
    socket: &std::path::Path,
    path: &Path,
    mode: u32,
    owner: &str,
) -> std::io::Result<()> {
    let payload = serde_json::json!({
        "verb": "mkdir",
        "path": path.to_string_lossy(),
        "mode": mode,
        "owner": owner,
    })
    .to_string();
    check(request_at(socket, payload)?, "mkdir")
}

/// mkdir -p inside an allowlisted tree (helper); `std::fs::create_dir_all`
/// when the helper is not active.
pub fn create_dir_all(path: &Path) -> std::io::Result<()> {
    if !active() {
        return std::fs::create_dir_all(path);
    }
    let payload = serde_json::json!({
        "verb": "mkdir",
        "path": path.to_string_lossy(),
        "mode": 0o755,
    })
    .to_string();
    check(request(payload)?, "mkdir")
}

/// Remove one allowlisted file through the helper.
pub fn remove_file(path: &Path) -> std::io::Result<()> {
    if !active() {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
    }
    let payload = serde_json::json!({
        "verb": "remove_file",
        "path": path.to_string_lossy(),
    })
    .to_string();
    check(request(payload)?, "remove_file")
}

/// chmod one allowlisted path through the helper.
pub fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    if !active() {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    let payload = serde_json::json!({
        "verb": "set_mode",
        "path": path.to_string_lossy(),
        "mode": mode,
    })
    .to_string();
    check(request(payload)?, "set_mode")
}

/// `chpasswd` for `user` (stdin-only, never argv) through the helper.
pub fn set_password(user: &str, password: &str) -> Result<(), std::io::Error> {
    let payload = serde_json::json!({
        "verb": "set_password",
        "user": user,
        "password": password,
    })
    .to_string();
    let reply = request(payload)?;
    if reply.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let stderr = reply
            .get("stderr")
            .and_then(serde_json::Value::as_str)
            .or_else(|| reply.get("error").and_then(serde_json::Value::as_str))
            .unwrap_or("rejected");
        return Err(io_err("set_password", stderr));
    }
    Ok(())
}

/// Point `/boot/autoboot.txt` at tryboot `slot` ("A"/"B") through the helper
/// and optionally drop `/boot/boot_state` (T-P26, CFG-039).
pub fn boot_select(slot: &str, clear_state: bool) -> std::io::Result<()> {
    let payload = serde_json::json!({
        "verb": "boot_select",
        "slot": slot,
        "clear_state": clear_state,
    })
    .to_string();
    check(request(payload)?, "boot_select")
}

fn check(reply: serde_json::Value, context: &str) -> std::io::Result<()> {
    if reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
        Ok(())
    } else {
        let message = reply
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("rejected");
        Err(io_err(context, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without a helper socket (CI, non-root), the client stays inactive and
    /// file ops keep the local std behaviour.
    #[test]
    fn inactive_when_socket_missing() {
        std::env::remove_var(ENV_SOCK);
        assert!(!active());
    }

    /// End-to-end protocol test against a stub helper: a real UDS server
    /// answering the JSON protocol, exercising write_file + exec + error
    /// mapping through the client path. The socket path is passed explicitly
    /// (request_at) so no process-global env is touched — other tests in this
    /// binary run concurrently and must never see the helper as active.
    #[test]
    fn client_roundtrip_against_stub_helper() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("apply.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let server = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(match stream.try_clone() {
                    Ok(s) => s,
                    Err(_) => return,
                });
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    let req: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                    let verb = req["verb"].as_str().unwrap().to_string();
                    let reply = match verb.as_str() {
                        "write_file" => serde_json::json!({"ok": true}),
                        // The stub mirrors the real helper's gate: only the
                        // programs the allowlist admits get a success reply.
                        "exec" if req["program"] == "systemctl" => serde_json::json!({
                            "ok": true, "stdout": "done\n", "stderr": "", "code": 0
                        }),
                        _ => serde_json::json!({"ok": false, "error": "rejected"}),
                    };
                    writeln!(stream, "{reply}").unwrap();
                    line.clear();
                }
            }
        });
        write_file_mode_at(&sock, &tmp.path().join("out.txt"), b"hello", 0o600).unwrap();
        let (out, _err, code) = exec_at(&sock, "systemctl", &["daemon-reload"]).unwrap();
        assert_eq!(out, "done\n");
        assert_eq!(code, 0);
        // Non-allowlisted programs are rejected by the stub's allowlist path.
        let err = exec_at(&sock, "sh", &[]).err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        drop(server);
    }
}
