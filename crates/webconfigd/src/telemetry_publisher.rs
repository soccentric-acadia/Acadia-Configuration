//! Telemetry publisher + durable-queue drain (T-P27: H05, G04, I07).
//!
//! `monitoring.telemetry` used to be stored and never acted on, and the
//! durable `TelemetryQueue` was filled by failed alert publishes but never
//! drained. This job closes both:
//!
//! * every `publish_interval_secs` (>= 5 s), when enabled with a
//!   `server_url`, a vitals sample is enqueued for that endpoint:
//!   `http(s)://…` → JSON `POST`; `mqtt(s)://host[:port]/topic` → MQTT publish;
//! * every tick the queue's due events are delivered and acked, or retried
//!   with the queue's capped backoff — including alert events queued by
//!   `alert_dispatch` when the broker was down.
//!
//! Credentials never go on argv (visible in `/proc/<pid>/cmdline`): curl gets
//! a 0600 `-K` config file, mosquitto_pub a 0600 options file found through
//! `XDG_CONFIG_HOME`. Network I/O only happens on the real root.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use webconfig_engine::applier::{run_local, run_local_env};
use webconfig_engine::store::monitoring::TelemetryConfig;
use webconfig_engine::store::services::MqttConfig;
use webconfig_engine::telemetry::{QueuedEvent, TelemetryQueue};
use webconfig_engine::Sysroot;

use crate::engine_bridge::EngineBridge;

/// Queue-topic prefixes naming the sink of an event.
pub const HTTP_SINK: &str = "telemetry-http";
pub const MQTT_SINK_PREFIX: &str = "telemetry-mqtt:";

/// Minimum publish interval (a zero/typo interval must not spin).
pub const MIN_INTERVAL_SECS: u64 = 5;

/// Where a telemetry `server_url` delivers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Http(String),
    Mqtt {
        host: String,
        port: u16,
        tls: bool,
        topic: String,
    },
}

/// Parse `monitoring.telemetry.server_url`.
pub fn parse_endpoint(url: &str) -> Option<Endpoint> {
    let url = url.trim();
    if url.starts_with("http://") || url.starts_with("https://") {
        return Some(Endpoint::Http(url.to_string()));
    }
    let (tls, rest) = match url.strip_prefix("mqtts://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("mqtt://")?),
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), if tls { 8883 } else { 1883 }),
    };
    if host.is_empty() {
        return None;
    }
    let topic = if path.is_empty() {
        "acadia/telemetry"
    } else {
        path
    };
    Some(Endpoint::Mqtt {
        host,
        port,
        tls,
        topic: topic.trim_end_matches('/').to_string(),
    })
}

/// Queue topic for a parsed endpoint.
pub fn queue_topic(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Http(_) => HTTP_SINK.to_string(),
        Endpoint::Mqtt { topic, .. } => format!("{MQTT_SINK_PREFIX}{topic}"),
    }
}

/// Write a 0600 file (credentials) — created with the final mode.
fn write_secret(path: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body.as_bytes())
}

/// curl `-K` config body carrying basic-auth credentials.
pub fn curl_auth_config(username: &str, password: &str) -> String {
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("user = \"{}:{}\"\n", esc(username), esc(password))
}

/// mosquitto_pub options-file body (one option per line).
pub fn mosquitto_options(username: &str, password: &str) -> String {
    format!("-u {username}\n-P {password}\n")
}

struct Staging {
    dir: PathBuf,
}

impl Staging {
    fn new(sysroot: &Sysroot) -> std::io::Result<Self> {
        let dir = sysroot.webconfig_dir().join("telemetry-out");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }
    fn payload(&self, event: &QueuedEvent) -> std::io::Result<PathBuf> {
        let path = self.dir.join(format!("event-{}.json", event.id));
        std::fs::write(&path, &event.payload)?;
        Ok(path)
    }
}

fn post_http(
    staging: &Staging,
    url: &str,
    cfg: &TelemetryConfig,
    file: &Path,
) -> Result<(), String> {
    let mut args: Vec<String> = vec![
        "--fail".into(),
        "-sS".into(),
        "-m".into(),
        "10".into(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        "Content-Type: application/json".into(),
        "--data-binary".into(),
        format!("@{}", file.display()),
    ];
    let auth = staging.dir.join("curl-auth.conf");
    if !cfg.username.is_empty() {
        write_secret(&auth, &curl_auth_config(&cfg.username, &cfg.password))
            .map_err(|e| e.to_string())?;
        args.push("-K".into());
        args.push(auth.display().to_string());
    }
    args.push(url.into());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = run_local("curl", &refs)
        .map(|_| ())
        .map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&auth);
    result
}

#[allow(clippy::too_many_arguments)]
fn publish_mqtt(
    staging: &Staging,
    host: &str,
    port: u16,
    tls: bool,
    topic: &str,
    username: &str,
    password: &str,
    file: &Path,
) -> Result<(), String> {
    let mut args: Vec<String> = vec![
        "-h".into(),
        host.into(),
        "-p".into(),
        port.to_string(),
        "-t".into(),
        topic.into(),
        "-f".into(),
        file.display().to_string(),
    ];
    if tls {
        args.push("--cafile".into());
        args.push("/etc/ssl/certs/ca-certificates.crt".into());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    if username.is_empty() {
        return run_local("mosquitto_pub", &refs)
            .map(|_| ())
            .map_err(|e| e.to_string());
    }
    // mosquitto_pub reads default options from $XDG_CONFIG_HOME/mosquitto_pub.
    let xdg = staging.dir.join("mqtt-options");
    std::fs::create_dir_all(&xdg).map_err(|e| e.to_string())?;
    let opts = xdg.join("mosquitto_pub");
    write_secret(&opts, &mosquitto_options(username, password)).map_err(|e| e.to_string())?;
    let xdg_s = xdg.display().to_string();
    let result = run_local_env(
        "mosquitto_pub",
        &refs,
        &[("XDG_CONFIG_HOME", xdg_s.as_str())],
    )
    .map(|_| ())
    .map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&opts);
    result
}

/// Publish one alert payload to the `services.mqtt` broker with credentials
/// kept off argv (used by alert_dispatch).
pub fn publish_alert_mqtt(
    sysroot: &Sysroot,
    cfg: &MqttConfig,
    topic: &str,
    payload: &str,
) -> Result<(), String> {
    let host = cfg.host.as_deref().unwrap_or("");
    if host.is_empty() {
        return Err("no MQTT broker host configured".into());
    }
    let staging = Staging::new(sysroot).map_err(|e| e.to_string())?;
    let file = staging.dir.join("alert.json");
    std::fs::write(&file, payload).map_err(|e| e.to_string())?;
    let result = publish_mqtt(
        &staging,
        host,
        cfg.port.unwrap_or(if cfg.tls { 8883 } else { 1883 }),
        cfg.tls,
        topic,
        cfg.username.as_deref().unwrap_or(""),
        cfg.password.as_deref().unwrap_or(""),
        &file,
    );
    let _ = std::fs::remove_file(&file);
    result
}

/// Deliver one queued event to its sink.
fn deliver(
    sysroot: &Sysroot,
    telemetry: &TelemetryConfig,
    mqtt: &MqttConfig,
    event: &QueuedEvent,
) -> Result<(), String> {
    let staging = Staging::new(sysroot).map_err(|e| e.to_string())?;
    let file = staging.payload(event).map_err(|e| e.to_string())?;
    let result = if event.topic == HTTP_SINK {
        match parse_endpoint(&telemetry.server_url) {
            Some(Endpoint::Http(url)) => post_http(&staging, &url, telemetry, &file),
            _ => Err("telemetry endpoint is no longer HTTP".into()),
        }
    } else if let Some(topic) = event.topic.strip_prefix(MQTT_SINK_PREFIX) {
        match parse_endpoint(&telemetry.server_url) {
            Some(Endpoint::Mqtt {
                host, port, tls, ..
            }) => publish_mqtt(
                &staging,
                &host,
                port,
                tls,
                topic,
                &telemetry.username,
                &telemetry.password,
                &file,
            ),
            _ => Err("telemetry endpoint is no longer MQTT".into()),
        }
    } else {
        // Alert events queued by alert_dispatch: `services.mqtt` broker.
        publish_alert_mqtt(sysroot, mqtt, &event.topic, &event.payload)
    };
    let _ = std::fs::remove_file(&file);
    result
}

/// One vitals sample as the published JSON document.
pub fn sample_payload(sysroot: &Sysroot, include_diagnostics: bool) -> String {
    let vitals = webconfig_engine::monitoring::read_vitals(sysroot);
    let hostname = std::fs::read_to_string(sysroot.join("/etc/hostname"))
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    let mut doc = serde_json::json!({
        "schema": "acadia.telemetry.v1",
        "ts_unix_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        "hostname": hostname,
        "vitals": vitals,
    });
    if include_diagnostics {
        doc["diagnostics"] = serde_json::json!({
            "webconfigd_version": env!("CARGO_PKG_VERSION"),
        });
    }
    doc.to_string()
}

/// The publisher loop (spawned by main).
pub async fn run(engine: EngineBridge, queue: Arc<Mutex<TelemetryQueue>>) {
    loop {
        let config = engine.load().ok();
        let interval = config
            .as_ref()
            .map(|c| c.monitoring.telemetry.publish_interval_secs)
            .unwrap_or(30)
            .max(MIN_INTERVAL_SECS);
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        let Some(config) = config else { continue };
        let sysroot = engine.sysroot.clone();
        let tel = config.monitoring.telemetry.clone();
        let mqtt = config.services.mqtt.clone();
        let queue = queue.clone();
        let _ = tokio::task::spawn_blocking(move || tick(&sysroot, &tel, &mqtt, &queue)).await;
    }
}

/// One publish + drain pass. Network delivery only on the real root; on a
/// fake sysroot samples are still enqueued (visible to tests).
pub fn tick(
    sysroot: &Sysroot,
    tel: &TelemetryConfig,
    mqtt: &MqttConfig,
    queue: &Mutex<TelemetryQueue>,
) {
    if tel.enabled {
        if let Some(endpoint) = parse_endpoint(&tel.server_url) {
            let payload = sample_payload(sysroot, tel.include_diagnostics);
            if let Ok(mut q) = queue.lock() {
                q.push(queue_topic(&endpoint), payload);
            }
        }
    }
    if !sysroot.is_real_root() {
        return;
    }
    let due = match queue.lock() {
        Ok(q) => q.due_now(),
        Err(_) => return,
    };
    for event in due {
        let outcome = deliver(sysroot, tel, mqtt, &event);
        if let Ok(mut q) = queue.lock() {
            match outcome {
                Ok(()) => q.ack(event.id),
                Err(e) => {
                    tracing::debug!(topic = %event.topic, error = %e, "telemetry delivery failed; retry scheduled");
                    q.fail(event.id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse() {
        assert_eq!(
            parse_endpoint("https://t.example/ingest"),
            Some(Endpoint::Http("https://t.example/ingest".into()))
        );
        assert_eq!(
            parse_endpoint("mqtts://broker.example/acadia/dev1"),
            Some(Endpoint::Mqtt {
                host: "broker.example".into(),
                port: 8883,
                tls: true,
                topic: "acadia/dev1".into()
            })
        );
        assert_eq!(
            parse_endpoint("mqtt://10.0.0.5:1884"),
            Some(Endpoint::Mqtt {
                host: "10.0.0.5".into(),
                port: 1884,
                tls: false,
                topic: "acadia/telemetry".into()
            })
        );
        assert_eq!(parse_endpoint("ftp://x"), None);
        assert_eq!(parse_endpoint("mqtt://:1883/x"), None);
        assert_eq!(parse_endpoint(""), None);
    }

    #[test]
    fn credentials_files_escape_and_stay_off_argv() {
        assert_eq!(curl_auth_config("u", "p\"q"), "user = \"u:p\\\"q\"\n");
        assert_eq!(mosquitto_options("u", "p w"), "-u u\n-P p w\n");
    }

    #[test]
    fn tick_enqueues_a_sample_for_the_configured_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let sysroot = Sysroot::at(tmp.path());
        let queue = Mutex::new(TelemetryQueue::load(tmp.path()));
        let tel = TelemetryConfig {
            enabled: true,
            server_url: "mqtt://broker/acadia/x".into(),
            publish_interval_secs: 30,
            ..Default::default()
        };
        tick(&sysroot, &tel, &MqttConfig::default(), &queue);
        let q = queue.lock().unwrap();
        let due = q.due_now();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].topic, "telemetry-mqtt:acadia/x");
        let doc: serde_json::Value = serde_json::from_str(&due[0].payload).unwrap();
        assert_eq!(doc["schema"], "acadia.telemetry.v1");
        assert!(doc["vitals"].is_object());
    }

    /// Real curl against a local listener: the JSON body and the basic-auth
    /// header (from the 0600 -K file) arrive; the auth file is removed.
    #[test]
    fn http_delivery_with_curl_config_credentials() {
        use std::io::{Read, Write};
        if std::process::Command::new("curl")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("curl not installed; skipping");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = sock.read(&mut buf) {
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&req);
                if let Some(idx) = text.find("\r\n\r\n") {
                    let len = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if req.len() >= idx + 4 + len {
                        break;
                    }
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .unwrap();
            String::from_utf8_lossy(&req).to_string()
        });
        let tmp = tempfile::tempdir().unwrap();
        let sysroot = Sysroot::at(tmp.path());
        let staging = Staging::new(&sysroot).unwrap();
        let event = QueuedEvent {
            id: 7,
            topic: HTTP_SINK.into(),
            payload: r#"{"schema":"acadia.telemetry.v1"}"#.into(),
            enqueued_unix: 0,
            attempts: 0,
            next_after_unix: 0,
        };
        let file = staging.payload(&event).unwrap();
        let cfg = TelemetryConfig {
            enabled: true,
            server_url: format!("http://127.0.0.1:{port}/ingest"),
            username: "dev".into(),
            password: "s3cret".into(),
            ..Default::default()
        };
        post_http(&staging, &cfg.server_url, &cfg, &file).expect("POST delivered");
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /ingest"), "{request}");
        // base64("dev:s3cret")
        assert!(
            request.contains("Authorization: Basic ZGV2OnMzY3JldA=="),
            "{request}"
        );
        assert!(request.contains(r#"{"schema":"acadia.telemetry.v1"}"#));
        assert!(
            !staging.dir.join("curl-auth.conf").exists(),
            "auth file removed"
        );
    }

    #[test]
    fn disabled_telemetry_enqueues_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let sysroot = Sysroot::at(tmp.path());
        let queue = Mutex::new(TelemetryQueue::load(tmp.path()));
        tick(
            &sysroot,
            &TelemetryConfig::default(),
            &MqttConfig::default(),
            &queue,
        );
        assert!(queue.lock().unwrap().is_empty());
    }
}
