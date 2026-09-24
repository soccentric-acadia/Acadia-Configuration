# Changelog

## 2026-09-24 — Integration-production pass (T-P20…T-P35, backlog)

- T-P20: HQ-driven power, update confirm/rollback, service control, log bundles and users.* on the device; power actions run 5 s after the ack. Typed HQ commands execute locally rather than being relayed to istate (`465e5e2`).
- T-P22/T-P24/T-P25: upload correlation (`client_ref`, UploadComplete), the DeviceStatus heartbeat snapshot, and the configuration operations contract plus a vendored Instrumentation catalog.
- T-P26…T-P29:
  - applyd `boot_select` verb and SWUpdate client install;
  - telemetry publisher, with curl/mosquitto run locally;
  - streaming SHA-256 and OTA staging under `/var/lib/webconfig-ota`;
  - board-LED policy and camera applier;
  - remote syslog through rsyslog omfwd.
- T-P00e: deferred features (ptp, ap_mode, wireguard, cellular) are hidden in the UI and refused by the server.
- T-P33: a single factory-reset contract with levels settings, settings+users and full (RMA). The full wipe runs at next boot (`acadia-factory-wipe`). The claim code is kept, so a reset device can only be re-claimed with its label code.
- P-A10/OS-071: first-use provisioning (`/api/v1/provisioning`) covers the HQ CA, the config-signing key and the IV&V client config, and adds a Provisioning page.
- CFG-003/008/018/019/020:
  - the root-password control and helper `chpasswd` are removed;
  - a shared password policy (≥10 characters, common/username/sequence checks) is enforced everywhere, including `POST /system/users`;
  - the login throttle persists across restarts;
  - `whoami` returns CSRF only when authenticated;
  - the service allowlist now lists the product services.
- SSH toggling now drives `sshd.socket` on the socket-activated image. Previously, disabling SSH left it listening.
- CFG-034: the OS image-wiring gate runs in CI, and the binary-size CI step was fixed.
- Validation: `make check` green at every commit; cross-repo E2E 15/15; `make build BOARD=rpi5` with webconfigd `1063cac`.

## 2026-09-21 — Cross-repo API surface audit: webconfigd contract consumption (task 009)

### Added

- Verbatim proto contract copies for telemetry, faults, and logmanager
  synced from Acadia-Instrumentation; new `hq_bridge` for HQ command
  forwarding; extended istate_client, jobs, and system/updates APIs
  against the new surface.
- New `proto_contract` integration test pinning the webconfigd protos
  against the Instrumentation contract sources.

## 2026-09-21 — istate peer heartbeat (Instrumentation §3.1)

### Added

- webconfigd heartbeats istate every 5 s over the `ConfigurationApi.Heartbeat`
  RPC (`jobs::run_istate_heartbeat`, spawned from main): istate reports the
  configuration peer as connected from this cadence. Previously the RPC had no
  caller, so the configuration peer always rendered unresponsive.
- `IstateClient::heartbeat` trait method with a live gRPC implementation and an
  `Unavailable` default; failures log and retry on the next tick — a quiet hub
  never stops the web UI (R10 degrade, don't block).

## 2026-09-21 — Root-agent feature workflow guard (task 006)

- Added a canonical instruction requiring leaf-started agents to refuse feature
  changes and direct the user to the Acadia parent root.

## 2026-09-18 — Agent documentation and task workflow standardization

- Added an `AGENTS.md` pointer and concise canonical agent document with Rust
  build, validation, and test instructions.
- Added ignored local `Plan.md` and `Task.md` workflow artifacts.
- Verified the required document shape and the declared `make build`,
  `make check`, and `make test` targets.

Maintained by the Loop Engine. One entry per loop that touched this repo,
newest first, appended on loop close (pass or fail) and committed on the loop's
own feature branch. See the master repo's `Acadia-Loop-Orchestration-Spec-v2.md` §11.1.

Entries written by hand are fine; the engine inserts directly under this header.
