# Changelog

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
