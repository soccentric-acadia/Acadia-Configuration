# Task 009 — Acadia-Configuration scope (leaf plan)
- **Status:** IMPLEMENTED — validated (see parent task validation.md)

Parent task: [`tasks/009-cross-repo-api-surface-audit/`](../../../../../tasks/009-cross-repo-api-surface-audit/plan.md)
in the Acadia parent repository.

## Role

webconfigd is the istate `ConfigurationApi` client (gRPC-over-UDS) and hosts
the hq-agent AgentLink client plus the device side of the HQ data plane.

## Changes implemented

- `crates/webconfigd/proto/`: replaced with **verbatim copies** of
  Instrumentation's `proto/{common,istate,telemetry,faults,logmanager}.proto`
  (findings C2/C4/C5 — 13 previously unreachable RPCs now compile; the
  wire-incompatible `HealthScoreReply` copy is gone).
- `crates/webconfigd/build.rs`: compiles the full import set.
- `crates/webconfigd/tests/proto_contract.rs`: SHA-256 drift guard + service
  surface check (17 + 1 RPCs).
- `crates/webconfigd/src/jobs.rs`: peer heartbeat now uses the monotonic
  clock domain (`/proc/uptime`); the configuration peer renders `connected`
  (finding C1).
- `crates/webconfigd/src/istate_client.rs`: full contract client —
  `StreamDeviceData` + `RelayCommand` methods, `PeerStatus.kind` modeling.
- `crates/hq-agent/src/lib.rs`:
  - `CommandOutcome` + `CommandAck.json_payload` populated (finding H1);
  - `AgentMailbox`/`mailbox_channel` — data-plane frame publisher;
  - `ServerFrameHooks` for `SignedUploadUrl` handling;
  - `run_agent` signature grew accordingly (hooks + receiver).
- `crates/webconfigd/src/hq_bridge.rs` (new): `DeviceOps` local execution of
  the `configuration` pseudo-daemon verbs (read/write with origin-hq envelope
  validation, backup creation + upload request, restore, update install with
  checksum verification, factory reset), `UploadCoordinator`/`UploadExecutor`
  (curl PUT against presigned URLs, bulk-socket bundle fetch), and
  `run_data_bridge` (istate → AgentLink mapping) — findings C3/H2/H3/H6/H7.
- `crates/webconfigd/src/hq_command_handler.rs`: local/spoke dispatch split,
  HQ factory-reset requires `required_confirmation=FACTORY-RESET` (H4), typed
  and envelope commands normalized, audit entries.
- `crates/webconfigd/src/api/system.rs`: `factory_reset_core` extracted and
  shared with the HQ path.
- `crates/webconfigd/src/main.rs`: wiring for mailbox, executor, bridge.

## Validation

- `cargo test --workspace`: 288 passed (5 hq-agent, 177 engine, 106 webconfigd).
- 0 unused warnings.
- Cross-repo evidence in the parent `validation.md`.