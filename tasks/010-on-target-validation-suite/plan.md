# Task 010 — On-target validation suite (leaf record: Acadia-Configuration)

Parent task: `tasks/010-on-target-validation-suite/plan.md` (Acadia root).

| Field | Value |
|---|---|
| Class | validation-only (no source changes in this repo) |
| Track | Production |
| Date | 2026-09-26 |

## Scope in this repository

The Acadia root gains `validation/` — a Python suite executed from an x86 host.
This repository's on-device component, `webconfigd`, is covered as an
**optional** unit check in the suite (config key `optional_units`):

- `webconfigd.service` present, enabled and active on RPi-class images;
- the SB-4/T-P04 drop-in contract preserved: `webconfigd` holds
  `SupplementaryGroups=instr` so it can connect to the istate-created
  `configuration.sock` (0660, instr-configuration:instr);
- istate liveness implies the Configuration peer can register — the suite
  warns (does not fail) when webconfigd is absent, since Instrumentation ships
  and runs unchanged on machines without it (cm5).

## Affected interfaces

None changed.

## Local tests / role in cross-repository validation

None added (validation-only). The suite's liveness phase provides the
Instrumentation⇄Configuration socket-contract evidence on the device.