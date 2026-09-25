# Task 014 — Device provisioning verification (VB-3) — Acadia-Configuration scope (validation-only)

Parent task: [`Acadia/tasks/014-device-provisioning-verification/plan.md`](https://github.com/soccentric-acadia/Acadia/blob/develop/tasks/014-device-provisioning-verification/plan.md)

## Scope in this repository

Validation-only. No code change. `integration-ivv.md` VB-3 and
`improvements.md` OS-062 both described `/etc/acadia/client.conf`
provisioning as missing/open. Re-reading this repo's code directly found
that is stale: `crates/webconfigd/src/api/provisioning.rs`
(`put_ivv_client`) already validates input, renders and writes
`/var/lib/acadia/client.conf` through the privileged helper
(`webconfig_engine::priv_client::write_file_owner`), restarts
`acadia-client.service`, and is wired to a route
(`PUT /api/v1/provisioning/ivv-client`, `routes.rs`) and a frontend page
(`frontend/pages/provisioning.js`), with a unit test on the rendering logic.

## Role in cross-repository validation

Confirms the consumer side (`Acadia-Client`'s `acadia-client.service`,
gated by `ConditionPathExists=/var/lib/acadia/client.conf` since task 010)
and this provider side already form a complete, working loop. Nothing to
fix here; `improvements.md` OS-062 corrected from stale-open to
verified-done.
