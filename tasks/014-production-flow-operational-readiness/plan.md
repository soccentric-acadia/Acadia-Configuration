# Task 014 — Acadia-Configuration scope

Parent plan: [Acadia Task 014](../../../../tasks/014-production-flow-operational-readiness/plan.md).

## Scope

Configuration owns webconfigd/hq-agent, secure configuration application, local operation execution, and the bridge between Instrumentation and HQ. Execute P0-01, P0-02, P0-04 through P1-12, P2-13, P0-16, P1-18, P1-20 through P2-22, P2-25, and P0-26 where they affect Configuration.

## Interfaces and expected work

- Verified Ed25519 configuration envelopes and key lifecycle.
- Durable command ID, acknowledgment/result, retry, timeout, cancellation, and authorization behavior.
- AgentLink data uploads with correlation/completion semantics; local logs/update/reset behavior and accurate unsupported-feature errors.

## Local and cross-repository validation

Run Cargo workspace tests and contract digest checks; add invalid-signature, duplicate-command, reconnect, concurrent-upload, and target-apply tests. Participate in HQ gateway/istate real-binary compose and HIL lifecycle validation.
