# Task 014 — Acadia-Configuration Phase 0 validation

- `cargo test -p webconfigd --test proto_contract` — passed, 3/3.
- `cargo test -p webconfig-engine manifest::tests --lib` — passed, 4/4.

The tests verify the vendored production contract lock/catalog and reject
wrong board revisions, unapproved peripherals, and reserved console use.

## Phase 1 P0-05 through P0-07

- `cargo test -p webconfig-engine pairing::tests --lib` — passed, 7/7.
- `cargo test -p hq-agent` — passed, 6/6.
- `cargo test -p webconfigd hq_command_handler::tests` — passed, 18/18.

These tests cover private atomic pairing persistence, credential expiration
with bounded clock skew, reset removal of enrollment material, and continued
mandatory Ed25519 write validation. Hardware/compose re-enrollment remains
required release evidence.

## Phase 1 P1-08 and P1-09

- `cargo test -p hq-agent --lib` — passed: 8/8, including persistent duplicate
  replay after restart and mismatched ID rejection.
- `cargo test -p webconfigd hq_command_handler::tests` — passed: 19/19.
- `cargo test -p webconfigd istate_client::tests` — passed: 4/4.

## Phase 1 audit findings 1 and 2 — 2026-09-28

- `cargo test -p webconfigd hq_command_handler::tests` — passed, **19/19**.
  The generated-key Ed25519 test verifies the canonical HQ-compatible field
  set and rejects config/key-ID tampering.
- `cargo test -p hq-agent --lib` — passed, **10/10**, including issued-expiry
  persistence, authenticated credential renewal, expired behavior, and
  revocation behavior.
- The vendored AgentLink proto matches HQ byte-for-byte (`cmp -s` passed).
- Workspace `cargo fmt --check` reports only pre-existing formatting drift in
  `crates/webconfigd/tests/proto_contract.rs`; the modified hq-agent source
  was formatted with `rustfmt --edition 2021`.
