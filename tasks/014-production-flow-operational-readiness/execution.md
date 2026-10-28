# Task 014 — Acadia-Configuration execution record

- **Approval date:** 2026-09-28
- **Approved scope:** Parent Task 014 Phase 0 participation in P0-01, P0-02, and P0-04.

## Checklist

- [ ] P0-01 Consume and verify the frozen contract baseline.
- [ ] P0-02 Consume the generated operation catalog.
- [x] P0-04 Consume the supported production capability matrix.
- [x] P0-05 Establish one device identity lifecycle.
- [x] P0-06 Implement provisioned Ed25519 configuration signing.
- [x] P0-07 Complete device credential lifecycle.

## Implementation record

### P0-04 — 2026-09-28

- Added Hardware matrix version and board-revision fields to the Acadia board
  manifest and enforced them in every JSON/YAML manifest load and compiled-in
  fallback path.
- Restricted the production manifest to Hardware-approved RS-485, Pico UART,
  and classic-CAN entries. Removed ungrounded I2C/SPI/GPIO/MCU/camera/network
  declarations so Configuration cannot offer actions outside matrix v1.
- Added negative coverage for an unsupported board revision and the reserved
  `ttyAMA10` console. No P0-01 contract baseline or P0-02 operation catalog
  file was changed.

Validation executed:

| Command | Result |
| --- | --- |
| `cargo test -p webconfig-engine manifest::tests --lib` | Passed: 4/4. |
| `cargo check -p webconfigd` | Passed. |

### P0-05 through P0-07 — 2026-09-28

- Persisted pairing credentials atomically as owner-private state and wipe
  them on every factory reset while retaining OS/factory identity.
- Bound provisioned Ed25519 configuration trust to a signed active key ID;
  replacing the provisioned key changes the acceptable key ID and revokes the
  prior signer.
- Added expiry/skew-aware local credential behavior; offline reconnects keep
  bounded retry behavior, while expired credentials require renewal or
  re-provisioning.

### P1-08 and P1-09 — 2026-09-28

- Replaced process-local command-result deduplication in webconfigd with an
  atomically persisted terminal-result journal at
  `/pst/acadia/webconfig/command-results.tsv`. Reconnects/restarts replay the
  stored result payload without repeating the device operation.
- Bound AgentLink command and idempotency IDs, derive a stable non-zero
  Instrumentation uint64 request ID, and reject invalid IDs before relay.
- Added explicit local confirmations for restore, apply-update, and
  service-control and consume the shared authorization/state matrix.

### Phase 1 audit findings 1 and 2 — 2026-09-28

- Made `signing_key_id`, when present, part of the exact canonical Ed25519
  signed set shared with HQ; a substituted key ID invalidates the signature.
- Store the authoritative credential expiry and an authenticated AgentLink
  renewal atomically in the private pairing record. Expired/revoked
  credentials never retry; offline operation allows only the documented
  five-minute clock-skew allowance and does not renew.
- Vendored the matching AgentLink proto; Rust code is generated during the
  `hq-agent` build. Added the target-storage/policy pointer to deployment
  documentation. No commit/push.
