# Task 008 (leaf: Acadia-Configuration) — Validation-only reference for HQ device UI parity

Parent: [`tasks/008-hq-device-ui-webconfig-parity/plan.md`](../../../tasks/008-hq-device-ui-webconfig-parity/plan.md)
- **Status:** PROPOSED — awaiting plan approval
- **Role in task:** validation-only (no code changes)

## Scope

Acadia-Configuration (WebConfig) is the reference implementation for the HQ device-level UI:

- `frontend/styles/tokens.css` — design tokens to be ported into HQ web.
- `frontend/styles/layout.css` + `components/sidebar.js` + `components/topbar.js` — app-shell
  layout to replicate.
- `frontend/pages/registry.js` — the section registry (categories, labels, icons, order,
  adminOnly flags, shortcut keys) that HQ's registry must mirror 1:1.
- `frontend/components/schema-form.js` — descriptor shape (string | int | bool | enum |
  secret, validation, help) reused by the HQ schema-driven forms.

## Affected interfaces

None. No device code, schema, or API changes. The existing `hq_command_handler.rs` already
accepts the operations HQ sends (`backup`, `restore`, `factory_reset`, `apply_update`,
`configuration.read`, `configuration.write`).

## Local tests

None required. Validation artifacts: registry diff (HQ registry vs `registry.js`) and token
diff (HQ theme vs `tokens.css`) recorded in the parent task's `validation.md`.

## Exclusions

Device-side `configuration.read/write` contract integration (istate signing/verification
end-to-end) remains a separate future task; this task only requires that WebConfig's
published contract status (`awaiting_configuration_contract`) is honored by the HQ UI.