# Operation catalog contracts (T-P25, N04)

* `configuration-operations.json` — **owned here.** Every device-local verb of
  the `configuration` pseudo-daemon that `hq_command_handler.rs` executes
  (name, HQ command kind, required confirmation). A webconfigd test fails if
  the handler does not accept a listed verb. Acadia-HQ vendors this file.
* `instrumentation-operation-catalog.json` — **vendored** from
  Acadia-Instrumentation `contracts/operation-catalog.json` (generated from
  the spokes' command tables). Refresh it by copying after a regeneration
  there; `GET /api/v1/operations` serves both lists.
