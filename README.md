# SoCcentric WebConfig

An **on-device, browser-based configuration web UI** for the Acadia Yocto/embedded-Linux
platform (Raspberry Pi 5). One small Rust daemon serves a vanilla-JS frontend over TLS;
board-specific data lives in a single board-manifest file (`board-manifests/acadia.json`).

> The full design specification lives in [`docs/webconfig-spec.md`](docs/webconfig-spec.md).

## What it is

A field engineer or operator points a browser at the device (`https://<device>:8443`) and
configures it: system identity, networking, services, updates, monitoring, logs, alerts,
security, and I/O — all behind authenticated, role-based access with a commit/confirm rollback
safety net for networking changes.

- **One daemon**, `current_thread` tokio runtime, rustls (no OpenSSL), no database (JSON + ring
files). Target: <15 MB RAM, 3-6 MB stripped binary.
- **Vanilla JS frontend**, no build step, no node at build time, <500 KB total.
- **Schema-driven rendering**: adding a setting is a schema file — zero UI code.
- **Flagship networking rollback**: network changes are provisional; reconnect and confirm
within a window or they auto-roll-back.
- **Real + mock system interactions**: RAUC/zbus talk to real backends on-device and to mocks on
the fake-sysroot test harness (no hardware to test).

## Repository layout

```
Cargo.toml                  # workspace, pinned deps, exact release profile
crates/
  webconfig-engine/         # config store, appliers, schema, manifest, alert/monitoring
  webconfigd/               # axum HTTP daemon (TLS, auth, CSRF, 9 section APIs, SSE)
frontend/                   # vanilla JS: index.html, styles.css, schema-form.js, pages.js, app.js
schemas/                    # *.schema.json — schema-driven rendering + validation
board-manifests/            # acadia.json (board-specific data) + generic.yaml fallback
meta-webconfig/             # Yocto layer: daemon, static assets, schemas, manifest, hardened unit
docs/                       # spec, API reference, schema format, board-manifest spec, planning/audits
Makefile                    # build | release | test | lint | fmt | vendor | cross | run | clean
```

## Build & test

The repo-root Makefile is the single entry point (per SoCcentric conventions):

```bash
make build    # debug build (host target)
make release  # exact spec release profile (opt-level=z, lto, panic=abort, stripped)
make test     # engine + HTTP integration tests (fake sysroot, no hardware)
make lint     # clippy -D warnings + rustfmt --check
make vendor   # regenerate the offline crate tarball for reproducible builds
make cross    # build all three cross-targets: x86_64, aarch64, armv7
make run-mock # run against a tempdir fake sysroot (mock backends) — DEFAULT dev loop
make run      # run against the REAL host (/proc, real backends) — hardware only
make check    # build && test && lint — the validation gate
```

Validation gate (used by the git workflows and CI): `make check` (= build && test && lint).
Default development loop is `make run-mock` (no hardware needed); `make run` touches the
live host and is only meaningful on a target device.

## Cross-targets

`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`.
Vendored crates + `CARGO_NET_OFFLINE=1` make builds fully offline and reproducible.

## Deploying (Yocto)

Add the layer and packages to your image:

```bitbake
IMAGE_INSTALL:append = " webconfigd webconfig-static webconfig-schemas webconfig-manifest"
```

Map your BSP `MACHINE` to its board manifest in
`meta-webconfig/recipes-core/webconfig/webconfig-manifest.bbappend`. See
[`meta-webconfig/README.md`](meta-webconfig/README.md).

## Documentation

- [Design specification](docs/webconfig-spec.md)
- [REST API reference](docs/api-reference.md)
- [Schema format](docs/schema-format.md)
- [Board-manifest format](docs/board-manifest.md)
- [Production-readiness audit](docs/planning/MasterPlan.md) and its [acceptance
checklist](docs/planning/Checkpoint.md)

## Feature Status

| # | Name / Description | Implemented? | Test Coverage? | Manual Test |
|---:|---|---|---|---|
| 1 | Rust workspace and release profile | Implemented | Build/lint commands documented; execution not verified here | [ ] Manual verification required |
| 2 | Configuration engine and persistent store | Implemented | Engine tests present; extent not fully mapped | [ ] Manual verification required |
| 3 | JSON schema and board-manifest loading | Implemented | Unknown | [ ] Manual verification required |
| 4 | System appliers for network, security, services, I/O, and time | Implemented | Fake-sysroot integration path documented | [ ] Manual verification required |
| 5 | Commit/confirm network rollback | Implemented | Unknown | [ ] Manual verification required |
| 6 | Auth, roles, CSRF, and TLS | Implemented | Daemon tests present; scope unknown | [ ] Manual verification required |
| 7 | HTTP section APIs and SSE | Implemented | HTTP integration tests present | [ ] Manual verification required |
| 8 | Alerts, monitoring, audit, backups, and updates | Partial: code exists; feature-level coverage varies | Partial | [ ] Manual verification required |
| 9 | Vanilla-JS schema-driven frontend | Implemented | Unknown | [ ] Manual verification required |
| 10 | Yocto layer and deployable packages | Implemented | Unknown | [ ] Manual verification required |
| 11 | Offline vendor and cross-target builds | Implemented | Documentation/command evidence only | [ ] Manual verification required |

## Project Description

Acadia-Configuration is the on-device WebConfig service for configuring an Acadia embedded-Linux
board from a browser. It is a Rust workspace composed of `webconfig-engine`, which owns
configuration state and policy, and `webconfigd`, which exposes the daemon and HTTP surface. The
engine includes manifest and JSON-schema handling, persistent storage, backups, audit records,
monitoring, alerts, user management, update coordination, and a fake-sysroot boundary used by
host tests. Its appliers translate requested settings into system interactions for networking,
Wi-Fi, WireGuard, firewall, hostname, time, serial, GPIO, CAN, SSH, journald, and access-point
behavior. Board-specific data is supplied by `board-manifests/`, with schemas under `schemas/`
and Yocto packaging under `meta-webconfig/`.

The daemon uses Tokio, Axum, rustls, authentication, CSRF protection, TLS setup, route modules,
background jobs, systemd integration, and server-sent events. The frontend is buildless vanilla
JavaScript with schema-driven forms and page scripts. Network changes have a commit/confirm
rollback model, but successful operation against real device services is environment-dependent.
The repository documents compact deployment and cross-targets for x86_64, aarch64, and armv7.

The root Makefile is the main workflow: `make build`, `make test`, `make lint`, `make release`,
`make vendor`, `make cross`, and `make run`. Rust tests are present in the engine and
`crates/webconfigd/src/tests.rs`; the documented test path uses a fake sysroot and does not
prove hardware behavior. This summary separates code presence from verified device behavior.

The service is intended to keep failure-prone changes recoverable: a configuration request is
validated, applied through an applier, persisted, and, for networking, confirmed or rolled back.
That lifecycle crosses HTTP, filesystem, systemd, and board-manifest boundaries, so deployment
permissions and service availability remain part of acceptance rather than assumptions.

## Test Evidence

- `crates/webconfigd/src/tests.rs` and engine tests under `crates/webconfig-engine/src/`.
- Recommended gate: `make build && make test && make lint`.

## License

CLOSED (SoCcentric internal IV&V tooling).