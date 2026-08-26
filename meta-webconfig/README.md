# meta-webconfig

Yocto layer that adds the SoCcentric **WebConfig** on-device configuration UI to
an Acadia image: the `webconfigd` Rust daemon, its vanilla-JS frontend, schema
files, and the Acadia board manifest.

Per the SoCcentric global rules, **all OS customization lives in this meta
layer — upstream Yocto/BSP layers are never patched.**

## Recipes

| Recipe | Installs | Purpose |
|---|---|---|
| `webconfigd` | `/usr/bin/webconfigd`, systemd unit, polkit rule | The daemon (spec §2). Non-root, hardened. |
| `webconfig-static` | `/usr/share/webconfig/static/` | Frontend assets (<500 KB, no build step). |
| `webconfig-schemas` | `/usr/share/webconfig/schemas/*.schema.json` | Schema-driven rendering + validation (spec §3). |
| `webconfig-manifest` | `/usr/share/webconfig/board-manifest.json` | Acadia board manifest (spec §3 platform layer). |

## Yocto / Scarthgap toolchain requirement

The `webconfigd` Rust daemon needs a **rustc >= 1.86** (its Cargo.lock is v4
format and the locked tree uses edition-2024 crates such as `icu_*`/`idna_adapter`).
Yocto **Scarthgap (5.0)** ships **Rust 1.75.0** by default, which cannot build it.

To build on Scarthgap, add the official `meta-lts-mixins` **`scarthgap/rust`**
mixin layer — it backports a current Rust toolchain (currently **1.87.0**) from
oe-core master and overrides oe-core's `cargo.bbclass`/`rust` recipes. Its layer
collection name is `scarthgap-rust-mixin`; `conf/layer.conf` already declares the
`LAYERDEPENDS` on it.

```
# bblayers.conf
BBLAYERS += "${TOPDIR}/../meta-lts-mixins/rust"
```

```git
# meta-lts-mixins, branch scarthgap/rust
https://github.com/nedap/meta-lts-mixins (branch scarthgap/rust)
```

Newer Yocto releases (styhead/walnutar) that already ship rustc >= 1.86 need no
extra layer; if their oe-core rust is still older than 1.86, add their
corresponding rust mixin the same way.

## Adding to an image

```bitbake
IMAGE_INSTALL:append = " webconfigd webconfig-static webconfig-schemas webconfig-manifest"
```

## Machine manifest

Board-specific behavior lives **only** in the board manifest.
`webconfig-manifest.bb` defaults `WEBCONFIG_BOARD_FILE` to the real
`acadia.json` (this repo is Acadia-only), referenced directly from the
repo-root `board-manifests/` directory inside the same source tarball
`webconfigd.bb`/`webconfig-static.bb` fetch — never copied into this layer, so
there's exactly one source of truth. Override per `MACHINE` only if a future
board revision needs a distinct manifest file, in
`recipes-core/webconfig/webconfig-manifest.bbappend`:

```bitbake
WEBCONFIG_BOARD_FILE:raspberrypi5 = "acadia.json"
```

## Adding a customer setting (zero UI code — spec §3)

1. Drop a `my-app.schema.json` into a bbappend:
   ```bitbake
   # webconfig-schemas.bbappend
   WEBCONFIG_SCHEMAS_EXTRA:append = " file://my-app.schema.json"
   ```
2. The frontend renders it generically; the backend validates it. No UI code,
   no daemon rebuild for new *schema-driven* settings.

## Hardening (spec §4.8)

- Runs as a non-root system user (`webconfig`).
- systemd unit: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateDevices`,
  `ProtectKernel*`, `MemoryDenyWriteExecute`, `CapabilityBoundingSet=` (none —
  privileged ops go through D-Bus + polkit), `MemoryMax=32M`.
- polkit rule grants only the curated service allowlist + reboot/poweroff.
- TLS by default (self-signed on first boot); plain HTTP is an opt-in.

## Supply chain (global §1)

- Vendored crate tarball, offline build (`CARGO_NET_OFFLINE=1`).
- Reproducible release profile in `Cargo.toml` (opt-level=z, lto, panic=abort).
- SPDX/SBOM via `create-spdx`; tarball checksums recorded in `webconfigd.bb`.

## Notes / assumptions (spec §7)

- `cargo.bbclass` from oe-core (scarthgap+) is used; `meta-rust` is not required.
- The vendored tarball and source tarball SHA-256s are **real immutable release
  checksums** recorded in `webconfigd.bb` (`SRC_URI[src.sha256sum]` and
  `SRC_URI[vendor.sha256sum]`), produced by `make release-artifacts`
  (`tools/release-artifacts.sh`). Regenerate both at every release cut — the
  checksum is only valid for the exact tarball contents it was computed from.
  No `TODO_REPLACE_WITH_RELEASED_TARBALL_SHA256` placeholders remain; the gate
  (`make lint-checksums`) fails if any reappears.
- The frontend/manifest/schema files in `files/` are copied from the repo root
  at release time; the repo-root copies are the source of truth for the engine
  and tests.