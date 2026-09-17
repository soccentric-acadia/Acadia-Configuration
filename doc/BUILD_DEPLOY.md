# Acadia-Configuration Build and Deployment

## Scope

Acadia-Configuration is the Rust Cargo workspace for the on-device WebConfig daemon and
configuration engine. The root Makefile is the required entry point for host builds, tests,
linting, cross-target parity, release artifact generation, and daemon execution. All builds are
native: plain cargo on the host and GNU cross-compiles for the device targets. Deployment is
the meta-webconfig Yocto layer — the OS image builds webconfigd itself from the release
tarballs.

## 1. Prerequisites

- Linux with `make`, `curl`, and a working C compiler/linker.
- Rustup and the pinned Rust toolchain. `make toolchain` installs rustup if needed, Rust
`1.97.1`, `rustfmt`, `clippy`, and targets `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, and `armv7-unknown-linux-gnueabihf`.
- Network access is required for rustup, Cargo dependencies, and the KAS/Yocto integration
that consumes this component.
- Cross builds additionally need the GNU cross linkers (`gcc-aarch64-linux-gnu`,
`gcc-arm-linux-gnueabihf`), which `make toolchain`'s rustup targets plus
`.cargo/config.toml` expect to be on the PATH.

The workspace uses Rust edition 2021, a bundled SQLite build, rustls rather than OpenSSL, and a
release profile with size optimization, LTO, one codegen unit, abort-on-panic, and stripped
symbols.

## 2. Setup

```sh
make toolchain
make help
```

`make toolchain` is conditional and downloads from `sh.rustup.rs` and `static.rust-lang.org`; do
not run it in a restricted or offline environment without provisioning the toolchain first.

## 3. Build and compile

```sh
make build
make release
make cross
```

`build` runs `cargo build --workspace`; `release` runs the same with `--release` (the exact
spec profile: opt-level=z, LTO, panic=abort, stripped); `cross` release-builds the workspace
for `aarch64-unknown-linux-gnu` and `armv7-unknown-linux-gnueabihf`. The daemon package is
`crates/webconfigd`; the engine is `crates/webconfig-engine`.

## 4. Test and lint

```sh
make test
make lint
make fmt
make check
```

`test` runs `cargo test --workspace --all-targets` against fake sysroot behavior and does not
require hardware. `lint` runs Clippy with `-D warnings` and `cargo fmt --check`; `fmt` formats
in place. `check` is the aggregate build/test/lint gate.

## 5. Packaging and artifacts

```sh
make vendor
make release-artifacts
```

`make vendor` regenerates the versioned offline Cargo vendor tree and should be rerun after
dependency changes. `make release-artifacts` invokes `tools/release-artifacts.sh` to package the
source and vendor tarballs and print SHA-256 checksums. Release binaries are emitted by Cargo
under `target/release/<target>/` as applicable.

## 6. Deployment, install, and run

```sh
make run-mock
make run WEBCONFIG_PORT=8443
```

`run-mock` uses a temporary fake sysroot and has no hardware side effects. `run` uses the real
host `/proc` and `/sys`, real systemd/update backends, persistent `./data`, and port `8443` by
default; treat it as conditional and suitable only on the intended device or a disposable host.
For device deployment, install the cross-built binary plus the frontend, schemas, and board
manifest via the meta-webconfig Yocto packages (`webconfigd`, `webconfig-static`,
`webconfig-schemas`, `webconfig-manifest`) into the canonical layout
(`/usr/share/webconfig/...`).

## 7. Cleanup

```sh
make stop
make clean
```

`stop` terminates the process holding `WEBCONFIG_PORT`; `clean` runs `cargo clean` and removes
`target/`. The `./data` directory is deliberately
persistent for development and must be removed manually when resetting first-boot state.

## 8. Hardware, cloud, and manual verification caveats

There is no cloud deployment target here. Tests and `run-mock` cannot prove real `/proc`,
`/sys`, systemd, update, GPIO, storage, TLS, or Raspberry Pi behavior. Before shipping, install
the correct target binary, provision certificates and configuration according to the Yocto
image, confirm the port and first-boot admin flow, and exercise restart/update behavior on
target hardware. Keep release signing and deployment credentials outside the repository.
