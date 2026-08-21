# Acadia-Configuration Build and Deployment

## Scope

Acadia-Configuration is the Rust Cargo workspace for the on-device WebConfig daemon and
configuration engine. The root Makefile is the required entry point for host builds, tests,
linting, cross-target parity, release artifact generation, and Docker execution.

## 1. Prerequisites

- Linux with `make`, `curl`, and a working C compiler/linker.
- Rustup and the pinned Rust toolchain. `make toolchain` installs rustup if needed, Rust
`1.97.1`, `rustfmt`, `clippy`, and targets `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, and `armv7-unknown-linux-gnueabihf`.
- Docker for image targets; network access is required for rustup, Cargo dependencies, and the
KAS/Yocto integration that consumes this component.

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

`build` runs `cargo build --workspace`; `release` runs the same with `--release`; `cross` builds
release binaries for all three pinned targets. The daemon package is `crates/webconfigd`; the
engine is `crates/webconfig-engine`.

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
under `target/release/<target>/` as applicable. Docker targets build the production `webconfigd`
image, using the repository Dockerfile and canonical install layout.

## 6. Deployment, install, and run

```sh
make run-mock
make run WEBCONFIG_PORT=8443
make docker-build
make docker-build-arm64
make docker-run
make docker-logs
make docker-stop
```

`run-mock` uses a temporary fake sysroot and has no hardware side effects. `run` uses the real
host `/proc` and `/sys`, real systemd/update backends, persistent `./data`, and port `8443` by
default; treat it as conditional and suitable only on the intended device or a disposable host.
`docker-build-arm64` is conditional on Docker/buildx and an ARM64-capable build environment. The
Docker run target exposes the production container on port 8443 according to `docker/Makefile`.

## 7. Cleanup

```sh
make stop
make clean
make docker-clean
```

`stop` terminates the process holding `WEBCONFIG_PORT`; `clean` runs `cargo clean` and removes
`target/`; `docker-clean` removes the built image. The `./data` directory is deliberately
persistent for development and must be removed manually when resetting first-boot state.

## 8. Hardware, cloud, and manual verification caveats

There is no cloud deployment target here. Tests and `run-mock` cannot prove real `/proc`,
`/sys`, systemd, update, GPIO, storage, TLS, or Raspberry Pi behavior. Before shipping, install
the correct target binary, provision certificates and configuration according to the Yocto
image, confirm the port and first-boot admin flow, and exercise restart/update behavior on
target hardware. Keep release signing and deployment credentials outside the repository.
