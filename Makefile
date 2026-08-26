# SoCcentric WebConfig — top-level Makefile.
#
# Per SoCcentric global CLAUDE.md §12, the repo-root Makefile is the single
# entry point for build/test/lint, wrapping the underlying tool (cargo). The
# git workflows (§9 step 6) run `make build && make test && make lint`.
#
# Targets:
#   make toolchain  — install rustup + the exact pinned toolchain (one-time
#                     host setup; see rust-toolchain.toml)
#   make build      — debug build of the daemon (host target)
#   make release    — release build with the exact spec §2 profile
#   make test       — engine + HTTP integration tests (fake sysroot, no HW)
#   make lint       — clippy + rustfmt --check
#   make fmt        — format in place
#   make vendor     — (re)generate the vendored offline crate tarball
#   make cross      — build all three cross-targets (CI parity; uses
#                     cargo-zigbuild automatically if the GNU cross
#                     toolchain isn't installed)
#   make run        — run the daemon against the real host (live /proc, real
#                     backends); persistent state in ./data (dev)
#   make run-mock   — run against a tempdir fake sysroot (mock backends, no HW)
#   make stop       — stop the process listening on the WebConfig TCP port
#   make clean      — remove target/

# Install rustup (if missing) plus the exact pinned toolchain, components,
# and cross targets declared in rust-toolchain.toml (spec §6 host/CI parity).
# Idempotent — safe to re-run. Needs network access to static.rust-lang.org /
# sh.rustup.rs; not usable in network-restricted sandboxes.
.DEFAULT_GOAL := help

toolchain: ## Install rustup + the exact pinned toolchain (one-time host setup)
	@set -e; \
	export PATH="$$HOME/.cargo/bin:$$PATH"; \
	if ! command -v rustup >/dev/null 2>&1; then \
		echo "==> rustup not found; installing"; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
			| sh -s -- -y --default-toolchain none --profile minimal; \
	fi; \
	echo "==> installing toolchain $(RUST_CHANNEL) (rustfmt, clippy)"; \
	rustup toolchain install $(RUST_CHANNEL) --profile minimal \
		--component rustfmt --component clippy; \
	echo "==> adding cross targets: $(TARGETS)"; \
	rustup target add --toolchain $(RUST_CHANNEL) $(TARGETS); \
	echo "==> ready: $$(rustup run $(RUST_CHANNEL) rustc --version)"

# Prefer the standard rustup installation even when the caller's shell has not
# sourced ~/.cargo/env; an explicit CARGO override still takes precedence.
CARGO ?= $(if $(wildcard $(HOME)/.cargo/bin/cargo),$(HOME)/.cargo/bin/cargo,cargo)
WEBCONFIG_PORT ?= 8443
export WEBCONFIG_PORT
TARGETS := x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu armv7-unknown-linux-gnueabihf
# Pinned channel, read straight from rust-toolchain.toml so this target can't
# drift from the pin.
RUST_CHANNEL := $(shell grep -m1 '^channel' rust-toolchain.toml | sed -E 's/.*"([^"]*)".*/\1/')

.PHONY: help build release test lint fmt vendor release-artifacts cross run run-mock stop clean check toolchain docker-build docker-build-arm64 docker-build-armv7 docker-run docker-stop docker-logs docker-clean

# Bare `make` prints help rather than building, so a stray invocation never
# kicks off a network install or a build by surprise.


build: ## Debug build of the daemon (host target)
	$(CARGO) build --workspace

release: ## Release build, exact spec §2 profile (opt-level=z, lto, stripped)
	$(CARGO) build --workspace --release

test: ## Engine + HTTP integration tests (fake sysroot, no hardware)
	$(CARGO) test --workspace --all-targets

test-image: ## Image-level boot integration tests (webconfigd under systemd; requires a booted image)
	@if command -v bats >/dev/null 2>&1; then \
		bats meta-webconfig/recipes-core/webconfig/tests; \
	else \
		echo "bats not installed — image-level tests skipped (target-required)"; \
	fi

lint-image-wiring: ## Static check that the OS image installs webconfig packages (task 26/27)
	@fail=0; \
	for p in webconfigd webconfig-static webconfig-schemas webconfig-manifest; do \
		if grep -q "IMAGE_INSTALL:append.*$$p" ../Acadia-OS/meta/meta-acadia/recipes-core/images/acadia-image.bb 2>/dev/null; then \
			echo "  OK: $$p referenced in acadia-image.bb"; \
		else \
			echo "  FAIL: $$p not referenced in Acadia-OS acadia-image.bb"; fail=1; \
		fi; \
	done; \
	[ "$$fail" -eq 0 ] || { echo "ERROR: webconfig packages missing from OS image recipe"; exit 1; }

lint-checksums: ## Fail if any placeholder/invalid release checksum remains in the recipes (task 28)
	@fail=0; \
	echo "Checking release checksums in meta-webconfig recipes..."; \
	if grep -rn 'TODO_REPLACE_WITH_RELEASED_TARBALL_SHA256' meta-webconfig/recipes-*; then \
		echo "  FAIL: placeholder checksum present"; fail=1; \
	else \
		echo "  OK: no placeholder checksum present"; \
	fi; \
	for f in meta-webconfig/recipes-core/webconfig/webconfigd.bb; do \
		[ -f "$$f" ] || continue; \
		for var in src vendor; do \
			sha=$$(grep -oE "SRC_URI\[$$var\.sha256sum\] = \"[0-9a-f]{64}\"" "$$f" | grep -oE '[0-9a-f]{64}'); \
			if [ -z "$$sha" ]; then \
				echo "  FAIL: $$f missing a valid 64-hex $$var checksum"; fail=1; \
			else \
				echo "  OK: $$var checksum = $$sha"; \
			fi; \
		done; \
	done; \
	[ "$$fail" -eq 0 ] || { echo "ERROR: release checksum gate failed (task 28)"; exit 1; }
lint: ## clippy -D warnings + rustfmt --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) fmt --all -- --check

lint-toolchain: ## Assert one pinned Rust toolchain across rust-toolchain.toml, GH Actions, GitLab (task 30)
	@set -e; \
	echo "Checking Rust toolchain consistency..."; \
	PINNED=$$(sed -n 's/^channel = "\([0-9.]*\)"/\1/p' rust-toolchain.toml | head -1); \
	[ -n "$$PINNED" ] || { echo "FAIL: no channel in rust-toolchain.toml"; exit 1; }; \
	echo "  pinned channel: $$PINNED"; \
	if ! grep -q "toolchain: \"$$PINNED\"" .github/workflows/ci.yml; then \
		echo "FAIL: GH Actions does not pin $$PINNED (see .github/workflows/ci.yml)"; exit 1; \
	fi; \
	if ! grep -q "rust:$$PINNED" .gitlab-ci.yml; then \
		echo "FAIL: GitLab CI does not pin rust:$$PINNED"; exit 1; \
	fi; \
	actual=$$(rustc --version | awk '{print $$2}'); \
	if [ "$$actual" != "$$PINNED" ]; then \
		echo "WARN: local rustc is $$actual, pinned is $$PINNED"; \
	fi; \
	echo "  OK: one pinned toolchain $$PINNED everywhere"

fmt: ## Format the workspace in place
	$(CARGO) fmt --all

# Regenerate vendored sources for offline builds (spec §2). Run after any
# dependency change; commit the result.
vendor: ## Regenerate the vendored offline crate tarball
	$(CARGO) vendor --versioned-dirs vendor

# Package the release artifacts webconfigd.bb fetches (source + vendor
# tarballs) and print their real SHA-256 checksums (Checkpoint 3.2). Requires
# `make vendor` to have been run at least once.
release-artifacts: ## Package release tarballs + compute real checksums for webconfigd.bb
	@./tools/release-artifacts.sh

# Cross-compile parity check for CI (spec §6).
#
# CI installs the GNU cross toolchains (gcc-aarch64-linux-gnu, gcc-arm-linux-gnueabihf)
# and the committed .cargo/config.toml points the linker at them. A local developer
# usually has neither, but the machine's alternate cross toolchain — cargo-zigbuild
# plus a zig compiler — produces the same result without any system gcc cross
# packages. Use GNU when present (true CI parity), otherwise fall back to zigbuild.
cross: ## Build all three cross-targets (x86_64/aarch64/armv7), CI parity
	@set -e; \
	if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then \
		echo "==> cross-compiling with GNU toolchain (CI parity)"; \
		CMD="$(CARGO) build --workspace --release --target"; \
	elif command -v cargo-zigbuild >/dev/null 2>&1; then \
		ZIG="$$(command -v zig 2>/dev/null || true)"; \
		if [ -z "$$ZIG" ] && [ -x "$$HOME/zig/zig" ]; then ZIG="$$HOME/zig/zig"; fi; \
		if [ -n "$$ZIG" ]; then \
			echo "==> GNU cross toolchain not found; using cargo-zigbuild (zig: $$ZIG)"; \
			export PATH="$$(dirname "$$ZIG"):$$PATH"; \
			CMD="$(CARGO) zigbuild --workspace --release --target"; \
		else \
			echo "ERROR: cargo-zigbuild present but no zig compiler on PATH or ~/zig/zig." >&2; \
			exit 1; \
		fi; \
	else \
		echo "ERROR: no cross toolchain. Install GNU cross gcc (gcc-aarch64-linux-gnu, gcc-arm-linux-gnueabihf) OR cargo-zigbuild + zig." >&2; \
		exit 1; \
	fi; \
	for t in $(TARGETS); do \
		echo "==> building $$t"; \
		$$CMD $$t || exit 1; \
	done

# Dev run against the REAL host sysroot (spec §6): no WEBCONFIG_SYSROOT is
# set, so resolve_sysroot() uses "/" and is_real_root() is true — the daemon
# reads live /proc + /sys and uses the real systemd/update backends (mock
# backends are only selected for a tempdir fake sysroot). State (config.db,
# cert.pem, key.pem) is redirected to a persistent, gitignored ./data so the
# first-boot admin and config survive restarts, mirroring a device's /data
# partition. Wipe ./data to reset to first-boot. For the no-hardware mock
# mode, use `make run-mock`.
run: ## Run the daemon against the real host (live /proc, real backends)
	@mkdir -p data; \
	WEBCONFIG_DATA_DIR="$$(pwd)/data" \
	RUST_LOG=info \
	$(CARGO) run -p webconfigd -- --

# Mock mode: run against a tempdir fake sysroot so no hardware is required and
# no host side effects occur (spec §6). Vitals read as zeros; backends are
# mocks. The tempdir is wiped by the OS on reboot; state does not persist.
run-mock: ## Run against a tempdir fake sysroot (mock backends, no hardware)
	WEBCONFIG_SYSROOT=$$(mktemp -d) \
	WEBCONFIG_DATA_DIR=$$WEBCONFIG_SYSROOT/data \
	RUST_LOG=info \
	$(CARGO) run -p webconfigd -- --

# Stop the process holding the default daemon port, or an overridden
# WEBCONFIG_PORT. A clear port is already in the desired state.
stop: ## Stop the process listening on WEBCONFIG_PORT (default: 8443)
	@case "$$WEBCONFIG_PORT" in \
		[1-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-9][0-9][0-9][0-9][0-9]) ;; \
		*) echo "WEBCONFIG_PORT must be an integer between 1 and 65535" >&2; exit 2 ;; \
	esac; \
	if [ "$$WEBCONFIG_PORT" -lt 1 ] || [ "$$WEBCONFIG_PORT" -gt 65535 ]; then \
		echo "WEBCONFIG_PORT must be an integer between 1 and 65535" >&2; exit 2; \
	fi; \
	fuser "$$WEBCONFIG_PORT/tcp" >/dev/null 2>&1; status=$$?; \
	if [ $$status -eq 0 ]; then \
		fuser -k -TERM "$$WEBCONFIG_PORT/tcp" >/dev/null || exit $$?; \
		for attempt in 1 2 3 4 5; do \
			if ! fuser "$$WEBCONFIG_PORT/tcp" >/dev/null 2>&1; then \
				echo "Stopped process listening on port $$WEBCONFIG_PORT"; exit 0; \
			fi; \
			sleep 1; \
		done; \
		echo "Port $$WEBCONFIG_PORT is still in use after SIGTERM" >&2; exit 1; \
	fi; \
	if [ $$status -eq 1 ]; then \
		echo "No process is listening on port $$WEBCONFIG_PORT"; \
	else \
		echo "Unable to inspect port $$WEBCONFIG_PORT" >&2; exit $$status; \
	fi

clean: ## Remove target/
	$(CARGO) clean

# ── Docker ────────────────────────────────────────────────────────────────────
# Production container image: the webconfigd daemon + frontend + schemas +
# board manifest in the canonical install layout. See docker/Dockerfile.

docker-build: ## docker-build — build the production webconfigd image (host arch)
	$(MAKE) -C docker build IMAGE_NAME=$(shell basename $$(pwd) | tr 'A-Z' 'a-z' | sed 's/-configuration/-webconfigd/')

docker-build-arm64: ## docker-build-arm64 — cross-build the arm64 webconfigd image (Raspberry Pi 5 / Zynq MPSoC)
	$(MAKE) -C docker build-arm64 IMAGE_NAME=$(shell basename $$(pwd) | tr 'A-Z' 'a-z' | sed 's/-configuration/-webconfigd/')

docker-build-armv7: ## docker-build-armv7 — cross-build the armv7 webconfigd image (32-bit Pi 2/3-class)
	$(MAKE) -C docker build-armv7 IMAGE_NAME=$(shell basename $$(pwd) | tr 'A-Z' 'a-z' | sed 's/-configuration/-webconfigd/')

docker-run: ## docker-run — run the container (production, port 8443)
	$(MAKE) -C docker run IMAGE_NAME=$(shell basename $$(pwd) | tr 'A-Z' 'a-z' | sed 's/-configuration/-webconfigd/')

docker-stop: ## docker-stop — stop and remove the container
	$(MAKE) -C docker stop

docker-logs: ## docker-logs — tail container logs
	$(MAKE) -C docker logs

docker-clean: ## docker-clean — remove the built image
	$(MAKE) -C docker clean IMAGE_NAME=$(shell basename $$(pwd) | tr 'A-Z' 'a-z' | sed 's/-configuration/-webconfigd/')

# Convenience alias: full validation gate (§9 step 6).
check: build test lint ## Full validation gate: build && test && lint

# ── Fleet-standard aliases ────────────────────────────────────────────────────
# Same verbs mean the same thing in every repo; these forward to this
# repo's own targets rather than duplicating their recipes.
.PHONY: format
format: fmt ## Alias for fmt

# ── Help ──────────────────────────────────────────────────────────────────────
# Targets are self-documenting: text after `## ` on a target line is picked up
# by `make help` automatically, so the listing can never drift from the rules.
.PHONY: help
help: ## Show this help
	@printf '\n  \033[1m%s\033[0m\n' 'Acadia-Configuration'
	@printf '  Usage: make <target> [VAR=value ...]\n'
	@printf '\n'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9_.\/-]+:.*?## / { printf "    \033[36m%-24s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf '\n'
