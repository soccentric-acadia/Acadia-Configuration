#!/usr/bin/env bash
# Acadia-Configuration — per-repo validation gate.  See .claude/lib/validate-lib.sh.
#
#   quick   seconds. Manifest/schema parse + clippy & rustfmt.
#   full    minutes. `make check` = build && test && lint.
#
# WebConfig: the on-device config daemon + UI. Ships into Acadia-OS as the
# meta-webconfig Yocto layer, so a broken board manifest breaks the image build
# in a repo that has no idea why.
set -uo pipefail
# shellcheck source=lib/validate-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/validate-lib.sh"

TIER="$(tier_or_die "${1:-quick}")"

# --- quick -----------------------------------------------------------------

check "board manifests are valid JSON" "python3" \
  'for f in board-manifests/*.json; do
     python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" \
       || { echo "invalid JSON: $f"; exit 1; }
   done'

check "acadia board manifest declares its hardware blocks" "python3" \
  'python3 - <<PY
import json, sys
m = json.load(open("board-manifests/acadia.json"))
blob = json.dumps(m).lower()
missing = [k for k in ("stm32", "can") if k not in blob]
if missing:
    print("acadia.json no longer mentions:", ", ".join(missing))
    sys.exit(1)
PY'

check "MCU firmware trust anchor is a real key (task 41)" "python3" \
  'python3 - <<PY
import json, sys
m = json.load(open("board-manifests/acadia.json"))
for p in m.get("peripherals", []):
    if p.get("kind") == "mcu":
        key = p.get("caps", {}).get("firmware_pubkey_ed25519", "")
        if key in ("", "PLACEHOLDER"):
            print("MCU firmware_pubkey_ed25519 is still a placeholder"); sys.exit(1)
        try:
            if len(bytes.fromhex(key)) != 32:
                print("MCU trust anchor is not 32-byte ED25519"); sys.exit(1)
        except ValueError:
            print("MCU trust anchor is not valid hex"); sys.exit(1)
print("OK: MCU firmware trust anchor is a real 32-byte key")
PY'

check "JSON schemas parse" "python3" \
  'for f in schemas/*.json; do
     python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" \
       || { echo "invalid JSON: $f"; exit 1; }
   done'

# Task 34: cellular schema is versioned and declares the modem/APN/PIN/auth/
# secret contract.
check "cellular-5g schema is versioned" "python3" \
  'python3 - <<PY
import json, sys
try:
    d = json.load(open("schemas/cellular-5g.schema.json"))
except FileNotFoundError:
    print("schemas/cellular-5g.schema.json missing"); sys.exit(1)
if not d.get("schema_version"):
    print("cellular-5g schema must declare schema_version"); sys.exit(1)
field_ids = {f["id"] for g in d["groups"] for f in g["fields"]}
for key in ("modem_device", "apn", "auth_method", "pin"):
    if key not in field_ids:
        print(f"cellular-5g schema missing field {key}"); sys.exit(1)
print("OK: cellular-5g schema versioned:", d["schema_version"])
PY'

assert "meta-webconfig layer.conf present for the OS build" \
  'test -f meta-webconfig/conf/layer.conf'

# Directory on disk is meta-webconfig; soccentric-webconfig is the Yocto
# *collection* name inside layer.conf. Distinct concepts, previously confused.
assert "layer.conf declares its collection" \
  'grep -qE "BBFILE_COLLECTIONS|LAYERDEPENDS|BBPATH" meta-webconfig/conf/layer.conf'

check "clippy -D warnings + rustfmt --check" "cargo" 'make lint'

[ "$TIER" = "quick" ] && { report "$TIER"; exit $?; }

# --- full ------------------------------------------------------------------

# `make check` is the repo's own documented full gate: build && test && lint.
check "full gate (build && test && lint)" "cargo" 'make check'

# OS image wiring (task 26/27): webconfig packages must be referenced by the
# Acadia-OS image recipe so a booted image actually carries webconfigd.
assert "OS image installs webconfig packages" \
  'make lint-image-wiring 2>/dev/null || \
   for p in webconfigd webconfig-static webconfig-schemas webconfig-manifest; do \
     grep -q "IMAGE_INSTALL:append.*$$p" ../Acadia-OS/meta/meta-acadia/recipes-core/images/acadia-image.bb || exit 1; \
   done'

# Task 28: real immutable release checksums, no placeholders.
assert "release checksums are real (no placeholders)" 'make lint-checksums'

# Task 30: one pinned Rust toolchain across local + all CI pipelines.
assert "one pinned Rust toolchain everywhere" 'make lint-toolchain'

# Task 31: systemd-networkd owns networking (contract doc/network-manager-contract.md).
assert "networkd applier targets /etc/systemd/network (systemd-networkd)" \
  'grep -q "/etc/systemd/network" crates/webconfig-engine/src/appliers/networkd.rs \
     || { echo "networkd applier must target /etc/systemd/network (systemd-networkd contract)"; exit 1; }'

report "$TIER"
