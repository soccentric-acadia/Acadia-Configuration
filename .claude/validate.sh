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

check "JSON schemas parse" "python3" \
  'for f in schemas/*.json; do
     python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" \
       || { echo "invalid JSON: $f"; exit 1; }
   done'

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

report "$TIER"
