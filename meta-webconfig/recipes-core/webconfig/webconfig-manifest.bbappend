# webconfig-manifest.bbappend — Acadia board manifest selection (spec §3).
#
# This repo is Acadia-only; board-specific data lives solely in the board
# manifest. `webconfig-manifest.bb` already defaults WEBCONFIG_BOARD_FILE to
# the real "acadia.json", so no override is required to get a correct image.
# This bbappend exists for the one case that still needs a MACHINE-specific
# override: a future Acadia board revision that ships a distinct manifest
# file under a different MACHINE name.
#
# Real Raspberry Pi 5 MACHINE name (Acadia-OS default board, per its own docs):
WEBCONFIG_BOARD_FILE:raspberrypi5 = "acadia.json"

# Mirror the platform id into the daemon environment so the embedded
# compiled-in fallback manifest agrees with the installed one if the BSP file
# is ever missing (spec §3). This lives in a webconfigd.bbappend per machine:
#   WEBCONFIG_PLATFORM:raspberrypi5 = "acadia"
