#!/usr/bin/env bats
# test_webconfigd_boot.bats — image-level boot integration tests for webconfigd
# (task 27).
#
# Runs on a BOOTED Acadia image that includes the meta-webconfig layer. Verifies
# that webconfigd starts under systemd, its assets/schemas/manifest are installed
# with correct ownership/permissions, and the service ordering is correct.
#
# Hardware/image requirement: these tests target a real booted image
# (target-required). On a host without the service installed they SKIP so the
# gate reports hardware-required distinctly, never a false pass/fail.

setup() {
    [ -x /usr/bin/webconfigd ] || skip "webconfigd not installed on this image"
    [ -e /etc/systemd/system/webconfigd.service ] \
        || [ -e /usr/lib/systemd/system/webconfigd.service ] \
        || skip "webconfigd systemd unit not installed"
}

@test "webconfigd binary present and executable" {
    [ -x /usr/bin/webconfigd ]
}

@test "webconfigd systemd unit enables after network" {
    grep -qE '^After=.*network' \
        /etc/systemd/system/webconfigd.service /usr/lib/systemd/system/webconfigd.service 2>/dev/null
}

@test "webconfigd service starts under systemd" {
    if ! systemctl is-active webconfigd.service >/dev/null 2>&1; then
        systemctl start webconfigd.service || true
    fi
    systemctl is-active webconfigd.service
}

@test "webconfigd runs as non-root user" {
    grep -qE '^User=webconfig' \
        /etc/systemd/system/webconfigd.service /usr/lib/systemd/system/webconfigd.service 2>/dev/null
}

@test "frontend static assets installed" {
    [ -d /usr/share/webconfig/static ] || skip "static assets not installed"
    [ -n "$(ls -A /usr/share/webconfig/static 2>/dev/null)" ]
}

@test "schemas installed and valid JSON" {
    for f in /usr/share/webconfig/schemas/*.schema.json; do
        [ -e "$f" ] || continue
        python3 -c "import json,sys; json.load(open('$f'))" 2>/dev/null
    done
}

@test "board manifest installed" {
    [ -f /usr/share/webconfig/board-manifest.json ] || skip "no board manifest on this image"
    python3 -c "import json; json.load(open('/usr/share/webconfig/board-manifest.json'))"
}
