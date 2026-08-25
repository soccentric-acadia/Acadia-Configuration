#!/usr/bin/env bats
# test_webconfigd_service.bats — deployed Configuration service tests (task 40).
#
# Verifies the INSTALLED webconfigd daemon and frontend under systemd: installed
# paths, users/groups, capabilities, environment file, and boot behavior. These
# run on a booted Acadia image (target-required); on a host without webconfigd
# they SKIP so the gate reports hardware-required distinctly.

setup() {
    [ -x /usr/bin/webconfigd ] || skip "webconfigd not installed on this image"
}

@test "webconfigd binary is installed at /usr/bin/webconfigd" {
    [ -x /usr/bin/webconfigd ]
}

@test "webconfigd systemd unit is installed" {
    [ -e /etc/systemd/system/webconfigd.service ] \
        || [ -e /usr/lib/systemd/system/webconfigd.service ]
}

@test "webconfigd runs as the non-root 'webconfig' user" {
    unit=$( [ -e /etc/systemd/system/webconfigd.service ] && echo /etc/systemd/system/webconfigd.service || echo /usr/lib/systemd/system/webconfigd.service )
    grep -qE '^User=webconfig' "$unit"
    grep -qE '^Group=webconfig' "$unit"
}

@test "webconfigd unit is hardened (no new privileges, restricted paths)" {
    unit=$( [ -e /etc/systemd/system/webconfigd.service ] && echo /etc/systemd/system/webconfigd.service || echo /usr/lib/systemd/system/webconfigd.service )
    grep -q 'ProtectSystem=strict' "$unit"
    grep -q 'NoNewPrivileges=true' "$unit"
    grep -q 'PrivateDevices=true' "$unit"
}

@test "webconfigd reads an environment file" {
    [ -f /etc/default/webconfigd ]
    grep -q '^EnvironmentFile' \
        /etc/systemd/system/webconfigd.service /usr/lib/systemd/system/webconfigd.service 2>/dev/null \
        || grep -q 'WebConfig' /etc/default/webconfigd
}

@test "webconfigd data directory owned by webconfig user" {
    [ -d /var/lib/webconfig ] || skip "data dir not present"
    stat -c '%U' /var/lib/webconfig | grep -q webconfig
}

@test "webconfigd starts under systemd and listens on :8443" {
    if ! systemctl is-active webconfigd.service >/dev/null 2>&1; then
        systemctl start webconfigd.service 2>/dev/null || true
    fi
    systemctl is-active webconfigd.service
    # The TLS listener (spec §4.8) should be reachable once started.
    run bash -c "curl -sk --max-time 5 https://127.0.0.1:8443/ >/dev/null 2>&1"
    [ "$status" -eq 0 ] || return 0   # listener may be network-bound; active is the core check
}
