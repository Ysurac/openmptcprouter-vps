#!/bin/bash
# Tests for omr-vxlan-run, the VPS-side vxlan device manager:
#   - l3 (default) mode: raw device gets LOCALTUNIP/LOCALTUNIP6, no bridging
#   - l2 mode: raw device gets no address, joins BRIDGE instead (creating it
#     if missing, reusing it if another client on the same VNI already made it)
#   - stop: device always removed; a now-empty shared bridge is cleaned up,
#     a still-populated one (another client's port still enslaved) is left alone
#
# The real script shells out to `ip` and reads bridge membership from
# /sys/class/net/<bridge>/brif; both are faked here (PATH-injected `ip`,
# SYSFS_NET override) so this runs without root or real netlink devices.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$SCRIPT_DIR/../omr-vxlan-run"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS+1)); printf '  PASS %s\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL %s\n    expected=%s\n    got=%s\n' "$desc" "$expected" "$actual"
    fi
}

assert_calls_contain() {
    local desc="$1" calls_file="$2" pattern="$3"
    if grep -qF -- "$pattern" "$calls_file" 2>/dev/null; then
        PASS=$((PASS+1)); printf '  PASS %s\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL %s\n    missing: %s\n    calls:\n%s\n' "$desc" "$pattern" "$(sed 's/^/      /' "$calls_file" 2>/dev/null)"
    fi
}

assert_calls_lack() {
    local desc="$1" calls_file="$2" pattern="$3"
    if grep -qF -- "$pattern" "$calls_file" 2>/dev/null; then
        FAIL=$((FAIL+1))
        printf '  FAIL %s\n    unexpectedly present: %s\n' "$desc" "$pattern"
    else
        PASS=$((PASS+1)); printf '  PASS %s\n' "$desc"
    fi
}

# Fails if pattern_before does not appear strictly before pattern_after
assert_order() {
    local desc="$1" calls_file="$2" before="$3" after="$4"
    local line_before line_after
    line_before=$(grep -nF -- "$before" "$calls_file" | head -n1 | cut -d: -f1)
    line_after=$(grep -nF -- "$after" "$calls_file" | head -n1 | cut -d: -f1)
    if [ -n "$line_before" ] && [ -n "$line_after" ] && [ "$line_before" -lt "$line_after" ]; then
        PASS=$((PASS+1)); printf '  PASS %s\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL %s\n    "%s" (line %s) not before "%s" (line %s)\n' "$desc" "$before" "$line_before" "$after" "$line_after"
    fi
}

# ── Fake `ip` ─────────────────────────────────────────────────────────────────
# Logs every call to $IP_CALLS. `ip link show $IP_LINK_SHOW_EXISTS` (if set)
# reports the device as present, driving the pre-delete-and-recreate branch;
# every other device reports absent, like a fresh boot.

FAKE_BIN="$TMPDIR/bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/ip" << 'EOF'
#!/bin/sh
echo "ip $*" >> "$IP_CALLS"
if [ "$1 $2" = "link show" ] && [ "$3" = "${IP_LINK_SHOW_EXISTS:-}" ] && [ -n "${IP_LINK_SHOW_EXISTS:-}" ]; then
    echo "3: $3: <BROADCAST,MULTICAST> mtu 1500"
    exit 0
fi
[ "$1 $2" = "link show" ] && exit 1
exit 0
EOF
chmod +x "$FAKE_BIN/ip"

# ── Helpers ───────────────────────────────────────────────────────────────────

_run() {
    # _run <action> <config-file-content...via file already written>
    local action="$1" cfgfile="$2"
    IP_CALLS="$TMPDIR/ip_calls.log"
    : > "$IP_CALLS"
    unset IP_LINK_SHOW_EXISTS
    PATH="$FAKE_BIN:$PATH" IP_CALLS="$IP_CALLS" SYSFS_NET="$TMPDIR/sysfs/net" \
        sh "$SCRIPT" "$action" "$cfgfile" >/dev/null 2>&1
    echo "$IP_CALLS"
}

_write_cfg() {
    local name="$1"; shift
    local f="$TMPDIR/$name"
    : > "$f"
    for kv in "$@"; do echo "$kv" >> "$f"; done
    echo "$f"
}

# ── l3 (default) mode ─────────────────────────────────────────────────────────

test_l3_start_sets_tunnel_ips_no_bridge() {
    local cfg calls
    cfg=$(_write_cfg user_l3 'VNI=6' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.3' \
        'LOCALTUNIP=10.255.249.17/30' 'LOCALTUNIP6=fd00::b04:1/126' 'MTU=1380')
    calls=$(_run start "$cfg")
    assert_calls_contain "vxlan device created with VNI/local/remote" "$calls" \
        "ip link add vx-user_l3 type vxlan id 6 local 10.0.0.1 remote 10.0.0.3 dstport 4789"
    assert_calls_contain "ipv4 tunnel address set" "$calls" "ip addr add 10.255.249.17/30 dev vx-user_l3"
    assert_calls_contain "ipv6 tunnel address set" "$calls" "ip -6 addr add fd00::b04:1/126 dev vx-user_l3"
    assert_calls_contain "mtu set" "$calls" "ip link set mtu 1380 dev vx-user_l3"
    assert_calls_contain "device brought up" "$calls" "ip link set vx-user_l3 up"
    assert_calls_lack "no bridge master" "$calls" "master"
}

test_l3_is_the_implicit_default_when_mode_unset() {
    local cfg calls
    cfg=$(_write_cfg user_l3_nomode 'VNI=6' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.3' 'LOCALTUNIP=10.255.249.17/30')
    calls=$(_run start "$cfg")
    assert_calls_contain "still gets a tunnel IP without MODE=" "$calls" "ip addr add 10.255.249.17/30 dev vx-user_l3_nomode"
}

# ── l2 (bridged) mode ─────────────────────────────────────────────────────────

test_l2_creates_bridge_when_missing() {
    local cfg calls
    cfg=$(_write_cfg user_l2_new 'VNI=5' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.2' \
        'MODE=l2' 'BRIDGE=br-vxlan5' 'MTU=1380')
    calls=$(_run start "$cfg")
    assert_calls_contain "vxlan device created" "$calls" "ip link add vx-user_l2_new type vxlan id 5 local 10.0.0.1 remote 10.0.0.2 dstport 4789"
    assert_calls_contain "bridge created (didn't exist)" "$calls" "ip link add br-vxlan5 type bridge"
    assert_calls_contain "bridge brought up" "$calls" "ip link set br-vxlan5 up"
    assert_calls_contain "device enslaved to bridge" "$calls" "ip link set vx-user_l2_new master br-vxlan5"
    assert_calls_lack "no tunnel IP assigned in l2 mode" "$calls" "addr add"
}

test_l2_reuses_existing_bridge() {
    local cfg calls
    mkdir -p "$TMPDIR/sysfs/net/br-vxlan5"
    cfg=$(_write_cfg user_l2_join 'VNI=5' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.4' 'MODE=l2' 'BRIDGE=br-vxlan5')
    calls=$(_run start "$cfg")
    assert_calls_lack "bridge NOT recreated (already existed)" "$calls" "link add br-vxlan5 type bridge"
    assert_calls_contain "still enslaves this client's device" "$calls" "ip link set vx-user_l2_join master br-vxlan5"
}

test_l2_without_bridge_var_skips_bridging_entirely() {
    local cfg calls
    cfg=$(_write_cfg user_l2_nobridge 'VNI=5' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.2' 'MODE=l2')
    calls=$(_run start "$cfg")
    assert_calls_lack "no bridge created" "$calls" "type bridge"
    assert_calls_lack "no master assignment" "$calls" "master"
    assert_calls_lack "no tunnel IP either" "$calls" "addr add"
}

# ── shared start behavior ──────────────────────────────────────────────────────

test_existing_device_is_deleted_before_recreation() {
    local cfg calls
    cfg=$(_write_cfg user_stale 'VNI=6' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.3')
    IP_LINK_SHOW_EXISTS="vx-user_stale" \
        PATH="$FAKE_BIN:$PATH" IP_CALLS="$TMPDIR/ip_calls.log" SYSFS_NET="$TMPDIR/sysfs/net" \
        sh "$SCRIPT" start "$cfg" >/dev/null 2>&1
    calls="$TMPDIR/ip_calls.log"
    assert_calls_contain "stale device deleted" "$calls" "ip link del vx-user_stale"
    assert_order "delete happens before recreate" "$calls" "ip link del vx-user_stale" "ip link add vx-user_stale type vxlan"
}

# ── stop ──────────────────────────────────────────────────────────────────────

test_stop_deletes_device_l3_no_bridge_touched() {
    local cfg calls
    cfg=$(_write_cfg user_l3_stop 'VNI=6' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.3')
    calls=$(_run stop "$cfg")
    assert_calls_contain "device deleted" "$calls" "ip link del vx-user_l3_stop"
    assert_calls_lack "no bridge deletion attempted" "$calls" "link del br-"
}

test_stop_removes_now_empty_shared_bridge() {
    local cfg calls
    mkdir -p "$TMPDIR/sysfs/net/br-vxlan9/brif"
    cfg=$(_write_cfg user_l2_last 'VNI=9' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.2' 'MODE=l2' 'BRIDGE=br-vxlan9')
    calls=$(_run stop "$cfg")
    assert_calls_contain "device deleted" "$calls" "ip link del vx-user_l2_last"
    assert_calls_contain "now-empty bridge deleted too" "$calls" "ip link del br-vxlan9"
}

test_stop_keeps_bridge_still_used_by_another_client() {
    local cfg calls
    mkdir -p "$TMPDIR/sysfs/net/br-vxlan9/brif"
    touch "$TMPDIR/sysfs/net/br-vxlan9/brif/vx-otheruser"
    cfg=$(_write_cfg user_l2_notlast 'VNI=9' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.3' 'MODE=l2' 'BRIDGE=br-vxlan9')
    calls=$(_run stop "$cfg")
    assert_calls_contain "this device still deleted" "$calls" "ip link del vx-user_l2_notlast"
    assert_calls_lack "bridge left alone (other client still on it)" "$calls" "link del br-vxlan9"
}

# ── config file is data, never shell code ─────────────────────────────────────

test_config_is_not_run_as_shell_code() {
    # The file carries values a router sent through the API, and the script
    # runs as root: nothing in it may run, and only the expected keys apply.
    local cfg calls
    rm -f "$TMPDIR/pwned"*
    cfg=$(_write_cfg user_inject 'VNI=6' 'LOCALIP=10.0.0.1' 'REMOTEIP=10.0.0.3' \
        'LOCALTUNIP=10.255.249.17/30$(touch '"$TMPDIR"'/pwned1)' \
        'LOCALTUNIP6=fd00::b04:1/126;touch '"$TMPDIR"'/pwned2' \
        'touch '"$TMPDIR"'/pwned3' \
        'PATH=/nonexistent' 'MTU=1380')
    calls=$(_run start "$cfg")
    assert_eq "no command from the file ran" "" "$(ls "$TMPDIR"/pwned* 2>/dev/null)"
    assert_calls_contain "valid keys still applied" "$calls" \
        "ip link add vx-user_inject type vxlan id 6 local 10.0.0.1 remote 10.0.0.3 dstport 4789"
    assert_calls_contain "PATH not taken from the file" "$calls" "ip link set mtu 1380 dev vx-user_inject"
    assert_calls_lack "invalid LOCALTUNIP ignored" "$calls" "ip addr add"
    assert_calls_lack "invalid LOCALTUNIP6 ignored" "$calls" "ip -6 addr add"
}

# ── Run ───────────────────────────────────────────────────────────────────────

for t in \
    test_l3_start_sets_tunnel_ips_no_bridge \
    test_l3_is_the_implicit_default_when_mode_unset \
    test_l2_creates_bridge_when_missing \
    test_l2_reuses_existing_bridge \
    test_l2_without_bridge_var_skips_bridging_entirely \
    test_existing_device_is_deleted_before_recreation \
    test_stop_deletes_device_l3_no_bridge_touched \
    test_stop_removes_now_empty_shared_bridge \
    test_stop_keeps_bridge_still_used_by_another_client \
    test_config_is_not_run_as_shell_code \
; do
    printf '\n▶ %s\n' "$t"
    "$t"
done

printf '\n─────────────────────────────────────\n'
printf 'Results: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
