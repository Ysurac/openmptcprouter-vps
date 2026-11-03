#!/bin/bash
# Tests for omr-reserved-ports, which lists the ports this VPS's services
# listen on in net.ipv4.ip_local_reserved_ports.
#
# 90-shadowsocks.conf sets ip_local_port_range = 9999 65000. Inside it sit the
# v2ray (10085) and xray (10086) API inbounds and, above all, the
# dokodemo-door inbounds omr-admin adds for every port a router forwards
# through a v2ray/xray proxy, on a port the user picked. If an outgoing
# connection holds one of those when v2ray/xray restarts, the daemon cannot
# bind that inbound and fails to start altogether. Reserved ports are skipped
# by automatic assignment only; an explicit bind() still works (verified on a
# netns: with 40001-40002 reserved in a 40000-40003 range, bind(0) got 40000
# and 40003 and a third listener failed rather than take a reserved port).
#
# Config files are read from a fixture tree through OMR_RP_ROOT, sysctl is a
# PATH-injected fake, and only the report modes (-s/-n) are driven, so nothing
# is written to /proc. Requires: bash, jq.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$SCRIPT_DIR/.."
SCRIPT="$REPO/omr-reserved-ports"
PATH_UNIT="$REPO/omr-reserved-ports.path.in"
SERVICE_UNIT="$REPO/omr-reserved-ports.service.in"

command -v jq >/dev/null 2>&1 || { echo "SKIP jq is not installed"; exit 77; }

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

setup() {
    T="$(mktemp -d)"
    mkdir -p "$T/bin" "$T/etc/v2ray" "$T/etc/xray" "$T/etc/shadowsocks-go" \
        "$T/etc/shadowsocks-libev" "$T/etc/mqvpn" "$T/etc/sysctl.d" \
        "$T/etc/openmptcprouter-vps-admin"
    cat > "$T/bin/sysctl" << 'EOF'
#!/bin/sh
[ "$1" = "-n" ] || exit 1
case "$2" in
    net.ipv4.ip_local_port_range) printf '9999\t65000\n' ;;
    net.ipv4.ip_unprivileged_port_start) echo 1024 ;;
    net.ipv4.ip_local_reserved_ports) echo "" ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$T/bin/sysctl"
}
teardown() { rm -rf "$T"; }

run() { ( export PATH="$T/bin:$PATH" OMR_RP_ROOT="$T"; "$SCRIPT" "$@" ); }
list() { run -s 2>/dev/null | sed -n 's/^reserved (new) *: //p'; }

# has <list> <port>: is <port> inside one of the list's ranges?
has() {
    echo "$1" | tr ',' '\n' | awk -v p="$2" -F- '
        { a = $1 + 0; b = ($2 == "" ? a : $2 + 0); if (p >= a && p <= b) f = 1 }
        END { exit !f }'
}
assert_reserved()     { if has "$2" "$3"; then assert_eq "$1" yes yes; else assert_eq "$1" "reserved" "missing from '$2'"; fi; }
assert_not_reserved() { if has "$2" "$3"; then assert_eq "$1" "not reserved" "reserved in '$2'"; else assert_eq "$1" yes yes; fi; }

# ── Tests ──────────────────────────────────────────────────────────────────

test_v2ray_xray_inbounds_including_forwarded_ports() {
    setup
    # omr-admin's v2ray_add_port()/xray_add_port() shape: dokodemo-door inbound
    cat > "$T/etc/v2ray/v2ray-server.json" << 'EOF'
{"inbounds": [
  {"tag": "omrin-tunnel", "port": 65228},
  {"tag": "api", "port": 10085},
  {"tag": "user_redir_tcp_8080", "port": 25565, "protocol": "dokodemo-door"}
], "outbounds": [{"tag": "direct", "settings": {"port": 44444}}]}
EOF
    cat > "$T/etc/xray/xray-server.json" << 'EOF'
{"inbounds": [
  {"tag": "api", "port": 10086},
  {"tag": "range", "port": "40000-40002"},
  {"tag": "list", "port": "41000,41001"},
  {"tag": "socket", "listen": "/run/x.sock"}
]}
EOF
    local l; l=$(list)
    assert_reserved "v2ray API inbound" "$l" 10085
    assert_reserved "xray API inbound" "$l" 10086
    assert_reserved "forwarded port (dokodemo-door inbound)" "$l" 25565
    assert_reserved "tunnel inbound above the range" "$l" 65228
    assert_reserved "xray range port, start" "$l" 40000
    assert_reserved "xray range port, end" "$l" 40002
    assert_reserved "xray list port, second" "$l" 41001
    assert_not_reserved "outbound settings are not listeners" "$l" 44444
    teardown
}

test_shadowsocks_go_libev_and_mqvpn() {
    setup
    cat > "$T/etc/shadowsocks-go/server.json" << 'EOF'
{"servers": [{"name": "ss", "tcpListeners": [{"address": ":65280"}],
               "udpListeners": [{"address": "[::]:65281"}]}],
 "api": {"listeners": [{"address": "127.0.0.1:65279"}]},
 "dns": [{"addrPort": "8.8.8.8:53"}]}
EOF
    cat > "$T/etc/shadowsocks-libev/manager.json" << 'EOF'
{"server_port": 65101, "port_password": {"65102": "a", "65103": "b"}}
EOF
    cat > "$T/etc/mqvpn/server.json" << 'EOF'
{"listen": "0.0.0.0:65443", "control_listen": "127.0.0.1:19090"}
EOF
    local l; l=$(list)
    assert_reserved "shadowsocks-go tcp listener" "$l" 65280
    assert_reserved "shadowsocks-go udp listener ([::]:port)" "$l" 65281
    assert_reserved "shadowsocks-go API listener" "$l" 65279
    assert_reserved "ss-manager server_port" "$l" 65101
    assert_reserved "ss-manager per-user port" "$l" 65103
    assert_reserved "mqvpn listener" "$l" 65443
    assert_reserved "mqvpn control listener" "$l" 19090
    teardown
}

test_vxlan_from_config_and_files() {
    setup
    cat > "$T/etc/openmptcprouter-vps-admin/omr-admin-config.json" << 'EOF'
{"users": [{
  "alice": {"vxlan": {"enabled": true}},
  "bob":   {"vxlan": {"enabled": true, "port": 14789}},
  "carol": {"vxlan": {"enabled": false, "port": 24789}},
  "dave":  {"vxlan": null}
}]}
EOF
    mkdir -p "$T/etc/openmptcprouter-vps-admin/omr-vxlan"
    printf 'VNI=5\nPORT=34789\n' > "$T/etc/openmptcprouter-vps-admin/omr-vxlan/user5"
    local l; l=$(list)
    assert_reserved "enabled user without a port: omr-admin's 4789" "$l" 4789
    assert_reserved "enabled user with a port" "$l" 14789
    assert_not_reserved "disabled user" "$l" 24789
    assert_reserved "per-user file omr-vxlan-run reads" "$l" 34789
    teardown
}

test_admin_extras_file() {
    setup
    cat > "$T/etc/openmptcprouter-vps-admin/reserved-ports" << 'EOF'
# my services
12345
20000-20002   # a range
30000,30001
EOF
    local l; l=$(list)
    assert_reserved "single port" "$l" 12345
    assert_reserved "range end" "$l" 20002
    assert_reserved "comma list" "$l" 30001
    teardown
}

test_list_is_canonical_and_privileged_ports_dropped() {
    setup
    cat > "$T/etc/v2ray/v2ray-server.json" << 'EOF'
{"inbounds": [{"port": 10086}, {"port": 10085}, {"port": 10085}, {"port": 443}]}
EOF
    # The kernel prints the list back in the same form, so an unchanged list
    # compares equal and is never rewritten.
    assert_eq "sorted, deduplicated, folded, <1024 dropped" "10085-10086" "$(list)"
    teardown
}

test_nothing_installed_is_fine() {
    setup
    assert_eq "no configs: empty list" "<none>" "$(list)"
    run -n >/dev/null 2>&1
    assert_eq "no configs: exit 0" "0" "$?"
    teardown
}

test_refuses_to_reserve_most_of_the_range() {
    setup
    echo "9999-50000" > "$T/etc/openmptcprouter-vps-admin/reserved-ports"
    run -n >/dev/null 2>&1
    assert_eq "a reservation over half the range is refused" "1" "$?"
    teardown
}

test_quiet_is_quiet() {
    setup
    echo '{"inbounds": [{"port": 10085}]}' > "$T/etc/v2ray/v2ray-server.json"
    assert_eq "-q -n prints nothing" "" "$(run -q -n 2>&1)"
    teardown
}

# Every file the script reads must be watched by the path unit, or a change to
# it would only be picked up at the next boot.
test_path_unit_watches_every_input() {
    local var path missing=""
    for var in V2RAY_CONFIG XRAY_CONFIG SSGO_CONFIG SSLIBEV_CONFIG MQVPN_CONFIG \
               OMR_CONFIG VXLAN_DIR EXTRA_FILE; do
        path=$(sed -n "s|^${var}=\"\${ROOT}\(.*\)\"$|\1|p" "$SCRIPT")
        [ -n "$path" ] || { missing="$missing $var(unparsed)"; continue; }
        grep -qx "PathChanged=$path" "$PATH_UNIT" || missing="$missing $path"
    done
    assert_eq "omr-reserved-ports.path watches every input" "" "$missing"
    local n; n=$(grep -c '^PathChanged=' "$PATH_UNIT")
    assert_eq "and nothing else" "8" "$n"
}

# The path unit starts the service on every write of a watched file, and a
# router sync makes several in a burst: under systemd's default start limit
# that fails the service and takes the path unit down with it.
test_service_has_no_start_limit() {
    local v; v=$(sed -n 's/^StartLimitIntervalSec=//p' "$SERVICE_UNIT")
    assert_eq "omr-reserved-ports.service has no start limit" "0" "$v"
}

for t in \
    test_v2ray_xray_inbounds_including_forwarded_ports \
    test_shadowsocks_go_libev_and_mqvpn \
    test_vxlan_from_config_and_files \
    test_admin_extras_file \
    test_list_is_canonical_and_privileged_ports_dropped \
    test_nothing_installed_is_fine \
    test_refuses_to_reserve_most_of_the_range \
    test_quiet_is_quiet \
    test_path_unit_watches_every_input \
    test_service_has_no_start_limit \
; do
    printf '\n▶ %s\n' "$t"
    "$t"
done

printf '\n─────────────────────────────────────\n'
printf 'Results: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
