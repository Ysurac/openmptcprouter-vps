#!/bin/bash
# Regression coverage for runtime shell paths that are difficult to exercise
# without a VPS. Commands that would change networking are replaced by mocks.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT" || exit 1

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }

assert_contains() {
    local description="$1" needle="$2" haystack="$3"
    if grep -Fqx -- "$needle" <<< "$haystack"; then
        pass "$description"
    else
        fail "$description"
        printf '         missing: %s\n' "$needle"
    fi
}

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "== vpn1 route migration =="
# Like the real ip, "route show dev vpn1" leaves the dev field out: it is the
# filter. A route copied without it fails with "No such device".
route_calls="$({
    ip() {
        case "$*" in
            '-4 route show default dev vpn1')
                printf '%s\n' 'default via 192.0.2.1 proto static '
                ;;
            '-4 route show dev vpn1')
                printf '%s\n' \
                    'default via 192.0.2.1 proto static ' \
                    '192.0.2.0/24 proto kernel scope link src 192.0.2.2 '
                ;;
            *)
                printf 'ip'
                printf ' <%s>' "$@"
                printf '\n'
                ;;
        esac
    }
    eval "$(sed -n '/^_vpn1()/,/^}/p' omr-service)"
    _vpn1
} 2>&1)"

assert_contains "default route is copied as a complete route" \
    'ip <-4> <route> <replace> <table> <991337> <default> <via> <192.0.2.1> <proto> <static> <dev> <vpn1>' "$route_calls"
assert_contains "connected route is copied as a complete route" \
    'ip <-4> <route> <replace> <table> <991337> <192.0.2.0/24> <proto> <kernel> <scope> <link> <src> <192.0.2.2> <dev> <vpn1>' "$route_calls"
assert_contains "main-table default is removed only after it was copied" \
    'ip <-4> <route> <del> <default> <via> <192.0.2.1> <proto> <static> <dev> <vpn1>' "$route_calls"

copy_line="$(grep -n '<route> <replace>.*<default>' <<< "$route_calls" | cut -d: -f1)"
delete_line="$(grep -n '<route> <del> <default>' <<< "$route_calls" | cut -d: -f1)"
if [ -n "$copy_line" ] && [ -n "$delete_line" ] && [ "$copy_line" -lt "$delete_line" ]; then
    pass "policy route is installed before the main default is deleted"
else
    fail "policy route is installed before the main default is deleted"
fi

failed_copy_calls="$({
    ip() {
        case "$*" in
            '-4 route show default dev vpn1'|'-4 route show dev vpn1')
                printf '%s\n' 'default via 192.0.2.1 '
                ;;
            '-4 route replace'*)
                printf '%s\n' replace-failed
                return 1
                ;;
            *)
                printf 'ip'
                printf ' <%s>' "$@"
                printf '\n'
                ;;
        esac
    }
    eval "$(sed -n '/^_vpn1()/,/^}/p' omr-service)"
    _vpn1
} 2>&1)"
if grep -q '^replace-failed$' <<< "$failed_copy_calls" \
    && ! grep -q '<route> <del>' <<< "$failed_copy_calls"; then
    pass "a failed policy copy leaves the working default route in place"
else
    fail "a failed policy copy leaves the working default route in place"
fi

echo
echo "== LAN routes from stored lanips =="
# A config stored before the API checked lanips without client2client can
# hold any network: only router LANs are routed, overlap between users is
# kept, and the ccd duplicate check compares whole lines.
mkdir -p "$TMPDIR/etc/openmptcprouter-vps-admin" "$TMPDIR/etc/openvpn/ccd"
cat > "$TMPDIR/etc/openmptcprouter-vps-admin/omr-admin-config.json" <<'JSON'
{"users": [{
  "openmptcprouter": {"username": "openmptcprouter", "vpnremoteip": "10.255.255.2",
    "lanips": ["192.168.1.1/24", "0.0.0.0/0", "10.255.252.0/24", "10.0.0.0/8", "8.8.8.0/24"]},
  "user2": {"username": "user2", "vpnremoteip": "10.255.255.6",
    "lanips": ["192.168.1.1/24", "172.16.5.1/24", "100.64.1.1/24"]}
}]}
JSON
printf 'iroute 192.168.100.0 255.255.255.0\n' > "$TMPDIR/etc/openvpn/ccd/openmptcprouter"
printf 'iroute 172.16.5.0 255.255.255.0\n' > "$TMPDIR/etc/openvpn/ccd/user2"
# The function sends ip's output to /dev/null: the mock logs to a file.
: > "$TMPDIR/ip.log"
(
    ipcalc() {
        local net mask
        case "$2" in
            192.168.1.1/24) net=192.168.1.0/24 mask=255.255.255.0 ;;
            0.0.0.0/0) net=0.0.0.0/0 mask=0.0.0.0 ;;
            10.255.252.0/24) net=10.255.252.0/24 mask=255.255.255.0 ;;
            10.0.0.0/8) net=10.0.0.0/8 mask=255.0.0.0 ;;
            8.8.8.0/24) net=8.8.8.0/24 mask=255.255.255.0 ;;
            172.16.5.1/24) net=172.16.5.0/24 mask=255.255.255.0 ;;
            100.64.1.1/24) net=100.64.1.0/24 mask=255.255.255.0 ;;
        esac
        printf 'Netmask:   %s = x\nNetwork:   %s\n' "$mask" "$net"
    }
    ip() {
        case "$*" in
            'r show '*) ;;
            *) { printf 'ip'; printf ' <%s>' "$@"; printf '\n'; } >> "$TMPDIR/ip.log" ;;
        esac
    }
    eval "$(sed -n '/^_lan_routable()/,/^}/p;/^_lan_route()/,/^}/p' omr-service | sed "s#/etc/#$TMPDIR/etc/#g")"
    _lan_route
)
lan_calls="$(cat "$TMPDIR/ip.log")"
assert_contains "a router LAN is routed to its router" \
    'ip <r> <replace> <192.168.1.0/24> <via> <10.255.255.2>' "$lan_calls"
assert_contains "the same LAN behind another router is routed too" \
    'ip <r> <replace> <192.168.1.0/24> <via> <10.255.255.6>' "$lan_calls"
assert_contains "a 172.16.0.0/12 LAN is routed" \
    'ip <r> <replace> <172.16.5.0/24> <via> <10.255.255.6>' "$lan_calls"
assert_contains "a 100.64.0.0/10 LAN is routed" \
    'ip <r> <replace> <100.64.1.0/24> <via> <10.255.255.6>' "$lan_calls"
for bad in 0.0.0.0/0 10.255.252.0/24 10.0.0.0/8 8.8.8.0/24; do
    if grep -Fq "<$bad>" <<< "$lan_calls" \
        || grep -Fq "iroute ${bad%/*} " "$TMPDIR/etc/openvpn/ccd/openmptcprouter"; then
        fail "$bad is neither routed nor written to ccd"
    else
        pass "$bad is neither routed nor written to ccd"
    fi
done
assert_contains "192.168.1.0 is added next to an existing 192.168.100.0 iroute" \
    'iroute 192.168.1.0 255.255.255.0' "$(cat "$TMPDIR/etc/openvpn/ccd/openmptcprouter")"
if [ "$(grep -c '^iroute 172\.16\.5\.0 255\.255\.255\.0$' "$TMPDIR/etc/openvpn/ccd/user2")" = 1 ]; then
    pass "an iroute already in ccd is not written twice"
else
    fail "an iroute already in ccd is not written twice"
fi

echo
echo "== GRE tunnels of every user =="
# add_gre_tunnels() writes intf files for other users than openmptcprouter:
# the remote end is the vpnremoteip of the file's USERNAME.
mkdir -p "$TMPDIR/etc/openmptcprouter-vps-admin/intf"
cat > "$TMPDIR/etc/openmptcprouter-vps-admin/intf/gre-user0-ip0" <<'INTF'
INTF=eth0
INTFADDR=192.0.2.10
INTFNETMASK=255.255.255.0
NETWORK=10.255.249.0/30
LOCALIP=10.255.249.1
REMOTEIP=10.255.249.2
NETMASK=255.255.255.252
BROADCASTIP=10.255.249.3
USERNAME=openmptcprouter
USERID=0
INTF
cat > "$TMPDIR/etc/openmptcprouter-vps-admin/intf/gre-user1-ip0" <<'INTF'
INTF=eth0
INTFADDR=192.0.2.10
INTFNETMASK=255.255.255.0
NETWORK=10.255.249.4/30
LOCALIP=10.255.249.5
REMOTEIP=10.255.249.6
NETMASK=255.255.255.252
BROADCASTIP=10.255.249.7
USERNAME=user2
USERID=1
INTF
# An old file: no USERNAME, and no NETWORK either.
cat > "$TMPDIR/etc/openmptcprouter-vps-admin/intf/gre-user2-ip0" <<'INTF'
INTFADDR=198.51.100.10
LOCALIP=10.255.249.9
INTF
: > "$TMPDIR/ip.log"
(
    ip() {
        case "$*" in
            'tunnel show '*) ;;
            *) { printf 'ip'; printf ' <%s>' "$@"; printf '\n'; } >> "$TMPDIR/ip.log" ;;
        esac
    }
    eval "$(sed -n '/^_gre_tunnels()/,/^}/p' omr-service | sed "s#/etc/#$TMPDIR/etc/#g")"
    _gre_tunnels
)
gre_calls="$(cat "$TMPDIR/ip.log")"
assert_contains "openmptcprouter's tunnel goes to its vpnremoteip" \
    'ip <tunnel> <add> <gre-user0-ip0> <mode> <gre> <local> <192.0.2.10> <remote> <10.255.255.2>' "$gre_calls"
assert_contains "another user's tunnel goes to that user's vpnremoteip" \
    'ip <tunnel> <add> <gre-user1-ip0> <mode> <gre> <local> <192.0.2.10> <remote> <10.255.255.6>' "$gre_calls"
assert_contains "a file without USERNAME belongs to openmptcprouter" \
    'ip <tunnel> <add> <gre-user2-ip0> <mode> <gre> <local> <198.51.100.10> <remote> <10.255.255.2>' "$gre_calls"
if grep -Fq '<10.255.249.4/30> <dev> <gre-user2-ip0>' <<< "$gre_calls"; then
    fail "a key missing from a file is not taken from the previous one"
else
    pass "a key missing from a file is not taken from the previous one"
fi

echo
echo "== multipath device match =="
# "ip mptcp endpoint show" prints "... dev eth0 ": eth0 must not pick up the
# endpoints of eth0.100.
mkdir -p "$TMPDIR/bin"
cat > "$TMPDIR/bin/ip" <<'IP'
#!/bin/sh
case "$*" in
    'mptcp endpoint show')
        printf '%s\n' '192.0.2.1 id 1 signal dev eth0.100 ' '192.0.2.2 id 2 subflow fullmesh dev eth0 ' '192.0.2.3 id 3 subflow '
        ;;
    *) echo "ip $*" ;;
esac
IP
chmod +x "$TMPDIR/bin/ip"
endpoint_lookup="$(sed -n '/^        \(ENDPOINTS\|ID\)=/,/^        IFF=/p' multipath)"
for case in 'eth0:ID=2 IFF=subflow' 'eth0.100:ID=1 IFF=signal' 'eth1:ID= IFF='; do
    device="${case%%:*}"
    got="$(PATH="$TMPDIR/bin:$PATH" DEVICE="$device" sh -c "$endpoint_lookup"'
        echo "ID=$ID IFF=$IFF"')"
    if [ -n "$endpoint_lookup" ] && [ "$got" = "${case#*:}" ]; then
        pass "$device only gets its own endpoints"
    else
        fail "$device only gets its own endpoints"
        printf '         got: %s\n' "$got"
    fi
done

echo
echo "== unit-file existence guard =="
unit_function="$(sed -n '/^_unit_exists()/,/^}/p' omr-service)"
if bash -c 'systemctl() { return 0; }; eval "$1"; _unit_exists missing.service' _ "$unit_function"; then
    fail "an empty systemctl result is treated as absent"
else
    pass "an empty systemctl result is treated as absent"
fi
if bash -c 'systemctl() { printf "%s\n" "present.service enabled enabled"; }; eval "$1"; _unit_exists present.service' _ "$unit_function"; then
    pass "a listed systemd unit is treated as present"
else
    fail "a listed systemd unit is treated as present"
fi

echo
echo "== update and bypass safety invariants =="
if grep -q 'https://www\.openmptcprouter\.com/${VPSPATH}/debian\.sh' omr-update \
    && ! grep -Eq 'wget[^|]*\|[[:space:]]*(ba)?sh' omr-update; then
    pass "full update is downloaded over TLS before execution"
else
    fail "full update is downloaded over TLS before execution"
fi
# The full reinstall takes the channel of the installed installer (a
# server-test VPS stays on server-test), stable "server" when it has none.
upd_tmp="$(mktemp -d)"
sed "s|/usr/share/omr-server/debian9-x86_64.sh|$upd_tmp/installer.sh|" omr-update > "$upd_tmp/omr-update"
upd_channel() {
    sed -n '/^INSTALLED_INSTALLER=/,/^\[ -n "\$VPSPATH" \]/p' "$upd_tmp/omr-update" > "$upd_tmp/head.sh"
    sh -c ". '$upd_tmp/head.sh'; echo \"\$VPSPATH\""
}
if grep -q 'https://www\.openmptcprouter\.com/${VPSPATH}/debian\.sh' omr-update; then
    pass "full update URL follows VPSPATH"
else
    fail "full update URL no longer follows VPSPATH"
fi
printf 'VPSPATH="server-test"\n' > "$upd_tmp/installer.sh"
[ "$(upd_channel)" = "server-test" ] && pass "channel read from the installed installer" || fail "channel not read from the installed installer (got $(upd_channel))"
rm -f "$upd_tmp/installer.sh"
[ "$(upd_channel)" = "server" ] && pass "channel defaults to server without an installed installer" || fail "channel default is $(upd_channel), not server"
printf 'VPSPATH="x/../../evil"\n' > "$upd_tmp/installer.sh"
[ "$(upd_channel)" = "server" ] && pass "a VPSPATH that is not a plain name is ignored" || fail "VPSPATH $(upd_channel) taken as is"
rm -rf "$upd_tmp"

ipv6_rule_line="$(grep -n 'ip -6 rule add' omr-bypass | cut -d: -f1)"
ipv6_route_line="$(grep -n 'ip -6 route replace default' omr-bypass | cut -d: -f1)"
checksum_line="$(grep -Fn '.bypass_checksum = $c' omr-bypass | tail -n 1 | cut -d: -f1)"
if [ -n "$ipv6_rule_line" ] && [ -n "$ipv6_route_line" ]; then
    pass "IPv6 bypass uses the IPv6 rule and route families"
else
    fail "IPv6 bypass uses the IPv6 rule and route families"
fi
if [ -n "$checksum_line" ] && [ "$checksum_line" -gt "$ipv6_route_line" ]; then
    pass "bypass checksum is committed after routing succeeds"
else
    fail "bypass checksum is committed after routing succeeds"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
