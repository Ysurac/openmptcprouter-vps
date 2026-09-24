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

echo "== vpn1 route migration =="
route_calls="$({
    ip() {
        case "$*" in
            '-4 route show default dev vpn1')
                printf '%s\n' 'default via 192.0.2.1 dev vpn1 proto static'
                ;;
            '-4 route show dev vpn1')
                printf '%s\n' \
                    'default via 192.0.2.1 dev vpn1 proto static' \
                    '192.0.2.0/24 proto kernel scope link src 192.0.2.2'
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
    'ip <-4> <route> <replace> <table> <991337> <default> <via> <192.0.2.1> <dev> <vpn1> <proto> <static>' "$route_calls"
assert_contains "connected route is copied as a complete route" \
    'ip <-4> <route> <replace> <table> <991337> <192.0.2.0/24> <proto> <kernel> <scope> <link> <src> <192.0.2.2>' "$route_calls"
assert_contains "main-table default is removed only after it was copied" \
    'ip <-4> <route> <del> <default> <via> <192.0.2.1> <dev> <vpn1> <proto> <static>' "$route_calls"

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
                printf '%s\n' 'default via 192.0.2.1 dev vpn1'
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
if grep -q 'https://www\.openmptcprouter\.com/server/debian\.sh' omr-update \
    && ! grep -Eq 'wget[^|]*\|[[:space:]]*(ba)?sh' omr-update; then
    pass "full update is downloaded over TLS before execution"
else
    fail "full update is downloaded over TLS before execution"
fi

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
