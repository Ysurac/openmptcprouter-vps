#!/bin/bash
# Tests for omr-6in4-run, the VPS-side 6in4 tunnel of each user:
#   - start: sit tunnel to REMOTEIP, LOCALIP6 on it, route to the ULA prefix
#     (none for ULA=auto)
#   - the config file is read as data: it carries values a router sent
#     through the API and the script runs as root, so nothing in it may run
#
# `ip` is faked (PATH-injected) so this runs without root or real devices.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$SCRIPT_DIR/../omr-6in4-run"
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

# ── Fake `ip`: logs every call, every device absent ───────────────────────────

FAKE_BIN="$TMPDIR/bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/ip" << 'FAKE'
#!/bin/sh
echo "ip $*" >> "$IP_CALLS"
exit 0
FAKE
chmod +x "$FAKE_BIN/ip"

_run() {
    local action="$1" cfgfile="$2"
    IP_CALLS="$TMPDIR/ip_calls.log"
    : > "$IP_CALLS"
    PATH="$FAKE_BIN:$PATH" IP_CALLS="$IP_CALLS" sh "$SCRIPT" "$action" "$cfgfile" >/dev/null 2>&1
    echo "$IP_CALLS"
}

_write_cfg() {
    local name="$1"; shift
    local f="$TMPDIR/$name"
    : > "$f"
    for kv in "$@"; do echo "$kv" >> "$f"; done
    echo "$f"
}

# ── start ─────────────────────────────────────────────────────────────────────

test_start_sets_tunnel_address_and_ula_route() {
    local cfg calls
    cfg=$(_write_cfg user0 'LOCALIP=10.255.255.1' 'REMOTEIP=10.255.255.2' \
        'LOCALIP6=fd00::a00:1/126' 'REMOTEIP6=fd00::a00:2/126' 'ULA=fd12:3456:789a::/48')
    calls=$(_run start "$cfg")
    assert_calls_contain "sit tunnel created" "$calls" \
        "ip tunnel add omr-6in4-user0 mode sit remote 10.255.255.2 local 10.255.255.1"
    assert_calls_contain "tunnel address set" "$calls" "ip -6 addr add fd00::a00:1/126 dev omr-6in4-user0"
    assert_calls_contain "ULA routed to the router" "$calls" \
        "ip route replace fd12:3456:789a::/48 via fd00::a00:2 dev omr-6in4-user0"
}

test_ula_auto_adds_no_route() {
    local cfg calls
    cfg=$(_write_cfg user1 'LOCALIP=10.255.255.5' 'REMOTEIP=10.255.255.6' \
        'LOCALIP6=fd00::a01:1/126' 'REMOTEIP6=fd00::a01:2/126' 'ULA=auto')
    calls=$(_run start "$cfg")
    assert_calls_lack "no ULA route" "$calls" "ip route replace"
}

test_config_is_not_run_as_shell_code() {
    local cfg calls
    rm -f "$TMPDIR/pwned"*
    cfg=$(_write_cfg user2 'LOCALIP=10.255.255.9' 'REMOTEIP=10.255.255.10' \
        'LOCALIP6=fd00::a02:1/126$(touch '"$TMPDIR"'/pwned1)' \
        'REMOTEIP6=fd00::a02:2/126' \
        'ULA=fd12::/48;touch '"$TMPDIR"'/pwned2' \
        'touch '"$TMPDIR"'/pwned3' \
        'PATH=/nonexistent')
    calls=$(_run start "$cfg")
    assert_eq "no command from the file ran" "" "$(ls "$TMPDIR"/pwned* 2>/dev/null)"
    assert_calls_contain "valid keys still applied, PATH not taken from the file" "$calls" \
        "ip tunnel add omr-6in4-user2 mode sit remote 10.255.255.10 local 10.255.255.9"
    assert_calls_lack "invalid LOCALIP6 ignored" "$calls" "\$(touch"
    assert_calls_lack "invalid ULA ignored" "$calls" "ip route replace"
}

# ── Run ───────────────────────────────────────────────────────────────────────

for t in \
    test_start_sets_tunnel_address_and_ula_route \
    test_ula_auto_adds_no_route \
    test_config_is_not_run_as_shell_code \
; do
    printf '\n▶ %s\n' "$t"
    "$t"
done

printf '\n─────────────────────────────────────\n'
printf 'Results: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
