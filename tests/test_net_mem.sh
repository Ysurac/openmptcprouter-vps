#!/bin/bash
# Tests for omr-net-mem, which sizes net.ipv4.tcp_mem / udp_mem from RAM.
#
# 90-shadowsocks.conf used to carry fixed page counts - tcp_mem
# "409600 819200 1638400" and udp_mem "4096 87380 16777216" (the tcp_rmem byte
# triple pasted into a page-count sysctl) - which on a 1 GB VPS put the TCP
# pressure threshold at 3.2 GB and the UDP ceiling at 64 GB, so the kernel
# could never apply memory pressure and socket memory grew until the OOM
# killer fired. The same bug on the router OOM-killed netifd on the bench.
#
# /proc/meminfo and the persisted file come from a fixture tree through
# OMR_NM_ROOT; sysctl and ip are PATH-injected fakes, sysctl keeping what it
# is told in files, so the apply path runs too. Requires: bash.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$SCRIPT_DIR/.."
SCRIPT="$REPO/omr-net-mem"
UNIT="$REPO/omr-net-mem.service.in"

PASS=0
FAIL=0
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS+1)); printf '  PASS %s\n' "$desc"
    else
        FAIL=$((FAIL+1)); printf '  FAIL %s\n    expected=%s\n    got=%s\n' "$desc" "$expected" "$actual"
    fi
}
assert_true() { if eval "$2"; then assert_eq "$1" ok ok; else assert_eq "$1" ok "false: $2"; fi; }

setup() {
    T="$(mktemp -d)"
    mkdir -p "$T/bin" "$T/proc" "$T/etc/sysctl.d" "$T/etc/default" "$T/sysctl"
    printf 'MemTotal:         %s kB\n' "${1:-982016}" > "$T/proc/meminfo"   # 959 MB
    printf '409600\t819200\t1638400\n' > "$T/sysctl/net.ipv4.tcp_mem"
    printf '4096\t87380\t16777216\n'  > "$T/sysctl/net.ipv4.udp_mem"
    printf '4096\t87380\t16777216\n'  > "$T/sysctl/net.ipv4.tcp_rmem"
    printf '4096\t87380\t16777216\n'  > "$T/sysctl/net.ipv4.tcp_wmem"
    # what the shipped 90-shadowsocks.conf configures now
    printf 'net.ipv4.tcp_rmem = 4096 87380 134217728\nnet.ipv4.tcp_wmem = 4096 87380 134217728\n' \
        > "$T/etc/sysctl.d/90-shadowsocks.conf"
    cat > "$T/bin/sysctl" << 'EOF'
#!/bin/sh
case "$1" in
    -n) [ -f "$NM_SYSCTL/$2" ] && cat "$NM_SYSCTL/$2" || exit 1 ;;
    -qw) k=${2%%=*}; v=${2#*=}; printf '%s\n' "$v" > "$NM_SYSCTL/$k"; echo "$k" >> "$NM_SYSCTL/.writes" ;;
    *) exit 1 ;;
esac
EOF
    printf '#!/bin/sh\necho "add_addr_accepted 8 subflows 8"\n' > "$T/bin/ip"   # (report only)
    chmod +x "$T/bin/sysctl" "$T/bin/ip"
}
teardown() { rm -rf "$T"; }
run() { ( export PATH="$T/bin:$PATH" OMR_NM_ROOT="$T" NM_SYSCTL="$T/sysctl"; "$SCRIPT" "$@" ); }
# computed triple for tcp or udp
triple() { run -s "${@:2}" 2>/dev/null | sed -n "s/^$1_mem computed *: //p"; }
f() { echo "$1" | awk -v i="$2" '{ print $i }'; }

test_shape_and_ceilings_at_every_size() {
    setup
    local ram t u ram_pages
    for ram in 64 128 256 512 1024 2048 4096 8192 16384; do
        t=$(triple tcp --ram-mb "$ram"); u=$(triple udp --ram-mb "$ram")
        ram_pages=$(( ram * 256 ))
        assert_true "${ram} MB: tcp low < pressure < max" "[ $(f "$t" 1) -lt $(f "$t" 2) ] && [ $(f "$t" 2) -lt $(f "$t" 3) ]"
        assert_true "${ram} MB: tcp+udp ceiling under half the RAM" "[ $(( $(f "$t" 3) + $(f "$u" 3) )) -lt $(( ram_pages / 2 )) ]"
        assert_true "${ram} MB: never below the kernel's RAM/16 and RAM/8" "[ $(f "$t" 2) -ge $(( ram_pages / 16 )) ] && [ $(f "$u" 2) -ge $(( ram_pages / 8 )) ]"
    done
    teardown
}

# A 1 GB droplet reports ~960 MB; it must get the 1 GB tier.
test_tier_boundary_allows_for_memtotal_shortfall() {
    setup
    local p960 p1024
    p960=$(f "$(triple tcp --ram-mb 960)" 2); p1024=$(f "$(triple tcp --ram-mb 1024)" 2)
    assert_true "960 MB is sized like a 1 GB VPS" "[ $p960 -gt $(( p1024 * 9 / 10 )) ]"
    teardown
}

test_this_vps_gets_sane_values() {
    setup
    local t u
    t=$(triple tcp); u=$(triple udp)
    # 959 MB = 245504 pages: 16% for TCP; for UDP 12% (29460) is below the
    # kernel's own RAM/8 (30688), so the kernel default is kept
    assert_eq "tcp_mem for 959 MB" "29460 39280 58920" "$t"
    assert_eq "udp_mem for 959 MB" "23016 30688 46032" "$u"
    teardown
}

test_defaults_file_overrides() {
    setup
    printf 'TCP_PERCENT=20\nUDP_PERCENT=10\n' > "$T/etc/default/omr-net-mem"
    local t; t=$(triple tcp)
    assert_eq "TCP_PERCENT from /etc/default" "$(( 245504 * 20 / 100 ))" "$(f "$t" 2)"
    printf 'TCP_PERCENT=70\n' > "$T/etc/default/omr-net-mem"
    run -n >/dev/null 2>&1
    assert_eq "a 70% share is refused" "1" "$?"
    printf 'TCP_PERCENT=40\nUDP_PERCENT=40\n' > "$T/etc/default/omr-net-mem"
    run -n >/dev/null 2>&1
    assert_eq "ceilings over 75% of RAM are refused" "1" "$?"
    teardown
}

test_apply_persists_once() {
    setup
    run -q
    assert_eq "first run succeeds" "0" "$?"
    assert_eq "tcp_mem applied" "29460 39280 58920" "$(cat "$T/sysctl/net.ipv4.tcp_mem")"
    assert_eq "udp_mem applied" "23016 30688 46032" "$(cat "$T/sysctl/net.ipv4.udp_mem")"
    assert_true "persisted file written" "grep -qx 'net.ipv4.tcp_mem = 29460 39280 58920' '$T/etc/sysctl.d/99-omr-net-mem.conf'"
    assert_eq "tcp_rmem raised to the configured 128 MB" "4096 87380 134217728" "$(cat "$T/sysctl/net.ipv4.tcp_rmem")"
    assert_true "tcp_rmem persisted" "grep -qx 'net.ipv4.tcp_rmem = 4096 87380 134217728' '$T/etc/sysctl.d/99-omr-net-mem.conf'"
    : > "$T/sysctl/.writes"
    local before; before=$(stat -c %Y.%s "$T/etc/sysctl.d/99-omr-net-mem.conf")
    sleep 1; run -q
    assert_eq "second run writes no sysctl" "" "$(cat "$T/sysctl/.writes")"
    assert_eq "second run leaves the file alone" "$before" "$(stat -c %Y.%s "$T/etc/sysctl.d/99-omr-net-mem.conf")"
    teardown
}

test_show_and_dry_run_change_nothing() {
    setup
    run -s >/dev/null 2>&1; run -n >/dev/null 2>&1
    assert_eq "no sysctl written" "no" "$([ -s "$T/sysctl/.writes" ] && echo yes || echo no)"
    assert_eq "no file written" "no" "$([ -f "$T/etc/sysctl.d/99-omr-net-mem.conf" ] && echo yes || echo no)"
    run --ram-mb 2048 >/dev/null 2>&1
    assert_eq "--ram-mb refuses to apply" "1" "$?"
    teardown
}

# rmem/wmem max as computed, from -s
sock() { run -s "$@" 2>/dev/null | awk '/^tcp_rmem configured/ { r = $NF } /^tcp_wmem configured/ { w = $NF } END { print r, w }'; }

# The requirement: a VPS with enough memory (the supported minimum is 1 GB)
# lets one connection reach 10 Gbit/s, i.e. keeps the 128 MB max.
test_one_gigabyte_vps_keeps_10gbit_buffers() {
    setup
    local ram
    for ram in 960 1024 2048 8192; do
        assert_eq "${ram} MB keeps 128 MB" "134217728 134217728" "$(sock --ram-mb $ram)"
    done
    case "$(run -s)" in *"~10.7 at 50 ms"*) assert_eq "reports ~10 Gbit/s at 50 ms" ok ok ;;
                         *) assert_eq "reports ~10 Gbit/s at 50 ms" "~10.7 at 50 ms" "$(run -s | grep '^per connection')" ;; esac
    teardown
}

test_smaller_vps_is_capped_at_the_pressure_threshold() {
    setup
    local v p
    v=$(sock --ram-mb 512); p=$(( $(f "$(triple tcp --ram-mb 512)" 2) * 4096 ))
    assert_eq "512 MB: rmem max = pressure threshold" "$p" "$(f "$v" 1)"
    assert_eq "512 MB: wmem max = pressure threshold" "$p" "$(f "$v" 2)"
    printf 'SOCKET_BUFFERS=0\n' > "$T/etc/default/omr-net-mem"
    assert_eq "SOCKET_BUFFERS=0 keeps the configured max" "134217728 134217728" "$(sock --ram-mb 512)"
    printf 'CONN_SHARE=2\n' > "$T/etc/default/omr-net-mem"
    assert_eq "CONN_SHARE=2 halves the cap" "$(( p / 2 ))" "$(f "$(sock --ram-mb 512)" 1)"
    teardown
}

test_cap_never_raises_and_has_a_kernel_floor() {
    setup
    printf 'net.ipv4.tcp_rmem = 4096 87380 4194304\nnet.ipv4.tcp_wmem = 4096 87380 4194304\n' \
        > "$T/etc/sysctl.d/90-shadowsocks.conf"
    assert_eq "a configured 4 MB max stays 4 MB" "4194304 4194304" "$(sock --ram-mb 8192)"
    printf 'net.ipv4.tcp_rmem = 4096 87380 134217728\nnet.ipv4.tcp_wmem = 4096 87380 134217728\n' \
        > "$T/etc/sysctl.d/90-shadowsocks.conf"
    printf 'CONN_SHARE=50\n' > "$T/etc/default/omr-net-mem"
    # 1 GB: RAM/128 = 7.5 MB rmem floor, wmem floor capped at 4 MB
    assert_eq "floored at the kernel's own default max" "7856128 4194304" "$(sock)"
    teardown
}

# The cap is computed from the configured value, not the live one: after a
# capped run the live value is our cap, and the next run must still see 128 MB.
test_base_comes_from_sysctl_d_not_live() {
    setup
    printf '4096\t87380\t1000000\n' > "$T/sysctl/net.ipv4.tcp_rmem"
    printf 'net.ipv4.tcp_rmem = 1 2 3\n' > "$T/etc/sysctl.d/99-omr-net-mem.conf"
    assert_eq "configured value read from 90-shadowsocks.conf, own file skipped" \
        "134217728" "$(f "$(sock)" 1)"
    teardown
}

# omr-service re-applies 90-shadowsocks.conf with "sysctl -p" on every start,
# so a template that still set these would undo the sizing each time.
test_templates_no_longer_set_the_pools() {
    local f n
    for f in shadowsocks.conf shadowsocks.6.1.conf shadowsocks.6.18.conf; do
        n=$(sed -e 's/#.*//' "$REPO/$f" | grep -cE '^[[:space:]]*net\.ipv4\.(tcp_mem|udp_mem)[[:space:]]*=')
        assert_eq "$f sets no tcp_mem/udp_mem" "0" "$n"
    done
    # systemd-sysctl applies files in name order: ours must come after it
    assert_true "99-omr-net-mem.conf sorts after 90-shadowsocks.conf" "[[ 99-omr-net-mem.conf > 90-shadowsocks.conf ]]"
    for f in shadowsocks.6.1.conf shadowsocks.6.18.conf; do
        assert_true "$f: tcp_rmem max 128 MB (10 Gbit/s up to ~50 ms)" "grep -qE '^net.ipv4.tcp_rmem = [0-9]+ [0-9]+ 134217728$' '$REPO/$f'"
        assert_true "$f: tcp_wmem max 128 MB" "grep -qE '^net.ipv4.tcp_wmem = [0-9]+ [0-9]+ 134217728$' '$REPO/$f'"
    done
    # ...and omr-service must put our file back on top when it re-applies its own
    local l90 l99
    l90=$(grep -n 'sysctl -p /etc/sysctl.d/90-shadowsocks.conf' "$REPO/omr-service" | head -1 | cut -d: -f1)
    l99=$(grep -n 'sysctl -p /etc/sysctl.d/99-omr-net-mem.conf' "$REPO/omr-service" | head -1 | cut -d: -f1)
    assert_true "omr-service re-applies 99-omr-net-mem.conf after 90-shadowsocks.conf" "[ -n '$l99' ] && [ '${l99:-0}' -gt '${l90:-0}' ]"
}

test_unit_runs_early() {
    assert_true "DefaultDependencies=no" "grep -qx 'DefaultDependencies=no' '$UNIT'"
    assert_true "after systemd-sysctl" "grep -q '^After=.*systemd-sysctl.service' '$UNIT'"
    assert_true "before sysinit.target" "grep -q '^Before=.*sysinit.target' '$UNIT'"
    assert_true "wanted by sysinit.target" "grep -qx 'WantedBy=sysinit.target' '$UNIT'"
}

for t in \
    test_shape_and_ceilings_at_every_size \
    test_tier_boundary_allows_for_memtotal_shortfall \
    test_this_vps_gets_sane_values \
    test_defaults_file_overrides \
    test_apply_persists_once \
    test_show_and_dry_run_change_nothing \
    test_one_gigabyte_vps_keeps_10gbit_buffers \
    test_smaller_vps_is_capped_at_the_pressure_threshold \
    test_cap_never_raises_and_has_a_kernel_floor \
    test_base_comes_from_sysctl_d_not_live \
    test_templates_no_longer_set_the_pools \
    test_unit_runs_early \
; do
    printf '\n▶ %s\n' "$t"
    "$t"
done

printf '\n─────────────────────────────────────\n'
printf 'Results: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
