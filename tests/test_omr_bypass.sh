#!/bin/bash
# Tests for omr-bypass, which sends the traffic to the addresses the router
# lists in /bypass out through bypass_intf (vpn1 by default): it marks them
# (0x539) from its own nftables table, inet omr_bypass, and routes the mark
# through table 991337. nftables/omr.nft forwards and masquerades that mark.
#
# Issue #4384: the iptables/ipset version failed with exit 127 on every run
# where iptables isn't installed, stayed off for good after an nftables
# reload or a reboot (the list's checksum still matched, so it exited before
# doing anything), and one address ipset refused ended every run under set -e.
# On top of that, the router's IPv4 for the bypassed addresses hit omr.nft's
# forward reject, and what did get out left vpn1 with a tunnel address.
#
# 1. omr-bypass against PATH-injected nft/ip/iptables/ipset fakes, with its
#    config directory redirected to a temporary one. Always runs.
# 2. The real nft in a network namespace of its own (root, or an unprivileged
#    user namespace): the sets it loads, the ruleset it survives, the packets
#    it marks.
# 3. Root only: a router, an upstream VPN peer and the internet, each in a
#    namespace, around a VPS one with the shipped ruleset: the bypassed
#    addresses only answer through vpn1, and only to vpn1's address.
#
# Requires: bash, jq. Optional: nft, unshare, ping (sections 2 and 3).

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPT="$ROOT/omr-bypass"
cd "$ROOT" || exit 1

command -v jq > /dev/null 2>&1 || { echo "SKIP jq is not installed"; exit 77; }

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
note() { printf '  note %s\n' "$1"; }
assert_eq() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1"
        printf '         expected: %s\n         got:      %s\n' "$(printf '%s' "$2" | tr '\n' ' ')" "$(printf '%s' "$3" | tr '\n' ' ')"
    fi
}
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }

T="$(mktemp -d)"
cleanup() {
    for ns in vps router vpnpeer inet; do ip netns del "omrbt-$ns" 2> /dev/null; done
    rm -rf "$T"
}
trap cleanup EXIT

# omr-bypass with its config directory in $T/cfg.
sed "s#/etc/openmptcprouter-vps-admin#$T/cfg#g" "$SCRIPT" > "$T/omr-bypass"

# ── 1. against fakes ─────────────────────────────────────────────────────

# $T/sys: the real tools the script and the fakes use, and nothing else, so
# that iptables and ipset only exist when a test puts a fake of them in $T/bin.
mkdir -p "$T/sys"
for c in jq awk grep tr md5sum mv cat sed rm touch basename; do
    ln -s "$(command -v $c)" "$T/sys/$c"
done

fake_nft() {
    cat > "$T/bin/nft" << 'EOF'
#!/bin/sh
echo "nft $*" >> "$LOG"
rejected() { for bad in $NFT_REJECT; do case "$1" in *"$bad"*) return 0 ;; esac; done; return 1; }
case "$*" in
"list chain inet omr_bypass output")
    [ -f "$ST/table" ] ;;
"-f -")
    in="$(cat)"
    case "$in" in
    "add element inet omr_bypass "*)
        rejected "$in" && exit 1
        set="$(echo "$in" | awk '{print $5}')"
        for e in $(echo "$in" | sed 's/.*{ \(.*\) }.*/\1/' | tr ',' ' '); do
            echo "$set $e" >> "$ST/elements"
        done ;;
    *)
        printf '%s\n' "$in" > "$ST/table"
        rm -f "$ST/elements" ;;
    esac ;;
"add element inet omr_bypass "*)
    rejected "$6" && exit 1
    echo "$5 $(echo "$6" | sed 's/[{} ]//g')" >> "$ST/elements" ;;
*)
    echo "unexpected: nft $*" >> "$LOG"; exit 1 ;;
esac
EOF
}

fake_ip() {
    cat > "$T/bin/ip" << 'EOF'
#!/bin/sh
echo "ip $*" >> "$LOG"
case "$*" in
"rule show")
    [ -f "$ST/rule4" ] && printf '1:\tfrom all fwmark 0x539 lookup 991337\n'
    exit 0 ;;
"rule del prio 1 fwmark 0x539 lookup 991337")
    [ -f "$ST/rule4" ] && rm "$ST/rule4" ;;
"rule add prio 1 fwmark 0x539 lookup 991337")
    touch "$ST/rule4" ;;
"-6 rule del prio 1 fwmark 0x539 lookup 991337")
    [ -f "$ST/rule6" ] && rm "$ST/rule6" ;;
"-6 rule add prio 1 fwmark 0x539 lookup 991337")
    touch "$ST/rule6" ;;
"-4 r show dev "*)
    cat "$ST/main4" 2> /dev/null ;;
"-6 r show dev "*)
    cat "$ST/main6" 2> /dev/null ;;
"-4 route show table 991337 default")
    cat "$ST/t4" 2> /dev/null ;;
"-6 route show table 991337 default")
    cat "$ST/t6" 2> /dev/null ;;
"route replace default via "*" dev "*" table 991337")
    echo "default via $5 dev $7" > "$ST/t4" ;;
"-6 route replace default via "*" dev "*" table 991337")
    echo "default via $6 dev $8" > "$ST/t6" ;;
*)
    echo "unexpected: ip $*" >> "$LOG"; exit 1 ;;
esac
EOF
}

# The old script's leftovers: both chains, $1 jumps from PREROUTING and one
# from OUTPUT, in iptables and ip6tables; its two ipsets next to another one.
fake_old_leftovers() {
    for n in iptables ip6tables; do
        cat > "$T/bin/$n" << 'EOF'
#!/bin/sh
n="$(basename "$0")"
echo "$n $*" >> "$LOG"
take() { c="$(cat "$ST/$n.$1" 2> /dev/null || echo 0)"; [ "$c" -gt 0 ] || return 1; echo $((c - 1)) > "$ST/$n.$1"; }
case "$*" in
"-w -t mangle -n -L omr-bypass"|"-w -t mangle -n -L omr-bypass-local")
    [ -f "$ST/$n.chains" ] ;;
"-w -t mangle -D PREROUTING -j omr-bypass")
    take pre ;;
"-w -t mangle -D OUTPUT -m addrtype ! --dst-type LOCAL -j omr-bypass-local")
    take out ;;
"-w -t mangle -F omr-bypass"|"-w -t mangle -F omr-bypass-local")
    ;;
"-w -t mangle -X omr-bypass"|"-w -t mangle -X omr-bypass-local")
    [ -f "$ST/$n.pre" ] && [ "$(cat "$ST/$n.pre")" -gt 0 ] && exit 1
    echo "$2 $3 $4 $5" >> "$ST/$n.removed" ;;
*)
    echo "unexpected: $n $*" >> "$LOG"; exit 1 ;;
esac
EOF
        chmod +x "$T/bin/$n"
        touch "$T/st/$n.chains"
        echo "$1" > "$T/st/$n.pre"
        echo 1 > "$T/st/$n.out"
    done
    cat > "$T/bin/ipset" << 'EOF'
#!/bin/sh
echo "ipset $*" >> "$LOG"
case "$*" in
"-n list") cat "$ST/ipsets" ;;
"-q destroy "*) echo "$3" >> "$ST/destroyed" ;;
*) echo "unexpected: ipset $*" >> "$LOG"; exit 1 ;;
esac
EOF
    chmod +x "$T/bin/ipset"
    printf '%s\n' omr_dst_bypass_srv_vpn1 omr6_dst_bypass_srv_vpn1 omr_dst_bypass_srv_wg0 fail2ban-sshd > "$T/st/ipsets"
}

# A fresh VPS: vpn1 with a gateway in the main table, no checksum yet.
setup() {
    rm -rf "${T:?}/bin" "$T/st" "$T/cfg" "$T/log"
    mkdir -p "$T/bin" "$T/st" "$T/cfg"
    fake_nft; fake_ip; chmod +x "$T/bin/"*
    echo 'default via 10.8.0.1 proto static' > "$T/st/main4"
    echo '{"users":[],"bypass_intf":"vpn1"}' > "$T/cfg/omr-admin-config.json"
    NFT_REJECT=""
}
set_list() { printf '%s\n' "$1" > "$T/cfg/omr-bypass.json"; }
run_bypass() {
    : > "$T/log"
    env -i PATH="$T/bin:$T/sys" LOG="$T/log" ST="$T/st" NFT_REJECT="$NFT_REJECT" \
        /bin/sh "$T/omr-bypass" > "$T/out" 2> "$T/err"
    RC=$?
}
saved_checksum() { jq -r .bypass_checksum "$T/cfg/omr-admin-config.json"; }
list_checksum() { md5sum "$T/cfg/omr-bypass.json" | awk '{print $1}'; }
elements() { sort "$T/st/elements" 2> /dev/null; }
applied() { grep -q '^nft -f -$' "$T/log"; }
unexpected() { grep '^unexpected' "$T/log"; }

fake_tests() {
echo "== omr-bypass against fakes =="

setup
set_list '{"vpn1":{"ipv4":["8.8.8.8","1.1.1.0/24","9.9.9.1-9.9.9.9","5.5.5.5 6.6.6.6","1.1.1.1; flush ruleset","x{y}",null,7],"ipv6":["2606:4700::1111","2a00::/16"]}}'
run_bypass
assert_eq "applies a list with neither iptables nor ipset installed (was exit 127)" 0 "$RC"
assert_eq "no command outside the expected ones" "" "$(unexpected)"
check "the table is loaded in one nft -f" grep -q '^table inet omr_bypass {' "$T/st/table"
assert_eq "only the words that can be an address, a prefix or a range reach nft" \
    "$(printf '%s\n' 'dst4 1.1.1.0/24' 'dst4 5.5.5.5' 'dst4 6.6.6.6' 'dst4 8.8.8.8' 'dst4 9.9.9.1-9.9.9.9' 'dst6 2606:4700::1111' 'dst6 2a00::/16' | sort)" \
    "$(elements)"
assert_eq "each set is filled by one nft call" 2 "$(grep -c '^nft -f -$' "$T/log" | awk '{print $1 - 1}')"
check "the fwmark rule is in place" test -f "$T/st/rule4"
assert_eq "table 991337 routes through vpn1's gateway" "default via 10.8.0.1 dev vpn1" "$(cat "$T/st/t4" 2> /dev/null)"
check "no IPv6 rule without an IPv6 gateway" test ! -f "$T/st/rule6"
assert_eq "the checksum is saved after a run that applied the list" "$(list_checksum)" "$(saved_checksum)"

run_bypass
assert_eq "an unchanged list, still in place: exit 0" 0 "$RC"
check "an unchanged list, still in place: nothing is reloaded" eval '! applied'

rm "$T/st/table"
run_bypass
assert_eq "after an nftables reload (table gone, same checksum): exit 0" 0 "$RC"
check "after an nftables reload (table gone, same checksum): the list is applied again" applied
assert_eq "after an nftables reload: the addresses are back" 7 "$(elements | wc -l | tr -d ' ')"

rm "$T/st/rule4" "$T/st/t4"
run_bypass
assert_eq "after a reboot (rule and route gone, table back by itself): exit 0" 0 "$RC"
check "after a reboot: the rule is put back" test -f "$T/st/rule4"
check "after a reboot: the route is put back" test -s "$T/st/t4"

setup
set_list '{"vpn1":{"ipv4":["8.8.8.8"]}}'
rm "$T/st/main4"
echo 'default via 10.8.0.1 dev vpn1 proto static' > "$T/st/t4"
run_bypass
assert_eq "route only in table 991337, as omr-service leaves it: exit 0" 0 "$RC"
check "route only in table 991337: the route is not replaced" eval '! grep -q "route replace" "$T/log"'
assert_eq "route only in table 991337: the checksum is saved" "$(list_checksum)" "$(saved_checksum)"

setup
set_list '{"vpn1":{"ipv4":["8.8.8.8"]}}'
rm "$T/st/main4"
run_bypass
assert_eq "no route through vpn1 anywhere: exit 1, for the timer to retry" 1 "$RC"
check "no route through vpn1 anywhere: says why" grep -q 'no default route via vpn1 in table 991337' "$T/err"
assert_eq "no route through vpn1 anywhere: the checksum is not saved" null "$(saved_checksum)"
echo 'default via 10.8.0.1 dev vpn1 proto static' > "$T/st/t4"
run_bypass
assert_eq "no route, then omr-service copies it: the next run succeeds" 0 "$RC"

setup
set_list '{"vpn1":{"ipv4":["8.8.8.8"]}}'
printf '%s\n' '10.1.0.0/16 via 10.8.0.1 proto static' '10.2.0.0/16 via 10.8.0.9 proto static' > "$T/st/main4"
printf '%s\n' 'fe80::/64 proto kernel metric 256 pref medium' '2001:db8::/32 via fd00::1 metric 1024 pref medium' > "$T/st/main6"
run_bypass
assert_eq "several gateways: table 991337 uses the first one" "default via 10.8.0.1 dev vpn1" "$(cat "$T/st/t4")"
assert_eq "an IPv6 gateway: table 991337 gets an IPv6 default too" "default via fd00::1 dev vpn1" "$(cat "$T/st/t6" 2> /dev/null)"
check "an IPv6 gateway: the IPv6 rule is in place" test -f "$T/st/rule6"

setup
set_list '{"vpn1":{"ipv4":["8.8.8.8","300.1.1.1","9.9.9.9"]}}'
NFT_REJECT="300.1.1.1"
run_bypass
assert_eq "nft refuses one address: exit 0 (was exit 1 on every run)" 0 "$RC"
assert_eq "nft refuses one address: the others are added one at a time" \
    "$(printf '%s\n' 'dst4 8.8.8.8' 'dst4 9.9.9.9')" "$(elements)"
assert_eq "nft refuses one address: the checksum is saved" "$(list_checksum)" "$(saved_checksum)"

setup
echo '{"users":[],"bypass_intf":"wg0"}' > "$T/cfg/omr-admin-config.json"
set_list '{"vpn1":{"ipv4":["8.8.8.8"]},"wg0":{"ipv4":["9.9.9.9"]}}'
run_bypass
assert_eq "bypass_intf=wg0: the wg0 list is the one applied" "dst4 9.9.9.9" "$(elements)"
assert_eq "bypass_intf=wg0: table 991337 routes through wg0" "default via 10.8.0.1 dev wg0" "$(cat "$T/st/t4")"

setup
set_list '{"vpn2":{"ipv4":["8.8.8.8"]}}'
run_bypass
assert_eq "no list for the interface: exit 0" 0 "$RC"
check "no list for the interface: no element is added" eval '! grep -q "add element" "$T/log"'

setup
run_bypass
assert_eq "no omr-bypass.json: exit 0" 0 "$RC"
assert_eq "no omr-bypass.json: nothing is run" "" "$(cat "$T/log")"

setup
set_list '{"vpn1":{"ipv4":["8.8.8.8"]}}'
fake_old_leftovers 2
run_bypass
assert_eq "old iptables/ipset leftovers: exit 0" 0 "$RC"
assert_eq "no command outside the expected ones, with the leftovers" "" "$(unexpected)"
for n in iptables ip6tables; do
    assert_eq "$n: every PREROUTING jump is removed" 0 "$(cat "$T/st/$n.pre")"
    assert_eq "$n: the OUTPUT jump is removed" 0 "$(cat "$T/st/$n.out")"
    assert_eq "$n: both chains are deleted" \
        "$(printf '%s\n' '-t mangle -X omr-bypass' '-t mangle -X omr-bypass-local')" "$(cat "$T/st/$n.removed" 2> /dev/null)"
done
assert_eq "the old ipsets, and only them, are destroyed" \
    "$(printf '%s\n' omr_dst_bypass_srv_vpn1 omr6_dst_bypass_srv_vpn1 omr_dst_bypass_srv_wg0)" "$(cat "$T/st/destroyed" 2> /dev/null)"
}

# ── 2. the real nft, in a network namespace ──────────────────────────────

# Run in the namespace by section_netns below: prints PASS/FAIL lines.
netns_tests() {
    PATH="$PATH:/usr/sbin:/sbin"
    ip link set lo up
    ip link add wan type dummy && ip link set wan up
    ip addr add 192.0.2.2/24 dev wan && ip route add default via 192.0.2.1
    ip -6 addr add 2001:db8:1::2/64 dev wan nodad && ip -6 route add default via 2001:db8:1::1
    ip link add vpn1 type dummy && ip link set vpn1 up
    ip addr add 10.99.0.2/24 dev vpn1 && ip route add 10.98.0.0/16 via 10.99.0.1
    ip -6 addr add 2001:db8:99::2/64 dev vpn1 nodad && ip -6 route add 2001:db8:98::/48 via 2001:db8:99::1
    mkdir -p "$T/cfg"
    echo '{"users":[],"bypass_intf":"vpn1"}' > "$T/cfg/omr-admin-config.json"
    set_list '{"vpn1":{"ipv4":["8.8.8.8","1.1.1.0/24","1.1.1.5","9.9.9.1-9.9.9.9","300.1.1.1","4.4.4.4/24","2001:db8::1","5.5.5.5 6.6.6.6","1.1.1.1; flush ruleset"],"ipv6":["2606:4700::1111","2a00::/16","1.2.3.4"]}}'
    sh "$T/omr-bypass"
    assert_eq "nft takes the list, whatever is wrong with some of it: exit 0" 0 $?
    set_elements() { nft list set inet omr_bypass "$1" | tr -d '\n\t ' | sed -n 's/.*elements={\([^}]*\)}.*/\1/p' | tr ',' '\n' | sort; }
    assert_eq "dst4 holds the valid IPv4 words, prefixes masked, covered addresses merged" \
        "$(printf '%s\n' 1.1.1.0/24 4.4.4.0/24 5.5.5.5 6.6.6.6 8.8.8.8 9.9.9.1-9.9.9.9 | sort)" "$(set_elements dst4)"
    assert_eq "dst6 holds the valid IPv6 words only" \
        "$(printf '%s\n' 2606:4700::1111 2a00::/16 | sort)" "$(set_elements dst6)"
    check "the fwmark rule is in place" sh -c 'ip rule show | grep -q "fwmark 0x539 lookup 991337"'
    check "table 991337 routes through vpn1" sh -c 'ip route show table 991337 | grep -q "default via 10.99.0.1 dev vpn1"'
    check "table 991337 routes IPv6 through vpn1" sh -c 'ip -6 route show table 991337 | grep -q "default via 2001:db8:99::1 dev vpn1"'

    before="$(nft list ruleset | md5sum)"
    sh "$T/omr-bypass"
    assert_eq "an unchanged list, still in place: the ruleset is left alone" "$before" "$(nft list ruleset | md5sum)"

    # The shipped ruleset, loaded as nftables.service loads it: flush ruleset.
    mkdir -p "$T/fw"
    cp nftables/omr.nft nftables/omr-vars.nft "$T/fw/"
    sed "s|/etc/nftables/|$T/fw/|" nftables.conf > "$T/fw/nftables.conf"
    if nft -f "$T/fw/nftables.conf"; then
        check "the shipped nftables.conf removes the table (flush ruleset)" sh -c '! nft list table inet omr_bypass > /dev/null 2>&1'
        sh "$T/omr-bypass"
        assert_eq "after the shipped nftables.conf is reloaded: exit 0" 0 $?
        assert_eq "after the shipped nftables.conf is reloaded: the addresses are back" 6 "$(set_elements dst4 | wc -l | tr -d ' ')"
        check "the OMR ruleset is still there next to it" sh -c 'nft list chain inet omr forward > /dev/null'
    elif [ "$(id -u)" = 0 ] && [ -z "$NETNS_USERNS" ]; then
        fail "the shipped nftables.conf loads in the namespace"
    else
        note "the shipped nftables.conf does not load in an unprivileged namespace here (modules it needs are not loaded); run this test as root"
    fi

    # What the VPS sends itself, counted where it leaves through vpn1.
    nft -f - << 'EOF'
table inet omrbt_count {
    chain post {
        type filter hook postrouting priority 300; policy accept;
        oifname "vpn1" ip daddr 8.8.8.8 counter
        oifname "vpn1" ip daddr 8.8.4.4 counter
        oifname "vpn1" ip6 daddr 2606:4700::1111 counter
        oifname "vpn1" ip6 daddr 2606:4700::1001 counter
    }
}
EOF
    if command -v ping > /dev/null 2>&1; then
        for a in 8.8.8.8 8.8.4.4 2606:4700::1111 2606:4700::1001; do ping -c 3 -i 0.2 -W 1 -q "$a" > /dev/null 2>&1; done
        counted() { nft list chain inet omrbt_count post | grep -F "daddr $1 " | sed -n 's/.*counter packets \([0-9]*\).*/\1/p'; }
        assert_eq "the VPS's own IPv4 to a bypassed address leaves through vpn1" 3 "$(counted 8.8.8.8)"
        assert_eq "the VPS's own IPv4 to any other address doesn't" 0 "$(counted 8.8.4.4)"
        assert_eq "the VPS's own IPv6 to a bypassed address leaves through vpn1" 3 "$(counted 2606:4700::1111)"
        assert_eq "the VPS's own IPv6 to any other address doesn't" 0 "$(counted 2606:4700::1001)"
    else
        note "ping is not installed; skipping the marking check"
    fi
}

section_netns() {
echo
echo "== the real nft, in a network namespace =="
if ! command -v nft > /dev/null 2>&1 && ! [ -x /usr/sbin/nft ]; then
    note "nft is not installed; skipping"
elif ! command -v unshare > /dev/null 2>&1; then
    note "unshare is not installed; skipping"
else
    if [ "$(id -u)" = 0 ]; then ns_cmd="unshare -n"; else ns_cmd="env NETNS_USERNS=1 unshare -rn"; fi
    if ! $ns_cmd sh -c 'PATH="$PATH:/usr/sbin:/sbin"; ip link add omrbt0 type dummy && nft list tables' > /dev/null 2>&1; then
        note "cannot create a network namespace with nft in it here; run this test as root"
    else
        out="$($ns_cmd bash "$SCRIPT_DIR/$(basename "$0")" --in-netns 2>&1)"
        printf '%s\n' "$out" | grep -v '^netns-counts \|^== '
        counts="$(printf '%s\n' "$out" | sed -n 's/^netns-counts //p')"
        if [ -n "$counts" ]; then
            set -- $counts
            PASS=$((PASS + $1)); FAIL=$((FAIL + $2))
        else
            fail "the namespace run did not finish"
        fi
    fi
fi
}

# ── 3. end to end, through the shipped ruleset (root) ────────────────────

# router -- tun0 -- vps -- vpn1 -- vpnpeer
#                       `-- eth0 -- inet
# The bypassed addresses only exist at vpnpeer, the others only on the
# internet side, and neither has a route back to the router's tunnel address
# or to the other side: a reply comes back only when the packet went out the
# right interface with that interface's address.
e2e() {
    local vps=omrbt-vps router=omrbt-router peer=omrbt-vpnpeer inet=omrbt-inet ns l
    for ns in $vps $router $peer $inet; do ip netns add $ns && ip -n $ns link set lo up || return 1; done
    ip -n $vps link add tun0 type veth peer name tun0 netns $router
    ip -n $vps link add vpn1 type veth peer name vpn1 netns $peer
    ip -n $vps link add eth0 type veth peer name eth0 netns $inet
    for ns in $vps $router $peer $inet; do for l in tun0 vpn1 eth0; do ip -n $ns link set $l up 2> /dev/null; done; done
    ip netns exec $vps sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
    ip -n $vps addr add 10.255.252.1/30 dev tun0; ip -n $router addr add 10.255.252.2/30 dev tun0
    ip -n $router route add default via 10.255.252.1
    ip -n $vps -6 addr add fd00::a00:1/126 dev tun0 nodad; ip -n $router -6 addr add fd00::a00:2/126 dev tun0 nodad
    ip -n $router -6 route add default via fd00::a00:1
    ip -n $vps addr add 192.0.2.2/24 dev eth0; ip -n $inet addr add 192.0.2.1/24 dev eth0
    ip -n $vps route add default via 192.0.2.1
    ip -n $vps -6 addr add 2001:db8:1::2/64 dev eth0 nodad; ip -n $inet -6 addr add 2001:db8:1::1/64 dev eth0 nodad
    ip -n $vps -6 route add default via 2001:db8:1::1
    # vpn1 as omr-service leaves it: its IPv4 default only in table 991337.
    ip -n $vps addr add 10.99.0.2/24 dev vpn1; ip -n $peer addr add 10.99.0.1/24 dev vpn1
    ip -n $vps route add default via 10.99.0.1 dev vpn1 table 991337
    ip -n $vps -6 addr add 2001:db8:99::2/64 dev vpn1 nodad; ip -n $peer -6 addr add 2001:db8:99::1/64 dev vpn1 nodad
    ip -n $vps -6 route add 2001:db8:98::/48 via 2001:db8:99::1 dev vpn1
    ip -n $peer addr add 8.8.8.8/32 dev lo; ip -n $peer -6 addr add 2606:4700::1111/128 dev lo
    ip -n $inet addr add 8.8.4.4/32 dev lo; ip -n $inet -6 addr add 2606:4700::1001/128 dev lo

    mkdir -p "$T/cfg" "$T/fw"
    echo '{"users":[],"bypass_intf":"vpn1"}' > "$T/cfg/omr-admin-config.json"
    set_list '{"vpn1":{"ipv4":["8.8.8.8"],"ipv6":["2606:4700::1111"]}}'
    load_rules() {
        cp nftables/omr-vars.nft "$T/fw/"
        sed "s|/etc/nftables/|$T/fw/|" nftables.conf > "$T/fw/nftables.conf"
        ip netns exec $vps nft -f "$T/fw/nftables.conf" && ip netns exec $vps sh "$T/omr-bypass"
    }
    replies() { ip netns exec "$1" ping -c 2 -i 0.2 -W 1 -q "$2" > /dev/null 2>&1; }
    sleep 2   # IPv6 addresses settle

    cp nftables/omr.nft "$T/fw/"
    load_rules || { fail "the shipped ruleset and omr-bypass load in the VPS namespace"; return 1; }
    check "the router's IPv4 to a bypassed address gets an answer through vpn1" replies $router 8.8.8.8
    check "the router's IPv4 to any other address still gets one through eth0" replies $router 8.8.4.4
    check "the router's IPv6 to a bypassed address gets an answer through vpn1" replies $router 2606:4700::1111
    check "the router's IPv6 to any other address still gets one through eth0" replies $router 2606:4700::1001
    check "the VPS's own IPv4 to a bypassed address gets an answer through vpn1" replies $vps 8.8.8.8
    check "the VPS's own IPv6 to a bypassed address gets an answer through vpn1" replies $vps 2606:4700::1111

    # Without omr.nft's two bypass rules, the same checks have to fail, or
    # they prove nothing.
    grep -v 'meta mark 0x539' nftables/omr.nft > "$T/fw/omr.nft"
    load_rules || { fail "the ruleset without the bypass rules loads"; return 1; }
    check "without omr.nft's bypass rules, the router's IPv4 gets no answer (reject, no NAT)" eval '! replies $router 8.8.8.8'
    check "without omr.nft's bypass rules, the router's IPv6 gets no answer (no NAT)" eval '! replies $router 2606:4700::1111'
}

section_e2e() {
echo
echo "== end to end, through the shipped ruleset =="
if [ "$(id -u)" != 0 ]; then
    note "not root; skipping (run this test with sudo)"
elif ! command -v nft > /dev/null 2>&1 || ! command -v ping > /dev/null 2>&1; then
    note "nft or ping is not installed; skipping"
elif ! ip netns add omrbt-probe 2> /dev/null; then
    note "ip netns is not available here; skipping"
else
    ip netns del omrbt-probe
    e2e
fi
}

if [ "$1" = "--in-netns" ]; then
    netns_tests
    echo "netns-counts $PASS $FAIL"
    exit 0
fi
fake_tests
section_netns
section_e2e

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
