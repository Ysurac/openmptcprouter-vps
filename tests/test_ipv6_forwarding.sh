#!/bin/bash
# The installer's IPv6 forwarding block (openmptcprouter-vps#63): accept_ra 2
# on the WAN ($INTERFACE, $INTERFACE6) where it is 1 or 2, written before the
# forwarding line; accept_ra 0 and interfaces without IPv6 left alone; dotted
# names written with a slash; the ifupdown hook puts 2 back after ifup.
# The block runs under sh -e against a fixture tree, with a fake sysctl that
# logs the order of its writes. Requires: bash, awk, sed.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="$SCRIPT_DIR/../debian9-x86_64.sh"
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

awk '/^OMR_RA_IFACES=""/,/^sysctl -p \/etc\/sysctl.d\/90-omr-forwarding.conf/' "$INSTALLER" > "$TMPDIR/block.sh"
if ! grep -q 'accept_ra' "$TMPDIR/block.sh" || ! tail -n 1 "$TMPDIR/block.sh" | grep -q '^sysctl -p'; then
    echo "FAIL could not extract the IPv6 forwarding block from $INSTALLER"
    exit 1
fi

# sysctl: -p FILE applies "key = value" lines in order, -w key=value one;
# keys are dotted with slashes for dots in names (or the other way round).
mkdir -p "$TMPDIR/bin"
cat > "$TMPDIR/bin/sysctl" << 'EOF'
#!/bin/sh
apply() {
    k=$1; v=$2
    # dotted form: dots are separators, slashes are the dots of a name
    p=$(printf '%s' "$k" | tr './' '/.')
    [ -e "$FAKE_ROOT/proc/sys/$p" ] || { echo "sysctl: cannot stat /proc/sys/$p" >&2; return 1; }
    printf '%s\n' "$v" > "$FAKE_ROOT/proc/sys/$p"
    echo "$p=$v" >> "$FAKE_ROOT/writes"
}
rc=0
while [ $# -gt 0 ]; do
    case "$1" in
        -q|-e) shift ;;
        -p) f=$2; shift 2
            while IFS= read -r line; do
                case "$line" in ''|'#'*|';'*) continue ;; esac
                k=$(printf '%s' "${line%%=*}" | tr -d ' \t'); v=$(printf '%s' "${line#*=}" | tr -d ' \t')
                apply "$k" "$v" || rc=1
            done < "$f" ;;
        -w) shift; apply "${1%%=*}" "${1#*=}" || rc=1; shift ;;
        *) apply "${1%%=*}" "${1#*=}" || rc=1; shift ;;
    esac
done
exit $rc
EOF
chmod +x "$TMPDIR/bin/sysctl"

# setup NAME:ACCEPT_RA ... -- one interface per argument, "-" for no IPv6
setup() {
    R="$TMPDIR/root.$1"; shift
    rm -rf "$R"
    mkdir -p "$R/proc/sys/net/ipv4" "$R/proc/sys/net/ipv6/conf/all" "$R/etc/sysctl.d"
    echo 0 > "$R/proc/sys/net/ipv4/ip_forward"
    echo 0 > "$R/proc/sys/net/ipv6/conf/all/forwarding"
    for spec in "$@"; do
        name=${spec%%:*}; ra=${spec#*:}
        [ "$ra" = "-" ] && continue
        mkdir -p "$R/proc/sys/net/ipv6/conf/$name"
        echo "$ra" > "$R/proc/sys/net/ipv6/conf/$name/accept_ra"
    done
}
run_block() {
    sed -e "s|/proc/sys/|$R/proc/sys/|g" -e "s|/etc/|$R/etc/|g" "$TMPDIR/block.sh" > "$R/block.sh"
    ( export PATH="$TMPDIR/bin:$PATH" FAKE_ROOT="$R" INTERFACE="$1" INTERFACE6="$2"
      sh -e -c ". \"$R/block.sh\"; echo reached" ) 2> "$R/stderr"
}
conf() { grep -v '^$' "$R/etc/sysctl.d/90-omr-forwarding.conf" | tr '\n' '|'; }
ra() { cat "$R/proc/sys/net/ipv6/conf/$1/accept_ra"; }
# Line numbers in the write log: accept_ra of $1 must come before forwarding.
before_forwarding() {
    awk -v k="net/ipv6/conf/$1/accept_ra=2" -v f="net/ipv6/conf/all/forwarding=1" '
        $0 == k && !a { a = NR } $0 == f && !b { b = NR } END { exit !(a && b && a < b) }' "$R/writes"
}

echo "== 1. RAs handled by the kernel: accept_ra 2, ahead of forwarding =="
setup k eth0:1
assert_eq "the block runs to its end under sh -e" "reached" "$(run_block eth0 eth0)"
assert_eq "90-omr-forwarding.conf lists eth0's accept_ra first" \
    "net.ipv6.conf.eth0.accept_ra = 2|net.ipv4.ip_forward = 1|net.ipv6.conf.all.forwarding = 1|" "$(conf)"
assert_eq "eth0 accepts RAs while forwarding (accept_ra 2)" "2" "$(ra eth0)"
assert_eq "forwarding is on" "1" "$(cat "$R/proc/sys/net/ipv6/conf/all/forwarding")"
before_forwarding eth0 && assert_eq "accept_ra 2 is written before forwarding goes on" ok ok \
    || assert_eq "accept_ra 2 is written before forwarding goes on" ok "$(tr '\n' ' ' < "$R/writes")"

setup again eth0:2
run_block eth0 eth0 > /dev/null
assert_eq "an update run keeps an interface already at 2" \
    "net.ipv6.conf.eth0.accept_ra = 2|net.ipv4.ip_forward = 1|net.ipv6.conf.all.forwarding = 1|" "$(conf)"

echo
echo "== 2. left alone: accept_ra 0, no IPv6 =="
setup networkd enp1s0:0
run_block enp1s0 enp1s0 > /dev/null
assert_eq "accept_ra 0 (networkd, NetworkManager, static) gets no line" \
    "net.ipv4.ip_forward = 1|net.ipv6.conf.all.forwarding = 1|" "$(conf)"
assert_eq "and keeps 0" "0" "$(ra enp1s0)"
setup noipv6 eth0:-
assert_eq "an interface without IPv6 doesn't stop the block" "reached" "$(run_block eth0 "")"
assert_eq "and gets no line" "net.ipv4.ip_forward = 1|net.ipv6.conf.all.forwarding = 1|" "$(conf)"

echo
echo "== 3. IPv6 on a second NIC (#3271), and dotted names =="
setup twonics ens3:1 ens4:1 ens5:1
run_block ens3 ens4 > /dev/null
assert_eq "both INTERFACE and INTERFACE6 are listed, nothing else" \
    "net.ipv6.conf.ens3.accept_ra = 2|net.ipv6.conf.ens4.accept_ra = 2|net.ipv4.ip_forward = 1|net.ipv6.conf.all.forwarding = 1|" "$(conf)"
assert_eq "a third NIC is left alone" "1" "$(ra ens5)"
setup vlan eth0.100:1
run_block eth0.100 eth0.100 > /dev/null
assert_eq "eth0.100 is written as eth0/100" \
    "net.ipv6.conf.eth0/100.accept_ra = 2|net.ipv4.ip_forward = 1|net.ipv6.conf.all.forwarding = 1|" "$(conf)"
assert_eq "and set" "2" "$(ra eth0.100)"

echo
echo "== 4. the ifupdown hook =="
setup hook eth0.100:1 gt-tun0:1
mkdir -p "$R/etc/network/if-up.d"
run_block eth0.100 eth0.100 > /dev/null
HOOK="$R/etc/network/if-up.d/omr-accept-ra"
if [ -x "$HOOK" ]; then
    assert_eq "installed (executable) where ifupdown's hook directory exists" ok ok
    # (its /etc/ paths already point into the tree: the block was rewritten)
    echo 1 > "$R/proc/sys/net/ipv6/conf/eth0.100/accept_ra"     # what "inet6 dhcp" sets at ifup
    ( export PATH="$TMPDIR/bin:$PATH" FAKE_ROOT="$R" IFACE=eth0.100 ADDRFAM=inet6; sh "$HOOK" )
    assert_eq "it puts the WAN (eth0.100) back to 2 after ifup" "2" "$(ra eth0.100)"
    ( export PATH="$TMPDIR/bin:$PATH" FAKE_ROOT="$R" IFACE=gt-tun0 ADDRFAM=inet6; sh "$HOOK" )
    assert_eq "and leaves an interface the file doesn't list alone" "1" "$(ra gt-tun0)"
else
    assert_eq "installed (executable) where ifupdown's hook directory exists" ok "missing"
fi
setup nohook eth0:1
run_block eth0 eth0 > /dev/null
assert_eq "not installed without /etc/network/if-up.d" "no" "$([ -e "$R/etc/network/if-up.d/omr-accept-ra" ] && echo yes || echo no)"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
