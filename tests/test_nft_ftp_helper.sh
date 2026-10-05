#!/bin/bash
# The FTP conntrack helper (openmptcprouter#4365), which Shorewall had
# (CT:helper:ftp:PO tcp 21, AUTOHELPERS=Yes):
#   1. the helper object, assigned to tcp/21 in prerouting and output; every
#      "ct helper set" and jump to ct_helpers after conntrack (priority > -200)
#   2. the installer loads nf_nat_ftp, or takes the FTP lines out
#   3. (root) the shipped ruleset in a namespace, inet -- eth0 -- vps -- tun0 --
#      router, a port 21 redirect as omr-admin renders it, and Python's ftplib
#      fetching a file from the internet side: passive and active, IPv4 and IPv6
# Requires: bash, awk, sed; for 3, root, ip netns, nft, modprobe, python3.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"
CONF="$ROOT/nftables.conf"
VARS="$ROOT/nftables/omr-vars.nft"
RULES="$ROOT/nftables/omr.nft"

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
note() { printf '  NOTE %s\n' "$1"; }

prio() { # the numeric priority of a named base priority (nft's table for the inet family)
    case "$1" in
        raw) echo -300 ;; mangle) echo -150 ;; dstnat) echo -100 ;; filter) echo 0 ;;
        security) echo 50 ;; srcnat) echo 100 ;; *[!0-9-]*|'') echo x ;; *) echo "$1" ;;
    esac
}

echo "== the FTP helper, and where helpers are assigned =="
grep -qE '^[[:space:]]*ct helper ftp \{ type "ftp" protocol tcp; \}' "$RULES" \
    && pass "omr.nft declares the ftp helper object" || fail "omr.nft declares no ftp helper object"
# Chains as "name hook priority" (priority as a number), and the chains each
# "ct helper set" or "jump ct_helpers" is in.
CHAINS="$(mktemp)"
trap 'rm -f "$CHAINS" "$CHAINS.nft"' EXIT
awk '
    $1 == "chain" { c = $2; next }
    /type .* hook .* priority/ {
        h = $0; sub(/.*hook /, "", h); sub(/ .*/, "", h)
        p = $0; sub(/.*priority /, "", p); sub(/;.*/, "", p); gsub(/ /, "", p)
        print "chain", c, h, p
    }
    { line = $0; sub(/#.*/, "", line) }
    line ~ /ct helper set/ { print "set", c, line }
    line ~ /jump ct_helpers/ { print "jump", c }
' "$RULES" > "$CHAINS"
base_prio() { # chain -> numeric priority ("x" if not a base chain or unknown)
    local p
    p="$(awk -v c="$1" '$1 == "chain" && $2 == c { print $4; exit }' "$CHAINS")"
    case "$p" in
        *+*) echo $(( $(prio "${p%%+*}") + ${p#*+} )) ;;
        [a-z]*-*) echo $(( $(prio "${p%%-*}") - ${p#*-} )) ;;
        *) prio "$p" ;;
    esac
}
for hook in prerouting output; do
    found=no
    for c in $(awk '$1 == "set" && /tcp dport 21 ct helper set "ftp"/ { print $2 }' "$CHAINS"); do
        [ "$(awk -v c="$c" '$1 == "chain" && $2 == c { print $3 }' "$CHAINS")" = "$hook" ] && found=yes
    done
    [ "$found" = yes ] && pass "tcp/21 gets the ftp helper in $hook" || fail "tcp/21 gets no ftp helper in $hook"
done
bad=""
for c in $(awk '$1 == "set" || $1 == "jump" { print $2 }' "$CHAINS" | sort -u); do
    p="$(base_prio "$c")"
    if [ "$p" = x ] || [ "$p" -le -200 ]; then bad="$bad $c($p)"; fi
done
[ -z "$bad" ] && pass "every helper assignment, and every jump to ct_helpers, runs after conntrack (priority > -200)" \
    || fail "helpers assigned where conntrack has no connection yet, so the rules do nothing:$bad"

echo
echo "== the installer: nf_nat_ftp, and where it can't be loaded =="
block="$(grep -n 'modprobe nf_nat_ftp' "$INSTALLER" | head -n 1)"
if [ -z "$block" ]; then
    fail "the installer never loads nf_nat_ftp"
else
    pass "the installer loads nf_nat_ftp"
    grep -qE "echo nf_nat_ftp > /etc/modules-load\.d/[a-z0-9-]+\.conf" "$INSTALLER" \
        && pass "and at every boot (modules-load.d)" || fail "but not at boot"
    # The sed it runs where modprobe fails, against the shipped omr.nft: what is
    # left must hold no FTP helper and still declare everything else.
    sedline="$(grep -E "sed -i '/ct helper ftp " "$INSTALLER" | head -n 1 | sed 's/^[[:space:]]*//')"
    if [ -z "$sedline" ]; then
        fail "the installer leaves the FTP helper in omr.nft where nf_nat_ftp can't be loaded"
    else
        cp "$RULES" "${CHAINS}.nft"
        eval "$(printf '%s' "$sedline" | sed "s|/etc/nftables/omr.nft|${CHAINS}.nft|")"
        left="$(grep -cE 'ct helper ftp|ct helper set "ftp"' "${CHAINS}.nft")"
        [ "$left" = 0 ] && pass "without nf_nat_ftp, the installer's sed leaves no FTP helper line" \
            || fail "without nf_nat_ftp, $left FTP helper line(s) are left"
        [ "$(diff "$RULES" "${CHAINS}.nft" | grep -c '^<')" = 3 ] && pass "and takes out nothing else" \
            || fail "the sed takes out other lines too: $(diff "$RULES" "${CHAINS}.nft" | grep '^<' | tr '\n' ' ')"
        rm -f "${CHAINS}.nft"
    fi
fi

echo
echo "== end to end, through the shipped ruleset (root) =="
e2e() {
    local vps=omrftp-vps router=omrftp-router inet=omrftp-inet ns T fam mode got
    T="$(mktemp -d)"
    trap 'for ns in omrftp-vps omrftp-router omrftp-inet; do ip netns del $ns 2> /dev/null; done; rm -rf "$T"' RETURN
    for ns in $vps $router $inet; do ip netns add $ns && ip -n $ns link set lo up || return 1; done
    ip -n $vps link add tun0 type veth peer name tun0 netns $router
    ip -n $vps link add eth0 type veth peer name eth0 netns $inet
    for ns in $vps $router $inet; do ip -n $ns link set tun0 up 2> /dev/null; ip -n $ns link set eth0 up 2> /dev/null; done
    ip netns exec $vps sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
    ip -n $vps addr add 10.255.252.1/30 dev tun0; ip -n $router addr add 10.255.252.2/30 dev tun0
    ip -n $router route add default via 10.255.252.1
    ip -n $vps -6 addr add fd00::a00:1/126 dev tun0 nodad; ip -n $router -6 addr add fd00::a00:2/126 dev tun0 nodad
    ip -n $router -6 route add default via fd00::a00:1
    ip -n $vps addr add 192.0.2.2/24 dev eth0; ip -n $inet addr add 192.0.2.1/24 dev eth0
    ip -n $vps -6 addr add 2001:db8:1::2/64 dev eth0 nodad; ip -n $inet -6 addr add 2001:db8:1::1/64 dev eth0 nodad
    mkdir -p "$T/fw/nftables/custom.d"
    cp "$VARS" "$RULES" "$T/fw/nftables/"
    sed "s|/etc/nftables/|$T/fw/nftables/|" "$CONF" > "$T/fw/nftables.conf"
    if ! ip netns exec $vps nft -f "$T/fw/nftables.conf"; then
        fail "the shipped ruleset does not load"; return 0
    fi
    # The redirects exactly as omr-admin renders them (_render_fw_ports).
    ip netns exec $vps nft add rule inet omr user_dnat meta nfproto ipv4 tcp dport 21 dnat ip to 10.255.252.2 \
        comment '"OMR openmptcprouter redirect ftp tcp"'
    ip netns exec $vps nft add rule inet omr user_dnat meta nfproto ipv6 tcp dport 21 dnat ip6 to fd00::a00:2 \
        comment '"OMR openmptcprouter redirect ftp tcp"'
    # A minimal FTP server on the router: replies with the address the client
    # reached it on (its tunnel address), as an FTP server or the router's own
    # FTP helper does; one 256 KiB file.
    cat > "$T/ftpd.py" << 'EOF'
import socket, threading
DATA = bytes(range(256)) * 1024
srv = socket.socket(socket.AF_INET6)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
srv.bind(("::", 21)); srv.listen(8)
def handle(c):
    f = c.makefile("rb"); pasv = None; port = None
    local = c.getsockname()[0]
    v4 = local.startswith("::ffff:")
    def send(s): c.sendall(s.encode() + b"\r\n")
    send("220 test")
    while True:
        line = f.readline(1024).decode(errors="replace").strip()
        if not line: break
        cmd, _, arg = line.partition(" "); cmd = cmd.upper()
        if cmd == "USER": send("331 ok")
        elif cmd == "PASS": send("230 ok")
        elif cmd in ("TYPE", "NOOP"): send("200 ok")
        elif cmd in ("PASV", "EPSV"):
            pasv = socket.socket(socket.AF_INET6); pasv.bind((local, 0)); pasv.listen(1)
            p = pasv.getsockname()[1]
            if cmd == "PASV":
                send("227 Entering Passive Mode (%s,%d,%d)" % (local[7:].replace(".", ","), p >> 8, p & 255))
            else:
                send("229 Entering Extended Passive Mode (|||%d|)" % p)
        elif cmd in ("PORT", "EPRT"):
            if cmd == "PORT":
                n = arg.split(","); port = ("::ffff:" + ".".join(n[:4]), int(n[4]) * 256 + int(n[5]))
            else:
                d = arg[0]; _, _, a, p, _ = arg.split(d); port = (a if ":" in a else "::ffff:" + a, int(p))
            send("200 ok")
        elif cmd == "RETR":
            send("150 sending")
            try:
                if pasv:
                    pasv.settimeout(5); d, _ = pasv.accept()
                else:
                    d = socket.create_connection(port, timeout=5)
                d.sendall(DATA); d.close(); send("226 done")
            except OSError:
                send("425 no data connection")
            if pasv: pasv.close(); pasv = None
        elif cmd == "QUIT": send("221 bye"); break
        else: send("502 not implemented")
    c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
EOF
    cat > "$T/ftp.py" << 'EOF'
import ftplib, socket, sys
host, mode = sys.argv[1], sys.argv[2]
ftp = ftplib.FTP(timeout=6)
try:
    ftp.connect(host, 21)
    ftp.login()
    ftp.set_pasv(mode == "passive")
    buf = bytearray()
    ftp.retrbinary("RETR file", buf.extend)
    print("ok" if bytes(buf) == bytes(range(256)) * 1024 else "corrupt (%d bytes)" % len(buf))
except (OSError, EOFError, ftplib.Error) as e:
    print("failed (%s)" % (str(e).strip() or e.__class__.__name__))
EOF
    ip netns exec $router timeout 120 python3 "$T/ftpd.py" &
    sleep 1
    for fam in 192.0.2.2 2001:db8:1::2; do
        for mode in passive active; do
            got="$(ip netns exec $inet timeout 30 python3 "$T/ftp.py" "$fam" $mode)"
            [ "$got" = ok ] && pass "$mode transfer from the internet through the redirect, to $fam: $got" \
                || fail "$mode transfer from the internet through the redirect, to $fam: $got"
        done
    done
    kill %1 2> /dev/null; wait 2> /dev/null
    return 0
}
if [ "$(id -u)" != 0 ]; then
    note "not root; skipping (run this test with sudo)"
elif ! command -v nft > /dev/null 2>&1 || ! command -v python3 > /dev/null 2>&1; then
    note "nft or python3 is not installed; skipping"
elif ! modprobe nf_nat_ftp 2> /dev/null; then
    note "nf_nat_ftp can't be loaded here; skipping"
elif ! ip netns add omrftp-probe 2> /dev/null; then
    note "ip netns is not available here; skipping"
else
    ip netns del omrftp-probe
    e2e || fail "could not build the namespaces"
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
