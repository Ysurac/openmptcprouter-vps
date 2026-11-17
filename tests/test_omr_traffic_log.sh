#!/bin/bash
# Tests for omr-traffic-log, the traffic log with usernames:
#   - tunnel IP -> user maps: MQVPN ADDRESS_ASSIGN lines, OpenVPN "MULTI:
#     Learn" lines (single IPs only, not iroute subnets), Glorytun tun<userid>
#     files + omr-admin userids (tun0 without REMOTEIP = the default .2)
#   - a flow keeps the user it had at NEW even if the IP moves to another user
#   - outbound flows and port forwards are logged; flows to the VPS, between
#     clients, opened by the VPS, or off the tunnels are not
#   - Xray and V2Ray "accepted ... email:" lines, not the ones without a user
#   - every line is one JSON object with shadowsocks-go's keys
#
# journalctl, conntrack, sysctl, ip and sleep are faked (PATH-injected), with
# line formats taken from conntrack 1.4.8, mqvpn 0.19, OpenVPN 2.6, Xray 26.7
# and V2Ray 5.54 on a live VPS.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$SCRIPT_DIR/../omr-traffic-log"
TMPDIR="$(mktemp -d)"
trap 'kill -- -"$PID" 2>/dev/null; rm -rf "$TMPDIR"' EXIT

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

assert_line() {
    local desc="$1" line="$2"
    if grep -qxF -- "$line" "$OUT"; then
        PASS=$((PASS+1)); printf '  PASS %s\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL %s\n    missing: %s\n    output:\n%s\n' "$desc" "$line" "$(sed 's/^/      /' "$OUT")"
    fi
}

export MARK="$TMPDIR" REAL_SLEEP="$(command -v sleep)"
FAKE_BIN="$TMPDIR/bin"
mkdir -p "$FAKE_BIN"
printf '#!/bin/sh\nexit 0\n' > "$FAKE_BIN/sysctl"

# The VPS addresses: the tunnel ends and the public IP.
cat > "$FAKE_BIN/ip" << 'FAKE'
#!/bin/sh
echo '1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever'
echo '2: eth0    inet 203.0.113.1/24 brd 203.0.113.255 scope global eth0\       valid_lft forever preferred_lft forever'
echo '9: mqvpn0    inet 10.255.220.1/24 scope global mqvpn0\       valid_lft forever preferred_lft forever'
FAKE

# The Glorytun loop calls "sleep 60" once its first MAP lines are written:
# that marks them as in the pipe before any conntrack line.
cat > "$FAKE_BIN/sleep" << 'FAKE'
#!/bin/sh
[ "$1" = 60 ] && touch "$MARK/mapped"
exec "$REAL_SLEEP" "$@"
FAKE

cat > "$FAKE_BIN/journalctl" << 'FAKE'
#!/bin/sh
case "$*" in
*xray*)
	echo '1763042400.123456 testhost xray[10]: 2026/11/13 14:00:00.123456 from tcp:82.65.241.147:5555 accepted tcp:1.1.1.1:443 [omrin-tunnel >> direct] email: openmptcprouter'
	echo '1763042400.223456 testhost xray[10]: 2026/11/13 14:00:00.223456 from 127.0.0.1:24633 accepted tcp:127.0.0.1:10086 [api -> api]'
	echo '1763042401.000000 testhost v2ray[11]: 2026/11/13 14:00:01 82.65.241.147:6666 accepted udp:8.8.8.8:53 [omrin-vmess-tunnel] email: openmptcprouter'
	;;
*)
	echo '14:59:13.788 [INF] [svr] ADDRESS_ASSIGN: client=10.255.220.2/32 (user=alice)'
	echo '14:59:13.900 [INF] [svr] ADDRESS_ASSIGN: client=10.255.220.3/32 (user=bob)'
	echo 'dave/tcp6-server:82.65.241.147:55032 MULTI: Learn: 10.255.252.2 -> dave/tcp6-server:82.65.241.147:55032'
	echo 'dave/tcp6-server:82.65.241.147:55032 MULTI: Learn: 10.103.0.0/24 -> dave/tcp6-server:82.65.241.147:55032'
	while [ ! -e "$MARK/new_done" ]; do "$REAL_SLEEP" 0.05; done
	echo '15:00:00.000 [INF] [svr] ADDRESS_ASSIGN: client=10.255.220.2/32 (user=carol)'
	touch "$MARK/moved"
	;;
esac
"$REAL_SLEEP" 600
FAKE

# NEW lines first, then 10.255.220.2 goes to carol, then the DESTROY lines.
cat > "$FAKE_BIN/conntrack" << 'FAKE'
#!/bin/sh
while [ ! -e "$MARK/mapped" ]; do "$REAL_SLEEP" 0.05; done
echo '    [NEW] ipv4     2 udp      17 30 src=10.255.220.2 dst=9.9.9.9 sport=35891 dport=53 [UNREPLIED] src=9.9.9.9 dst=203.0.113.1 sport=53 dport=35891 id=111'
echo '    [NEW] ipv4     2 tcp      6 120 SYN_SENT src=198.51.100.7 dst=203.0.113.1 sport=40000 dport=8080 [UNREPLIED] src=10.255.220.3 dst=198.51.100.7 sport=8080 dport=40000 id=222'
touch "$MARK/new_done"
while [ ! -e "$MARK/moved" ]; do "$REAL_SLEEP" 0.05; done
echo '[DESTROY] ipv4     2 udp      17 src=10.255.220.2 dst=9.9.9.9 sport=35891 dport=53 packets=1 bytes=60 src=9.9.9.9 dst=203.0.113.1 sport=53 dport=35891 packets=1 bytes=120 id=111'
echo '[DESTROY] ipv4     2 tcp      6 src=198.51.100.7 dst=203.0.113.1 sport=40000 dport=8080 packets=5 bytes=400 src=10.255.220.3 dst=198.51.100.7 sport=8080 dport=40000 packets=4 bytes=3000 [ASSURED] id=222'
echo '[DESTROY] ipv4     2 icmp     1 src=10.255.220.3 dst=1.1.1.1 type=8 code=0 id=15787 packets=3 bytes=252 src=1.1.1.1 dst=203.0.113.1 type=0 code=0 id=15787 packets=3 bytes=252 id=444'
echo '[DESTROY] ipv4     2 tcp      6 src=10.255.252.2 dst=8.8.4.4 sport=50000 dport=443 packets=10 bytes=1000 src=8.8.4.4 dst=203.0.113.1 sport=443 dport=50000 packets=20 bytes=20000 [ASSURED] id=888'
echo '[DESTROY] ipv4     2 tcp      6 src=10.255.255.2 dst=93.184.215.14 sport=50001 dport=80 packets=6 bytes=500 src=93.184.215.14 dst=203.0.113.1 sport=80 dport=50001 packets=8 bytes=9000 [ASSURED] id=901'
echo '[DESTROY] ipv4     2 udp      17 src=10.255.254.6 dst=1.0.0.1 sport=50002 dport=53 packets=1 bytes=70 src=1.0.0.1 dst=203.0.113.1 sport=53 dport=50002 packets=1 bytes=150 id=902'
# not logged: to the VPS, between clients, from the VPS, iroute subnet, off the tunnels
echo '[DESTROY] ipv4     2 udp      17 src=10.255.220.2 dst=10.255.220.1 sport=35000 dport=53 packets=1 bytes=60 src=10.255.220.1 dst=10.255.220.2 sport=53 dport=35000 packets=1 bytes=120 id=555'
echo '[DESTROY] ipv4     2 udp      17 src=10.255.220.2 dst=10.255.220.3 sport=35001 dport=5000 packets=1 bytes=60 src=10.255.220.3 dst=10.255.220.2 sport=5000 dport=35001 packets=1 bytes=60 id=666'
echo '[DESTROY] ipv4     2 tcp      6 src=10.255.220.1 dst=10.255.220.2 sport=41000 dport=80 packets=4 bytes=300 src=10.255.220.2 dst=10.255.220.1 sport=80 dport=41000 packets=4 bytes=900 [ASSURED] id=777'
echo '[DESTROY] ipv4     2 udp      17 src=10.103.0.5 dst=9.9.9.9 sport=35002 dport=53 packets=1 bytes=60 src=9.9.9.9 dst=203.0.113.1 sport=53 dport=35002 packets=1 bytes=120 id=999'
echo '[DESTROY] ipv4     2 tcp      6 src=198.51.100.9 dst=203.0.113.1 sport=40001 dport=22 packets=3 bytes=180 src=203.0.113.1 dst=198.51.100.9 sport=22 dport=40001 packets=2 bytes=120 id=333'
touch "$MARK/done"
"$REAL_SLEEP" 600
FAKE
chmod +x "$FAKE_BIN"/*

# Glorytun: frank (userid 0) on tcp tun0 without REMOTEIP, gina (userid 1) on udp tun1.
ETC="$TMPDIR/etc"
mkdir -p "$ETC/glorytun-tcp" "$ETC/glorytun-udp" "$ETC/openmptcprouter-vps-admin"
printf 'PORT=65001\nDEV=tun0\n' > "$ETC/glorytun-tcp/tun0"
echo SECRET > "$ETC/glorytun-tcp/tun0.key"
printf 'BIND_PORT=65001\nDEV=tun1\n\nLOCALIP=10.255.254.5\nREMOTEIP=10.255.254.6\n' > "$ETC/glorytun-udp/tun1"
echo SECRET > "$ETC/glorytun-udp/tun1.key"
echo '{"users": [{"admin": {"userid": null}, "frank": {"userid": 0}, "gina": {"userid": 1}}]}' \
    > "$ETC/openmptcprouter-vps-admin/omr-admin-config.json"

OUT="$TMPDIR/out"
OMR_TRAFFIC_LOG_ETC="$ETC" PATH="$FAKE_BIN:$PATH" setsid sh "$SCRIPT" > "$OUT" 2>&1 &
PID=$!
for _ in $(seq 100); do
    [ -e "$TMPDIR/done" ] && [ "$(wc -l < "$OUT")" -ge 8 ] && break
    "$REAL_SLEEP" 0.1
done
"$REAL_SLEEP" 0.3

assert_line "MQVPN: outbound flow keeps the user it had at NEW" \
    '{"server": "mqvpn", "network": "udp", "clientAddress": "10.255.220.2:35891", "username": "alice", "targetAddress": "9.9.9.9:53", "nl2r": 60, "nr2l": 120}'
assert_line "MQVPN: port forward attributed by its reply source, target after DNAT" \
    '{"server": "mqvpn", "network": "tcp", "clientAddress": "198.51.100.7:40000", "username": "bob", "targetAddress": "10.255.220.3:8080", "nl2r": 400, "nr2l": 3000}'
assert_line "MQVPN: ICMP flow seen only at DESTROY: no ports, conntrack id ignored" \
    '{"server": "mqvpn", "network": "icmp", "clientAddress": "10.255.220.3", "username": "bob", "targetAddress": "1.1.1.1", "nl2r": 252, "nr2l": 252}'
assert_line "OpenVPN: user from the MULTI: Learn line" \
    '{"server": "openvpn", "network": "tcp", "clientAddress": "10.255.252.2:50000", "username": "dave", "targetAddress": "8.8.4.4:443", "nl2r": 1000, "nr2l": 20000}'
assert_line "Glorytun TCP: userid 0 tunnel without REMOTEIP uses the default .2" \
    '{"server": "glorytun-tcp", "network": "tcp", "clientAddress": "10.255.255.2:50001", "username": "frank", "targetAddress": "93.184.215.14:80", "nl2r": 500, "nr2l": 9000}'
assert_line "Glorytun UDP: user from tun<userid> REMOTEIP and omr-admin userid" \
    '{"server": "glorytun-udp", "network": "udp", "clientAddress": "10.255.254.6:50002", "username": "gina", "targetAddress": "1.0.0.1:53", "nl2r": 70, "nr2l": 150}'
assert_line "Xray: accepted line with email" \
    '{"server": "xray", "network": "tcp", "clientAddress": "82.65.241.147:5555", "username": "openmptcprouter", "targetAddress": "1.1.1.1:443"}'
assert_line "V2Ray: accepted line with email" \
    '{"server": "v2ray", "network": "udp", "clientAddress": "82.65.241.147:6666", "username": "openmptcprouter", "targetAddress": "8.8.8.8:53"}'
assert_eq "nothing else is logged (local, between clients, from the VPS, iroute subnet, off tunnel, no email)" \
    "8" "$(wc -l < "$OUT" | tr -d ' ')"
if command -v python3 > /dev/null; then
    assert_eq "every line is valid JSON" "ok" \
        "$(python3 -c 'import json,sys; [json.loads(l) for l in sys.stdin]; print("ok")' < "$OUT" 2>&1 | tail -1)"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
