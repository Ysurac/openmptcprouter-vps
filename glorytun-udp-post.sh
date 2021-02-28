#!/bin/sh
[ ! -f $(readlink -f "$1") ] && exit 1
. "$(readlink -f "$1")"

INTF=gt-udp-${DEV}
[ -z "$LOCALIP" ] && LOCALIP="10.255.254.1"
[ -z "$BROADCASTIP" ] && BROADCASTIP="10.255.254.3"
while [ -z "$(ip link show $INTF 2>/dev/null)" ]; do
	sleep 2
done
[ "$(ip addr show dev $INTF | grep -o 'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | grep -o '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')" != "$LOCALIP" ] && {
	ip link set dev ${INTF} up 2>&1 >/dev/null
	ip addr add ${LOCALIP}/30 brd ${BROADCASTIP} dev ${INTF} 2>&1 >/dev/null
}
tc qdisc replace dev $INTF root cake
ip link set $INTF txqlen 100
glorytun set dev gt-udp-tun0 kxtimeout 7d 2>&1 >/dev/null