#!/bin/sh
[ ! -f $(readlink -f "$1") ] && exit 1
. "$(readlink -f "$1")"

INTF=gt-${DEV}
[ -z "$LOCALIP" ] && LOCALIP="10.255.255.1"
[ -z "$BROADCASTIP" ] && BROADCASTIP="10.255.255.3"
# Bounded: a tunnel that never comes up must not leave this waiting forever
# (systemd's ExecStartPost would hit its start timeout, and omr-service
# starts it again on its next pass anyway).
tries=0
while [ -z "$(ip link show $INTF 2>/dev/null)" ]; do
	tries=$((tries + 1))
	[ "$tries" -gt 30 ] && exit 1
	sleep 2
done
[ "$(ip addr show dev $INTF | grep -o 'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*' | grep -o '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')" != "$LOCALIP" ] && {
	ip link set dev ${INTF} up 2>&1 >/dev/null
	ip addr add ${LOCALIP}/30 brd ${BROADCASTIP} dev ${INTF} 2>&1 >/dev/null
}
