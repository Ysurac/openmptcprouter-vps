#!/bin/sh
. "$(readlink -f "$1")"

INTF=gt-${DEV}
[ -z "$LOCALIP" ] && LOCALIP="10.255.255.1"
[ -z "$BROADCASTIP" ] && BROADCASTIP="10.255.255.3"
ip link set dev ${INTF} up
ip addr add ${LOCALIP}/30 brd ${BROADCASTIP} dev ${INTF}
