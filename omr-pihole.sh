#!/bin/sh
if [ -f /etc/os-release ]; then
	. /etc/os-release
else
	. /usr/lib/os-release
fi
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ]; then
        echo "This script doesn't work with Debian Stretch (9.x)"
        exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "You must run the script as root"
	exit 1
fi

echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "You can select any interface and set any IPs during Pi-hole configuration, this will be modified for OpenMPTCProuter at the end."
echo "Don't apply Pi-hole firewall rules."
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
# read -n/-s/-p are bash only (dash rejects them, and this runs under sh):
# take one key with the terminal in non-canonical mode instead.
if [ -t 0 ]; then
	printf 'Press any key to continue'
	stty_saved="$(stty -g)"
	stty -icanon -echo min 1 time 0
	dd bs=1 count=1 >/dev/null 2>&1
	stty "$stty_saved"
	echo
else
	sleep 5
fi

# A setupVars.conf next to pihole.toml can only come from an earlier run of
# this script on Pi-hole v6. The installer would take it for a v5 install to
# migrate, and rebuild pihole.toml from it: the upstream DNS servers are lost.
[ -f /etc/pihole/pihole.toml ] && rm -f /etc/pihole/setupVars.conf

echo "Run Pi-hole install script..."
curl -sSL https://install.pi-hole.net | bash
echo "Done"
echo "-------------------------------------------------------------------------------------------------------------------------------"
if ! command -v pihole-FTL >/dev/null 2>&1; then
	echo "Pi-hole is not installed, OMR Pi-hole configuration not applied."
	exit 1
fi
echo "OMR Pi-hole configuration..."
# FTL rewrites pihole.toml from the settings it runs with when it applies a
# change, so a change written while it runs can be lost: write them while it
# is stopped.
systemctl -q stop pihole-FTL
# The installer writes the upstream DNS servers chosen while FTL is starting,
# and can lose them the same way: with none, every query is refused. Use
# Quad9, the DNS server the tunnels already give.
if ! pihole-FTL --config dns.upstreams | grep -q '[[:alnum:]]'; then
	echo "No upstream DNS server set, using Quad9 (9.9.9.9, 149.112.112.112)"
	pihole-FTL --config dns.upstreams '[ "9.9.9.9", "149.112.112.112" ]' >/dev/null
fi
# Pi-hole v6, what its installer sets up now, keeps all its settings in
# /etc/pihole/pihole.toml: it no longer reads setupVars.conf or
# /etc/dnsmasq.d, and has no lighttpd.
# Its default listening mode (LOCAL) only answers clients on a local subnet,
# so it ignores the peer of a point-to-point tunnel such as DSVPN. Answer on
# the tunnel interfaces (the ones the firewall accepts) and loopback instead,
# whatever the client address, and never on the WAN.
pihole-FTL --config dns.listeningMode NONE >/dev/null
pihole-FTL --config misc.dnsmasq_lines '[ "interface=lo", "interface=gt-tun*", "interface=gt-udp-tun*", "interface=tun*", "interface=mlvpn*", "interface=dsvpn*", "interface=wg*", "interface=client-wg*", "interface=mqvpn*", "interface=omr-bonding", "interface=tap_softether", "interface=gre-user*", "interface=vx-user*" ]' >/dev/null
# The router sends the queries of the whole LAN from its tunnel address, so
# turn off the rate limit (by default 1000 queries a minute per client).
pihole-FTL --config dns.rateLimit.count 0 >/dev/null
pihole-FTL --config dns.rateLimit.interval 0 >/dev/null
# The web interface is built into FTL and listens on 80 and 443 on all
# interfaces by default. Keep it on the tunnels' VPS addresses (Glorytun TCP,
# Glorytun UDP, OpenVPN, MLVPN, DSVPN) and on loopback for the pihole command,
# and leave 443 free for SoftEther and acme.sh. "o" makes each address
# optional, so an address that is down doesn't stop the others.
pihole-FTL --config webserver.port "127.0.0.1:80o,10.255.255.1:80o,10.255.254.1:80o,10.255.252.1:80o,10.255.253.1:80o,10.255.251.1:80o" >/dev/null
# FTL only binds at start: start it after the tunnels, so their addresses exist.
mkdir -p /etc/systemd/system/pihole-FTL.service.d
cat > /etc/systemd/system/pihole-FTL.service.d/omr.conf <<-EOF
[Unit]
After=glorytun-tcp@tun0.service glorytun-udp@tun0.service openvpn@tun0.service mlvpn@mlvpn0.service dsvpn-server@dsvpn0.service
EOF
systemctl daemon-reload
systemctl -q start pihole-FTL
echo "Done"
echo "======================================================================================================================================"
echo "To use Pi-hole in OpenMPTCProuter, you need to 'Save & Apply' the wizard again in System->OpenMPTCProuter then reboot OpenMPTCProuter."
echo "Web interface will be available on http://10.255.255.1/admin if you use Glorytun TCP, http://10.255.254.1/admin if you use Glorytun UDP."
echo "======================================================================================================================================"
exit 0
