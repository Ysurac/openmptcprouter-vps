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
[ "`tty`" != "not a tty" ] && read -n 1 -s -r -p "Press any key to continue" || sleep 5

# A setupVars.conf next to pihole.toml can only come from an earlier run of
# this script on Pi-hole v6. The installer would take it for a v5 install to
# migrate, and rebuild pihole.toml from it: the upstream DNS servers are lost.
[ -f /etc/pihole/pihole.toml ] && rm -f /etc/pihole/setupVars.conf

echo "Run Pi-hole install script..."
curl -sSL https://install.pi-hole.net | bash
echo "Done"
echo "-------------------------------------------------------------------------------------------------------------------------------"
echo "OMR Pi-hole configuration..."
# Pi-hole v6, what its installer sets up now, keeps all its settings in
# /etc/pihole/pihole.toml: it no longer reads setupVars.conf or
# /etc/dnsmasq.d, and has no lighttpd. Its default listening mode answers
# the subnets of all the tunnels, and the VPS firewall keeps port 53 closed
# on the WAN.
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
systemctl -q restart pihole-FTL
echo "Done"
echo "======================================================================================================================================"
echo "To use Pi-hole in OpenMPTCProuter, you need to 'Save & Apply' the wizard again in System->OpenMPTCProuter then reboot OpenMPTCProuter."
echo "Web interface will be available on http://10.255.255.1/admin if you use Glorytun TCP, http://10.255.254.1/admin if you use Glorytun UDP."
echo "======================================================================================================================================"
exit 0
