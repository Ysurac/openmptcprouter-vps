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
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "You can select any interface and set any IPs during Pi-hole configuration, this will be modified for OpenMPTCProuter at the end."
echo "Don't apply Pi-hole firewall rules."
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
[ "`tty`" != "not a tty" ] && read -n 1 -s -r -p "Press any key to continue" || sleep 5

echo "Run Pi-hole install script..."
curl -sSL https://install.pi-hole.net | bash
echo "Done"
echo "-------------------------------------------------------------------------------------------------------------------------------"
echo "OMR Pi-hole configuration..."
cat > /etc/lighttpd/external.conf << 'EOF'
server.bind="10.255.255.1"
$SERVER["socket"] == "10.255.254.1:80" { }
$SERVER["socket"] == "10.255.252.1:80" { }
$SERVER["socket"] == "10.255.251.1:80" { }
$SERVER["socket"] == "10.255.253.1:80" { }
EOF
systemctl -q restart lighttpd
grep -v -e PIHOLE_INTERFACE -e IPV4_ADDRESS -e IPV6_ADDRESS /etc/pihole/setupVars.conf > /etc/pihole/setupVars.new.conf
mv /etc/pihole/setupVars.new.conf /etc/pihole/setupVars.conf
cat >> /etc/pihole/setupVars.conf <<-EOF
PIHOLE_INTERFACE=gt-tun0
IPV4_ADDRESS=10.255.0.0/16
IPV6_ADDRESS=fe80::aff:ff01/64
RATE_LIMIT=0/0
EOF

grep -v interface /etc/dnsmasq.d/01-pihole.conf > /etc/dnsmasq.d/01-pihole.new.conf
mv /etc/dnsmasq.d/01-pihole.new.conf /etc/dnsmasq.d/01-pihole.conf
cat > /etc/dnsmasq.d/99-omr.conf <<-EOF
interface=gt-tun0
interface=gt-udp-tun0
interface=tun0
interface=mlvpn0
interface=dsvpn0
EOF
systemctl -q restart pihole-FTL
echo "Done"
echo "======================================================================================================================================"
echo "To use Pi-hole in OpenMPTCProuter, you need to 'Save & Apply' the wizard again in System->OpenMPTCProuter then reboot OpenMPTCProuter."
echo "Web interface will be available on 10.255.255.1 if you use Glorytun TCP, 10.255.254.1 if you use Glorytun UDP."
echo "======================================================================================================================================"
exit 0