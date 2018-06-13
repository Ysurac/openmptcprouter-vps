#!/bin/sh
MLVPN_PASS=${MLVPN_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
INTERFACE=${INTERFACE:-$(ip -o -4 route show to default | awk '{print $5}' | tr -d "\n")}
DEBIAN_VERSION=$(sed 's/\..*//' /etc/debian_version)

set -e
umask 0022
update="0"
if [ $DEBIAN_VERSION -ne 9 ]; then
	echo "This script only work with Debian Stretch (9.x)"
	exit 1
fi

if [ -f "/etc/mlvpn/mlvpn0.conf" ] ; then
	update="1"
fi
if ! grep -q 'DefaultLimitNOFILE=65536' /etc/systemd/system.conf ; then
	echo 'DefaultLimitNOFILE=65536' >> /etc/systemd/system.conf
fi

# Install MLVPN
if systemctl -q is-active mlvpn@mlvpn0.service; then
	systemctl -q stop mlvpn@mlvpn0 > /dev/null 2>&1
fi
apt-get -y install build-essential pkg-config autoconf automake
cd /tmp
wget -O /tmp/mlvpn-2.3.2.tar.gz https://github.com/zehome/MLVPN/archive/2.3.2.tar.gz
cd /tmp
tar xzf mlvpn-2.3.2.tar.gz
cd MLVPN-2.3.2
./autogen.sh
./configure
make
make install
wget -O /lib/systemd/network/mlvpn.network http://www.openmptcprouter.com/server/mlvpn.network
mkdir -p /etc/mlvpn
if [ "$update" = "0" ]; then
	wget -O /etc/mlvpn/mlvpn0.conf http://www.openmptcprouter.com/server/mlvpn0.conf
	sed -i "s:MLVPN_PASS:$MLVPN_PASS:" /etc/mlvpn/mlvpn0.conf
fi
systemctl enable mlvpn@mlvpn0.service
systemctl enable systemd-networkd.service
cd /tmp
rm -r /tmp/MLVPN-2.3.2

# Add 6in4 support
wget -O /usr/local/bin/omr-6in4 http://www.openmptcprouter.com/server/omr-6in4
chmod 755 /usr/local/bin/omr-6in4
wget -O /usr/local/bin/omr-6in4-service http://www.openmptcprouter.com/server/omr-6in4-service
chmod 755 /usr/local/bin/omr-6in4-service
wget -O /lib/systemd/system/omr-6in4.service http://www.openmptcprouter.com/server/omr-6in4.service.in
systemctl enable omr-6in4.service

# Change SSH port to 65222
sed -i 's:#Port 22:Port 65222:g' /etc/ssh/sshd_config
sed -i 's:Port 22:Port 65222:g' /etc/ssh/sshd_config

# Remove Bind9 if available
#systemctl -q disable bind9

# Remove fail2ban if available
#systemctl -q disable fail2ban

if [ "$update" = "0" ]; then
	# Install and configure the firewall using shorewall
	apt-get -y install shorewall shorewall6
	wget -O /etc/shorewall/openmptcprouter-shorewall.tar.gz http://www.openmptcprouter.com/server/openmptcprouter-shorewall.tar.gz
	tar xzf /etc/shorewall/openmptcprouter-shorewall.tar.gz -C /etc/shorewall
	rm /etc/shorewall/openmptcprouter-shorewall.tar.gz
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	systemctl enable shorewall
	wget -O /etc/shorewall6/openmptcprouter-shorewall6.tar.gz http://www.openmptcprouter.com/server/openmptcprouter-shorewall6.tar.gz
	tar xzf /etc/shorewall6/openmptcprouter-shorewall6.tar.gz -C /etc/shorewall6
	rm /etc/shorewall6/openmptcprouter-shorewall6.tar.gz
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall6/*
	systemctl enable shorewall6
else
	# Update only needed firewall files
	wget -O /etc/shorewall/interfaces http://www.openmptcprouter.com/server/shorewall4/interfaces
	wget -O /etc/shorewall/snat http://www.openmptcprouter.com/server/shorewall4/snat
	wget -O /etc/shorewall/stoppedrules http://www.openmptcprouter.com/server/shorewall4/stoppedrules
	wget -O /etc/shorewall/params.vpn http://www.openmptcprouter.com/server/shorewall4/params.vpn
	wget -O /etc/shorewall/params http://www.openmptcprouter.com/server/shorewall4/params
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	sed -i 's:10.0.0.2:$OMR_ADDR:g' /etc/shorewall/rules
	wget -O /etc/shorewall6/interfaces http://www.openmptcprouter.com/server/shorewall6/interfaces
	wget -O /etc/shorewall6/stoppedrules http://www.openmptcprouter.com/server/shorewall6/stoppedrules
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall6/*
fi

if [ "$update" = "0" ]; then
	# Display important info
	echo '=========================================================================================='
	echo 'OpenMPTCProuter VPS MLVPN is now configured !'
	echo 'SSH port: 65222 (instead of port 22)'
	echo 'MLVPN first port: 65201'
	echo 'Your MLVPN password: '
	echo $MLVPN_PASS
	echo '=========================================================================================='
	echo 'Keys are also saved in /root/openmptcprouter_mlvpn_config.txt, you are free to remove them'
	echo '=========================================================================================='

	# Save info in file
	cat > /root/openmptcprouter_mlvpn_config.txt <<-EOF
	SSH port: 65222 (instead of port 22)
	MLVPN first port: 65201
	Your MLVPN password:
	${MLVPN_PASS}
	EOF
	if [ -f "/root/openmptcprouter_config.txt" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		MLVPN first port: 65201
		Your MLVPN password:
		${MLVPN_PASS}
		EOF
	fi
else
	echo '===================================================================================='
	echo 'OpenMPTCProuter VPS MLVPN is now updated !'
	echo 'Keys are not changed, shorewall rules files preserved'
	echo '===================================================================================='
	echo 'Restarting mlvpn and omr-6in4...'
	systemctl -q start mlvpn@mlvpn0
	systemctl -q restart omr-6in4
	echo 'done'
	echo 'Restarting shorewall...'
	systemctl -q restart shorewall
	systemctl -q restart shorewall6
	echo 'done'
fi
