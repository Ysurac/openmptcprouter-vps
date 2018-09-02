#!/bin/sh
SHADOWSOCKS_PASS=${SHADOWSOCKS_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
GLORYTUN_PASS=${GLORYTUN_PASS:-$(od  -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
#NBCPU=${NBCPU:-$(nproc --all | tr -d "\n")}
NBCPU=${NBCPU:-$(grep -c '^processor' /proc/cpuinfo | tr -d "\n")}
OBFS=${OBFS:-no}
MLVPN=${MLVPN:-no}
OPENVPN=${OPENVPN:-no}
INTERFACE=${INTERFACE:-$(ip -o -4 route show to default | awk '{print $5}' | tr -d "\n")}
DEBIAN_VERSION=$(sed 's/\..*//' /etc/debian_version)
KERNEL_VERSION="4.14.64-mptcp-16e8846"

set -e
umask 0022
update="0"
if [ $DEBIAN_VERSION -ne 9 ]; then
	echo "This script only work with Debian Stretch (9.x)"
	exit 1
fi
# Fix old string...
if grep --quiet 'OpenMPCTProuter VPS' /etc/motd ; then
	sed -i 's/OpenMPCTProuter/OpenMPTCProuter/g' /etc/motd
fi
if grep --quiet 'OpenMPTCProuter VPS' /etc/motd ; then
	update="1"
fi
# Install mptcp kernel and shadowsocks
apt-get update
apt-get -y install dirmngr patch
#apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 379CE192D401AB61
#echo 'deb http://dl.bintray.com/cpaasch/deb jessie main' >> /etc/apt/sources.list
echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/stretch-backports.list
apt-get update
wget -O /tmp/linux-image-${KERNEL_VERSION}.amd64.deb https://www.openmptcprouter.com/kernel/linux-image-${KERNEL_VERSION}.amd64.deb
wget -O /tmp/linux-headers-${KERNEL_VERSION}.amd64.deb https://www.openmptcprouter.com/kernel/linux-headers-${KERNEL_VERSION}.amd64.deb
# Rename bzImage to vmlinuz, needed when custom kernel was used
cd /boot
apt-get -y install rename
rename 's/^bzImage/vmlinuz/s' * >/dev/null 2>&1
#apt-get -y install linux-mptcp
dpkg -E -i /tmp/linux-image-${KERNEL_VERSION}.amd64.deb
dpkg -E -i /tmp/linux-headers-${KERNEL_VERSION}.amd64.deb

# Check if mptcp kernel is grub default kernel
echo "Set MPTCP kernel as grub default..."
wget -O /tmp/update-grub.sh https://www.openmptcprouter.com/server/update-grub.sh
cd /tmp
bash update-grub.sh ${KERNEL_VERSION}

#apt -t stretch-backports -y install shadowsocks-libev
## Compile Shadowsocks
rm -rf /tmp/shadowsocks-libev-3.2.0
wget -O /tmp/shadowsocks-libev-3.2.0.tar.gz http://github.com/shadowsocks/shadowsocks-libev/releases/download/v3.2.0/shadowsocks-libev-3.2.0.tar.gz
cd /tmp
tar xzf shadowsocks-libev-3.2.0.tar.gz
cd shadowsocks-libev-3.2.0
wget https://raw.githubusercontent.com/Ysurac/openmptcprouter-feeds/master/shadowsocks-libev/patches/020-NOCRYPTO.patch
patch -p1 < 020-NOCRYPTO.patch
apt-get -y install --no-install-recommends devscripts equivs apg libcap2-bin libpam-cap
apt -y -t stretch-backports install libsodium-dev
mk-build-deps --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
dpkg-buildpackage -b -us -uc
cd ..
dpkg -i shadowsocks-libev_3.2.0-1_amd64.deb
rm -rf /tmp/shadowsocks-libev-3.2.0

# Load OLIA Congestion module at boot time
if ! grep -q olia /etc/modules ; then
	echo mptcp_olia >> /etc/modules
fi
# Load BBR Congestion module at boot time
if ! grep -q bbr /etc/modules ; then
	echo tcp_bbr >> /etc/modules
fi

# Get shadowsocks optimization
wget -O /etc/sysctl.d/90-shadowsocks.conf https://www.openmptcprouter.com/server/shadowsocks.conf

# Install shadowsocks config and add a shadowsocks by CPU
if [ "$update" = "0" ]; then
	wget -O /etc/shadowsocks-libev/config.json https://www.openmptcprouter.com/server/config.json
	SHADOWSOCKS_PASS_JSON=$(echo $SHADOWSOCKS_PASS | sed 's/+/-/g; s/\//_/g;')
	sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/config.json
fi
sed -i 's:aes-256-cfb:chacha20:g' /etc/shadowsocks-libev/config.json
#sed -i 's:json:json --mptcp:g' /lib/systemd/system/shadowsocks-libev-server@.service
systemctl disable shadowsocks-libev
systemctl enable shadowsocks-libev-server@config.service
if [ $NBCPU -gt 1 ]; then
	for i in $NBCPU; do
		ln -fs /etc/shadowsocks-libev/config.json /etc/shadowsocks-libev/config$i.json
		systemctl enable shadowsocks-libev-server@config$i.service
	done
fi
if ! grep -q 'DefaultLimitNOFILE=65536' /etc/systemd/system.conf ; then
	echo 'DefaultLimitNOFILE=65536' >> /etc/systemd/system.conf
fi

# Install simple-obfs
if [ "$OBFS" = "yes" ]; then
	rm -rf /tmp/simple-obfs
	cd /tmp
	sudo apt-get install -y --no-install-recommends build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake git ca-certificates
	git clone https://github.com/shadowsocks/simple-obfs.git /tmp/simple-obfs
	cd /tmp/simple-obfs
	git submodule update --init --recursive
	./autogen.sh
	./configure && make
	make install
	cd /tmp
	rm -rf /tmp/simple-obfs
	sed -i 's%"mptcp": true%"mptcp": true,\n"plugin": "/usr/local/bin/obfs-server",\n"plugin_opts": "obfs=http;mptcp;fast-open;t=400"%' /etc/shadowsocks-libev/config.json
else
	sed -i -e '/plugin/d' -e 's/,,//' /etc/shadowsocks-libev/config.json
fi

if [ "$MLVPN" = "yes" ]; then
	cd /tmp
	wget -O /tmp/debian9-x86_64-mlvpn.sh https://www.openmptcprouter.com/server/debian9-x86_64-mlvpn.sh
	sh debian9-x86_64-mlvpn.sh
fi

if systemctl -q is-active openvpn-server@tun0.service; then
	systemctl -q stop openvpn-server@tun0 > /dev/null 2>&1
	systemctl -q disable openvpn-server@tun0 > /dev/null 2>&1
fi
if [ "$OPENVPN" = "yes" ]; then
	apt-get -y install openvpn
	wget -O /lib/systemd/network/openvpn.network https://www.openmptcprouter.com/server/openvpn.network
	if [ ! -f "/etc/openvpn/server/static.key" ]; then
		wget -O /etc/openvpn/tun0.conf https://www.openmptcprouter.com/server/openvpn-tun0.conf
		cd /etc/openvpn/server
		openvpn --genkey --secret static.key
	fi
	systemctl enable openvpn@tun0.service
fi

# Install Glorytun UDP
if systemctl -q is-active glorytun-udp@tun0.service; then
	systemctl -q stop glorytun-udp@tun0 > /dev/null 2>&1
fi
apt-get -y install meson pkg-config ca-certificates
rm -rf /tmp/glorytun-0.0.99-mud
cd /tmp
wget -O /tmp/glorytun-0.0.99-mud.tar.gz https://github.com/angt/glorytun/releases/download/v0.0.99-mud/glorytun-0.0.99-mud.tar.gz
tar xzf glorytun-0.0.99-mud.tar.gz
cd glorytun-0.0.99-mud
meson build
ninja -C build install
sed -i 's:EmitDNS=yes:EmitDNS=no:g' /lib/systemd/network/glorytun.network
rm /lib/systemd/system/glorytun*
rm /lib/systemd/network/glorytun*
wget -O /usr/local/bin/glorytun-udp-run https://www.openmptcprouter.com/server/glorytun-udp-run
chmod 755 /usr/local/bin/glorytun-udp-run
wget -O /lib/systemd/system/glorytun-udp@.service https://www.openmptcprouter.com/server/glorytun-udp%40.service.in
wget -O /lib/systemd/network/glorytun-udp.network https://www.openmptcprouter.com/server/glorytun-udp.network
mkdir -p /etc/glorytun-udp
wget -O /etc/glorytun-udp/tun0 https://www.openmptcprouter.com/server/tun0.glorytun-udp
if [ "$update" = "0" ]; then
	echo "$GLORYTUN_PASS" > /etc/glorytun-udp/tun0.key
elif [ ! -f /etc/glorytun-udp/tun0.key ] && [ -f /etc/glorytun-tcp/tun0.key ]; then
	cp /etc/glorytun-tcp/tun0.key /etc/glorytun-udp/tun0.key
fi
systemctl enable glorytun-udp@tun0.service
systemctl enable systemd-networkd.service
cd /tmp
rm -rf /tmp/glorytun-0.0.99-mud

# Install Glorytun TCP
if systemctl -q is-active glorytun-tcp@tun0.service; then
	systemctl -q stop glorytun-tcp@tun0 > /dev/null 2>&1
fi
apt -t stretch-backports -y install libsodium-dev
apt-get -y install build-essential pkg-config autoconf automake
rm -rf /tmp/glorytun-0.0.35
cd /tmp
wget -O /tmp/glorytun-0.0.35.tar.gz http://github.com/angt/glorytun/releases/download/v0.0.35/glorytun-0.0.35.tar.gz
tar xzf glorytun-0.0.35.tar.gz
cd glorytun-0.0.35
./autogen.sh
./configure
make
cp glorytun /usr/local/bin/glorytun-tcp
wget -O /usr/local/bin/glorytun-tcp-run https://www.openmptcprouter.com/server/glorytun-tcp-run
chmod 755 /usr/local/bin/glorytun-tcp-run
wget -O /lib/systemd/system/glorytun-tcp@.service https://www.openmptcprouter.com/server/glorytun-tcp%40.service.in
wget -O /lib/systemd/network/glorytun-tcp.network https://www.openmptcprouter.com/server/glorytun.network
mkdir -p /etc/glorytun-tcp
wget -O /etc/glorytun-tcp/tun0 https://www.openmptcprouter.com/server/tun0.glorytun
if [ "$update" = "0" ]; then
	echo "$GLORYTUN_PASS" > /etc/glorytun-tcp/tun0.key
fi
systemctl enable glorytun-tcp@tun0.service
systemctl enable systemd-networkd.service
cd /tmp
rm -rf /tmp/glorytun-0.0.35

# Load tun module at boot time
if ! grep -q tun /etc/modules ; then
	echo tun >> /etc/modules
fi

# Add multipath utility
wget -O /usr/local/bin/multipath https://www.openmptcprouter.com/server/multipath
chmod 755 /usr/local/bin/multipath

# Add OpenMPTCProuter service
wget -O /usr/local/bin/omr-service https://www.openmptcprouter.com/server/omr-service
chmod 755 /usr/local/bin/omr-service
wget -O /lib/systemd/system/omr.service https://www.openmptcprouter.com/server/omr.service.in
if systemctl -q is-active omr-6in4.service; then
	systemctl -q stop omr-6in4 > /dev/null 2>&1
	systemctl -q disable omr-6in4 > /dev/null 2>&1
fi
systemctl enable omr.service


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
	wget -O /etc/shorewall/openmptcprouter-shorewall.tar.gz https://www.openmptcprouter.com/server/openmptcprouter-shorewall.tar.gz
	tar xzf /etc/shorewall/openmptcprouter-shorewall.tar.gz -C /etc/shorewall
	rm /etc/shorewall/openmptcprouter-shorewall.tar.gz
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	systemctl enable shorewall
	wget -O /etc/shorewall6/openmptcprouter-shorewall6.tar.gz https://www.openmptcprouter.com/server/openmptcprouter-shorewall6.tar.gz
	tar xzf /etc/shorewall6/openmptcprouter-shorewall6.tar.gz -C /etc/shorewall6
	rm /etc/shorewall6/openmptcprouter-shorewall6.tar.gz
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall6/*
	systemctl enable shorewall6
else
	# Update only needed firewall files
	wget -O /etc/shorewall/interfaces https://www.openmptcprouter.com/server/shorewall4/interfaces
	wget -O /etc/shorewall/snat https://www.openmptcprouter.com/server/shorewall4/snat
	wget -O /etc/shorewall/stoppedrules https://www.openmptcprouter.com/server/shorewall4/stoppedrules
	wget -O /etc/shorewall/params https://www.openmptcprouter.com/server/shorewall4/params
	wget -O /etc/shorewall/params.vpn https://www.openmptcprouter.com/server/shorewall4/params.vpn
	wget -O /etc/shorewall/params.net https://www.openmptcprouter.com/server/shorewall4/params.net
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	sed -i 's:10.0.0.2:$OMR_ADDR:g' /etc/shorewall/rules
	wget -O /etc/shorewall6/params https://www.openmptcprouter.com/server/shorewall6/params
	wget -O /etc/shorewall6/params.net https://www.openmptcprouter.com/server/shorewall6/params.net
	wget -O /etc/shorewall6/interfaces https://www.openmptcprouter.com/server/shorewall6/interfaces
	wget -O /etc/shorewall6/stoppedrules https://www.openmptcprouter.com/server/shorewall6/stoppedrules
	wget -O /etc/shorewall6/snat https://www.openmptcprouter.com/server/shorewall6/snat
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall6/*
fi

# Add OpenMPTCProuter VPS script version to /etc/motd
if grep --quiet 'OpenMPTCProuter VPS' /etc/motd; then
	sed -i 's:< OpenMPTCProuter VPS [0-9]*\.[0-9]* >:< OpenMPCTProuter VPS 0.48 >:' /etc/motd
else
	echo '< OpenMPTCProuter VPS 0.48 >' >> /etc/motd
fi

if [ "$update" = "0" ]; then
	# Display important info
	echo '===================================================================================='
	echo 'OpenMPTCProuter VPS is now configured !'
	echo 'SSH port: 65222 (instead of port 22)'
	echo 'Shadowsocks port: 65101'
	echo 'Shadowsocks encryption: chacha20'
	echo 'Your shadowsocks key: '
	echo $SHADOWSOCKS_PASS
	echo 'Glorytun port: 65001'
	echo 'Glorytun encryption: chacha20'
	echo 'Your glorytun key: '
	echo $GLORYTUN_PASS
	echo '===================================================================================='
	echo 'Keys are also saved in /root/openmptcprouter_config.txt, you are free to remove them'
	echo '===================================================================================='
	echo '  /!\ You need to reboot to enable MPTCP, shadowsocks, glorytun and shorewall /!\'
	echo '------------------------------------------------------------------------------------'
	echo ' After reboot, check with uname -a that the kernel name contain mptcp.'
	echo ' Else, you may have to modify GRUB_DEFAULT in /etc/defaut/grub'
	echo '===================================================================================='

	# Save info in file
	cat > /root/openmptcprouter_config.txt <<-EOF
	SSH port: 65222 (instead of port 22)
	Shadowsocks port: 65101
	Shadowsocks encryption: chacha20
	Your shadowsocks key:
	${SHADOWSOCKS_PASS}
	Glorytun port: 65001
	Glorytun encryption: chacha20
	Your glorytun key:
	${GLORYTUN_PASS}
	EOF
	if [ -f "/root/openmptcprouter_mlvpn_config.txt" ]; then
		cat /root/openmptcprouter_mlvpn_config.txt >> /root/openmptcprouter_config.txt
	fi
else
	echo '===================================================================================='
	echo 'OpenMPTCProuter VPS is now updated !'
	echo 'Keys are not changed, shorewall rules files preserved'
	echo 'You need OpenMPTCProuter >= 0.30'
	echo '===================================================================================='
	echo 'Restarting systemd network...'
	systemctl -q restart systemd-networkd
	echo 'done'
	echo 'Restarting glorytun and omr...'
	systemctl -q start glorytun-tcp@tun0
	systemctl -q start glorytun-udp@tun0
	systemctl -q restart omr
	echo 'done'
	echo 'Restarting shadowsocks...'
	systemctl -q restart shadowsocks-libev-server@config
	if [ $NBCPU -gt 1 ]; then
		for i in $NBCPU; do
			systemctl restart shadowsocks-libev-server@config$i
		done
	fi
	echo 'done'
	if [ "$OPENVPN" = "yes" ]; then
		echo 'Restarting OpenVPN'
		systemctl -q restart openvpn@tun0
		echo 'done'
	fi
	echo 'Restarting shorewall...'
	systemctl -q restart shorewall
	systemctl -q restart shorewall6
	echo 'done'
	echo 'Apply latest sysctl...'
	sysctl -p /etc/sysctl.d/90-shadowsocks.conf > /dev/null 2>&1
	echo 'done'
fi
