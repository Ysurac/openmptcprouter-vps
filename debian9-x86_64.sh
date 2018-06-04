#!/bin/sh
SHADOWSOCKS_PASS=${SHADOWSOCKS_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
GLORYTUN_PASS=${GLORYTUN_PASS:-$(od  -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
#NBCPU=${NBCPU:-$(nproc --all | tr -d "\n")}
NBCPU=${NBCPU:-$(grep -c '^processor' /proc/cpuinfo | tr -d "\n")}
OBFS=${OBFS:-no}
INTERFACE=${INTERFACE:-$(ip -o -4 route show to default | awk '{print $5}' | tr -d "\n")}
DEBIAN_VERSION=$(sed 's/\..*//' /etc/debian_version)

set -e
umask 0022
update=0
if [ $DEBIAN_VERSION -ne 9 ]; then
	echo "This script only work with Debian Stretch (9.x)"
	exit 1
fi

# Install mptcp kernel and shadowsocks
apt-get update
apt-get -y install dirmngr patch
#apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 379CE192D401AB61
#echo 'deb http://dl.bintray.com/cpaasch/deb jessie main' >> /etc/apt/sources.list
echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/stretch-backports.list
apt-get update
wget -O /tmp/linux-image-4.14.24-mptcp-64056fa.amd64.deb http://www.openmptcprouter.com/kernel/linux-image-4.14.24-mptcp-64056fa.amd64.deb
wget -O /tmp/linux-headers-4.14.24-mptcp-64056fa.amd64.deb http://www.openmptcprouter.com/kernel/linux-headers-4.14.24-mptcp-64056fa.amd64.deb
# Rename bzImage to vmlinuz, needed when custom kernel was used
cd /boot
apt-get -y install rename
rename 's/^bzImage/vmlinuz/s' * >/dev/null 2>&1
#apt-get -y install linux-mptcp
dpkg -i /tmp/linux-image-4.14.24-mptcp-64056fa.amd64.deb
dpkg -i /tmp/linux-headers-4.14.24-mptcp-64056fa.amd64.deb

# Check if mptcp kernel is grub default kernel
echo "Set MPTCP kernel as grub default..."
wget -O /tmp/update-grub.sh http://www.openmptcprouter.com/server/update-grub.sh
cd /tmp
bash update-grub.sh 4.14.24-mptcp

#apt -t stretch-backports -y install shadowsocks-libev
## Compile Shadowsocks
wget -O /tmp/shadowsocks-libev-3.1.3.tar.gz http://github.com/shadowsocks/shadowsocks-libev/releases/download/v3.1.3/shadowsocks-libev-3.1.3.tar.gz
cd /tmp
tar xzf shadowsocks-libev-3.1.3.tar.gz
cd shadowsocks-libev-3.1.3
wget http://github.com/Ysurac/openmptcprouter-feeds/raw/master/shadowsocks-libev/patches/020-NOCRYPTO.patch
patch -p1 < 020-NOCRYPTO.patch
apt-get -y install --no-install-recommends devscripts equivs apg libcap2-bin libpam-cap
apt -y -t stretch-backports install libsodium-dev
mk-build-deps --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
dpkg-buildpackage -b -us -uc
cd ..
dpkg -i shadowsocks-libev_3.1.3-1_amd64.deb
rm -r /tmp/shadowsocks-libev-3.1.3

# Load OLIA Congestion module at boot time
if ! grep -q olia /etc/modules ; then
	echo mptcp_olia >> /etc/modules
fi

# Get shadowsocks optimization
wget -O /etc/sysctl.d/90-shadowsocks.conf http://www.openmptcprouter.com/server/shadowsocks.conf

# Install shadowsocks config and add a shadowsocks by CPU
if [ ! -f /etc/shadowsocks-libev/config.json ]; then
	wget -O /etc/shadowsocks-libev/config.json http://www.openmptcprouter.com/server/config.json
	SHADOWSOCKS_PASS_JSON=$(echo $SHADOWSOCKS_PASS | sed 's/+/-/g; s/\//_/g;')
	sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/config.json
else
	update=1
fi
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
	sed -i 's%"mptcp": true%"mptcp": true,\n"plugin": "/usr/local/bin/obfs-server --obfs http --mptcp --fast-open"%' /etc/shadowsocks-libev/config.json
fi

# Install Glorytun UDP
if systemctl -q is-active glorytun-udp@tun0.service; then
	systemctl -q stop glorytun-udp@tun0 > /dev/null 2>&1
fi
apt-get -y install meson pkg-config ca-certificates
cd /tmp
wget -O /tmp/glorytun-0.0.99-mud.tar.gz https://github.com/angt/glorytun/releases/download/v0.0.99-mud/glorytun-0.0.99-mud.tar.gz
tar xzf glorytun-0.0.99-mud.tar.gz
cd glorytun-0.0.99-mud
meson build
ninja -C build install
sed -i 's:EmitDNS=yes:EmitDNS=no:g' /lib/systemd/network/glorytun.network
rm /lib/systemd/system/glorytun*
rm /lib/systemd/network/glorytun*
wget -O /usr/local/bin/glorytun-udp-run http://www.openmptcprouter.com/server/glorytun-udp-run
chmod 755 /usr/local/bin/glorytun-udp-run
wget -O /lib/systemd/system/glorytun-udp@.service http://www.openmptcprouter.com/server/glorytun-udp%40.service.in
wget -O /lib/systemd/network/glorytun-udp.network http://www.openmptcprouter.com/server/glorytun-udp.network
mkdir -p /etc/glorytun-udp
wget -O /etc/glorytun-udp/tun0 http://www.openmptcprouter.com/server/tun0.glorytun-udp
if [ "$update" -eq "0" ]; then
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
cd /tmp
wget -O /tmp/glorytun-0.0.35.tar.gz http://github.com/angt/glorytun/releases/download/v0.0.35/glorytun-0.0.35.tar.gz
cd /tmp
tar xzf glorytun-0.0.35.tar.gz
cd glorytun-0.0.35
./autogen.sh
./configure
make
cp glorytun /usr/local/bin/glorytun-tcp
wget -O /usr/local/bin/glorytun-tcp-run http://www.openmptcprouter.com/server/glorytun-tcp-run
chmod 755 /usr/local/bin/glorytun-tcp-run
wget -O /lib/systemd/system/glorytun-tcp@.service http://www.openmptcprouter.com/server/glorytun-tcp%40.service.in
wget -O /lib/systemd/network/glorytun-tcp.network http://www.openmptcprouter.com/server/glorytun.network
mkdir -p /etc/glorytun-tcp
wget -O /etc/glorytun-tcp/tun0 http://www.openmptcprouter.com/server/tun0.glorytun
if [ "$update" -eq "0" ]; then
	echo "$GLORYTUN_PASS" > /etc/glorytun-tcp/tun0.key
fi
systemctl enable glorytun-tcp@tun0.service
systemctl enable systemd-networkd.service
cd /tmp
rm -r /tmp/glorytun-0.0.35

# Load tun module at boot time
if ! grep -q tun /etc/modules ; then
	echo tun >> /etc/modules
fi

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

if [ "$update" -eq "0" ]; then
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
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	wget -O /etc/shorewall6/interfaces http://www.openmptcprouter.com/server/shorewall6/interfaces
	wget -O /etc/shorewall6/stoppedrules http://www.openmptcprouter.com/server/shorewall6/stoppedrules
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall6/*
fi

# Add OpenMPTCProuter VPS script version to /etc/motd
if grep --quiet 'OpenMPTCProuter VPS' /etc/motd; then
	sed -i 's:< OpenMPTCProuter VPS [0-9]*\.[0-9]* >:< OpenMPCTProuter VPS 0.20 >:' /etc/motd
else
	echo '< OpenMPCTProuter VPS 0.20 >' >> /etc/motd
fi

if [ "$update" -eq "0" ]; then
	# Display important info
	echo '===================================================================================='
	echo 'OpenMPTCProuter VPS is now configured !'
	echo 'SSH port: 65222 (instead of port 22)'
	echo 'Shadowsocks port: 65101'
	echo 'Shadowsocks encryption: aes-256-cfb'
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
	Shadowsocks encryption: aes-256-cfb
	Your shadowsocks key:
	${SHADOWSOCKS_PASS}
	Glorytun port: 65001
	Glorytun encryption: chacha20
	Your glorytun key:
	${GLORYTUN_PASS}
	EOF
else
	echo '===================================================================================='
	echo 'OpenMPTCProuter VPS is now updated !'
	echo 'Keys are not changed, shorewall rules files preserved'
	echo '===================================================================================='
	echo 'Restarting glorytun and omr-6in4...'
	systemctl -q start glorytun-tcp@tun0
	systemctl -q start glorytun-udp@tun0
	systemctl -q restart omr-6in4
	echo 'done'
	echo 'Restarting shorewall...'
	systemctl -q restart shorewall
	systemctl -q restart shorewall6
	echo 'done'
	echo 'Restarting shadowsocks...'
	systemctl -q restart shadowsocks-libev
	echo 'done'
fi
