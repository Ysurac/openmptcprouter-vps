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
cd /boot
for file in bzImage* ; do mv $file ${file/bzImage/vmlinuz} ; done
#apt-get -y install linux-mptcp
dpkg -i /tmp/linux-image-4.14.24-mptcp-64056fa.amd64.deb
dpkg -i /tmp/linux-headers-4.14.24-mptcp-64056fa.amd64.deb


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
wget -O /etc/shadowsocks-libev/config.json http://www.openmptcprouter.com/server/config.json
SHADOWSOCKS_PASS_JSON=$(echo $SHADOWSOCKS_PASS | sed 's/+/-/g; s/\//_/g;')
sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/config.json
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
#apt-get -y install meson pkg-config ca-certificates
#cd /tmp
#wget -O /tmp/glorytun-0.0.98-mud.tar.gz https://github.com/angt/glorytun/releases/download/v0.0.98-mud/glorytun-0.0.98-mud.tar.gz
#tar xzf glorytun-0.0.98-mud.tar.gz
#cd glorytun-0.0.98-mud
#meson build
#ninja -C build install
#sed -i 's:EmitDNS=yes:EmitDNS=no:g' /lib/systemd/network/glorytun.network
#rm /lib/systemd/system/glorytun*
#rm /lib/systemd/network/glorytun*
#wget -O /usr/local/bin/glorytun-run http://www.openmptcprouter.com/server/glorytun-udp-run
#chmod 755 /usr/local/bin/glorytun-run
#wget -O /lib/systemd/system/glorytun-udp@.service http://www.openmptcprouter.com/server/glorytun-udp%40.service.in
#wget -O /lib/systemd/network/glorytun-udp.network http://www.openmptcprouter.com/server/glorytun-udp.network
#mkdir -p /etc/glorytun-udp
#wget -O /etc/glorytun-udp/tun0 http://www.openmptcprouter.com/server/tun0.glorytun-udp
#echo "$GLORYTUN_PASS" > /etc/glorytun-udp/tun0.key
#systemctl enable glorytun-udp@tun0.service
#systemctl enable systemd-networkd.service
#cd /tmp
#rm -r /tmp/glorytun-0.0.98-mud


# Install Glorytun TCP
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
wget -O /usr/local/bin/omr-6in4 http://www.openmptcprouter.com/server/omr-6in4
chmod 755 /usr/local/bin/omr-6in4
wget -O /lib/systemd/system/glorytun-tcp@.service http://www.openmptcprouter.com/server/glorytun-tcp%40.service.in
wget -O /lib/systemd/network/glorytun-tcp.network http://www.openmptcprouter.com/server/glorytun.network
mkdir -p /etc/glorytun-tcp
wget -O /etc/glorytun-tcp/tun0 http://www.openmptcprouter.com/server/tun0.glorytun
echo "$GLORYTUN_PASS" > /etc/glorytun-tcp/tun0.key
systemctl enable glorytun-tcp@tun0.service
systemctl enable systemd-networkd.service
cd /tmp
rm -r /tmp/glorytun-0.0.35

# Load tun module at boot time
if ! grep -q tun /etc/modules ; then
	echo tun >> /etc/modules
fi


# Change SSH port to 65222
sed -i 's:#Port 22:Port 65222:g' /etc/ssh/sshd_config
sed -i 's:Port 22:Port 65222:g' /etc/ssh/sshd_config

# Remove Bind9 if available
#systemctl -q disable bind9

# Remove fail2ban if available
#systemctl -q disable fail2ban

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

# Add OpenMPTCProuter VPS script version to /etc/motd
if grep --quiet 'OpenMPTCProuter VPS' /etc/motd; then
	sed -i 's:< OpenMPTCProuter VPS [0-9]*\.[0-9]* >:< OpenMPCTProuter VPS 0.18 >:' /etc/motd
else
	echo '< OpenMPCTProuter VPS 0.18 >' >> /etc/motd
fi

# Display important info
echo '================================================================================'
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
echo '================================================================================'
echo '/!\ You need to reboot to enable MPTCP, shadowsocks, glorytun and shorewall /!\'
echo '--------------------------------------------------------------------------------'
echo ' After reboot, check with uname -a that the kernel name contain mptcp.'
echo ' You may have to modify GRUB_DEFAULT in /etc/defaut/grub'
echo '================================================================================'
