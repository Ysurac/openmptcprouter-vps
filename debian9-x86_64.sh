#!/bin/sh
SHADOWSOCKS_PASS=${SHADOWSOCKS_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
GLORYTUN_PASS=${GLORYTUN_PASS:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
DSVPN_PASS=${DSVPN_PASS:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
#NBCPU=${NBCPU:-$(nproc --all | tr -d "\n")}
NBCPU=${NBCPU:-$(grep -c '^processor' /proc/cpuinfo | tr -d "\n")}
OBFS=${OBFS:-yes}
V2RAY=${V2RAY:-yes}
UPDATE_DEBIAN=${UPDATE_DEBIAN:-yes}
TLS=${TLS:-yes}
OMR_ADMIN=${OMR_ADMIN:-yes}
OMR_ADMIN_PASS=${OMR_ADMIN_PASS:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
OMR_ADMIN_PASS_ADMIN=${OMR_ADMIN_PASS_ADMIN:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
MLVPN=${MLVPN:-yes}
MLVPN_PASS=${MLVPN_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
OPENVPN=${OPENVPN:-yes}
DSVPN=${DSVPN:-yes}
INTERFACE=${INTERFACE:-$(ip -o -4 route show to default | grep -m 1 -Po '(?<=dev )(\S+)' | tr -d "\n")}
KERNEL_VERSION="4.19.80"
KERNEL_PACKAGE_VERSION="1.6+c62d9f6"
KERNEL_RELEASE="${KERNEL_VERSION}-mptcp_${KERNEL_PACKAGE_VERSION}"
GLORYTUN_UDP_VERSION="b9aaab661fb879e891d34a91b5d2e78088fd9d9d"
#MLVPN_VERSION="8f9720978b28c1954f9f229525333547283316d2"
MLVPN_VERSION="f45cec350a6879b8b020143a78134a022b5df2a7"
OBFS_VERSION="486bebd9208539058e57e23a12f23103016e09b4"
OMR_ADMIN_VERSION="6e819bc92915f8ce222107c951a384967c70247d"
DSVPN_VERSION="3b99d2ef6c02b2ef68b5784bec8adfdd55b29b1a"
#V2RAY_VERSION="v1.1.0"
V2RAY_VERSION="v1.2.0-2-g68e2207"
EASYRSA_VERSION="3.0.6"
SHADOWSOCKS_VERSION="3.3.3"
VPS_DOMAIN=${VPS_DOMAIN:-$(wget -4 -qO- -T 2 http://hostname.openmptcprouter.com)}
VPSPATH="server-test"

OMR_VERSION="0.1006-test1"

set -e
umask 0022
export LC_ALL=C
export PATH=$PATH:/sbin
export DEBIAN_FRONTEND=noninteractive 
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend

# Check Linux version
if test -f /etc/os-release ; then
	. /etc/os-release
else
	. /usr/lib/os-release
fi
if [ "$ID" = "debian" ] && [ "$VERSION_ID" != "9" ] && [ "$VERSION_ID" != "10" ]; then
	echo "This script only work with Debian Stretch (9.x) or Debian Buster (10.x)"
	exit 1
elif [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" != "18.04" ] && [ "$VERSION_ID" != "19.04" ]; then
	echo "This script only work with Ubuntu 18.04 or Ubuntu 19.04"
	exit 1
elif [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
	echo "This script only work with Ubuntu 18.04, Ubuntu 19.04, Debian Stretch (9.x) or Debian Buster (10.x)"
	exit 1
fi

# Fix old string...
if [ -f /etc/motd ] && grep --quiet 'OpenMPCTProuter VPS' /etc/motd ; then
	sed -i 's/OpenMPCTProuter/OpenMPTCProuter/g' /etc/motd
fi
if [ -f /etc/motd.head ] && grep --quiet 'OpenMPCTProuter VPS' /etc/motd.head ; then
	sed -i 's/OpenMPCTProuter/OpenMPTCProuter/g' /etc/motd.head
fi

# Check if OpenMPTCProuter VPS is already installed
update="0"
if [ -f /etc/motd ] && grep --quiet 'OpenMPTCProuter VPS' /etc/motd ; then
	update="1"
elif [ -f /etc/motd.head ] && grep --quiet 'OpenMPTCProuter VPS' /etc/motd.head ; then
	update="1"
elif [ -f /root/openmptcprouter_config.txt ]; then
	update="1"
fi

rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
rm -f /var/cache/apt/archives/lock
apt-get update
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
rm -f /var/cache/apt/archives/lock
apt-get -y install apt-transport-https gnupg

#if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ] && [ "$UPDATE_DEBIAN" = "yes" ] && [ "$update" = "0" ]; then
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ] && [ "$UPDATE_DEBIAN" = "yes" ]; then
	echo "Update Debian 9 Stretch to Debian 10 Buster"
	apt-get -y -f --force-yes upgrade
	apt-get -y -f --force-yes dist-upgrade
	sed -i 's:stretch:buster:g' /etc/apt/sources.list
	apt-get update
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" dist-upgrade
	VERSION_ID="10"
fi
# Add OpenMPTCProuter repo
echo 'deb https://repo.openmptcprouter.com stretch main' > /etc/apt/sources.list.d/openmptcprouter.list
cat <<EOF | tee /etc/apt/preferences.d/openmptcprouter.pref
Explanation: Prefer OpenMPTCProuter provided packages over the Debian native ones
Package: *
Pin: origin repo.openmptcprouter.com
Pin-Priority: 1001
EOF
wget -O - http://repo.openmptcprouter.com/openmptcprouter.gpg.key | apt-key add -

# Install mptcp kernel and shadowsocks
apt-get update
sleep 2
apt-get -y install dirmngr patch
#apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 379CE192D401AB61
if [ "$ID" = "debian" ]; then
	if [ "$VERSION_ID" = "9" ]; then
		#echo 'deb http://dl.bintray.com/cpaasch/deb jessie main' >> /etc/apt/sources.list
		echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/stretch-backports.list
	fi
elif [ "$ID" = "ubuntu" ]; then
	echo 'deb http://archive.ubuntu.com/ubuntu bionic-backports main' > /etc/apt/sources.list.d/bionic-backports.list
	echo 'deb http://archive.ubuntu.com/ubuntu bionic universe' > /etc/apt/sources.list.d/bionic-universe.list
fi
apt-get update
sleep 2
wget -O /tmp/linux-image-${KERNEL_RELEASE}_amd64.deb https://www.openmptcprouter.com/kernel/linux-image-${KERNEL_RELEASE}_amd64.deb
wget -O /tmp/linux-headers-${KERNEL_RELEASE}_amd64.deb https://www.openmptcprouter.com/kernel/linux-headers-${KERNEL_RELEASE}_amd64.deb
# Rename bzImage to vmlinuz, needed when custom kernel was used
cd /boot
apt-get -y install rename curl
rename 's/^bzImage/vmlinuz/s' * >/dev/null 2>&1
#apt-get -y install linux-mptcp
#dpkg --remove --force-remove-reinstreq linux-image-${KERNEL_VERSION}-mptcp
#dpkg --remove --force-remove-reinstreq linux-headers-${KERNEL_VERSION}-mptcp
if [ "$(dpkg -l | grep linux-image-${KERNEL_VERSION} | grep ${KERNEL_PACKAGE_VERSION})" = "" ]; then
	echo "Install kernel linux-image-${KERNEL_RELEASE}"
	echo "if kernel install fail run: dpkg --remove --force-remove-reinstreq linux-image-${KERNEL_VERSION}-mptcp"
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_RELEASE}_amd64.deb
	dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_RELEASE}_amd64.deb
fi

# Check if mptcp kernel is grub default kernel
echo "Set MPTCP kernel as grub default..."
wget -O /tmp/update-grub.sh https://www.openmptcprouter.com/${VPSPATH}/update-grub.sh
cd /tmp
bash update-grub.sh ${KERNEL_VERSION}-mptcp
bash update-grub.sh ${KERNEL_RELEASE}

echo "Install tracebox and iperf3 OpenMPTCProuter edition"
apt-get -y -o Dpkg::Options::="--force-overwrite" install tracebox omr-iperf3

#apt -t stretch-backports -y install shadowsocks-libev
## Compile Shadowsocks
rm -rf /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}
wget -O /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}.tar.gz http://github.com/shadowsocks/shadowsocks-libev/releases/download/v${SHADOWSOCKS_VERSION}/shadowsocks-libev-${SHADOWSOCKS_VERSION}.tar.gz
cd /tmp
tar xzf shadowsocks-libev-${SHADOWSOCKS_VERSION}.tar.gz
cd shadowsocks-libev-${SHADOWSOCKS_VERSION}
wget https://raw.githubusercontent.com/Ysurac/openmptcprouter-feeds/master/shadowsocks-libev/patches/020-NOCRYPTO.patch
patch -p1 < 020-NOCRYPTO.patch
wget https://github.com/Ysurac/shadowsocks-libev/commit/31b93ac2b054bc3f68ea01569649e6882d72218e.patch
patch -p1 < 31b93ac2b054bc3f68ea01569649e6882d72218e.patch
wget https://github.com/Ysurac/shadowsocks-libev/commit/2e52734b3bf176966e78e77cf080a1e8c6b2b570.patch
patch -p1 < 2e52734b3bf176966e78e77cf080a1e8c6b2b570.patch
# Shadowsocks eBPF support
#wget https://raw.githubusercontent.com/Ysurac/openmptcprouter-feeds/master/shadowsocks-libev/patches/030-eBPF.patch
#patch -p1 < 030-eBPF.patch
#rm -f /var/lib/dpkg/lock
#apt-get install -y --no-install-recommends build-essential git ca-certificates libcap-dev libelf-dev libpcap-dev
#cd /tmp
#rm -rf libbpf
#git clone https://github.com/libbpf/libbpf.git
#cd libbpf
#if [ "$ID" = "debian" ]; then
#	rm -f /var/lib/dpkg/lock
#	apt -y -t stretch-backports install linux-libc-dev
#elif [ "$ID" = "ubuntu" ]; then
#	rm -f /var/lib/dpkg/lock
#	apt-get -y install linux-libc-dev
#fi
#BUILD_SHARED=y make -C src CFLAGS="$CFLAGS -DCOMPAT_NEED_REALLOCARRAY"
#cp /tmp/libbpf/src/libbpf.so /usr/lib
#cp /tmp/libbpf/src/*.h /usr/include/bpf
#cd /tmp
#rm -rf /tmp/libbpf
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
apt-get -y install --no-install-recommends devscripts equivs apg libcap2-bin libpam-cap libc-ares2 libc-ares-dev libev4 haveged
sleep 1
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
systemctl enable haveged

if [ "$ID" = "debian" ]; then
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	if [ "$VERSION_ID" = "9" ]; then
		apt -y -t stretch-backports install libsodium-dev
	else
		apt -y install libsodium-dev
	fi
elif [ "$ID" = "ubuntu" ]; then
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get -y install libsodium-dev
fi
cd /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
mk-build-deps --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
dpkg-buildpackage -b -us -uc
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
cd /tmp
dpkg -i shadowsocks-libev_${SHADOWSOCKS_VERSION}-1_amd64.deb
#mkdir -p /usr/lib/shadowsocks-libev
#cp -f /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}/src/*.ebpf /usr/lib/shadowsocks-libev
rm -rf /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}

# Load OLIA Congestion module at boot time
if ! grep -q olia /etc/modules ; then
	echo mptcp_olia >> /etc/modules
fi
# Load WVEGAS Congestion module at boot time
if ! grep -q wvegas /etc/modules ; then
	echo mptcp_wvegas >> /etc/modules
fi
# Load BALIA Congestion module at boot time
if ! grep -q balia /etc/modules ; then
	echo mptcp_balia >> /etc/modules
fi
# Load BBR Congestion module at boot time
if ! grep -q bbr /etc/modules ; then
	echo tcp_bbr >> /etc/modules
fi
# Load mctcpdesync Congestion module at boot time
if ! grep -q mctcp_desync /etc/modules ; then
	echo mctcp_desync >> /etc/modules
fi
# Load ndiffports module at boot time
if ! grep -q mctcp_ndiffports /etc/modules ; then
	echo mctcp_ndiffports >> /etc/modules
fi
# Load redundant module at boot time
if ! grep -q mctcp_redundant /etc/modules ; then
	echo mctcp_redundant >> /etc/modules
fi
# Load rr module at boot time
if ! grep -q mctcp_rr /etc/modules ; then
	echo mctcp_rr >> /etc/modules
fi
# Load mctcp ECF scheduler at boot time
if ! grep -q mctcp_ecf /etc/modules ; then
	echo mctcp_ecf >> /etc/modules
fi
# Load mctcp BLEST scheduler at boot time
if ! grep -q mctcp_blest /etc/modules ; then
	echo mctcp_blest >> /etc/modules
fi

if systemctl -q is-active omr-admin.service; then
	systemctl -q stop omr-admin > /dev/null 2>&1
fi

if [ "$OMR_ADMIN" = "yes" ]; then
	echo 'Install OpenMPTCProuter VPS Admin'
	if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ]; then
		#echo 'deb http://ftp.de.debian.org/debian buster main' > /etc/apt/sources.list.d/buster.list
		#echo 'APT::Default-Release "stretch";' | tee -a /etc/apt/apt.conf.d/00local
		#apt-get update
		apt-get -y install unzip
		#apt-get -y -t buster install python3.7-dev
		#apt-get -y -t buster install python3-pip python3-setuptools python3-wheel
		if [ "$(whereis python3 | grep python3.7)" = "" ]; then
			apt-get -y install libffi-dev build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev wget
			wget -O /tmp/Python-3.7.2.tgz https://www.python.org/ftp/python/3.7.2/Python-3.7.2.tgz
			cd /tmp
			tar xzf Python-3.7.2.tgz
			cd Python-3.7.2
			./configure --enable-optimizations
			make
			make altinstall
			cd /tmp
			rm -rf /tmp/Python-3.7.2
			update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.7 1
			update-alternatives --install /usr/bin/pip3 pip3 /usr/local/bin/pip3.7 1
			sed -i 's:/usr/bin/python3 :/usr/bin/python3\.7 :g' /usr/bin/lsb_release
		fi
		pip3 -q install setuptools wheel
		pip3 -q install pyopenssl
	else
		apt-get -y install unzip python3-openssl python3-pip python3-setuptools python3-wheel python3-dev
	fi
	#apt-get -y install unzip gunicorn python3-flask-restful python3-openssl python3-pip python3-setuptools python3-wheel
	#apt-get -y install unzip python3-openssl python3-pip python3-setuptools python3-wheel
	echo '-- pip3 install needed python modules'
	#pip3 -q install flask-jwt-simple netjsonconfig
	pip3 install pyjwt passlib uvicorn fastapi netjsonconfig python-multipart
	mkdir -p /etc/openmptcprouter-vps-admin
	mkdir -p /var/opt/openmptcprouter
	wget -O /lib/systemd/system/omr-admin.service https://www.openmptcprouter.com/${VPSPATH}/omr-admin.service.in
	wget -O /tmp/openmptcprouter-vps-admin.zip https://github.com/Ysurac/openmptcprouter-vps-admin/archive/${OMR_ADMIN_VERSION}.zip
	cd /tmp
	unzip -q -o openmptcprouter-vps-admin.zip
	if [ -f /usr/local/bin/omr-admin.py ]; then
		apt-get -y install jq
		cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin.py /usr/local/bin/
		OMR_ADMIN_PASS=$(grep -Po '"'"pass"'"\s*:\s*"\K([^"]*)' /etc/openmptcprouter-vps-admin/omr-admin-config.json | tr -d  "\n")
		[ -z "$OMR_ADMIN_PASS" ] && OMR_ADMIN_PASS=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.user_password | tr -d "\n")
	else
		cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin-config.json /etc/openmptcprouter-vps-admin/
		cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin.py /usr/local/bin/
		cd /etc/openmptcprouter-vps-admin
	fi
	if [ "$(grep user_password /etc/openmptcprouter-vps-admin/omr-admin-config.json)" = "" ]; then
		cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin-config.json /etc/openmptcprouter-vps-admin/
		cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin.py /usr/local/bin/
		cd /etc/openmptcprouter-vps-admin
	fi
	openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout key.pem -out cert.pem -subj "/C=US/ST=Oregon/L=Portland/O=OpenMPTCProuterVPS/OU=Org/CN=www.openmptcprouter.vps"
	sed -i "s:AdminMySecretKey:$OMR_ADMIN_PASS_ADMIN:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	sed -i "s:MySecretKey:$OMR_ADMIN_PASS:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	chmod u+x /usr/local/bin/omr-admin.py
	systemctl enable omr-admin.service
	rm -rf /tmp/tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}
fi

# Get shadowsocks optimization
wget -O /etc/sysctl.d/90-shadowsocks.conf https://www.openmptcprouter.com/${VPSPATH}/shadowsocks.conf

if [ "$update" != 0 ] && [ ! -f /etc/shadowsocks-libev/manager.json ]; then
	SHADOWSOCKS_PASS=$(grep -Po '"'"key"'"\s*:\s*"\K([^"]*)' /etc/shadowsocks-libev/config.json | tr -d  "\n" | sed 's/-/+/g; s/_/\//g;')
fi

# Install shadowsocks config and add a shadowsocks by CPU
if [ "$update" = "0" ] || [ ! -f /etc/shadowsocks-libev/manager.json ]; then
	#wget -O /etc/shadowsocks-libev/config.json https://www.openmptcprouter.com/${VPSPATH}/config.json
	wget -O /etc/shadowsocks-libev/manager.json https://www.openmptcprouter.com/${VPSPATH}/manager.json
	SHADOWSOCKS_PASS_JSON=$(echo $SHADOWSOCKS_PASS | sed 's/+/-/g; s/\//_/g;')
	#sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/config.json
	sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/manager.json
fi
[ ! -f /etc/shadowsocks-libev/local.acl ] && touch /etc/shadowsocks-libev/local.acl
#sed -i 's:aes-256-cfb:chacha20:g' /etc/shadowsocks-libev/config.json
#sed -i 's:json:json --no-delay:g' /lib/systemd/system/shadowsocks-libev-server@.service
wget -O /lib/systemd/system/shadowsocks-libev-manager@.service https://www.openmptcprouter.com/${VPSPATH}/shadowsocks-libev-manager@.service.in
systemctl disable shadowsocks-libev
[ -f /etc/shadowsocks-libev/config.json ] && systemctl disable shadowsocks-libev-server@config.service
systemctl enable shadowsocks-libev-manager@manager.service
if [ $NBCPU -gt 1 ]; then
	for i in $NBCPU; do
		[ -f /etc/shadowsocks-libev/config$i.json ] && systemctl disable shadowsocks-libev-server@config$i.service
	done
fi
if ! grep -q 'DefaultLimitNOFILE=65536' /etc/systemd/system.conf ; then
	echo 'DefaultLimitNOFILE=65536' >> /etc/systemd/system.conf
fi
# Install simple-obfs
if [ "$OBFS" = "yes" ]; then
	echo "Install OBFS"
	rm -rf /tmp/simple-obfs
	cd /tmp
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ]; then
		#apt-get install -y --no-install-recommends -t buster libssl-dev
		apt-get install -y --no-install-recommends libssl-dev
		apt-get install -y --no-install-recommends build-essential autoconf libtool libpcre3-dev libev-dev asciidoc xmlto automake git ca-certificates
	else
		apt-get install -y --no-install-recommends build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake git ca-certificates
	fi
	git clone https://github.com/shadowsocks/simple-obfs.git /tmp/simple-obfs
	cd /tmp/simple-obfs
	git checkout ${OBFS_VERSION}
	git submodule update --init --recursive
	./autogen.sh
	./configure && make
	make install
	cd /tmp
	rm -rf /tmp/simple-obfs
	#sed -i 's%"mptcp": true%"mptcp": true,\n"plugin": "/usr/local/bin/obfs-server",\n"plugin_opts": "obfs=http;mptcp;fast-open;t=400"%' /etc/shadowsocks-libev/config.json
fi

# Install v2ray-plugin
if [ "$V2RAY" = "yes" ]; then
	echo "Install v2ray plugin"
	rm -rf /tmp/v2ray-plugin-linux-amd64-${V2RAY_VERSION}.tar.gz
	#wget -O /tmp/v2ray-plugin-linux-amd64-${V2RAY_VERSION}.tar.gz https://github.com/shadowsocks/v2ray-plugin/releases/download/${V2RAY_VERSION}/v2ray-plugin-linux-amd64-${V2RAY_VERSION}.tar.gz
	wget -O /tmp/v2ray-plugin-linux-amd64-${V2RAY_VERSION}.tar.gz https://www.openmptcprouter.com/${VPSPATH}/bin/v2ray-plugin-linux-amd64-${V2RAY_VERSION}.tar.gz
	cd /tmp
	tar xzvf v2ray-plugin-linux-amd64-${V2RAY_VERSION}.tar.gz
	cp v2ray-plugin_linux_amd64 /usr/local/bin/v2ray-plugin
	cd /tmp
	rm -rf /tmp/v2ray-plugin_linux_amd64
	rm -rf /tmp/v2ray-plugin-linux-amd64-${V2RAY_VERSION}.tar.gz
	
	#rm -rf /tmp/v2ray-plugin
	#cd /tmp
	#rm -f /var/lib/dpkg/lock
	#apt-get install -y --no-install-recommends git ca-certificates golang-go
	#git clone https://github.com/shadowsocks/v2ray-plugin.git /tmp/v2ray-plugin
	#cd /tmp/v2ray-plugin
	#git checkout ${V2RAY_VERSION}
	#git submodule update --init --recursive
	#CGO_ENABLED=0 go build -o v2ray-plugin
	#cp v2ray-plugin /usr/local/bin/v2ray-plugin
	#cd /tmp
	#rm -rf /tmp/simple-obfs
fi

if [ "$OBFS" = "no" ] && [ "$V2RAYPLUGIN" = "no" ]; then
	sed -i -e '/plugin/d' -e 's/,,//' /etc/shadowsocks-libev/config.json
fi

if systemctl -q is-active mlvpn@mlvpn0.service; then
	systemctl -q stop mlvpn@mlvpn0 > /dev/null 2>&1
	systemctl -q disable mlvpn@mlvpn0 > /dev/null 2>&1
fi
echo "install mlvpn"
# Install MLVPN
if [ "$MLVPN" = "yes" ]; then
	echo 'Install MLVPN'
	mlvpnupdate="0"
	if [ -f /etc/mlvpn/mlvpn0.conf ]; then
		mlvpnupdate="1"
	fi
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get -y install build-essential pkg-config autoconf automake libpcap-dev unzip git
	rm -rf /tmp/mlvpn
	cd /tmp
	#git clone https://github.com/markfoodyburton/MLVPN.git /tmp/mlvpn
	git clone https://github.com/flohoff/MLVPN.git /tmp/mlvpn
	#git clone https://github.com/link4all/MLVPN.git /tmp/mlvpn
	cd /tmp/mlvpn
	git checkout ${MLVPN_VERSION}
	./autogen.sh
	./configure --sysconfdir=/etc
	make
	make install
	wget -O /lib/systemd/network/mlvpn.network https://www.openmptcprouter.com/${VPSPATH}/mlvpn.network
	wget -O /lib/systemd/system/mlvpn@.service https://www.openmptcprouter.com/${VPSPATH}/mlvpn@.service.in
	mkdir -p /etc/mlvpn
	if [ "$mlvpnupdate" = "0" ]; then
		wget -O /etc/mlvpn/mlvpn0.conf https://www.openmptcprouter.com/${VPSPATH}/mlvpn0.conf
		sed -i "s:MLVPN_PASS:$MLVPN_PASS:" /etc/mlvpn/mlvpn0.conf
	fi
	chmod 0600 /etc/mlvpn/mlvpn0.conf
	adduser --quiet --system --home /var/opt/mlvpn --shell /usr/sbin/nologin mlvpn
	mkdir -p /var/opt/mlvpn
	usermod -d /var/opt/mlvpn mlvpn
	chown mlvpn /var/opt/mlvpn
	systemctl enable mlvpn@mlvpn0.service
	systemctl enable systemd-networkd.service
	cd /tmp
	rm -rf /tmp/mlvpn
fi
echo "install mlvpn done"
if systemctl -q is-active openvpn-server@tun0.service; then
	systemctl -q stop openvpn-server@tun0 > /dev/null 2>&1
	systemctl -q disable openvpn-server@tun0 > /dev/null 2>&1
fi
if [ "$OPENVPN" = "yes" ]; then
	echo "Install OpenVPN"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get -y install openvpn easy-rsa
	#wget -O /lib/systemd/network/openvpn.network https://www.openmptcprouter.com/${VPSPATH}/openvpn.network
	rm -f /lib/systemd/network/openvpn.network
	#if [ ! -f "/etc/openvpn/server/static.key" ]; then
	#	wget -O /etc/openvpn/tun0.conf https://www.openmptcprouter.com/${VPSPATH}/openvpn-tun0.conf
	#	cd /etc/openvpn/server
	#	openvpn --genkey --secret static.key
	#fi
	if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "18.04" ]; then
		wget -O /tmp/EasyRSA-unix-v${EASYRSA_VERSION}.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.6/EasyRSA-unix-v${EASYRSA_VERSION}.tgz
		cd /tmp
		tar xzvf EasyRSA-unix-v${EASYRSA_VERSION}.tgz
		cd /tmp/EasyRSA-v${EASYRSA_VERSION}
		mkdir -p /etc/openvpn/ca/pki/private /etc/openvpn/ca/pki/issued
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "openmptcprouter" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		mv pki/ca.crt /etc/openvpn/ca/pki/ca.crt
		mv pki/private/ca.key /etc/openvpn/ca/pki/private/ca.key
		mv pki/issued/server.crt /etc/openvpn/ca/pki/issued/server.crt
		mv pki/private/server.key /etc/openvpn/ca/pki/private/server.key
		mv pki/crl.pem /etc/openvpn/ca/pki/crl.pem
		mv pki/issued/openmptcprouter.crt /etc/openvpn/ca/pki/issued/openmptcprouter.crt
		mv pki/private/openmptcprouter.key /etc/openvpn/ca/pki/private/openmptcprouter.key
	fi

	if [ -f "/etc/openvpn/server/server.crt" ]; then
		if [ ! -d /etc/openvpn/ca ]; then
			make-cadir /etc/openvpn/ca
		fi
		mkdir -p /etc/openvpn/ca/pki/private /etc/openvpn/ca/pki/issued
		mv /etc/openvpn/server/ca.crt /etc/openvpn/ca/pki/ca.crt
		mv /etc/openvpn/server/ca.key /etc/openvpn/ca/pki/private/ca.key
		mv /etc/openvpn/server/server.crt /etc/openvpn/ca/pki/issued/server.crt
		mv /etc/openvpn/server/server.key /etc/openvpn/ca/pki/private/server.key
		mv /etc/openvpn/server/crl.pem /etc/openvpn/ca/pki/crl.pem
		mv /etc/openvpn/client/client.crt /etc/openvpn/ca/pki/issued/openmptcprouter.crt
		mv /etc/openvpn/client/client.key /etc/openvpn/ca/pki/private/openmptcprouter.key
	fi
	if [ ! -f "/etc/openvpn/ca/pki/issued/server.crt" ]; then
		openssl dhparam -out /etc/openvpn/server/dh2048.pem 2048
		if [ ! -d /etc/openvpn/ca ]; then
			make-cadir /etc/openvpn/ca
		fi
		cd /etc/openvpn/ca
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "openmptcprouter" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	fi
	if [ ! -f "/etc/openvpn/ca/pki/issued/openmptcprouter.crt" ]; then
		mv /etc/openvpn/ca/pki/issued/client.crt /etc/openvpn/ca/pki/issued/openmptcprouter.crt
		mv /etc/openvpn/ca/pki/private/client.key /etc/openvpn/ca/pki/private/openmptcprouter.key
	fi
	wget -O /etc/openvpn/tun0.conf https://www.openmptcprouter.com/${VPSPATH}/openvpn-tun0.conf
	wget -O /etc/openvpn/tun1.conf https://www.openmptcprouter.com/${VPSPATH}/openvpn-tun1.conf
	systemctl enable openvpn@tun0.service
	systemctl enable openvpn@tun1.service
fi

echo 'Glorytun UDP'
# Install Glorytun UDP
if systemctl -q is-active glorytun-udp@tun0.service; then
	systemctl -q stop glorytun-udp@tun0 > /dev/null 2>&1
fi
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
apt-get install -y --no-install-recommends build-essential git ca-certificates meson pkg-config
rm -rf /tmp/glorytun-udp
cd /tmp
git clone https://github.com/angt/glorytun.git /tmp/glorytun-udp
cd /tmp/glorytun-udp
git checkout ${GLORYTUN_UDP_VERSION}
git submodule update --init --recursive
meson build
ninja -C build install
sed -i 's:EmitDNS=yes:EmitDNS=no:g' /lib/systemd/network/glorytun.network
rm /lib/systemd/system/glorytun*
rm /lib/systemd/network/glorytun*
wget -O /usr/local/bin/glorytun-udp-run https://www.openmptcprouter.com/${VPSPATH}/glorytun-udp-run
chmod 755 /usr/local/bin/glorytun-udp-run
wget -O /lib/systemd/system/glorytun-udp@.service https://www.openmptcprouter.com/${VPSPATH}/glorytun-udp%40.service.in
wget -O /lib/systemd/network/glorytun-udp.network https://www.openmptcprouter.com/${VPSPATH}/glorytun-udp.network
mkdir -p /etc/glorytun-udp
wget -O /etc/glorytun-udp/tun0 https://www.openmptcprouter.com/${VPSPATH}/tun0.glorytun-udp
if [ "$update" = "0" ] || [ ! -f /etc/glorytun-udp/tun0.key ]; then
	echo "$GLORYTUN_PASS" > /etc/glorytun-udp/tun0.key
elif [ ! -f /etc/glorytun-udp/tun0.key ] && [ -f /etc/glorytun-tcp/tun0.key ]; then
	cp /etc/glorytun-tcp/tun0.key /etc/glorytun-udp/tun0.key
fi
systemctl enable glorytun-udp@tun0.service
systemctl enable systemd-networkd.service
cd /tmp
rm -rf /tmp/glorytun-udp

# Add chrony for time sync
apt-get install -y chrony
systemctl enable chrony

if [ "$DSVPN" = "yes" ]; then
	echo 'A Dead Simple VPN'
	# Install A Dead Simple VPN
	if systemctl -q is-active dsvpn-server.service; then
		systemctl -q stop dsvpn-server > /dev/null 2>&1
	fi
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get install -y --no-install-recommends build-essential git ca-certificates
	rm -rf /tmp/dsvpn
	cd /tmp
	git clone https://github.com/jedisct1/dsvpn.git /tmp/dsvpn
	cd /tmp/dsvpn
	git checkout ${DSVPN_VERSION}
	wget https://github.com/Ysurac/openmptcprouter-feeds/raw/develop/dsvpn/patches/nofirewall.patch
	patch -p1 < nofirewall.patch
	make CFLAGS='-DNO_DEFAULT_ROUTES -DNO_DEFAULT_FIREWALL'
	make install
	rm -f /lib/systemd/system/dsvpn/*
	wget -O /lib/systemd/system/dsvpn-server.service https://www.openmptcprouter.com/${VPSPATH}/dsvpn-server.service.in
	mkdir -p /etc/dsvpn
	if [ "$update" = "0" ] || [ ! -f /etc/dsvpn/dsvpn.key ]; then
		echo "$DSVPN_PASS" > /etc/dsvpn/dsvpn.key
	fi
	systemctl enable dsvpn-server.service
	cd /tmp
	rm -rf /tmp/dsvpn
fi

# Install Glorytun TCP
if systemctl -q is-active glorytun-tcp@tun0.service; then
	systemctl -q stop glorytun-tcp@tun0 > /dev/null 2>&1
fi
if [ "$ID" = "debian" ]; then
	if [ "$VERSION_ID" = "9" ]; then
		apt -t stretch-backports -y install libsodium-dev
	else
		apt -y install libsodium-dev
	fi
elif [ "$ID" = "ubuntu" ]; then
	apt-get -y install libsodium-dev
fi
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
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
wget -O /usr/local/bin/glorytun-tcp-run https://www.openmptcprouter.com/${VPSPATH}/glorytun-tcp-run
chmod 755 /usr/local/bin/glorytun-tcp-run
wget -O /lib/systemd/system/glorytun-tcp@.service https://www.openmptcprouter.com/${VPSPATH}/glorytun-tcp%40.service.in
wget -O /lib/systemd/network/glorytun-tcp.network https://www.openmptcprouter.com/${VPSPATH}/glorytun.network
mkdir -p /etc/glorytun-tcp
wget -O /etc/glorytun-tcp/tun0 https://www.openmptcprouter.com/${VPSPATH}/tun0.glorytun
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
wget -O /usr/local/bin/multipath https://www.openmptcprouter.com/${VPSPATH}/multipath
chmod 755 /usr/local/bin/multipath

# Add OpenMPTCProuter service
wget -O /usr/local/bin/omr-service https://www.openmptcprouter.com/${VPSPATH}/omr-service
chmod 755 /usr/local/bin/omr-service
wget -O /lib/systemd/system/omr.service https://www.openmptcprouter.com/${VPSPATH}/omr.service.in
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
	wget -O /etc/shorewall/openmptcprouter-shorewall.tar.gz https://www.openmptcprouter.com/${VPSPATH}/openmptcprouter-shorewall.tar.gz
	tar xzf /etc/shorewall/openmptcprouter-shorewall.tar.gz -C /etc/shorewall
	rm /etc/shorewall/openmptcprouter-shorewall.tar.gz
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	systemctl enable shorewall
	wget -O /etc/shorewall6/openmptcprouter-shorewall6.tar.gz https://www.openmptcprouter.com/${VPSPATH}/openmptcprouter-shorewall6.tar.gz
	tar xzf /etc/shorewall6/openmptcprouter-shorewall6.tar.gz -C /etc/shorewall6
	rm /etc/shorewall6/openmptcprouter-shorewall6.tar.gz
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall6/*
	systemctl enable shorewall6
else
	# Update only needed firewall files
	wget -O /etc/shorewall/interfaces https://www.openmptcprouter.com/${VPSPATH}/shorewall4/interfaces
	wget -O /etc/shorewall/snat https://www.openmptcprouter.com/${VPSPATH}/shorewall4/snat
	wget -O /etc/shorewall/stoppedrules https://www.openmptcprouter.com/${VPSPATH}/shorewall4/stoppedrules
	wget -O /etc/shorewall/tcinterfaces https://www.openmptcprouter.com/${VPSPATH}/shorewall4/tcinterfaces
	wget -O /etc/shorewall/shorewall.conf https://www.openmptcprouter.com/${VPSPATH}/shorewall4/shorewall.conf
	wget -O /etc/shorewall/params https://www.openmptcprouter.com/${VPSPATH}/shorewall4/params
	wget -O /etc/shorewall/params.vpn https://www.openmptcprouter.com/${VPSPATH}/shorewall4/params.vpn
	wget -O /etc/shorewall/params.net https://www.openmptcprouter.com/${VPSPATH}/shorewall4/params.net
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	sed -i 's/^.*#DNAT/#DNAT/g' /etc/shorewall/rules
	sed -i 's:10.0.0.2:$OMR_ADDR:g' /etc/shorewall/rules
	wget -O /etc/shorewall6/params https://www.openmptcprouter.com/${VPSPATH}/shorewall6/params
	wget -O /etc/shorewall6/params.net https://www.openmptcprouter.com/${VPSPATH}/shorewall6/params.net
	wget -O /etc/shorewall6/interfaces https://www.openmptcprouter.com/${VPSPATH}/shorewall6/interfaces
	wget -O /etc/shorewall6/stoppedrules https://www.openmptcprouter.com/${VPSPATH}/shorewall6/stoppedrules
	wget -O /etc/shorewall6/snat https://www.openmptcprouter.com/${VPSPATH}/shorewall6/snat
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall6/*
fi
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ]; then
	apt-get -y install iptables
	update-alternatives --set iptables /usr/sbin/iptables-legacy
	update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
fi
if ([ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ]) || ([ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "19.04" ]); then
	sed -i 's:DROP_DEFAULT=Drop:DROP_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall/shorewall.conf
	sed -i 's:REJECT_DEFAULT=Reject:REJECT_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall/shorewall.conf
	sed -i 's:DROP_DEFAULT=Drop:DROP_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall6/shorewall6.conf
	sed -i 's:REJECT_DEFAULT=Reject:REJECT_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall6/shorewall6.conf
fi

if [ "$TLS" = "yes" ]; then
	VPS_CERT=0
	apt-get -y install dnsutils socat
	if [ "$VPS_DOMAIN" != "" ] && [ "$(dig +noall +answer $VPS_DOMAIN)" != "" ] && [ "$(ping -c 1 -w 1 $VPS_DOMAIN)" ]; then
		if [ ! -f "/root/.acme.sh/$VPS_DOMAIN/$VPS_DOMAIN.cer" ]; then
			echo "Generate certificate for V2Ray"
			set +e
			#[ "$(shorewall  status | grep stopped)" = "" ] && shorewall open all all tcp 443
			curl https://get.acme.sh | sh
			systemctl -q restart shorewall
			~/.acme.sh/acme.sh --force --alpn --issue -d $VPS_DOMAIN --pre-hook 'shorewall open all all tcp 443 2>&1 >/dev/null' --post-hook 'shorewall close all all tcp 443 2>&1 >/dev/null' 2>&1 >/dev/null
			set -e
#			mkdir -p /etc/ssl/v2ray
#			ln -f -s /root/.acme.sh/$reverse/$reverse.key /etc/ssl/v2ray/omr.key
#			ln -f -s /root/.acme.sh/$reverse/fullchain.cer /etc/ssl/v2ray/omr.cer
			#[ "$(shorewall  status | grep stopped)" = "" ] && shorewall close all all tcp 443
		fi
		VPS_CERT=1
	else
		echo "No working domain detected..."
	fi
fi



# Add OpenMPTCProuter VPS script version to /etc/motd
if [ -f /etc/motd.head ]; then
	if grep --quiet 'OpenMPTCProuter VPS' /etc/motd.head; then
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-test[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd.head
		sed -i "s:< OpenMPTCProuter VPS \$OMR_VERSION >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd.head
	else
		echo "< OpenMPTCProuter VPS $OMR_VERSION >" >> /etc/motd.head
	fi
elif [ -f /etc/motd ]; then
	if grep --quiet 'OpenMPTCProuter VPS' /etc/motd; then
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-test[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd
		sed -i "s:< OpenMPTCProuter VPS \$OMR_VERSION >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd
	else
		echo "< OpenMPTCProuter VPS $OMR_VERSION >" >> /etc/motd
	fi
else
	echo "< OpenMPTCProuter VPS $OMR_VERSION >" > /etc/motd
fi

if [ "$update" = "0" ]; then
	# Display important info
	echo '===================================================================================='
	echo "OpenMPTCProuter Server $OMR_VERSION is now installed !"
	echo 'SSH port: 65222 (instead of port 22)'
	if [ "$OMR_ADMIN" = "yes" ]; then
		echo '===================================================================================='
		echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
		echo 'OpenMPTCProuter Server key (you need OpenMPTCProuter >= 0.42):'
		echo $OMR_ADMIN_PASS
		echo 'OpenMPTCProuter Server username (you need OpenMPTCProuter >= 0.42):'
		echo 'openmptcprouter'
		echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
		echo '===================================================================================='
	fi
	echo 'Shadowsocks port: 65101'
	echo 'Shadowsocks encryption: chacha20'
	echo 'Your shadowsocks key: '
	echo $SHADOWSOCKS_PASS
	echo 'Glorytun port: 65001'
	echo 'Glorytun encryption: chacha20'
	echo 'Your glorytun key: '
	echo $GLORYTUN_PASS
	if [ "$DSVPN" = "yes" ]; then
		echo 'A Dead Simple VPN port: 65011'
		echo 'A Dead Simple VPN key: '
		echo $DSVPN_PASS
	fi
	if [ "$MLVPN" = "yes" ]; then
		echo 'MLVPN first port: 65201'
		echo 'Your MLVPN password: '
		echo $MLVPN_PASS
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		echo 'OpenMPTCProuter API Admin key: '
		echo $OMR_ADMIN_PASS_ADMIN
		echo 'OpenMPTCProuter Server key: '
		echo $OMR_ADMIN_PASS
		echo 'OpenMPTCProuter Server username: '
		echo 'openmptcprouter'
	fi
	if [ "$VPS_CERT" = "0" ]; then
		echo 'No working domain detected, not able to generate certificate for v2ray.'
		echo 'You can set VPS_DOMAIN to a working domain if you want a certificate.'
	fi
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
	Your shadowsocks key: ${SHADOWSOCKS_PASS}
	Glorytun port: 65001
	Glorytun encryption: chacha20
	Your glorytun key: ${GLORYTUN_PASS}
	EOF
	if [ "$DSVPN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		A Dead Simple VPN port: 65011
		A Dead Simple VPN key: ${DSVPN_PASS}
		EOF
	fi
	if [ "$MLVPN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		MLVPN first port: 65201'
		Your MLVPN password: $MLVPN_PASS
		EOF
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		Your OpenMPTCProuter ADMIN API Server key: $OMR_ADMIN_PASS_ADMIN
		Your OpenMPTCProuter Server key: $OMR_ADMIN_PASS
		Your OpenMPTCProuter Server username: openmptcprouter
		EOF
	fi
else
	echo '===================================================================================='
	echo "OpenMPTCProuter Server is now updated to version $OMR_VERSION !"
	echo 'Keys are not changed, shorewall rules files preserved'
	echo 'You need OpenMPTCProuter >= 0.30'
	echo '===================================================================================='
	echo 'Restarting systemd network...'
	systemctl -q restart systemd-networkd
	echo 'done'
	if [ "$MLVPN" = "yes" ]; then
		echo 'Restarting mlvpn...'
		systemctl -q start mlvpn@mlvpn0
		echo 'done'
	fi
	if [ "$DSVPN" = "yes" ]; then
		echo 'Restarting dsvpn...'
		systemctl -q start dsvpn-server
		echo 'done'
	fi
	echo 'Restarting glorytun and omr...'
	systemctl -q start glorytun-tcp@tun0
	systemctl -q start glorytun-udp@tun0
	systemctl -q restart omr
	echo 'done'
	if [ "$OPENVPN" = "yes" ]; then
		echo 'Restarting OpenVPN'
		systemctl -q restart openvpn@tun0
		systemctl -q restart openvpn@tun1
		echo 'done'
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		echo 'Restarting OpenMPTCProuter VPS admin'
		systemctl -q restart omr-admin
		echo 'done'
		if ! grep -q 'VPS Admin key' /root/openmptcprouter_config.txt ; then
			cat >> /root/openmptcprouter_config.txt <<-EOF
			Your OpenMPTCProuter Server key: $OMR_ADMIN_PASS
			Your OpenMPTCProuter Server username: openmptcprouter
			EOF
			echo '===================================================================================='
			echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
			echo 'OpenMPTCProuter Server key (you need OpenMPTCProuter >= 0.42):'
			echo $OMR_ADMIN_PASS
			echo 'OpenMPTCProuter Server username (you need OpenMPTCProuter >= 0.42):'
			echo 'openmptcprouter'
			echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
			echo '===================================================================================='
		fi
	fi
	if [ "$VPS_CERT" = "0" ]; then
		echo 'No working domain detected, not able to generate certificate for v2ray.'
		echo 'You can set VPS_DOMAIN to a working domain if you want a certificate.'
	fi
	echo 'Restarting shorewall...'
	systemctl -q restart shorewall
	systemctl -q restart shorewall6
	echo 'done'
	echo 'Apply latest sysctl...'
	sysctl -p /etc/sysctl.d/90-shadowsocks.conf > /dev/null 2>&1
	echo 'done'
	echo 'Restarting shadowsocks...'
	systemctl -q restart shadowsocks-libev-manager@manager
#	if [ $NBCPU -gt 1 ]; then
#		for i in $NBCPU; do
#			systemctl restart shadowsocks-libev-server@config$i
#		done
#	fi
	echo 'done'
fi
