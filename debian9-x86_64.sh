#!/bin/sh
#
# Copyright (C) 2018-2025 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
#
# This is free software, licensed under the GNU General Public License v3 or later.
# See /LICENSE for more information.
#

KERNEL=${KERNEL:-6.12}
UPSTREAM=${UPSTREAM:-no}
[ "$UPSTREAM" = "yes" ] && KERNEL="6.1"
UPSTREAM6=${UPSTREAM6:-no}
[ "$UPSTREAM6" = "yes" ] && KERNEL="6.1"
SHADOWSOCKS_PASS=${SHADOWSOCKS_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
GLORYTUN_PASS=${GLORYTUN_PASS:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
DSVPN_PASS=${DSVPN_PASS:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
#NBCPU=${NBCPU:-$(nproc --all | tr -d "\n")}
NBCPU=${NBCPU:-$(grep -c '^processor' /proc/cpuinfo | tr -d "\n")}
OBFS=${OBFS:-yes}
V2RAY_PLUGIN=${V2RAY_PLUGIN:-no}
V2RAY=${V2RAY:-yes}
V2RAY_UUID=${V2RAY_UUID:-$(cat /proc/sys/kernel/random/uuid | tr -d "\n")}
XRAY=${XRAY:-yes}
XRAY_UUID=${XRAY_UUID:-$V2RAY_UUID}
SHADOWSOCKS=${SHADOWSOCKS:-yes}
SHADOWSOCKS_GO=${SHADOWSOCKS_GO:-yes}
PSK=${PSK:-$(head -c 32 /dev/urandom | base64 -w0)}
UPSK=${UPSK:-$(head -c 32 /dev/urandom | base64 -w0)}
UPDATE_OS=${UPDATE_OS:-yes}
FORCE_UPDATE_OS=${FORCE_UPDATE_OS:-no}
UPDATE=${UPDATE:-yes}
TLS=${TLS:-yes}
OMR_ADMIN=${OMR_ADMIN:-yes}
OMR_ADMIN_PASS=${OMR_ADMIN_PASS:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
OMR_ADMIN_PASS_ADMIN=${OMR_ADMIN_PASS_ADMIN:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
MLVPN=${MLVPN:-yes}
MLVPN_PASS=${MLVPN_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
UBOND=${UBOND:-no}
UBOND_PASS=${UBOND_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
OPENVPN=${OPENVPN:-yes}
OPENVPN_BONDING=${OPENVPN_BONDING:-yes}
SOFTETHERVPN=${SOFTETHERVPN:-no}
SOFTETHERVPN_PASS_ADMIN=${SOFTETHERVPN_PASS_ADMIN:-$(od -vN "16" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
SOFTETHERVPN_PASS_USER=${SOFTETHERVPN_PASS_USER:-$(od -vN "16" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
DSVPN=${DSVPN:-yes}
WIREGUARD=${WIREGUARD:-yes}
FAIL2BAN=${FAIL2BAN:-yes}
SOURCES=${SOURCES:-no}
#if [ "$KERNEL" != "5.4" ]; then
#	SOURCES="yes"
#fi
NOINTERNET=${NOINTERNET:-no}
GRETUNNELS=${GRETUNNELS:-yes}
LANROUTES=${LANROUTES:-yes}
REINSTALL=${REINSTALL:-yes}
SPEEDTEST=${SPEEDTEST:-yes}
IPERF=${IPERF:-yes}
LOCALFILES=${LOCALFILES:-no}
INTERFACE=${INTERFACE:-$(ip -o -4 route show to default | grep -m 1 -Po '(?<=dev )(\S+)' | tr -d "\n")}
INTERFACE6=${INTERFACE6:-$(ip -o -6 route show to default | grep -m 1 -Po '(?<=dev )(\S+)' | tr -d "\n")}
[ -z "$INTERFACE6" ] && INTERFACE6="$INTERFACE"
KERNEL_VERSION="5.4.207"
KERNEL_PACKAGE_VERSION="1.22"
KERNEL_RELEASE="${KERNEL_VERSION}-mptcp_${KERNEL_PACKAGE_VERSION}"
#if [ "$KERNEL" = "5.15" ]; then
#	KERNEL_VERSION="5.15.57"
#	KERNEL_PACKAGE_VERSION="1.6"
#	KERNEL_RELEASE="${KERNEL_VERSION}-mptcp_${KERNEL_VERSION}-${KERNEL_PACKAGE_VERSION}"
#fi
if [ "$KERNEL" = "6.1" ]; then
	KERNEL_VERSION="6.1.0"
	KERNEL_PACKAGE_VERSION="1.30"
	KERNEL_RELEASE="${KERNEL_VERSION}-mptcp_${KERNEL_PACKAGE_VERSION}"
fi
GLORYTUN_UDP=${GLORYTUN_UDP:-yes}
GLORYTUN_UDP_VERSION="23100474922259d00a8c0c4b00a0c8de89202cf9"
GLORYTUN_UDP_BINARY_VERSION="0.3.4-5"
GLORYTUN_TCP=${GLORYTUN_TCP:-yes}
# Old Glorytun TCP version if sources is not enabled...
GLORYTUN_TCP_VERSION="8aebb3efb3b108b1276aa74679e200e003f298de"
GLORYTUN_TCP_BINARY_VERSION="0.0.35-6"
#MLVPN_VERSION="8f9720978b28c1954f9f229525333547283316d2"
MLVPN_VERSION="8aa1b16d843ea68734e2520e39a34cb7f3d61b2b"
MLVPN_BINARY_VERSION="3.0.0+20211028.git.ddafba3"
UBOND_VERSION="31af0f69ebb6d07ed9348dca2fced33b956cedee"
OBFS_VERSION="486bebd9208539058e57e23a12f23103016e09b4"
OBFS_BINARY_VERSION="0.0.5-1"
OMR_ADMIN_VERSION="86e5fec69cfa79df4ef6b3733620e2ca3f9df542"
OMR_ADMIN_BINARY_VERSION="0.16+20250918"
#OMR_ADMIN_BINARY_VERSION="0.3+20220827"
DSVPN_VERSION="3b99d2ef6c02b2ef68b5784bec8adfdd55b29b1a"
DSVPN_BINARY_VERSION="0.1.4-2"
V2RAY_VERSION="5.32.0"
V2RAY_PLUGIN_VERSION="4.43.0"
XRAY_VERSION="25.8.3"
EASYRSA_VERSION="3.2.2"
#SHADOWSOCKS_VERSION="7407b214f335f0e2068a8622ef3674d868218e17"
#if [ "$UPSTREAM" = "yes" ] || [ "$UPSTREAM6" = "yes" ]; then
	SHADOWSOCKS_VERSION="8fc18fcba3226e31f9f2bb9e60d6be6a1837862b"
#fi
IPROUTE2_VERSION="29da83f89f6e1fe528c59131a01f5d43bcd0a000"
SHADOWSOCKS_BINARY_VERSION="3.3.5-3"
SHADOWSOCKS_GO_VERSION="1.14.0"
DEFAULT_USER="openmptcprouter"
VPS_DOMAIN=${VPS_DOMAIN:-$(wget -4 -qO- -T 2 http://hostname.openmptcprouter.com)}
VPSPATH="server-test"
VPS_PUBLIC_IP=${VPS_PUBLIC_IP:-$(wget -4 -qO- -T 2 http://ip.openmptcprouter.com)}
VPSURL="https://www.openmptcprouter.com/"
REPO="repo.openmptcprouter.com"
CHINA=${CHINA:-no}

OMR_VERSION="0.1043-rolling-test"

DIR=$( pwd )
#"
set -e
umask 0022
export LC_ALL=C
export PATH=$PATH:/sbin
export DEBIAN_FRONTEND=noninteractive 

echo "Check user..."
if [ "$(id -u)" -ne 0 ]; then echo 'Please run as root.' >&2; exit 1; fi

# Check Kernel
if [ "$KERNEL" != "5.4" ] && [ "$KERNEL" != "6.1" ] && [ "$KERNEL" != "6.6" ] && [ "$KERNEL" != "6.10" ] && [ "$KERNEL" != "6.11" ] && [ "$KERNEL" != "6.12" ]; then
	echo "Only kernels 5.4, 6.1, 6.6, 6.10 and 6.11 are currently supported"
	exit 1
fi

# Check Linux version
echo "Check Linux version..."
if test -f /etc/os-release ; then
	. /etc/os-release
else
	. /usr/lib/os-release
fi
if [ "$ID" = "debian" ] && [ "$VERSION_ID" != "9" ] && [ "$VERSION_ID" != "10" ] && [ "$VERSION_ID" != "11" ] && [ "$VERSION_ID" != "12" ] && [ "$VERSION_ID" != "13" ]; then
	echo "This script only work with Debian Stretch (9.x), Debian Buster (10.x), Debian Bullseye (11.x), Debian Bookworm (12.x) or Debian Trixie (13.x)"
	exit 1
elif [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" != "18.04" ] && [ "$VERSION_ID" != "19.04" ] && [ "$VERSION_ID" != "20.04" ] && [ "$VERSION_ID" != "22.04" ]; then
	echo "This script only work with Ubuntu 18.04, 19.04, 20.04 or 22.04"
	echo "Use debian when possible"
	exit 1
elif [ "$ID" != "debian" ] && [ "$ID" != "ubuntu" ]; then
	echo "This script only work with Ubuntu 18.04, Ubuntu 19.04, Ubutun 20.04, Ubuntu 22.04, Debian Stretch (9.x), Debian Buster (10.x), Debian Bullseye (11.x) or Debian Bookworm (12.x)"
	echo "Use Debian when possible"
	exit 1
fi

echo "Check architecture..."
ARCH=$(dpkg --print-architecture | tr -d "\n")
if ([ "$KERNEL" = "5.4" ] || [ "$KERNEL" = "5.15" ]) && [ "$ARCH" != "amd64" ] && [ "$ID" != "debian" ]; then
	echo "Only x86_64 (amd64) is supported on this OS"
	exit 1
fi

if [ "$KERNEL" = "5.4" ] || [ "$KERNEL" = "5.15" ]; then
	echo "Check virtualized environment"
	VIRT="$(systemd-detect-virt 2>/dev/null || true)"
	if [ -z "$(uname -a | grep mptcp)" ] && [ -n "$VIRT" ] && ([ "$VIRT" = "openvz" ] || [ "$VIRT" = "lxc" ] || [ "$VIRT" = "docker" ]); then
		echo "Container are not supported: kernel can't be modified."
		exit 1
	fi
fi

# Check if DPKG is locked and for broken packages
#dpkg -i /dev/zero 2>/dev/null
#if [ "$?" -eq 2 ]; then
#	echo "E: dpkg database is locked. Check that an update is not running in background..."
#	exit 1
#fi
echo "Check about broken packages..."
if ! eval apt-get check >/dev/null 2>&1 ; then
	if ! eval apt-get -f install -y 2>&1 ; then
		echo "E: \`apt-get check\` failed, you may have broken packages. Aborting..."
		exit 1
	fi
fi

# Fix old string...
if [ -f /etc/motd ] && grep --quiet 'OpenMPCTProuter VPS' /etc/motd ; then
	sed -i 's/OpenMPCTProuter/OpenMPTCProuter/g' /etc/motd
fi
if [ -f /etc/motd.head ] && grep --quiet 'OpenMPCTProuter VPS' /etc/motd.head ; then
	sed -i 's/OpenMPCTProuter/OpenMPTCProuter/g' /etc/motd.head
fi

# Check if OpenMPTCProuter VPS is already installed
echo "Check if OpenMPTCProuter VPS is already installed..."
update="0"
if [ "$UPDATE" = "yes" ]; then
	if [ -f /etc/motd ] && grep --quiet 'OpenMPTCProuter VPS' /etc/motd ; then
		update="1"
	elif [ -f /etc/motd.head ] && grep --quiet 'OpenMPTCProuter VPS' /etc/motd.head ; then
		update="1"
	elif [ -f /root/openmptcprouter_config.txt ]; then
		update="1"
	fi
	echo "Update mode"
fi
# Force update key
#[ -f /etc/apt/sources.list.d/openmptcprouter.list ] && {
#	echo "Update OpenMPTCProuter repo key"
#	#wget -O - http://repo.openmptcprouter.com/openmptcprouter.gpg.key | apt-key add -
#	wget https://${REPO}/openmptcprouter.gpg.key -O /etc/apt/trusted.gpg.d/openmptcprouter.gpg
#}

CURRENT_OMR="$(grep -s 'OpenMPTCProuter VPS' /etc/* | awk '{print $4}' || true)"
if [ "$REINSTALL" = "no" ] && [ "$CURRENT_OMR" = "$OMR_VERSION" ]; then
	exit 1
fi

# Force update key
[ -f /etc/apt/sources.list.d/openmptcprouter.list ] && {
	echo "Update ${REPO} key"
	apt-key del '2FDF 70C8 228B 7F04 42FE  59F6 608F D17B 2B24 D936' >/dev/null 2>&1 || true
	if [ "$CHINA" = "yes" ]; then
		#wget -O - https://gitee.com/ysurac/openmptcprouter-vps-debian/raw/main/openmptcprouter.gpg.key | apt-key add -
		wget https://gitlab.com/ysurac/openmptcprouter-vps-debian/raw/main/openmptcprouter.gpg.key -O /etc/apt/trusted.gpg.d/openmptcprouter.gpg
	else
		#wget -O - https://${REPO}/openmptcprouter.gpg.key | apt-key add -
		wget https://${REPO}/openmptcprouter.gpg.key -O /etc/apt/trusted.gpg.d/openmptcprouter.gpg
	fi
}

echo "Remove lock and update packages list..."
rm -f /etc/apt/sources.list.d/xanmod*
rm -f /etc/apt/trusted.gpg.d/xanmod*

rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
rm -f /var/cache/apt/archives/lock
rm -f /etc/apt/sources.list.d/buster-backports.list
rm -f /etc/apt/sources.list.d/stretch-backports.list
[ ! -f /etc/apt/sources.list ] && touch /etc/apt/sources.list
sed -i '/buster-backports/d' /etc/apt/sources.list
sed -i '/stretch-backports/d' /etc/apt/sources.list
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ]; then
	apt-get update
else
	apt-get update --allow-releaseinfo-change
fi
rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend
rm -f /var/cache/apt/archives/lock
echo "Install apt-transport-https, gnupg and openssh-server..."
apt-get -y install apt-transport-https gnupg openssh-server libcrypt1 zstd

#if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ] && [ "$UPDATE_DEBIAN" = "yes" ] && [ "$update" = "0" ]; then
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ] && [ "$UPDATE_OS" = "yes" ]; then
	echo "Update Debian 9 Stretch to Debian 10 Buster"
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	sed -i 's:stretch:buster:g' /etc/apt/sources.list
	apt-get update --allow-releaseinfo-change
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	VERSION_ID="10"
fi
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ] && [ "$UPDATE_OS" = "yes" ]; then
	echo "Update Debian 10 Buster to Debian 11 Bullseye"
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	sed -i 's:buster:bullseye:g' /etc/apt/sources.list
	sed -i 's:archive:deb:g' /etc/apt/sources.list
	sed -i 's:bullseye/updates:bullseye-security:g' /etc/apt/sources.list
	sed -i 's:openmptcprouter:d' /etc/apt/sources.list
	apt-get update --allow-releaseinfo-change
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	VERSION_ID="11"
fi
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "11" ] && [ "$UPDATE_OS" = "yes" ]; then
	echo "Update Debian 11 Bullseye to Debian 12 Bookworm"
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	sed -i 's:archive:deb:g' /etc/apt/sources.list
	sed -i 's:bullseye:bookworm:g' /etc/apt/sources.list
	apt-get update --allow-releaseinfo-change
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	VERSION_ID="12"
fi

# Update to Debian 13 only if FORCE_UPDATE_OS is set to yes. No problem to use Debian 12 if not.
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "12" ] && [ "$UPDATE_OS" = "yes" ]; then
	echo "Update Debian 12 Bookworm to Debian 13 Trixie"
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	sed -i 's:archive:deb:g' /etc/apt/sources.list
	sed -i 's:bookworm:trixie:g' /etc/apt/sources.list
	sed -i 's|Signed-By: /usr/share/keyrings/debian-deb-keyring.gpg|Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg|g' /etc/apt/sources.list
	if [ -f  /etc/apt/sources.list.d/debian.sources ]; then
		sed -i 's:archive:deb:g' /etc/apt/sources.list.d/debian.sources
		sed -i 's:bookworm:trixie:g' /etc/apt/sources.list.d/debian.sources
		sed -i 's|Signed-By: /usr/share/keyrings/debian-deb-keyring.gpg|Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg|g' /etc/apt/sources.list.d/debian.sources
	fi
	apt-get update --allow-releaseinfo-change
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	VERSION_ID="13"
fi
if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "18.04" ] && [ "$UPDATE_OS" = "yes" ]; then
	echo "Update Ubuntu 18.04 to Ubuntu 20.04"
	apt-get -y -f --force-yes --allow-downgrades upgrade
	apt-get -y -f --force-yes --allow-downgrades dist-upgrade
	sed -i 's:bionic:focal:g' /etc/apt/sources.list
	apt-get update --allow-releaseinfo-change
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" dist-upgrade
	VERSION_ID="20.04"
fi
if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "18.04" ] && [ "$UPDATE_OS" = "yes" ]; then
	echo "Update Ubuntu 20.04 to Ubuntu 22.04"
	apt-get -y -f --force-yes --allow-downgrades upgrade
	apt-get -y -f --force-yes --allow-downgrades dist-upgrade
	sed -i 's:focal:jammy:g' /etc/apt/sources.list
	apt-get update --allow-releaseinfo-change
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" dist-upgrade
	VERSION_ID="22.04"
fi

# Add OpenMPTCProuter repo
echo "Add OpenMPTCProuter repo..."
if [ "$CHINA" = "yes" ]; then
	echo "Install git..."
	apt-get -y install git
	rm -rf /var/lib/openmptcprouter-vps-debian 
	if [ ! -d /var/lib/openmptcprouter-vps-debian ]; then
		#git clone https://gitee.com/ysurac/openmptcprouter-vps-debian.git /var/lib/openmptcprouter-vps-debian
		git clone https://gitlab.com/ysurac/openmptcprouter-vps-debian.git /var/lib/openmptcprouter-vps-debian
	fi
	cd /var/lib/openmptcprouter-vps-debian
	git pull
#	if [ "$VPSPATH" = "server-test" ]; then
#		git checkout develop
#	else
#		git checkout main
#	fi
	echo "deb [arch=amd64] file:/var/lib/openmptcprouter-vps-debian ./" > /etc/apt/sources.list.d/openmptcprouter.list
	cat /var/lib/openmptcprouter-vps-debian/openmptcprouter.gpg.key | apt-key add -
	rm -rf /usr/share/omr-server-git
	if [ ! -d /usr/share/omr-server-git ]; then
		#git clone https://gitee.com/ysurac/openmptcprouter-vps.git /usr/share/omr-server-git
		git clone https://gitlab.com/ysurac/openmptcprouter-vps.git /usr/share/omr-server-git
	fi
	cd /usr/share/omr-server-git
	git pull
	if [ "$VPSPATH" = "server-test" ]; then
		git checkout develop
	else
		git checkout master
	fi
	LOCALFILES="yes"
	TLS="no"
	DIR="/usr/share/omr-server-git"
else
	echo "deb [arch=amd64] https://${REPO} buster main" > /etc/apt/sources.list.d/openmptcprouter.list
	if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "13" ]; then
		cat <<-EOF | tee /etc/apt/preferences.d/openmptcprouter.pref
			Explanation: Prefer OpenMPTCProuter provided packages over the Debian native ones
			Package: *
			Pin: release o=${REPO}
			Pin-Priority: 999
			
		EOF
	else
		cat <<-EOF | tee /etc/apt/preferences.d/openmptcprouter.pref
			Explanation: Prefer OpenMPTCProuter provided packages over the Debian native ones
			Package: *
			Pin: release o=${REPO}
			Pin-Priority: 400
			
		EOF
	fi
	if [ -n "$(echo $OMR_VERSION | grep test)" ] || [ -n "$(echo $OMR_VERSION | grep rolling)" ]; then
		echo "deb [arch=amd64] https://${REPO} next main" > /etc/apt/sources.list.d/openmptcprouter-test.list
#		cat <<-EOF | tee -a /etc/apt/preferences.d/openmptcprouter.pref
#			Explanation: Prefer OpenMPTCProuter provided packages over the Debian native ones
#			Package: *
#			Pin: origin ${REPO}
#			Pin-Priority: 1002
#		EOF
	else
		rm -f /etc/apt/sources.list.d/openmptcprouter-test.list
	fi
	if [ "$ID" = "debian" ] && ([ "$VERSION_ID" = "11" ] || [ "$VERSION_ID" = "12" ] || [ "$VERSION_ID" = "13" ]); then
		cat <<-EOF | tee -a /etc/apt/preferences.d/openmptcprouter.pref
			Explanation: Prefer libuv1 Debian native package
			Package: libuv1
			Pin: version *
			Pin-Priority: 1003
		EOF
	fi
	#wget -O - https://${REPO}/openmptcprouter.gpg.key | apt-key add -
	wget https://${REPO}/openmptcprouter.gpg.key -O /etc/apt/trusted.gpg.d/openmptcprouter.gpg
fi

#apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 379CE192D401AB61
if [ "$ID" = "debian" ]; then
	if [ "$VERSION_ID" = "9" ]; then
		#echo 'deb http://dl.bintray.com/cpaasch/deb jessie main' >> /etc/apt/sources.list
		echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/stretch-backports.list
	fi
	# Add buster-backports repo
	echo 'deb http://archive.debian.org/debian buster-backports main' > /etc/apt/sources.list.d/buster-backports.list
	if [ "$VERSION_ID" = "12" ] || [ "$VERSION_ID" = "13" ]; then
		echo 'deb http://deb.debian.org/debian bullseye main' > /etc/apt/sources.list.d/bullseye.list
	fi
elif [ "$ID" = "ubuntu" ]; then
	echo 'deb https://ports.ubuntu.com/ubuntu-ports bionic-backports main' > /etc/apt/sources.list.d/bionic-backports.list
	echo 'deb https://ports.ubuntu.com/ubuntu-ports bionic universe' > /etc/apt/sources.list.d/bionic-universe.list
	[ "$VERSION_ID" = "22.04" ] && {
		apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32
		echo 'deb http://old-releases.ubuntu.com/ubuntu impish main universe' > /etc/apt/sources.list.d/impish-universe.list
	}
fi
# Install mptcp kernel and shadowsocks
echo "Install mptcp kernel and shadowsocks..."
apt-get update --allow-releaseinfo-change
sleep 2
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "13" ]; then
	apt-get -y install dirmngr patch rename curl unzip pkg-config ipset
else
	apt-get -y install dirmngr patch rename curl libcurl4 unzip pkg-config ipset
fi

if [ -z "$(dpkg-query -l | grep grub)" ]; then
	if [ -d /boot/grub2 ]; then
		apt-get -y install grub2
	elif [ -d /boot/grub ]; then
		apt-get -y install grub-legacy
	fi
	[ -n "$(grep 'net.ifnames=0' /boot/grub/grub.cfg)" ] && [ ! -f /etc/default/grub ] && {
		echo 'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"' > /etc/default/grub
	}
fi


if [ -z "$(dpkg-query -l | grep grub)" ]; then
	if [ -d /boot/grub2 ]; then
		apt-get -y install grub2
	elif [ -d /boot/grub ]; then
		apt-get -y install grub-legacy
	fi
	[ -n "$(grep 'net.ifnames=0' /boot/grub/grub.cfg)" ] && [ ! -f /etc/default/grub ] && {
		echo 'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"' > /etc/default/grub
	}
fi
if [ "$KERNEL" = "5.4" ] || [ "$KERNEL" = "5.15" ]; then
	if [ "$SOURCES" = "yes" ]; then
		wget -O /tmp/linux-image-${KERNEL_RELEASE}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_RELEASE}_amd64.deb
		wget -O /tmp/linux-headers-${KERNEL_RELEASE}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_RELEASE}_amd64.deb
		# Rename bzImage to vmlinuz, needed when custom kernel was used
		cd /boot
		apt-get -y install git
		rename 's/^bzImage/vmlinuz/s' * >/dev/null 2>&1
		#apt-get -y install linux-mptcp
		#dpkg --remove --force-remove-reinstreq linux-image-${KERNEL_VERSION}-mptcp
		#dpkg --remove --force-remove-reinstreq linux-headers-${KERNEL_VERSION}-mptcp
		if [ "$(dpkg -l | grep linux-image-${KERNEL_VERSION} | grep ${KERNEL_PACKAGE_VERSION})" = "" ]; then
			echo "Install kernel linux-image-${KERNEL_RELEASE} source release"
			echo "\033[1m !!! if kernel install fail run: dpkg --remove --force-remove-reinstreq linux-image-${KERNEL_VERSION}-mptcp !!! \033[0m"
			dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_RELEASE}_amd64.deb
			dpkg --force-all -i -B /tmp/linux-image-${KERNEL_RELEASE}_amd64.deb
		fi
	else
		cd /boot
		rename 's/^bzImage/vmlinuz/s' * >/dev/null 2>&1
		if [ "$(dpkg -l | grep linux-image-${KERNEL_VERSION} | grep ${KERNEL_PACKAGE_VERSION})" = "" ]; then
			echo "Install kernel linux-image-${KERNEL_RELEASE}"
			echo "\033[1m !!! if kernel install fail run: dpkg --remove --force-remove-reinstreq linux-image-${KERNEL_VERSION}-mptcp !!! \033[0m"
			apt-get -y install linux-image-${KERNEL_VERSION}-mptcp=${KERNEL_PACKAGE_VERSION} linux-headers-${KERNEL_VERSION}-mptcp=${KERNEL_PACKAGE_VERSION}
		fi
	fi


	# Check if mptcp kernel is grub default kernel
	echo "Set MPTCP kernel as grub default..."
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /tmp/update-grub.sh ${VPSURL}${VPSPATH}/update-grub.sh
		cd /tmp
	else
		cd ${DIR}
	fi
	[ -f /boot/grub/grub.cfg ] && [ -z "$(grep ${KERNEL_VERSION}-mptcp /boot/grub/grub.cfg)" ] && [ -n "$(which grub-mkconfig)" ] && grub-mkconfig -o /boot/grub/grub.cfg
	rm -f /etc/grub.d/30_os-prober
	bash update-grub.sh ${KERNEL_VERSION}-mptcp
	bash update-grub.sh ${KERNEL_RELEASE}
	[ -f /boot/grub/grub.cfg ] && sed -i 's/default="1>0"/default="0"/' /boot/grub/grub.cfg >/dev/null 2>&1
elif [ "$KERNEL" = "6.6" ] && [ "$ARCH" = "amd64" ]; then
	# awk command from xanmod website
	PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
	#'
	KERNEL_VERSION="6.6.36"
	KERNEL_REV="0~20240628.g36640c1"
	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1 source release"
	dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
	[ -f /etc/default/grub ] && {
		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
		[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
	}
elif [ "$KERNEL" = "6.10" ] && [ "$ARCH" = "amd64" ]; then
	# awk command from xanmod website
	PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
	#'
	if [ "$PSABI" = "x64v1" ]; then
		echo "psABI x86-64-v1 not supported by Xanmod kernel 6.10, use an older kernel"
		exit 0
	fi
	KERNEL_VERSION="6.10.2"
	KERNEL_REV="0~20240728.gae7b555"
	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1 source release"
	dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
	[ -f /etc/default/grub ] && {
		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
		[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
	}
elif [ "$KERNEL" = "6.11" ] && [ "$ARCH" = "amd64" ]; then
	# awk command from xanmod website
	PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
	#'
	if [ "$PSABI" = "x64v1" ]; then
		echo "psABI x86-64-v1 not supported by Xanmod kernel 6.11, use an older kernel"
		exit 0
	fi
	KERNEL_VERSION="6.11.0"
	KERNEL_REV="0~20240916.g9c60408"
	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1 source release"
	dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
	[ -f /etc/default/grub ] && {
		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
		[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
	}
elif [ "$KERNEL" = "6.12" ] && [ "$ARCH" = "amd64" ]; then
	# awk command from xanmod website
	PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
	#'
	if [ "$PSABI" = "x64v4" ]; then
		PSABI="x64v3"
	fi
	KERNEL_VERSION="6.12.47"
	KERNEL_REV="0~20250912.g88be869"
	if [ "$CHINA" = "yes" ]; then
		wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb https://sourceforge.net/projects/xanmod/files/releases/lts/${KERNEL_VERSION}-xanmod1/${KERNEL_VERSION}-${PSABI}-xanmod1/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
		wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb https://sourceforge.net/projects/xanmod/files/releases/lts/${KERNEL_VERSION}-xanmod1/${KERNEL_VERSION}-${PSABI}-xanmod1/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	else
		wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
		wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	fi
	echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1 source release"
	dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
	[ -f /etc/default/grub ] && {
		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
		[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
	}
elif [ "$KERNEL" = "6.6" ] && [ "$ID" = "debian" ]; then
	echo 'deb http://deb.debian.org/debian bookworm-backports main' > /etc/apt/sources.list.d/bookworm-backports.list
	apt-get update
	latestkernel=$(apt-cache search linux-image-6.6 | grep -v headers | grep -v dbg | grep -v rt | tail -n 1 | cut -d" " -f1)
	latestkernelheaders=$(echo $latestkernel | sed 's/image/headers/g')
	apt-get -y install $latestkernel $latestkernelheaders
	[ -f /etc/default/grub ] && {
		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
		[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
	}
else 
	if [ "$ID" = "ubuntu" ] && [ -z "$(uname -a | grep '6.1')" ]; then
		apt-get -y install $(apt-cache search linux-image-unsigned-6.1 | tail -n 1 | cut -d" " -f1)
	fi
	[ -f /etc/default/grub ] && {
		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
		[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
	}
fi

if [ "$ARCH" = "amd64" ]; then
	echo "Install tracebox OpenMPTCProuter edition"
	apt-get -y -o Dpkg::Options::="--force-overwrite" install tracebox
fi
if [ "$IPERF" = "yes" ] && [ "$CHINA" != "yes" ]; then
	#echo "Install iperf3 OpenMPTCProuter edition"
	#apt-get -y -o Dpkg::Options::="--force-overwrite" install omr-iperf3
	#chmod 644 /lib/systemd/system/iperf3.service
	echo "Install iperf3"
	[ "$ARCH" = "amd64" ] && apt-get -y remove omr-iperf3 omr-libiperf0 >/dev/null 2>&1
	if [ "$SOURCES" = "yes" ]; then
		apt-get -y remove iperf3 libiperf0
		apt-get -y install xz-utils devscripts equivs
		cd /tmp
		rm -rf iperf-3.18
		wget https://github.com/esnet/iperf/releases/download/3.18/iperf-3.18.tar.gz
		tar xzf iperf-3.18.tar.gz
		cd iperf-3.18
		wget --waitretry=1 --read-timeout=20 --timeout=15 -t 5 --continue --no-dns-cache https://www.openmptcprouter.com/debian/iperf3_3.18-2.debian.tar.xz
		tar xJf iperf3_3.18-2.debian.tar.xz
		sleep 1
		echo "Install iperf3 dependencies..."
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		mk-build-deps --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		echo "Build iperf3 package...."
		dpkg-buildpackage -b -us -uc >/dev/null 2>&1
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		cd /tmp
		echo "Install iperf3 package..."
		dpkg -i iperf3_*.deb libiperf0_*.deb >/dev/null 2>&1
		rm -rf iperf-3.18
		rm -f iperf* libiperf*
	else
		apt-get -y install iperf3 libiperf0
	fi
	if [ ! -f "/etc/iperf3/private.pem" ]; then
		mkdir -p /etc/iperf3
		openssl genrsa -out /etc/iperf3/private.pem 2048
		openssl rsa -in /etc/iperf3/private.pem -outform PEM -pubout -out /etc/iperf3/public.pem
		IPERFPASS=$(echo -n "{openmptcprouter}openmptcprouter" | sha256sum | awk '{ print $1 }')
		echo "openmptcprouter,$IPERFPASS" > /etc/iperf3/users.csv
	fi
	chown -Rf iperf3 /etc/iperf3 || true
	systemctl enable iperf3.service || true
	mkdir -p /etc/systemd/system/iperf3.service.d
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /etc/systemd/system/iperf3.service.d/override.conf ${VPSURL}${VPSPATH}/iperf3.override.conf
	else
		cp ${DIR}/iperf3.override.conf /etc/systemd/system/iperf3.service.d/override.conf
	fi
	echo "iperf3 installed"
fi

rm -f /var/lib/dpkg/lock
rm -f /var/lib/dpkg/lock-frontend

if [ "$KERNEL" != "5.4" ]; then
	if [ "$ID" = "debian" ] && ([ "$VERSION_ID" = "12" ] || [ "$VERSION_ID" = "13" ]); then
		apt-get -y install mptcpize
	else
		echo "Compile and install mptcpize..."
		apt-get -y install --no-install-recommends build-essential
		cd /tmp
		apt-get -y install git
		git clone https://github.com/Ysurac/mptcpize.git
		cd mptcpize
		make
		make install
		cd /tmp
		rm -rf /tmp/mptcpize
	fi
	if [ "$ID" = "debian" ] && ([ "$VERSION_ID" = "12" ] || [ "$VERSION_ID" = "13" ]); then
		apt-get -y install iproute2
	else
		echo "Compile and install iproute2..."
		apt-get -y install --no-install-recommends bison libbison-dev flex
		#wget https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.16.0.tar.gz
		#tar xzf iproute2-5.16.0.tar.gz
		#cd iproute2-5.16.0
		git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git 
		cd iproute2
		git checkout 29da83f89f6e1fe528c59131a01f5d43bcd0a000
		make
		make install
		cd /tmp
		rm -rf iproute2
	fi

	if [ "$ID" = "debian" ]; then
		echo "MPTCPize iperf3..."
		mptcpize enable iperf3 >/dev/null 2>&1 || true
	fi

	#if [ "$UPSTREAM6" = "yes" ]; then
	#	apt-get -y install $(dpkg --get-selections | grep linux-image-6.1 | grep -v dbg | cut -f1)-dbg
	#	apt-get -y install systemtap
	#	mkdir -p /usr/share/systemtap-mptcp
	#	wget -O /usr/share/systemtap-mptcp/mptcp-app.stap ${VPSURL}${VPSPATH}/mptcp-app.stap
	#fi
fi

echo "Remove Shadowsocks-libev..."
apt-get -y remove shadowsocks-libev >/dev/null 2>&1 || true
if [ "$SHADOWSOCKS" = "yes" ]; then
	echo "Install Shadowsocks-libev..."
	if [ "$SOURCES" = "yes" ]; then
		#apt -t stretch-backports -y install shadowsocks-libev
		## Compile Shadowsocks
		#rm -rf /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}
		#wget -O /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}.tar.gz http://github.com/shadowsocks/shadowsocks-libev/releases/download/v${SHADOWSOCKS_VERSION}/shadowsocks-libev-${SHADOWSOCKS_VERSION}.tar.gz
		cd /tmp
		rm -rf shadowsocks-libev
		git clone https://github.com/Ysurac/shadowsocks-libev.git
		cd shadowsocks-libev
		git checkout ${SHADOWSOCKS_VERSION}
		git submodule update --init --recursive
		#tar xzf shadowsocks-libev-${SHADOWSOCKS_VERSION}.tar.gz
		#cd shadowsocks-libev-${SHADOWSOCKS_VERSION}
		#wget https://raw.githubusercontent.com/Ysurac/openmptcprouter-feeds/master/shadowsocks-libev/patches/020-NOCRYPTO.patch
		#patch -p1 < 020-NOCRYPTO.patch
		#wget https://github.com/Ysurac/shadowsocks-libev/commit/31b93ac2b054bc3f68ea01569649e6882d72218e.patch
		#patch -p1 < 31b93ac2b054bc3f68ea01569649e6882d72218e.patch
		#wget https://github.com/Ysurac/shadowsocks-libev/commit/2e52734b3bf176966e78e77cf080a1e8c6b2b570.patch
		#patch -p1 < 2e52734b3bf176966e78e77cf080a1e8c6b2b570.patch
		#wget https://github.com/Ysurac/shadowsocks-libev/commit/dd1baa91e975a69508f9ad67d75d72624c773d24.patch
		#patch -p1 < dd1baa91e975a69508f9ad67d75d72624c773d24.patch
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
		apt-get -y install --no-install-recommends devscripts equivs apg libcap2-bin libpam-cap libc-ares2 libc-ares-dev libev4 haveged libpcre3-dev || true
		apt-get -y install --no-install-recommends asciidoc-base asciidoc-common docbook-xml docbook-xsl libev-dev libmbedcrypto3 libmbedtls-dev libmbedtls12 libmbedx509-0 libxml2-utils libxslt1.1 pkg-config sgml-base sgml-data xml-core xmlto xsltproc || true
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
				apt-get -y install libsodium-dev || true
			fi
		elif [ "$ID" = "ubuntu" ]; then
			rm -f /var/lib/dpkg/lock
			rm -f /var/lib/dpkg/lock-frontend
			apt-get -y install libsodium-dev
		fi
		#cd /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		mk-build-deps --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y" >/dev/null 2>&1 || true
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		dpkg-buildpackage -b -us -uc >/dev/null 2>&1 || true
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		cd /tmp
		#dpkg -i shadowsocks-libev_*.deb
		dpkg -i omr-shadowsocks-libev_*.deb >/dev/null 2>&1 || true
		#mkdir -p /usr/lib/shadowsocks-libev
		#cp -f /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}/src/*.ebpf /usr/lib/shadowsocks-libev
		#rm -rf /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}
		rm -rf /tmp/shadowsocks-libev
	else
		apt-get -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" install omr-shadowsocks-libev=${SHADOWSOCKS_BINARY_VERSION}
	fi
fi

echo "Add modules on server start..."
# Load BBR Congestion module at boot time
if ! grep -q bbr /etc/modules ; then
	echo tcp_bbr >> /etc/modules
fi

if [ "$KERNEL" = "5.4" ]; then
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
	# Load BBRv2 Congestion module at boot time
	if ! grep -q bbr2 /etc/modules ; then
		echo tcp_bbr2 >> /etc/modules
	fi
	# Load mctcpdesync Congestion module at boot time
	if ! grep -q mctcp_desync /etc/modules ; then
		echo mctcp_desync >> /etc/modules
	fi
	# Load ndiffports module at boot time
	if ! grep -q mptcp_ndiffports /etc/modules ; then
		echo mptcp_ndiffports >> /etc/modules
	fi
	# Load redundant module at boot time
	if ! grep -q mptcp_redundant /etc/modules ; then
		echo mptcp_redundant >> /etc/modules
	fi
	# Load rr module at boot time
	if ! grep -q mptcp_rr /etc/modules ; then
		echo mptcp_rr >> /etc/modules
	fi
	# Load mctcp ECF scheduler at boot time
	if ! grep -q mptcp_ecf /etc/modules ; then
		echo mptcp_ecf >> /etc/modules
	fi
	# Load mctcp BLEST scheduler at boot time
	if ! grep -q mptcp_blest /etc/modules ; then
		echo mptcp_blest >> /etc/modules
	fi
fi

echo "Stop OpenMPTCProuter VPS admin"
if systemctl -q is-active omr-admin.service 2>/dev/null; then
	systemctl -q stop omr-admin > /dev/null 2>&1 || true
fi
if systemctl -q is-active omr-admin-ipv6.service 2>/dev/null; then
	systemctl -q stop omr-admin-ipv6 > /dev/null 2>&1 || true
	systemctl -q disable omr-admin-ipv6 > /dev/null 2>&1 || true
fi

if [ "$OMR_ADMIN" = "yes" ]; then
	echo 'Install OpenMPTCProuter VPS Admin'
	if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "9" ]; then
		#echo 'deb http://ftp.de.debian.org/debian buster main' > /etc/apt/sources.list.d/buster.list
		#echo 'APT::Default-Release "stretch";' | tee -a /etc/apt/apt.conf.d/00local
		#apt-get update
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
		apt-get -y install python3-openssl python3-pip python3-setuptools python3-wheel python3-dev
	fi
	#apt-get -y install unzip gunicorn python3-flask-restful python3-openssl python3-pip python3-setuptools python3-wheel
	#apt-get -y install unzip python3-openssl python3-pip python3-setuptools python3-wheel
	if [ "$ID" = "ubuntu" ]; then
		apt-get -y install python3-passlib python3-netaddr
		apt-get -y remove python3-jwt
		pip3 -q install pyjwt
	else
		if [ "$ID" = "debian" ] && ([ "$VERSION_ID" = "10" ] || [ "$VERSION_ID" = "11" ] || [ "$VERSION_ID" = "12" ] || [ "$VERSION_ID" = "13" ]); then
			if [ "$VERSION_ID" = "13" ]; then
				apt-get -y --allow-downgrades install python3-passlib python3-jwt python3-netaddr libuv1t64 python3-uvloop
			elif [ "$VERSION_ID" = "12" ]; then
				apt-get -y --allow-downgrades install python3-passlib python3-jwt python3-netaddr libuv1
				pip3 -q install "uvloop==0.21.0" --break-system-packages
			else
				apt-get -y --allow-downgrades install python3-passlib python3-jwt python3-netaddr libuv1
				pip3 -q install "uvloop==0.21.0"
			fi
		else
			apt-get -y --allow-downgrades install python3-passlib python3-jwt python3-netaddr libuv1t64 python3-uvloop
		fi
	fi
	apt-get -y --allow-downgrades install python3-uvicorn jq ipcalc python3-netifaces python3-aiofiles python3-psutil python3-requests pwgen
	echo '-- pip3 install needed python modules'
	echo "If you see any error here, I really don't care: it's about a module not used for home users"
	#pip3 install pyjwt passlib uvicorn fastapi netjsonconfig python-multipart netaddr
	#pip3 -q install fastapi netjsonconfig python-multipart uvicorn -U
	if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "13" ]; then
		apt-get -y install python3-jsonschema python3-fastapi python3-multipart python3-starlette
	elif [ "$ID" = "debian" ] && [ "$VERSION_ID" = "12" ]; then
		#pip3 -q install netjsonconfig --break-system-packages
		pip3 -q install fastapi -U --break-system-packages
		pip3 -q install jsonschema -U --break-system-packages
		pip3 -q install python-multipart jinja2 -U --break-system-packages
		pip3 -q install starlette --break-system-packages
		pip3 -q install starlette --break-system-packages
	else
		#pip3 -q install netjsonconfig
		if [ "$ID" = "ubuntu" ] || ([ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ]); then
			pip3 -q install fastapi==0.99.1 -U
		else
			pip3 -q install fastapi -U
		fi
		pip3 -q install fastapi -U
		pip3 -q install jsonschema -U
		pip3 -q install python-multipart jinja2 -U
		pip3 -q install starlette
		pip3 -q install starlette
	fi
	mkdir -p /etc/openmptcprouter-vps-admin/omr-6in4
	mkdir -p /etc/openmptcprouter-vps-admin/intf
	#[ ! -f "/etc/openmptcprouter-vps-admin/current-vpn" ] && echo "glorytun_tcp" > /etc/openmptcprouter-vps-admin/current-vpn
	[ ! -f "/etc/openmptcprouter-vps-admin/current-vpn" ] && echo "openvpn" > /etc/openmptcprouter-vps-admin/current-vpn
	mkdir -p /var/opt/openmptcprouter
	if [ "$SOURCES" = "yes" ]; then
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /lib/systemd/system/omr-admin.service ${VPSURL}${VPSPATH}/omr-admin.service.in
			#wget -O /lib/systemd/system/omr-admin-ipv6.service ${VPSURL}${VPSPATH}/omr-admin-ipv6.service.in
		else
			cp ${DIR}/omr-admin.service.in /lib/systemd/system/omr-admin.service
		fi
		wget -O /tmp/openmptcprouter-vps-admin.zip https://github.com/Ysurac/openmptcprouter-vps-admin/archive/${OMR_ADMIN_VERSION}.zip
		cd /tmp
		unzip -q -o openmptcprouter-vps-admin.zip
		cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin.py /usr/local/bin/
		if [ -f /usr/local/bin/omr-admin.py ] || [ -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
			OMR_ADMIN_PASS2=$(grep -Po '"'"pass"'"\s*:\s*"\K([^"]*)' /etc/openmptcprouter-vps-admin/omr-admin-config.json | tr -d  "\n")
			[ -z "$OMR_ADMIN_PASS2" ] && OMR_ADMIN_PASS2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.user_password | tr -d "\n")
			[ -n "$OMR_ADMIN_PASS2" ] && OMR_ADMIN_PASS=$OMR_ADMIN_PASS2
			OMR_ADMIN_PASS_ADMIN2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].admin.user_password | tr -d "\n")
			[ -n "$OMR_ADMIN_PASS_ADMIN2" ] && OMR_ADMIN_PASS_ADMIN=$OMR_ADMIN_PASS_ADMIN2
		else
			cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin.py /usr/local/bin/
			cd /etc/openmptcprouter-vps-admin
		fi
		if [ "$(grep user_password /etc/openmptcprouter-vps-admin/omr-admin-config.json)" = "" ]; then
			cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin-config.json /etc/openmptcprouter-vps-admin/
			cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin.py /usr/local/bin/
			cd /etc/openmptcprouter-vps-admin
		fi
		rm -rf /tmp/tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}
		chmod u+x /usr/local/bin/omr-admin.py
	else
		if [ -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
			OMR_ADMIN_PASS2=$(grep -Po '"'"pass"'"\s*:\s*"\K([^"]*)' /etc/openmptcprouter-vps-admin/omr-admin-config.json | tr -d  "\n")
			[ -z "$OMR_ADMIN_PASS2" ] && OMR_ADMIN_PASS2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.user_password | tr -d "\n")
			[ -n "$OMR_ADMIN_PASS2" ] && [ "$OMR_ADMIN_PASS2" != "MySecretKey" ] && OMR_ADMIN_PASS=$OMR_ADMIN_PASS2
			OMR_ADMIN_PASS_ADMIN2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].admin.user_password | tr -d "\n")
			[ -n "$OMR_ADMIN_PASS_ADMIN2" ] && [ "$OMR_ADMIN_PASS_ADMIN2" != "AdminMySecretKey" ] && OMR_ADMIN_PASS_ADMIN=$OMR_ADMIN_PASS_ADMIN2
		fi
		apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y --allow-downgrades install omr-vps-admin=${OMR_ADMIN_BINARY_VERSION}
		if [ ! -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
			cp /usr/share/omr-admin/omr-admin-config.json /etc/openmptcprouter-vps-admin/
		fi
		#OMR_ADMIN_PASS=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.user_password | tr -d "\n")
		#OMR_ADMIN_PASS_ADMIN=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].admin.user_password | tr -d "\n")
	fi
	if [ ! -f /etc/openmptcprouter-vps-admin/key.pem ]; then
		cd /etc/openmptcprouter-vps-admin
		openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout key.pem -out cert.pem -subj "/C=US/ST=Oregon/L=Portland/O=OpenMPTCProuterVPS/OU=Org/CN=www.openmptcprouter.vps"
	fi
	sed -i "s:openmptcptouter:${DEFAULT_USER}:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	sed -i "s:AdminMySecretKey:$OMR_ADMIN_PASS_ADMIN:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	sed -i "s:MySecretKey:$OMR_ADMIN_PASS:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	[ "$NOINTERNET" = "yes" ] && {
		jq '. + {internet: false}' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp
		mv /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp /etc/openmptcprouter-vps-admin/omr-admin-config.json
		#sed -i 's/"port": 65500,/"port": 65500,\n    "internet": false,/' /etc/openmptcprouter-vps-admin/omr-admin-config.json
	}
	[ "$GRETUNNELS" = "no" ] && {
		jq '. + {gre_tunnels: false}' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp
		mv /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp /etc/openmptcprouter-vps-admin/omr-admin-config.json
		#sed -i 's/"port": 65500,/"port": 65500,\n    "gre_tunnels": false,/' /etc/openmptcprouter-vps-admin/omr-admin-config.json
	}
	[ "$LANROUTES" = "no" ] && {
		jq '. + {lan_routes: false}' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp
		mv /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp /etc/openmptcprouter-vps-admin/omr-admin-config.json
	}

	# IPv6 give an error on uvicorn
	jq '. + {host: "0.0.0.0"}' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp
	mv /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp /etc/openmptcprouter-vps-admin/omr-admin-config.json

	chmod 644 /lib/systemd/system/omr-admin.service
	#chmod 644 /lib/systemd/system/omr-admin-ipv6.service
	#[ "$(ip -6 a)" != "" ] && sed -i 's/0.0.0.0/::/g' /usr/local/bin/omr-admin.py
	#[ "$(ip -6 a)" != "" ] && {
	#	systemctl enable omr-admin-ipv6.service
	#}
	systemctl enable omr-admin.service
	if [ "$KERNEL" != "5.4" ]; then
		mptcpize enable omr-admin.service >/dev/null 2>&1
		#[ "$(ip -6 a)" != "" ] && mptcpize enable omr-admin-ipv6.service >/dev/null 2>&1
	fi
	if systemctl -q is-active omr-admin-ipv6.service 2>/dev/null; then
		systemctl -q stop omr-admin-ipv6 >/dev/null 2>&1
		systemctl -q disable omr-admin-ipv6 >/dev/null 2>&1
	fi
fi

# Get shadowsocks optimization
if [ "$LOCALFILES" = "no" ]; then
	if [ "$KERNEL" != "5.4" ]; then
		wget -O /etc/sysctl.d/90-shadowsocks.conf ${VPSURL}${VPSPATH}/shadowsocks.6.1.conf
	else
		wget -O /etc/sysctl.d/90-shadowsocks.conf ${VPSURL}${VPSPATH}/shadowsocks.conf
	fi
else
	if [ "$KERNEL" != "5.4" ]; then
		cp ${DIR}/shadowsocks.6.1.conf /etc/sysctl.d/90-shadowsocks.conf
	else
		cp ${DIR}/shadowsocks.conf /etc/sysctl.d/90-shadowsocks.conf
	fi
fi

if [ "$SHADOWSOCKS" = "yes" ]; then
	if [ "$update" != 0 ]; then
		if [ ! -f /etc/shadowsocks-libev/manager.json ]; then
			SHADOWSOCKS_PASS=$(grep -Po '"'"key"'"\s*:\s*"\K([^"]*)' /etc/shadowsocks-libev/config.json | tr -d  "\n" | sed 's/-/+/g; s/_/\//g;')
		elif [ -f /etc/shadowsocks-libev/manager.json ]; then
			SHADOWSOCKS_PASS=$(grep -Po '"'"65101"'":\s*"\K([^"]*)' /etc/shadowsocks-libev/manager.json | tr -d  "\n" | sed 's/-/+/g; s/_/\//g;')
		fi
	fi
	# Install shadowsocks config and add a shadowsocks by CPU
	if [ "$update" = "0" ] || [ ! -f /etc/shadowsocks-libev/manager.json ]; then
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /etc/shadowsocks-libev/manager.json ${VPSURL}${VPSPATH}/manager.json
		else
			cp ${DIR}/manager.json /etc/shadowsocks-libev/manager.json
		fi
		SHADOWSOCKS_PASS_JSON=$(echo $SHADOWSOCKS_PASS | sed 's/+/-/g; s/\//_/g;')
		if [ "$NBCPU" -gt "1" ]; then
			for i in $(seq 2 NBCPU); do
				sed -i '0,/65101/ s/        "65101.*/&\n&/' /etc/shadowsocks-libev/manager.json
			done
		fi
		#sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/config.json
		sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/manager.json
		[ "$(ip -6 a 2>/dev/null)" = "" ] && sed -i '/"\[::0\]"/d' /etc/shadowsocks-libev/manager.json
	elif [ "$update" != "0" ] && [ -f /etc/shadowsocks-libev/manager.json ] && [ "$(grep -c '65101' /etc/shadowsocks-libev/manager.json | tr -d '\n')" != "$NBCPU" ] && [ -z "$(grep port_conf /etc/shadowsocks-libev/manager.json)" ]; then
		for i in $(seq 2 $NBCPU); do
			sed -i '0,/65101/ s/        "65101.*/&\n&/' /etc/shadowsocks-libev/manager.json
		done
		sed -i 's/       "65101.*"$/&,/' /etc/shadowsocks-libev/manager.json
	fi
	[ ! -f /etc/shadowsocks-libev/local.acl ] && touch /etc/shadowsocks-libev/local.acl
	#sed -i 's:aes-256-cfb:chacha20:g' /etc/shadowsocks-libev/config.json
	#sed -i 's:json:json --no-delay:g' /lib/systemd/system/shadowsocks-libev-server@.service
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /lib/systemd/system/shadowsocks-libev-manager@.service ${VPSURL}${VPSPATH}/shadowsocks-libev-manager@.service.in
	else
		cp ${DIR}/shadowsocks-libev-manager@.service.in /lib/systemd/system/shadowsocks-libev-manager@.service
	fi
	if systemctl -q is-enabled shadowsocks-libev 2>/dev/null; then
		systemctl -q disable shadowsocks-libev
	fi
	[ -f /etc/shadowsocks-libev/config.json ] && systemctl disable shadowsocks-libev-server@config.service
	systemctl enable shadowsocks-libev-manager@manager.service
	if [ $NBCPU -gt 1 ]; then
		for i in $(seq 1 $NBCPU); do
			[ -f /etc/shadowsocks-libev/config$i.json ] && systemctl is-enabled shadowsocks-libev && systemctl disable shadowsocks-libev-server@config$i.service
		done
	fi
	if systemctl -q is-active shadowsocks-libev-manager@manager 2>/dev/null; then
		systemctl -q stop shadowsocks-libev-manager@manager > /dev/null 2>&1
	fi
fi
if ! grep -q 'DefaultLimitNOFILE=65536' /etc/systemd/system.conf ; then
	echo 'DefaultLimitNOFILE=65536' >> /etc/systemd/system.conf
fi

if [ "$LOCALFILES" = "no" ]; then
	wget -O /lib/systemd/system/omr-update.service ${VPSURL}${VPSPATH}/omr-update.service.in
	wget -O /usr/bin/omr-update ${VPSURL}${VPSPATH}/omr-update
	chmod 755 /usr/bin/omr-update
else
	cp ${DIR}/omr-update.service.in /lib/systemd/system/omr-update.service
	cp ${DIR}/omr-update /usr/bin/omr-update
	chmod 755 /usr/bin/omr-update
fi
chmod 644 /lib/systemd/system/omr-update.service

# Install simple-obfs
if [ "$OBFS" = "yes" ]; then
	echo "Install OBFS"
	if [ "$SOURCES" = "yes" ]; then
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
	else
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		apt-get -y -o Dpkg::Options::="--force-overwrite" install omr-simple-obfs=${OBFS_BINARY_VERSION}
	fi
	#sed -i 's%"mptcp": true%"mptcp": true,\n"plugin": "/usr/local/bin/obfs-server",\n"plugin_opts": "obfs=http;mptcp;fast-open;t=400"%' /etc/shadowsocks-libev/config.json
fi

# Install v2ray-plugin
if [ "$V2RAY_PLUGIN" = "yes" ]; then
	echo "Install v2ray plugin"
	if [ "$SOURCES" = "yes" ]; then
		rm -rf /tmp/v2ray-plugin-linux-amd64-${V2RAY_PLUGIN_VERSION}.tar.gz
		#wget -O /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz https://github.com/shadowsocks/v2ray-plugin/releases/download/${V2RAY_PLUGIN_VERSION}/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		#wget -O /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz ${VPSURL}${VPSPATH}/bin/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		wget -O /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz https://github.com/teddysun/v2ray-plugin/releases/download/v${V2RAY_PLUGIN_VERSION}/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		cd /tmp
		tar xzvf v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		cp -f v2ray-plugin_linux_amd64 /usr/local/bin/v2ray-plugin
		cd /tmp
		rm -rf /tmp/v2ray-plugin_linux_amd64
		rm -rf /tmp/v2ray-plugin-linux-amd64-${V2RAY_PLUGIN_VERSION}.tar.gz
	
		#rm -rf /tmp/v2ray-plugin
		#cd /tmp
		#rm -f /var/lib/dpkg/lock
		#apt-get install -y --no-install-recommends git ca-certificates golang-go
		#git clone https://github.com/shadowsocks/v2ray-plugin.git /tmp/v2ray-plugin
		#cd /tmp/v2ray-plugin
		#git checkout ${V2RAY_PLUGIN_VERSION}
		#git submodule update --init --recursive
		#CGO_ENABLED=0 go build -o v2ray-plugin
		#cp v2ray-plugin /usr/local/bin/v2ray-plugin
		#cd /tmp
		#rm -rf /tmp/simple-obfs
	else
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		apt-get -y install v2ray-plugin=${V2RAY_PLUGIN_VERSION}
	fi
fi

if [ "$OBFS" = "no" ] && [ "$V2RAY_PLUGIN" = "no" ] && [ -f /etc/shadowsocks-libev/config.json ]; then
	sed -i -e '/plugin/d' -e 's/,,//' /etc/shadowsocks-libev/config.json
fi

if systemctl -q is-active shadowsocks-go.service 2>/dev/null; then
	systemctl -q stop shadowsocks-go > /dev/null 2>&1
	systemctl -q disable shadowsocks-go > /dev/null 2>&1
fi

if [ "$SHADOWSOCKS_GO" = "yes" ]; then
	#if [ "$SOURCES" = "yes" ] || [ "$ARCH" = "arm64" ]; then
	if [ "$ARCH" = "arm64" ]; then
		if [ "$ARCH" = "amd64" ]; then
			wget -O /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-amd64.deb ${VPSURL}/debian/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-amd64.deb
			rm -f /var/lib/dpkg/lock
			rm -f /var/lib/dpkg/lock-frontend
			dpkg --force-all -i -B /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-amd64.deb
			rm -f /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-amd64.deb
		elif [ "$ARCH" = "arm64" ]; then
			wget -O /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-arm64.deb ${VPSURL}/debian/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-arm64.deb
			rm -f /var/lib/dpkg/lock
			rm -f /var/lib/dpkg/lock-frontend
			dpkg --force-all -i -B /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-arm64.deb
			rm -f /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-arm64.deb
		fi
	else
		apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y install shadowsocks-go=${SHADOWSOCKS_GO_VERSION}
	fi
	if [ -f /etc/shadowsocks-go/server.json ]; then
		PSK2=$(grep -Po '"'"psk"'"\s*:\s*"\K([^"]*)' /etc/shadowsocks-go/server.json | head -n 1 | tr -d "\n")
		[ -n "$PSK2" ] && [ "$PSK2" != "PSK" ] && [ "$PSK2" != "null" ] && PSK="$PSK2"
		UPSK2=$(grep -Po '"'"openmptcprouter"'"\s*:\s*"\K([^"]*)' /etc/shadowsocks-go/upsks.json | head -n 1 | tr -d "\n")
		[ -n "$UPSK2" ] && [ "$UPSK2" != "UPSK" ] && [ "$UPSK2" != "null" ] && UPSK="$UPSK2"
	fi
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /etc/shadowsocks-go/server.json ${VPSURL}${VPSPATH}/shadowsocks-go.server.json
	else
		cp ${DIR}/shadowsocks-go.server.json /etc/shadowsocks-go/server.json
	fi
	sed -i "s:\"PSK\":\"$PSK\":g" /etc/shadowsocks-go/server.json
	sed -i "s:UPSK:$UPSK:g" /etc/shadowsocks-go/upsks.json
	jq -M 'del(.users[0].openmptcprouter."shadowsocks-go")' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.new
	mv -f /etc/openmptcprouter-vps-admin/omr-admin-config.json /etc/openmptcprouter-vps-admin/omr-admin-config.json.bak
	mv -f /etc/openmptcprouter-vps-admin/omr-admin-config.json.new /etc/openmptcprouter-vps-admin/omr-admin-config.json

	chmod 644 /lib/systemd/system/shadowsocks-go.service
	systemctl daemon-reload
	systemctl enable shadowsocks-go.service
fi


if systemctl -q is-active v2ray.service 2>/dev/null; then
	systemctl -q stop v2ray > /dev/null 2>&1
	systemctl -q disable v2ray > /dev/null 2>&1
fi

if [ "$V2RAY" = "yes" ]; then
	#apt-get -y -o Dpkg::Options::="--force-overwrite" install v2ray
	#if [ "$SOURCES" = "yes" ] || [ "$ARCH" = "arm64" ]; then
	if [ "$ARCH" = "arm64" ]; then
		if [ "$ARCH" = "amd64" ]; then
			wget -O /tmp/v2ray-${V2RAY_VERSION}-amd64.deb ${VPSURL}/debian/v2ray-${V2RAY_VERSION}-amd64.deb
			rm -f /var/lib/dpkg/lock
			rm -f /var/lib/dpkg/lock-frontend
			dpkg --force-all -i -B /tmp/v2ray-${V2RAY_VERSION}-amd64.deb
			rm -f /tmp/v2ray-${V2RAY_VERSION}-amd64.deb
		elif [ "$ARCH" = "arm64" ]; then
			wget -O /tmp/v2ray-${V2RAY_VERSION}-arm64.deb ${VPSURL}/debian/v2ray-${V2RAY_VERSION}-arm64.deb
			rm -f /var/lib/dpkg/lock
			rm -f /var/lib/dpkg/lock-frontend
			dpkg --force-all -i -B /tmp/v2ray-${V2RAY_VERSION}-arm64.deb
			rm -f /tmp/v2ray-${V2RAY_VERSION}-arm64.deb
		fi
#		else
#			[ "$ARCH" = "i386" ] && V2RAY_FILENAME="v2ray-linux-32.zip"
#			[ "$ARCH" = "amd64" ] && V2RAY_FILENAME="v2ray-linux-64.zip"
#			[ "$ARCH" = "armel" ] && V2RAY_FILENAME="v2ray-linux-arm32-v7a.zip"
#			[ "$ARCH" = "armhf" ] && V2RAY_FILENAME="v2ray-linux-arm32-v7a.zip"
#			[ "$ARCH" = "arm64" ] && V2RAY_FILENAME="v2ray-linux-arm64-v8a.zip"
#			[ "$ARCH" = "mips64el" ] && V2RAY_FILENAME="v2ray-linux-mips64le.zip"
#			[ "$ARCH" = "mipsel" ] && V2RAY_FILENAME="v2ray-linux-mips32le.zip"
#			[ "$ARCH" = "riscv64" ] && V2RAY_FILENAME="v2ray-linux-riscv64.zip"
#			wget -O /tmp/v2ray-${V2RAY_VERSION}.zip https://github.com/v2fly/v2ray-core/releases/download/v${V2RAY_VERSION}/${V2RAY_FILENAME}
#			cd /tmp
#			rm -rf v2ray
#			mkdir -p v2ray
#			cd v2ray
#			unzip /tmp/v2ray-${V2RAY_VERSION}.zip
#			cp v2ray /usr/bin/
#			cp geoip.dat /usr/bin/
#			cp geosite.dat /usr/bin/
#			wget -O /lib/systemd/system/v2ray.service ${VPSURL}${VPSPATH}/v2ray.service
#		fi
	else
		apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y install v2ray=${V2RAY_VERSION}
	fi
	if [ -f /etc/v2ray/v2ray-server.json ]; then
		V2RAY_UUID2=$(grep -Po '"'"id"'"\s*:\s*"\K([^"]*)' /etc/v2ray/v2ray-server.json | head -n 1 | tr -d "\n")
		[ -n "$V2RAY_UUID2" ] && V2RAY_UUID="$V2RAY_UUID2"
	fi
	#if [ ! -f /etc/v2ray/v2ray-server.json ]; then
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /etc/v2ray/v2ray-server.json ${VPSURL}${VPSPATH}/v2ray-server.json
		else
			cp ${DIR}/v2ray-server.json /etc/v2ray/v2ray-server.json
		fi
		sed -i "s:V2RAY_UUID:$V2RAY_UUID:g" /etc/v2ray/v2ray-server.json
	#fi
	if [ "$KERNEL" != "5.4" ] && [ -z "$(grep mptcp /etc/v2ray/v2ray-server.json | grep true)" ]; then
		sed -i 's/"sockopt": {/&\n                    "mptcp": true,/' /etc/v2ray/v2ray-server.json
	fi
	rm -f /etc/v2ray/config.json
	ln -s /etc/v2ray/v2ray-server.json /etc/v2ray/config.json
	#if [ -f /etc/systemd/system/v2ray.service.dpkg-dist ]; then
	#	mv -f /etc/systemd/system/v2ray.service.dpkg-dist /etc/systemd/system/v2ray.service
	#fi
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /lib/systemd/system/v2ray.service ${VPSURL}${VPSPATH}/v2ray.service
	else
		cp ${DIR}/v2ray.service /lib/systemd/system/v2ray.service
	fi
	chmod 644 /lib/systemd/system/v2ray.service
	systemctl daemon-reload
	systemctl enable v2ray.service
	#if [ "$UPSTREAM" = "yes" ] || [ "$UPSTREAM6" = "yes" ]; then
	#	mptcpize enable v2ray
	#fi
fi

if systemctl -q is-active xray.service 2>/dev/null; then
	systemctl -q stop xray > /dev/null 2>&1
	systemctl -q disable xray > /dev/null 2>&1
fi

if [ "$XRAY" = "yes" ]; then
	#apt-get -y -o Dpkg::Options::="--force-overwrite" install xray
	#if [ "$SOURCES" = "yes" ] || [ "$ARCH" = "arm64" ]; then
	if [ "$ARCH" = "arm64" ]; then
		if [ "$ARCH" = "amd64" ]; then
			wget -O /tmp/xray-${XRAY_VERSION}-amd64.deb ${VPSURL}/debian/xray-${XRAY_VERSION}-amd64.deb
			rm -f /var/lib/dpkg/lock
			rm -f /var/lib/dpkg/lock-frontend
			dpkg --force-all -i -B /tmp/xray-${XRAY_VERSION}-amd64.deb
			rm -f /tmp/xray-${XRAY_VERSION}-amd64.deb
		elif [ "$ARCH" = "arm64" ]; then
			wget -O /tmp/xray-${XRAY_VERSION}-arm64.deb ${VPSURL}/debian/xray-${XRAY_VERSION}-arm64.deb
			rm -f /var/lib/dpkg/lock
			rm -f /var/lib/dpkg/lock-frontend
			dpkg --force-all -i -B /tmp/xray-${XRAY_VERSION}-arm64.deb
			rm -f /tmp/xray-${XRAY_VERSION}-arm64.deb
		fi
	else
		apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y install xray=${XRAY_VERSION}
	fi
	if [ -f /etc/xray/xray-server.json ]; then
		XRAY_UUID2=$(grep -Po '"'"id"'"\s*:\s*"\K([^"]*)' /etc/xray/xray-server.json | head -n 1 | tr -d "\n")
		[ -n "$XRAY_UUID2" ] && [ "$XRAY_UUID2" != "XRAY_UUID" ] && [ "$XRAY_UUID2" != "V2RAY_UUID" ] && XRAY_UUID="$XRAY_UUID2"
		PSK2=$(jq -r '.inbounds[] | select(.tag=="omrin-shadowsocks-tunnel") | .settings.password' /etc/xray/xray-server.json | tr -d "\n")
		[ "$PSK2" != "null" ] && [ -n "$PSK2" ] && [ "$PSK2" != "XRAY_PSK" ] && PSK="$PSK2"
		UPSK2=$(jq -r '.inbounds[] | select(.tag=="omrin-shadowsocks-tunnel") | .settings.clients[] | select(.email=="openmptcprouter") | .password' /etc/xray/xray-server.json | tr -d "\n")
		[ "$UPSK2" != "null" ] && [ -n "$UPSK2" ] && [ "$UPSK2" != "XRAY_UPSK" ] && UPSK="$UPSK2"
		XRAY_X25519_PRIVATE_KEY2=$(grep -Po '"'"privateKey"'"\s*:\s*"\K([^"]*)' /etc/xray/xray-vless_reality.json | head -n 1 | tr -d "\n")
		[ -n "$XRAY_X25519_PRIVATE_KEY2" ] && [ "$XRAY_X25519_PRIVATE_KEY2" != "XRAY_X25519_PRIVATE_KEY" ] && XRAY_X25519_PRIVATE_KEY="$XRAY_X25519_PRIVATE_KEY2"
		XRAY_X25519_PUBLIC_KEY2=$(grep -Po '"'"publicKey"'"\s*:\s*"\K([^"]*)' /etc/xray/xray-vless_reality.json | head -n 1 | tr -d "\n")
		[ -n "$XRAY_X25519_PUBLIC_KEY2" ] && [ "$XRAY_X25519_PUBLIC_KEY2" != "XRAY_X25519_PUBLIC_KEY" ] && XRAY_X25519_PUBLIC_KEY="$XRAY_X25519_PUBLIC_KEY2"
		#jq -M 'del(.transport)' /etc/xray/xray-server.json > /etc/xray/xray-server.json.tmp
		#mv -f /etc/xray/xray-server.json.tmp /etc/xray/xray-server.json

	fi
	if [ -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
		jq -M 'del(.users[0].openmptcprouter.xray)' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.new
		mv -f /etc/openmptcprouter-vps-admin/omr-admin-config.json /etc/openmptcprouter-vps-admin/omr-admin-config.json.bak
		mv -f /etc/openmptcprouter-vps-admin/omr-admin-config.json.new /etc/openmptcprouter-vps-admin/omr-admin-config.json
	fi
	if [ -f /etc/xray/xray-server.json ]; then
		jq -M 'del(.api.listen)' /etc/xray/xray-server.json > /etc/xray/xray-server.json.new
		mv -f /etc/xray/xray-server.json /etc/xray/xray-server.json.bak
		mv -f /etc/xray/xray-server.json.new /etc/xray/xray-server.json
	fi
	if [ ! -f /etc/xray/xray-server.json ] || [ -z "$(grep -i mptcp /etc/xray/xray-server.json | grep true)" ] || [ -z "$(grep -i transport /etc/xray/xray-server.json)" ]; then
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /etc/xray/xray-server.json ${VPSURL}${VPSPATH}/xray-server.json
		else
			cp ${DIR}/xray-server.json /etc/xray/xray-server.json
		fi
		sed -i "s:XRAY_UUID:$XRAY_UUID:g" /etc/xray/xray-server.json
		sed -i "s:V2RAY_UUID:$XRAY_UUID:g" /etc/xray/xray-server.json
		sed -i "s:XRAY_PSK:$PSK:g" /etc/xray/xray-server.json
		sed -i "s:XRAY_UPSK:$UPSK:g" /etc/xray/xray-server.json
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /etc/xray/xray-vless-reality.json ${VPSURL}${VPSPATH}/xray-vless-reality.json
		else
			cp ${DIR}/xray-vless-reality.json /etc/xray/xray-vless-reality.json
		fi
		if [ -z "$XRAY_X25519_PRIVATE_KEY" ]; then
			XRAY_X25519_KEYS=$(/usr/bin/xray x25519)
			XRAY_X25519_PRIVATE_KEY=$(echo "${XRAY_X25519_KEYS}" | grep Private | awk '{ print $3 }' | tr -d "\n")
			XRAY_X25519_PUBLIC_KEY=$(echo "${XRAY_X25519_KEYS}" | grep Public | awk '{ print $3 }' | tr -d "\n")
		fi
		sed -i "s:XRAY_UUID:$XRAY_UUID:g" /etc/xray/xray-vless-reality.json
		sed -i "s:XRAY_X25519_PRIVATE_KEY:$XRAY_X25519_PRIVATE_KEY:g" /etc/xray/xray-vless-reality.json
		sed -i "s:XRAY_X25519_PUBLIC_KEY:$XRAY_X25519_PUBLIC_KEY:g" /etc/xray/xray-vless-reality.json
		for xrayuser in $(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r '.users[0][].username'); do
			if [ "$xrayuser" != "admin" ] && [ "$xrayuser" != "openmptcprouter" ]; then
				xrayid="$(/usr/bin/xray uuid)"
				jq --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients) += [{"level": 0, "alterId": 0, "email": $xrayuser,"id": $xrayid}]' /etc/xray/xray-server.json > /etc/xray/xray-server.json.tmp
				mv /etc/xray/xray-server.json.tmp /etc/xray/xray-server.json
				jq --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-vmess-tunnel") | .settings.clients) += [{"level": 0, "alterId": 0, "email": $xrayuser,"id": $xrayid}]' /etc/xray/xray-server.json > /etc/xray/xray-server.json.tmp
				mv /etc/xray/xray-server.json.tmp /etc/xray/xray-server.json
				jq --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-socks-tunnel") | .settings.accounts) += [{"user": $xrayuser,"pass": $xrayid}]' /etc/xray/xray-server.json > /etc/xray/xray-server.json.tmp
				mv /etc/xray/xray-server.json.tmp /etc/xray/xray-server.json
				jq --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-trojan-tunnel") | .settings.clients) += [{"level": 0, "alterId": 0, "email": $xrayuser,"id": $xrayid}]' /etc/xray/xray-server.json > /etc/xray/xray-server.json.tmp
				mv /etc/xray/xray-server.json.tmp /etc/xray/xray-server.json
				[ -e /etc/shadowsocks-go/upsks.json ] && shadowsockspass="$(jq --arg xrayuser $xrayuser -r '.[$xrayuser]' /etc/shadowsocks-go/upsks.json)"
				[ -z "$shadowsockspass" ] && shadowsockspass=$(head -c 32 /dev/urandom | base64 -w0)
				jq --arg xrayuser "$xrayuser" --arg shadowsockspass "$shadowsockspass" '(.inbounds[] | select(.tag=="omrin-shadowsocks-tunnel") | .settings.clients) += [{"email": $xrayuser,"password": $shadowsockspass}]' /etc/xray/xray-server.json > /etc/xray/xray-server.json.tmp
				mv /etc/xray/xray-server.json.tmp /etc/xray/xray-server.json
			fi
		done
	fi
	#if ([ "$UPSTREAM" = "yes" ] || [ "$UPSTREAM6" = "yes" ]) && [ -z "$(grep mptcp /etc/xray/xray-server.json | grep true)" ]; then
	#	sed -i 's/"sockopt": {/&\n                    "mptcp": true,/' /etc/xray/xray-server.json
	#fi
	rm -f /etc/xray/config.json
	ln -s /etc/xray/xray-server.json /etc/xray/config.json
	#if [ -f /etc/systemd/system/xray.service.dpkg-dist ]; then
	#	mv -f /etc/systemd/system/xray.service.dpkg-dist /etc/systemd/system/xray.service
	#fi
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /lib/systemd/system/xray.service ${VPSURL}${VPSPATH}/xray.service
	else
		cp ${DIR}/xray.service /lib/systemd/system/xray.service
	fi
	chmod 644 /lib/systemd/system/xray.service
	systemctl daemon-reload
	systemctl enable xray.service
fi

if systemctl -q is-active mlvpn@mlvpn0.service 2>/dev/null; then
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
	mkdir -p /etc/mlvpn
	if [ "$SOURCES" = "yes" ]; then
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		apt-get -y install build-essential pkg-config autoconf automake libpcap-dev unzip git
		rm -rf /tmp/mlvpn
		cd /tmp
		#git clone https://github.com/markfoodyburton/MLVPN.git /tmp/mlvpn
		#git clone https://github.com/flohoff/MLVPN.git /tmp/mlvpn
		git clone https://github.com/zehome/MLVPN.git /tmp/mlvpn
		#git clone https://github.com/link4all/MLVPN.git /tmp/mlvpn
		cd /tmp/mlvpn
		git checkout ${MLVPN_VERSION}
		./autogen.sh
		./configure --sysconfdir=/etc
		make
		make install
		cd /tmp
		rm -rf /tmp/mlvpn
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /lib/systemd/network/mlvpn.network ${VPSURL}${VPSPATH}/mlvpn.network
			wget -O /lib/systemd/system/mlvpn@.service ${VPSURL}${VPSPATH}/mlvpn@.service.in
		else
			cp ${DIR}/mlvpn.network /lib/systemd/network/mlvpn.network
			cp ${DIR}/mlvpn@.service.in /lib/systemd/system/mlvpn@.service
		fi
		if [ "$mlvpnupdate" = "0" ]; then
			if [ "$LOCALFILES" = "no" ]; then
				wget -O /etc/mlvpn/mlvpn0.conf ${VPSURL}${VPSPATH}/mlvpn0.conf
			else
				cp ${DIR}/mlvpn0.conf /etc/mlvpn/mlvpn0.conf
			fi
		fi
	else
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		apt-get -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" install omr-mlvpn=${MLVPN_BINARY_VERSION}
	fi
	if [ "$mlvpnupdate" = "0" ]; then
		sed -i "s:MLVPN_PASS:$MLVPN_PASS:" /etc/mlvpn/mlvpn0.conf
	fi
	chmod 0600 /etc/mlvpn/mlvpn0.conf
	adduser --quiet --system --home /var/opt/mlvpn --shell /usr/sbin/nologin mlvpn
	mkdir -p /var/opt/mlvpn
	usermod -d /var/opt/mlvpn mlvpn
	chown mlvpn /var/opt/mlvpn
	systemctl enable mlvpn@mlvpn0.service
	systemctl enable systemd-networkd.service
	echo "install mlvpn done"
fi
if systemctl -q is-active ubond@ubond0.service 2>/dev/null; then
	systemctl -q stop ubond@ubond0 > /dev/null 2>&1
	systemctl -q disable ubond@ubond0 > /dev/null 2>&1
fi
echo "install ubond"
# Install UBOND
if [ "$UBOND" = "yes" ]; then
	echo 'Install UBOND'
	ubondupdate="0"
	if [ -f /etc/ubond/ubond0.conf ]; then
		ubondupdate="1"
	fi
#	if [ "$SOURCES" = "yes" ]; then
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		apt-get -y install build-essential pkg-config autoconf automake libpcap-dev unzip git
		rm -rf /tmp/ubond
		cd /tmp
		git clone https://github.com/markfoodyburton/ubond.git /tmp/ubond
		cd /tmp/ubond
		git checkout ${UBOND_VERSION}
		./autogen.sh
		./configure --sysconfdir=/etc
		make
		make install
		cd /tmp
		rm -rf /tmp/ubond
#	else
#		apt-get -y -o Dpkg::Options::="--force-overwrite" install ubond
#	fi
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /lib/systemd/network/ubond.network ${VPSURL}${VPSPATH}/ubond.network
		wget -O /lib/systemd/system/ubond@.service ${VPSURL}${VPSPATH}/ubond@.service.in
	else
		cp ${DIR}/ubond.network /lib/systemd/network/ubond.network
		cp ${DIR}/ubond@.service.in /lib/systemd/system/ubond@.service
	fi
	mkdir -p /etc/ubond
	if [ "$ubondupdate" = "0" ]; then
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /etc/ubond/ubond0.conf ${VPSURL}${VPSPATH}/ubond0.conf
		else
			cp ${DIR}/ubond0.conf /etc/ubond/ubond0.conf
		fi
		sed -i "s:UBOND_PASS:$UBOND_PASS:" /etc/ubond/ubond0.conf
	fi
	chmod 0600 /etc/ubond/ubond0.conf
	adduser --quiet --system --home /var/opt/ubond --shell /usr/sbin/nologin ubond
	mkdir -p /var/opt/ubond
	usermod -d /var/opt/ubond ubond
	chown ubond /var/opt/ubond
	systemctl enable ubond@ubond0.service
	systemctl enable systemd-networkd.service
	echo "install ubond done"
fi

if systemctl -q is-active wg-quick@wg0.service 2>/dev/null; then
	systemctl -q stop wg-quick@wg0 > /dev/null 2>&1
	systemctl -q disable wg-quick@wg0 > /dev/null 2>&1
fi

if [ "$WIREGUARD" = "yes" ]; then
	echo "Install WireGuard"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get -y install wireguard-tools --no-install-recommends
	if [ ! -f /etc/wireguard/wg0.conf ]; then
		cd /etc/wireguard
		umask 077; wg genkey | tee vpn-server-private.key | wg pubkey > vpn-server-public.key
		cat > /etc/wireguard/wg0.conf <<-EOF
		[Interface]
		PrivateKey = $(cat /etc/wireguard/vpn-server-private.key | tr -d "\n")
		ListenPort = 65311
		Address = 10.255.247.1/24
		SaveConfig = true
		EOF
	fi
	systemctl enable wg-quick@wg0
	if [ ! -f /etc/wireguard/client-wg0.conf ]; then
		cd /etc/wireguard
		umask 077; wg genkey | tee vpn-client-private.key | wg pubkey > vpn-client-public.key
		cat > /etc/wireguard/client-wg0.conf <<-EOF
		[Interface]
		PrivateKey = $(cat /etc/wireguard/vpn-server-private.key | tr -d "\n")
		ListenPort = 65312
		Address = 10.255.246.1/24
		SaveConfig = true
		
		[Peer]
		PublicKey = $(cat /etc/wireguard/vpn-client-public.key | tr -d "\n")
		AllowedIPs = 10.255.246.2/32
		EOF
	fi
	if [ ! -f /root/wireguard-client.conf ]; then
		cat > /root/wireguard-client.conf <<-EOF
		[Interface]
		Address = 10.255.246.2/24
		PrivateKey = $(cat /etc/wireguard/vpn-client-private.key | tr -d "\n")
		
		[Peer]
		PublicKey = $(cat /etc/wireguard/vpn-server-public.key | tr -d "\n")
		Endpoint = ${VPS_PUBLIC_IP}:65312
		AllowedIPs = 0.0.0.0/0, ::/0, 192.168.100.0/24
		EOF
	fi
	systemctl enable wg-quick@client-wg0
	echo "Install wireguard done"
fi

if systemctl -q is-active fail2ban.service 2>/dev/null; then
	systemctl -q stop fail2ban > /dev/null 2>&1
	systemctl -q disable fail2ban > /dev/null 2>&1
fi
if [ "$FAIL2BAN" = "yes" ]; then
	echo "Install Fail2ban"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get -y install fail2ban python3-systemd
	systemctl enable fail2ban
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /etc/fail2ban/jail.d/openmptcprouter.conf ${VPSURL}${VPSPATH}/fail2ban-jail-openmptcprouter.conf
		wget -O /etc/fail2ban/filter.d/openvpn.conf ${VPSURL}${VPSPATH}/fail2ban-filter-openvpn.conf
	else
		cp ${DIR}/fail2ban-jail-openmptcprouter.conf /etc/fail2ban/jail.d/openmptcprouter.conf
		cp ${DIR}/fail2ban-filter-openvpn.conf /etc/fail2ban/filter.d/openvpn.conf
	fi
	echo "Install Fail2ban done"
fi

if systemctl -q is-active openvpn-server@tun0.service 2>/dev/null; then
	systemctl -q stop openvpn-server@tun0 > /dev/null 2>&1
	systemctl -q disable openvpn-server@tun0 > /dev/null 2>&1
fi
if [ "$OPENVPN" = "yes" ]; then
	echo "Install OpenVPN"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	if [ "$VERSION_ID" = "13" ] && [ "$ID" = "debian" ]; then
		apt-get -y --allow-downgrades install openvpn easy-rsa
	else
		apt-get -y --default-release install openvpn easy-rsa
	fi
	#wget -O /lib/systemd/network/openvpn.network ${VPSURL}${VPSPATH}/openvpn.network
	rm -f /lib/systemd/network/openvpn.network
	#if [ ! -f "/etc/openvpn/server/static.key" ]; then
	#	wget -O /etc/openvpn/tun0.conf ${VPSURL}${VPSPATH}/openvpn-tun0.conf
	#	cd /etc/openvpn/server
	#	openvpn --genkey --secret static.key
	#fi
	if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "18.04" ] && [ ! -d /etc/openvpn/ca ]; then
		wget -O /tmp/EasyRSA-unix-v${EASYRSA_VERSION}.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-unix-v${EASYRSA_VERSION}.tgz
		cd /tmp
		tar xzvf EasyRSA-unix-v${EASYRSA_VERSION}.tgz
		cd /tmp/EasyRSA-v${EASYRSA_VERSION}
		mkdir -p /etc/openvpn/ca
		cp easyrsa /etc/openvpn/ca/
		cp openssl-easyrsa.cnf /etc/openvpn/ca/
		cp vars.example /etc/openvpn/ca/vars
		cp -r x509-types /etc/openvpn/ca/

		#mkdir -p /etc/openvpn/ca/pki/private /etc/openvpn/ca/pki/issued
		#./easyrsa init-pki
		#./easyrsa --batch build-ca nopass
		#EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
		#EASYRSA_CERT_EXPIRE=3650 EASYRSA_REQ_CN=openmptcprouter ./easyrsa build-client-full "openmptcprouter" nopass
		#EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		#mv pki/ca.crt /etc/openvpn/ca/pki/ca.crt
		#mv pki/private/ca.key /etc/openvpn/ca/pki/private/ca.key
		#mv pki/issued/server.crt /etc/openvpn/ca/pki/issued/server.crt
		#mv pki/private/server.key /etc/openvpn/ca/pki/private/server.key
		#mv pki/crl.pem /etc/openvpn/ca/pki/crl.pem
		#mv pki/issued/openmptcprouter.crt /etc/openvpn/ca/pki/issued/openmptcprouter.crt
		#mv pki/private/openmptcprouter.key /etc/openvpn/ca/pki/private/openmptcprouter.key
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
		if [ ! -d /etc/openvpn/ca ]; then
			make-cadir /etc/openvpn/ca
		fi
		cd /etc/openvpn/ca
		./easyrsa --batch init-pki >/dev/null 2>&1
		./easyrsa --batch build-ca nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full server nopass
		EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "openmptcprouter" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa --batch gen-crl
	fi
	chmod 644 /etc/openvpn/ca/pki/crl.pem >/dev/null 2>&1 || true
	if [ ! -f "/etc/openvpn/ca/pki/issued/openmptcprouter.crt" ]; then
		mv /etc/openvpn/ca/pki/issued/client.crt /etc/openvpn/ca/pki/issued/openmptcprouter.crt
		mv /etc/openvpn/ca/pki/private/client.key /etc/openvpn/ca/pki/private/openmptcprouter.key
	fi
	if [ ! -f "/etc/openvpn/server/dh2048.pem" ]; then
		openssl dhparam -out /etc/openvpn/server/dh2048.pem 2048
	fi
	if [ "$LOCALFILES" = "no" ]; then
		if [ "$KERNEL" != "5.4" ]; then
			wget -O /etc/openvpn/tun0.conf ${VPSURL}${VPSPATH}/openvpn-tun0.6.1.conf
			wget -O /etc/openvpn/tun1.conf ${VPSURL}${VPSPATH}/openvpn-tun1.6.1.conf
		else
			wget -O /etc/openvpn/tun0.conf ${VPSURL}${VPSPATH}/openvpn-tun0.conf
			wget -O /etc/openvpn/tun1.conf ${VPSURL}${VPSPATH}/openvpn-tun1.conf
		fi
		if [ "$OPENVPN_BONDING" = "yes" ]; then
			wget -O /etc/openvpn/bonding1.conf ${VPSURL}${VPSPATH}/openvpn-bonding1.conf
			wget -O /etc/openvpn/bonding2.conf ${VPSURL}${VPSPATH}/openvpn-bonding2.conf
			wget -O /etc/openvpn/bonding3.conf ${VPSURL}${VPSPATH}/openvpn-bonding3.conf
			wget -O /etc/openvpn/bonding4.conf ${VPSURL}${VPSPATH}/openvpn-bonding4.conf
			wget -O /etc/openvpn/bonding5.conf ${VPSURL}${VPSPATH}/openvpn-bonding5.conf
			wget -O /etc/openvpn/bonding6.conf ${VPSURL}${VPSPATH}/openvpn-bonding6.conf
			wget -O /etc/openvpn/bonding7.conf ${VPSURL}${VPSPATH}/openvpn-bonding7.conf
			wget -O /etc/openvpn/bonding8.conf ${VPSURL}${VPSPATH}/openvpn-bonding8.conf
		fi
	else
		if [ "$KERNEL" != "5.4" ]; then
			cp ${DIR}/openvpn-tun0.6.1.conf /etc/openvpn/tun0.conf
			cp ${DIR}/openvpn-tun1.6.1.conf /etc/openvpn/tun1.conf
		else
			cp ${DIR}/openvpn-tun0.conf /etc/openvpn/tun0.conf
			cp ${DIR}/openvpn-tun1.conf /etc/openvpn/tun1.conf
		fi
		if [ "$OPENVPN_BONDING" = "yes" ]; then
			cp ${DIR}/openvpn-bonding1.conf /etc/openvpn/bonding1.conf
			cp ${DIR}/openvpn-bonding2.conf /etc/openvpn/bonding2.conf
			cp ${DIR}/openvpn-bonding3.conf /etc/openvpn/bonding3.conf
			cp ${DIR}/openvpn-bonding4.conf /etc/openvpn/bonding4.conf
			cp ${DIR}/openvpn-bonding5.conf /etc/openvpn/bonding5.conf
			cp ${DIR}/openvpn-bonding6.conf /etc/openvpn/bonding6.conf
			cp ${DIR}/openvpn-bonding7.conf /etc/openvpn/bonding7.conf
			cp ${DIR}/openvpn-bonding8.conf /etc/openvpn/bonding8.conf
		fi
	fi
	if [ "$(ip -6 a 2>/dev/null)" = "" ]; then
		sed -i 's/proto tcp6-server//' /etc/openvpn/tun0.conf
		sed -i 's/proto udp6//' /etc/openvpn/tun1.conf
		if [ "$OPENVPN_BONDING" = "yes" ]; then
			sed -i 's/proto udp6//' /etc/openvpn/bonding1.conf
			sed -i 's/proto udp6//' /etc/openvpn/bonding2.conf
			sed -i 's/proto udp6//' /etc/openvpn/bonding3.conf
			sed -i 's/proto udp6//' /etc/openvpn/bonding4.conf
			sed -i 's/proto udp6//' /etc/openvpn/bonding5.conf
			sed -i 's/proto udp6//' /etc/openvpn/bonding6.conf
			sed -i 's/proto udp6//' /etc/openvpn/bonding7.conf
			sed -i 's/proto udp6//' /etc/openvpn/bonding8.conf
		fi
	fi
	mkdir -p /etc/openvpn/ccd
	if [ ! -f /etc/openvpn/ccd/ipp_tcp.txt ]; then
		echo 'openmptcprouter,10.255.250.2,' > /etc/openvpn/ccd/ipp_tcp.txt
	fi
	if [ ! -f /etc/openvpn/ccd/ipp_udp.txt ]; then
		echo 'openmptcprouter,10.255.252.2,' > /etc/openvpn/ccd/ipp_udp.txt
	fi
	if [ "$ID" = "ubuntu" ]; then
		# for old OpenVPN releases
		sed -i 's/disable-dco//' /etc/openvpn/tun0.conf
	fi
	chmod 755 /etc/openvpn/ccd/
	chmod 644 /etc/openvpn/ccd/*
	chmod 644 /lib/systemd/system/openvpn*.service
	systemctl enable openvpn@tun0.service
	systemctl enable openvpn@tun1.service
	if [ "$KERNEL" != "5.4" ]; then
		if [ "$VERSION_ID" != "13" ] && [ "$ID" != "debian" ]; then
			mptcpize enable openvpn@tun0 >/dev/null 2>&1
		fi
	fi
	if [ "$OPENVPN_BONDING" = "yes" ]; then
		systemctl enable openvpn@bonding1.service
		systemctl enable openvpn@bonding2.service
		systemctl enable openvpn@bonding3.service
		systemctl enable openvpn@bonding4.service
		systemctl enable openvpn@bonding5.service
		systemctl enable openvpn@bonding6.service
		systemctl enable openvpn@bonding7.service
		systemctl enable openvpn@bonding8.service
	fi
fi

echo 'Glorytun UDP'
# Install Glorytun UDP
if systemctl -q is-active glorytun-udp@tun0.service 2>/dev/null; then
	systemctl -q stop 'glorytun-udp@*' > /dev/null 2>&1
fi
if [ "$GLORYTUN_UDP" = "yes" ]; then
	if [ "$SOURCES" = "yes" ]; then
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		rm -f /usr/bin/glorytun
		apt-get install -y --no-install-recommends build-essential git ca-certificates meson pkg-config
		rm -rf /tmp/glorytun-udp
		cd /tmp
		git clone https://github.com/Ysurac/glorytun.git /tmp/glorytun-udp
		cd /tmp/glorytun-udp
		git checkout ${GLORYTUN_UDP_VERSION}
		git submodule update --init --recursive
		meson build
		ninja -C build install
		sed -i 's:EmitDNS=yes:EmitDNS=no:g' /lib/systemd/network/glorytun.network || true
		rm -f /lib/systemd/system/glorytun*
		rm -f /lib/systemd/network/glorytun*
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /usr/local/bin/glorytun-udp-run ${VPSURL}${VPSPATH}/glorytun-udp-run
		else
			cp ${DIR}/glorytun-udp-run /usr/local/bin/glorytun-udp-run
		fi
		chmod 755 /usr/local/bin/glorytun-udp-run
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /lib/systemd/system/glorytun-udp@.service ${VPSURL}${VPSPATH}/glorytun-udp%40.service.in
		else
			cp ${DIR}/glorytun-udp@.service.in /lib/systemd/system/glorytun-udp@.service
		fi
		chmod 644 /lib/systemd/system/glorytun-udp@.service
		#wget -O /lib/systemd/network/glorytun-udp.network ${VPSURL}${VPSPATH}/glorytun-udp.network
		rm -f /lib/systemd/network/glorytun-udp.network
		mkdir -p /etc/glorytun-udp
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /etc/glorytun-udp/post.sh ${VPSURL}${VPSPATH}/glorytun-udp-post.sh
			wget -O /etc/glorytun-udp/tun0 ${VPSURL}${VPSPATH}/tun0.glorytun-udp
		else
			cp ${DIR}/glorytun-udp-post.sh /etc/glorytun-udp/post.sh
			cp ${DIR}/tun0.glorytun-udp /etc/glorytun-udp/tun0
		fi
		chmod 755 /etc/glorytun-udp/post.sh
		if [ "$update" = "0" ] || [ ! -f /etc/glorytun-udp/tun0.key ]; then
			echo "$GLORYTUN_PASS" > /etc/glorytun-udp/tun0.key
		elif [ ! -f /etc/glorytun-udp/tun0.key ] && [ -f /etc/glorytun-tcp/tun0.key ]; then
			cp /etc/glorytun-tcp/tun0.key /etc/glorytun-udp/tun0.key
		fi
		systemctl enable glorytun-udp@tun0.service
		systemctl enable systemd-networkd.service
		cd /tmp
		rm -rf /tmp/glorytun-udp
	else
		rm -f /usr/local/bin/glorytun
		apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-overwrite" install --reinstall omr-glorytun=${GLORYTUN_UDP_BINARY_VERSION}
		chmod 644 /lib/systemd/system/glorytun-udp@.service
		GLORYTUN_PASS="$(cat /etc/glorytun-udp/tun0.key | tr -d '\n')"
	fi
	[ "$(ip -6 a 2>/dev/null)" != "" ] && sed -i 's/0.0.0.0/::/g' /etc/glorytun-udp/tun0
fi


# Add chrony for time sync
apt-get install -y chrony
systemctl enable chrony

if [ "$DSVPN" = "yes" ]; then
	echo 'A Dead Simple VPN'
	# Install A Dead Simple VPN
	if systemctl -q is-active dsvpn-server.service 2>/dev/null; then
		systemctl -q disable dsvpn-server > /dev/null 2>&1
		systemctl -q stop dsvpn-server > /dev/null 2>&1
	fi
	if [ "$SOURCES" = "yes" ]; then
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		apt-get install -y --no-install-recommends build-essential git ca-certificates
		rm -rf /tmp/dsvpn
		cd /tmp
		git clone https://github.com/ysurac/dsvpn.git /tmp/dsvpn
		cd /tmp/dsvpn
		git checkout ${DSVPN_VERSION}
		make CFLAGS='-DNO_DEFAULT_ROUTES -DNO_DEFAULT_FIREWALL'
		make install
		rm -f /lib/systemd/system/dsvpn/*
		mkdir -p /etc/dsvpn
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /usr/local/bin/dsvpn-run ${VPSURL}${VPSPATH}/dsvpn-run
			wget -O /lib/systemd/system/dsvpn-server@.service ${VPSURL}${VPSPATH}/dsvpn-server%40.service.in
			wget -O /etc/dsvpn/dsvpn0 ${VPSURL}${VPSPATH}/dsvpn0-config
		else
			cp ${DIR}/dsvpn-run /usr/local/bin/dsvpn-run
			cp ${DIR}/dsvpn-server@.service.in /lib/systemd/system/dsvpn-server@.service
			cp ${DIR}/dsvpn0-config /etc/dsvpn/dsvpn0
		fi
		chmod 755 /usr/local/bin/dsvpn-run
		chmod 644 /lib/systemd/system/dsvpn-server@.service
		if [ -f /etc/dsvpn/dsvpn.key ]; then
			mv /etc/dsvpn/dsvpn.key /etc/dsvpn/dsvpn0.key
		fi
		if [ "$update" = "0" ] || [ ! -f /etc/dsvpn/dsvpn0.key ]; then
			echo "$DSVPN_PASS" > /etc/dsvpn/dsvpn0.key
		fi
		systemctl enable dsvpn-server@dsvpn0.service
		cd /tmp
		rm -rf /tmp/dsvpn
	else
		apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-overwrite" install omr-dsvpn=${DSVPN_BINARY_VERSION}
		chmod 644 /lib/systemd/system/dsvpn-server@.service
		DSVPN_PASS=$(cat /etc/dsvpn/dsvpn0.key | tr -d "\n")
	fi
	if [ -n "$(ip addr | grep -m 1 inet6 2>/dev/null)" ]; then
		sed -i 's/0.0.0.0/::/' /etc/dsvpn/dsvpn0
	fi
	if [ "$KERNEL" != "5.4" ]; then
		mptcpize enable dsvpn-server@dsvpn0 >/dev/null 2>&1
	fi
fi

# Install Glorytun TCP
if systemctl -q is-active glorytun-tcp@tun0.service 2>/dev/null; then
	systemctl -q stop 'glorytun-tcp@*' > /dev/null 2>&1
fi
if [ "$GLORYTUN_TCP" = "yes" ]; then
	echo "Install Glorytun-TCP..."
	if [ "$SOURCES" = "yes" ]; then
		echo "install libsodium..."
		if [ "$ID" = "debian" ]; then
			if [ "$VERSION_ID" = "9" ]; then
				apt -t stretch-backports -y install libsodium-dev
			else
				apt-get -y install libsodium-dev || true
			fi
		elif [ "$ID" = "ubuntu" ]; then
			apt-get -y install libsodium-dev
		fi
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		rm -f /usr/bin/glorytun-tcp
		echo "Install needed build tools..."
		apt-get -y install build-essential pkg-config autoconf automake || true
		rm -rf /tmp/glorytun-0.0.35
		cd /tmp
		if [ "$KERNEL" != "5.4" ]; then
			#wget -O /tmp/glorytun-0.0.35.tar.gz https://github.com/Ysurac/glorytun/archive/refs/heads/tcp.tar.gz
			#if [ "$KERNEL" != "5.4" ]; then
			#	mv /tmp/glorytun-tcp /tmp/glorytun-0.0.35
			#fi
			echo "Clone glorytun"
			git clone https://github.com/Ysurac/glorytun.git glorytun-0.0.35
			cd glorytun-0.0.35
			echo "checkout ${GLORYTUN_TCP_VERSION}"
			git checkout ${GLORYTUN_TCP_VERSION}
		else
			wget -O /tmp/glorytun-0.0.35.tar.gz https://github.com/angt/glorytun/releases/download/v0.0.35/glorytun-0.0.35.tar.gz
			tar xzf glorytun-0.0.35.tar.gz
			cd glorytun-0.0.35
		fi
		if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "13" ]; then
			echo "Patch Glorytun TCP"
			wget https://github.com/Ysurac/openmptcprouter-feeds/raw/refs/heads/develop/glorytun/patches/001-fix-compilation-errors-gcc14.patch
			wget https://github.com/Ysurac/openmptcprouter-feeds/raw/refs/heads/develop/glorytun/patches/002-fix-crypto-aead-pointer-types.patch
			patch -p1 < 001-fix-compilation-errors-gcc14.patch
			patch -p1 < 002-fix-crypto-aead-pointer-types.patch
		fi
		./autogen.sh
		./configure
		make
		cp glorytun /usr/local/bin/glorytun-tcp
		mkdir -p /etc/glorytun-tcp
		if [ "$LOCALFILES" = "no" ]; then
			wget -O /usr/local/bin/glorytun-tcp-run ${VPSURL}${VPSPATH}/glorytun-tcp-run
			wget -O /lib/systemd/system/glorytun-tcp@.service ${VPSURL}${VPSPATH}/glorytun-tcp%40.service.in
			wget -O /etc/glorytun-tcp/post.sh ${VPSURL}${VPSPATH}/glorytun-tcp-post.sh
			wget -O /etc/glorytun-tcp/tun0 ${VPSURL}${VPSPATH}/tun0.glorytun
		else
			cp ${DIR}/glorytun-tcp-run /usr/local/bin/glorytun-tcp-run
			cp ${DIR}/glorytun-tcp@.service.in /lib/systemd/system/glorytun-tcp@.service
			cp ${DIR}/glorytun-tcp-post.sh /etc/glorytun-tcp/post.sh
			cp ${DIR}/tun0.glorytun /etc/glorytun-tcp/tun0
		fi
		chmod 755 /usr/local/bin/glorytun-tcp-run
		chmod 644 /lib/systemd/system/glorytun-tcp@.service
		rm -f /lib/systemd/network/glorytun-tcp.network
		chmod 755 /etc/glorytun-tcp/post.sh
		if [ "$update" = "0" ]; then
			echo "$GLORYTUN_PASS" > /etc/glorytun-tcp/tun0.key
		fi
		systemctl enable glorytun-tcp@tun0.service
		#systemctl enable systemd-networkd.service
		cd /tmp
		rm -rf /tmp/glorytun-0.0.35
	else
		rm -f /usr/local/bin/glorytun-tcp
		apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-overwrite" install --reinstall omr-glorytun-tcp=${GLORYTUN_TCP_BINARY_VERSION}
	fi
	[ "$(ip -6 a)" != "" ] && sed -i 's/0.0.0.0/::/g' /etc/glorytun-tcp/tun0
fi

if [ "$SOFTETHERVPN" = "yes" ]; then
	apt-get -y install softether-vpnserver
	if [ "$KERNEL" != "5.4" ]; then
		mptcpize enable softether-vpnserver >/dev/null 2>&1
	fi
	set +e
	softether_test() {
		# Check if SoftEther VPN is available...
		result=1
		while ! $($@ About >/dev/null 2>&1); do
			sleep 1
			echo -n '.'
		done
		echo "Server ready for configuration..."
	}
	softether_password=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .softethervpn_admin_password | tr -d "\n")
	#echo "softether : $softether_password"
	if [ "$softether_password" = "null" ]; then
		#echo "Generate pass..."
		softether_password=$SOFTETHERVPN_PASS_ADMIN
		softetherrun="vpncmd 127.0.0.1:443 /SERVER /CSV /CMD"
		softether_test "$softetherrun"
		$softetherrun ServerPasswordSet $softether_password
		softetherdefault="vpncmd 127.0.0.1:443 /SERVER /CSV /PASSWORD:$softether_password"
		jq --arg softether_password $softether_password '. + {softethervpn_admin_password: $softether_password}' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp
		mv -f /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp /etc/openmptcprouter-vps-admin/omr-admin-config.json
	else
		softetherdefault="vpncmd 127.0.0.1:65390 /SERVER /CSV /PASSWORD:$softether_password"
	fi

	softherether_user_name=$DEFAULT_USER
	softether_user_password=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.softethervpn | tr -d "\n")
	#echo "softether user : $softether_user_password"
	if [ "$softether_user_password" = "null" ]; then
		#echo "Generate user password"
		softether_user_password=$SOFTETHERVPN_PASS_USER
		jq --arg softether_user_password $softether_user_password '(.users[0].openmptcprouter) += {softethervpn: $softether_user_password}' /etc/openmptcprouter-vps-admin/omr-admin-config.json > /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp
		mv -f /etc/openmptcprouter-vps-admin/omr-admin-config.json.tmp /etc/openmptcprouter-vps-admin/omr-admin-config.json
	fi

	softetherrun="$softetherdefault /CMD"
	softetherhubrun="$softetherdefault /HUB:OMRVPN /CMD"
	softether_test "$softetherrun"

	#echo "$softetherrun ServerPasswordSet $softether_password"
	$softetherrun ServerPasswordSet "$softether_password"
	#echo "$softetherrun HubCreate OMRVPN"
	$softetherrun HubCreate OMRVPN /PASSWORD:"$softether_password"
	#echo "$softetherrun HubDelete DEFAULT"
	$softetherrun HubDelete DEFAULT
	#echo "$softetherrun BridgeCreate OMRVPN /DEVICE:softether /TAP:yes"
	$softetherrun BridgeCreate OMRVPN /DEVICE:softether /TAP:yes
	#echo "$softetherhubrun DHCPSet OMRVPN /START:10.255.210.2 /END:10.255.210.254 /MASK:255.255.255.0 /EXPIRE:7200 /GW:10.255.210.1 /DNS:none /DNS2:none /DOMAIN:none /LOG:yes"
	$softetherhubrun DHCPSet /START:10.255.210.2 /END:10.255.210.254 /MASK:255.255.255.0 /EXPIRE:7200 /GW:10.255.210.1 /DNS:none /DNS2:none /DOMAIN:none /LOG:yes
	#echo "$softetherhubrun DHCPSet OMRVPN DhcpEnable"
	$softetherhubrun DhcpEnable
	#echo "$softetherhubrun SecureNatEnable OMRVPN"
	$softetherhubrun SecureNatEnable
	#echo "$softetherhubrun SecureNatHostSet /IP:10.255.210.1 /MAC:none /MASK:none"
	$softetherhubrun SecureNatHostSet /IP:10.255.210.1 /MAC:none /MASK:none
	#echo "$softetherhubrun NatEnable OMRVPN"
	$softetherhubrun NatEnable
	#echo "$softetherhubrun UserCreate ${softherether_user_name} /GROUP:none /REALNAME:none /NOTE:none"
	$softetherhubrun UserCreate ${softherether_user_name} /GROUP:none /REALNAME:none /NOTE:none
	#echo "$softetherhubrun UserPasswordSet ${softherether_user_name} /PASSWORD:${softether_user_password}"
	$softetherhubrun UserPasswordSet ${softherether_user_name} /PASSWORD:${softether_user_password}
	#echo "$softetherhubrun ListenerCreate OMRVPN 65390"
	$softetherhubrun ListenerCreate 65390
	$softetherhubrun ListenerEnable 65390
	softetherdefault="vpncmd 127.0.0.1:65390 /SERVER /CSV /PASSWORD:$softether_password"
	softetherhubrun="$softetherdefault /HUB:OMRVPN /CMD"
	$softetherhubrun ListenerDisable 443
	$softetherhubrun ListenerDisable 992
	$softetherhubrun ListenerDisable 1194
	$softetherhubrun ListenerDisable 5555
	$softetherhubrun PortsUDPSet 0
	set -e
fi

# Load tun module at boot time
if ! grep -q tun /etc/modules ; then
	echo tun >> /etc/modules
fi

# Add multipath utility
if [ "$LOCALFILES" = "no" ]; then
	wget -O /usr/local/bin/multipath ${VPSURL}${VPSPATH}/multipath
else
	cp ${DIR}/multipath /usr/local/bin/multipath
fi
chmod 755 /usr/local/bin/multipath

# Add omr-test-speed utility
if [ "$LOCALFILES" = "no" ]; then
	wget -O /usr/local/bin/omr-test-speed ${VPSURL}${VPSPATH}/omr-test-speed
else
	cp ${DIR}/omr-test-speed /usr/local/bin/omr-test-speed
fi
chmod 755 /usr/local/bin/omr-test-speed

# Add OpenMPTCProuter service
if [ "$LOCALFILES" = "no" ]; then
	wget -O /usr/local/bin/omr-service ${VPSURL}${VPSPATH}/omr-service
	wget -O /lib/systemd/system/omr.service ${VPSURL}${VPSPATH}/omr.service.in
	wget -O /usr/local/bin/omr-6in4-run ${VPSURL}${VPSPATH}/omr-6in4-run
	wget -O /lib/systemd/system/omr6in4@.service ${VPSURL}${VPSPATH}/omr6in4%40.service.in
	wget -O /usr/local/bin/omr-bypass ${VPSURL}${VPSPATH}/omr-bypass
	wget -O /lib/systemd/system/omr-bypass.service ${VPSURL}${VPSPATH}/omr-bypass.service.in
	wget -O /lib/systemd/system/omr-bypass.timer ${VPSURL}${VPSPATH}/omr-bypass.timer.in
else
	cp ${DIR}/omr-service /usr/local/bin/omr-service
	cp ${DIR}/omr.service.in /lib/systemd/system/omr.service
	cp ${DIR}/omr-6in4-run /usr/local/bin/omr-6in4-run
	cp ${DIR}/omr6in4@.service.in /lib/systemd/system/omr6in4@.service
	cp ${DIR}/omr-bypass /usr/local/bin/omr-bypass
	cp ${DIR}/omr-bypass.service.in /lib/systemd/system/omr-bypass.service
	cp ${DIR}/omr-bypass.timer.in /lib/systemd/system/omr-bypass.timer

fi
chmod 644 /lib/systemd/system/omr.service
chmod 644 /lib/systemd/system/omr6in4@.service
chmod 755 /usr/local/bin/omr-service
chmod 755 /usr/local/bin/omr-bypass
chmod 755 /usr/local/bin/omr-6in4-run
chmod 644 /lib/systemd/system/omr-bypass.service
chmod 644 /lib/systemd/system/omr-bypass.timer
systemctl daemon-reload
if systemctl -q is-active omr-6in4.service 2>/dev/null; then
	systemctl -q stop omr-6in4 > /dev/null 2>&1
	systemctl -q disable omr-6in4 > /dev/null 2>&1
fi
systemctl enable omr6in4@user0.service
systemctl enable omr.service
systemctl enable omr-bypass.timer
systemctl enable omr-bypass.service

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
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /etc/shorewall/openmptcprouter-shorewall.tar.gz ${VPSURL}${VPSPATH}/openmptcprouter-shorewall.tar.gz
	else
		cp ${DIR}/openmptcprouter-shorewall.tar.gz /etc/shorewall/openmptcprouter-shorewall.tar.gz
	fi
	tar xzf /etc/shorewall/openmptcprouter-shorewall.tar.gz -C /etc/shorewall
	rm /etc/shorewall/openmptcprouter-shorewall.tar.gz
	if [ -n "$INTERFACE" ]; then
		sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
		systemctl enable shorewall
	fi
	if [ "$LOCALFILES" = "no" ]; then
		wget -O /etc/shorewall6/openmptcprouter-shorewall6.tar.gz ${VPSURL}${VPSPATH}/openmptcprouter-shorewall6.tar.gz
	else
		cp ${DIR}/openmptcprouter-shorewall6.tar.gz /etc/shorewall6/openmptcprouter-shorewall6.tar.gz
	fi
	tar xzf /etc/shorewall6/openmptcprouter-shorewall6.tar.gz -C /etc/shorewall6
	rm /etc/shorewall6/openmptcprouter-shorewall6.tar.gz
	if [ -n "$INTERFACE6" ]; then
		sed -i "s:eth0:$INTERFACE6:g" /etc/shorewall6/*
		systemctl enable shorewall6
	fi
else
	# Update only needed firewall files
	if [ "$LOCALFILES" = "no" ]; then
		mkdir -p ${DIR}
		wget -O ${DIR}/openmptcprouter-shorewall.tar.gz ${VPSURL}${VPSPATH}/openmptcprouter-shorewall.tar.gz
		wget -O ${DIR}/openmptcprouter-shorewall6.tar.gz ${VPSURL}${VPSPATH}/openmptcprouter-shorewall6.tar.gz
		mkdir -p ${DIR}/shorewall4
		tar xzvf ${DIR}/openmptcprouter-shorewall.tar.gz -C ${DIR}/shorewall4
		mkdir -p ${DIR}/shorewall6
		tar xzvf ${DIR}/openmptcprouter-shorewall6.tar.gz -C ${DIR}/shorewall6
	fi
	cp ${DIR}/shorewall4/interfaces /etc/shorewall/interfaces
	cp ${DIR}/shorewall4/snat /etc/shorewall/snat
	cp ${DIR}/shorewall4/stoppedrules /etc/shorewall/stoppedrules
	cp ${DIR}/shorewall4/tcinterfaces /etc/shorewall/tcinterfaces
	cp ${DIR}/shorewall4/shorewall.conf /etc/shorewall/shorewall.conf
	cp ${DIR}/shorewall4/policy /etc/shorewall/policy
	cp ${DIR}/shorewall4/params /etc/shorewall/params
	cp ${DIR}/shorewall4/zones /etc/shorewall/zones
	#cp ${DIR}/shorewall4/params.vpn /etc/shorewall/params.vpn
	#cp ${DIR}/shorewall4/params.net /etc/shorewall/params.net
	cp ${DIR}/shorewall6/params /etc/shorewall6/params
	#cp ${DIR}/shorewall6/params.net /etc/shorewall6/params.net
	#cp ${DIR}/shorewall6/params.vpn /etc/shorewall6/params.vpn
	cp ${DIR}/shorewall6/interfaces /etc/shorewall6/interfaces
	cp ${DIR}/shorewall6/stoppedrules /etc/shorewall6/stoppedrules
	cp ${DIR}/shorewall6/snat /etc/shorewall6/snat
	sed -i "s:eth0:$INTERFACE:g" /etc/shorewall/*
	sed -i 's/^.*#DNAT/#DNAT/g' /etc/shorewall/rules
	sed -i 's:10.0.0.2:$OMR_ADDR:g' /etc/shorewall/rules
	sed -i "s:eth0:$INTERFACE6:g" /etc/shorewall6/*
	if [ "$LOCALFILES" = "no" ]; then
		rm -rf ${DIR}/shorewall4
		rm -rf ${DIR}/shorewall6
		rm -f ${DIR}/openmptcprouter-shorewall.tar.gz
		rm -f ${DIR}/openmptcprouter-shorewall6.tar.gz
	fi
	if [ -f /etc/shorewall/params.vpn ]; then
		awk '!seen[$0]++' /etc/shorewall/params.vpn > params.vpn.new
		mv -f params.vpn.new params.vpn
	fi
fi
[ -z "$(grep nf_conntrack_sip /etc/modprobe.d/blacklist.conf)" ] && echo 'blacklist nf_conntrack_sip' >> /etc/modprobe.d/blacklist.conf
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ]; then
	apt-get -y install iptables
	update-alternatives --set iptables /usr/sbin/iptables-legacy
	update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
fi
if ([ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ]) || ([ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "19.04" ]) || ([ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "20.04" ]); then
	sed -i 's:DROP_DEFAULT=Drop:DROP_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall/shorewall.conf
	sed -i 's:REJECT_DEFAULT=Reject:REJECT_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall/shorewall.conf
	sed -i 's:DROP_DEFAULT=Drop:DROP_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall6/shorewall6.conf
	sed -i 's:REJECT_DEFAULT=Reject:REJECT_DEFAULT="Broadcast(DROP),Multicast(DROP)":g' /etc/shorewall6/shorewall6.conf
fi
if [ "$(ip r | awk '/default/&&/src/ {print $7}')" != "" ] && [ "$(ip r | awk '/default/&&/src/ {print $7}')" != "dhcp" ]; then
	sed -i "s/MASQUERADE/SNAT($(ip r | awk '/default/&&/src/ {print $7}'))/" /etc/shorewall/snat
fi

# Limit /var/log/journal size
sed -i 's/#SystemMaxUse=/SystemMaxUse=100M/' /etc/systemd/journald.conf

if [ "$TLS" = "yes" ]; then
	VPS_CERT=0
	apt-get -y install socat cron
	if [ "$VPS_DOMAIN" != "" ] && [ "$(getent hosts $VPS_DOMAIN | awk '{ print $1; exit }')" != "" ] && [ "$(ping -c 1 -w 1 $VPS_DOMAIN)" ]; then
		if [ ! -f "/root/.acme.sh/$VPS_DOMAIN/$VPS_DOMAIN.cer" ]; then
			echo "Generate certificate for V2Ray"
			set +e
			#[ "$(shorewall  status | grep stopped)" = "" ] && shorewall open all all tcp 443
			curl https://get.acme.sh | sh
			systemctl -q restart shorewall
			~/.acme.sh/acme.sh --force --alpn --issue -d $VPS_DOMAIN --pre-hook 'shorewall open all all tcp 443 >/dev/null 2>&1' --post-hook 'shorewall close all all tcp 443 >/dev/null 2>&1' >/dev/null 2>&1
			set -e
			if [ -f /root/.acme.sh/$VPS_DOMAIN/$VPS_DOMAIN.cer ]; then
				rm -f /etc/openmptcprouter-vps-admin/cert.pem
				ln -s /root/.acme.sh/$VPS_DOMAIN/$VPS_DOMAIN.cer /etc/openmptcprouter-vps-admin/cert.pem
				rm -f /etc/openmptcprouter-vps-admin/key.pem
				ln -s /root/.acme.sh/$VPS_DOMAIN/$VPS_DOMAIN.key /etc/openmptcprouter-vps-admin/key.pem
			fi
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

if [ "$SPEEDTEST" = "yes" ]; then
	mkdir -p /usr/share/omr-server/speedtest
	if [ ! -f /usr/share/omr-server/speedtest/test.img ] && [ "$(df /usr/share/omr-server/speedtest | awk '/[0-9]%/{print $(NF-2)}')" -gt 2000000 ]; then
		echo "Generate speedtest image..."
		dd if=/dev/urandom of=/usr/share/omr-server/speedtest/test.img count=1024 bs=1048576
		echo "Done"
	fi
fi

# Add OpenMPTCProuter VPS script version to /etc/motd
if [ -f /etc/motd.head ]; then
	if grep --quiet 'OpenMPTCProuter VPS' /etc/motd.head; then
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-test[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd.head
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-rolling[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd.head
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-rolling-test[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd.head
		sed -i "s:< OpenMPTCProuter VPS \$OMR_VERSION >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd.head
	else
		echo "< OpenMPTCProuter VPS $OMR_VERSION >" >> /etc/motd.head
	fi
elif [ -f /etc/motd ]; then
	if grep --quiet 'OpenMPTCProuter VPS' /etc/motd; then
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-test[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-rolling[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd
		sed -i "s:< OpenMPTCProuter VPS [0-9]*\.[0-9]*\(\|-rolling-test[0-9]*\) >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd
		sed -i "s:< OpenMPTCProuter VPS \$OMR_VERSION >:< OpenMPTCProuter VPS $OMR_VERSION >:g" /etc/motd
	else
		echo "< OpenMPTCProuter VPS $OMR_VERSION >" >> /etc/motd
	fi
else
	echo "< OpenMPTCProuter VPS $OMR_VERSION >" > /etc/motd
fi

if [ "$SOURCES" != "yes" ]; then
	apt-get -y install omr-server=${OMR_VERSION} >/dev/null 2>&1 || true
	rm -f /etc/openmtpcprouter-vps-admin/update-bin
fi

if [ "$update" = "0" ]; then
	# Display important info
	echo '===================================================================================='
	echo "OpenMPTCProuter Server $OMR_VERSION is now installed !"
	echo '\033[1m SSH port: 65222 (instead of port 22)\033[0m'
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
	echo 'Your shadowsocks 2022 key: '
	echo "${PSK}:${UPSK}"
	echo 'Glorytun port: 65001'
	echo 'Glorytun encryption: chacha20'
	echo 'Your glorytun key: '
	echo $GLORYTUN_PASS
	if [ "$DSVPN" = "yes" ]; then
		echo 'A Dead Simple VPN port: 65401'
		echo 'A Dead Simple VPN key: '
		echo $DSVPN_PASS
	fi
	if [ "$MLVPN" = "yes" ]; then
		echo 'MLVPN first port: 65201'
		echo 'Your MLVPN password: '
		echo $MLVPN_PASS
	fi
	if [ "$UBOND" = "yes" ]; then
		echo 'UBOND first port: 65251'
		echo 'Your UBOND password: '
		echo $UBOND_PASS
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		echo "OpenMPTCProuter API Admin key (only for configuration via API, you don't need it): "
		echo $OMR_ADMIN_PASS_ADMIN
		echo 'OpenMPTCProuter Server key: '
		echo "\033[1m${OMR_ADMIN_PASS}\033[0m"
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
	echo '\033[1m  /!\ You need to reboot to enable MPTCP, shadowsocks, glorytun and shorewall /!\ \033[0m'
	echo '------------------------------------------------------------------------------------'
	echo ' For kernel 5.4, after reboot, check with uname -a that the kernel name contain mptcp.'
	echo ' Else, you may have to modify GRUB_DEFAULT in /etc/default/grub'
	echo ' For 6.x kernels, check that a 6.x kernel is used, no kernel name changes.'
	echo '===================================================================================='

	# Save info in file
	cat > /root/openmptcprouter_config.txt <<-EOF
	SSH port: 65222 (instead of port 22)
	EOF
	if [ "$SHADOWSOCKS" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		Shadowsocks port: 65101
		Shadowsocks encryption: chacha20
		Your shadowsocks key: ${SHADOWSOCKS_PASS}
		EOF
	fi
	if [ "$SHADOWSOCKS_GO" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		Your shadowsocks 2022 key: ${PSK}:${UPSK}
		EOF
	fi
	if ([ "$GLORYTUN_TCP" = "yes" ] || [ "$GLORYTUN_UDP" = "yes" ]); then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		Glorytun port: 65001
		Glorytun encryption: chacha20
		Your glorytun key: ${GLORYTUN_PASS}
		EOF
	fi
	if [ "$DSVPN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		A Dead Simple VPN port: 65401
		A Dead Simple VPN key: ${DSVPN_PASS}
		EOF
	fi
	if [ "$MLVPN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		MLVPN first port: 65201
		Your MLVPN password: $MLVPN_PASS
		EOF
	fi
	if [ "$UBOND" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		UBOND first port: 65251
		Your UBOND password: $UBOND_PASS
		EOF
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		Your OpenMPTCProuter ADMIN API Server key (only for configuration via API access, you don't need it): $OMR_ADMIN_PASS_ADMIN
		Your OpenMPTCProuter Server key: $OMR_ADMIN_PASS
		Your OpenMPTCProuter Server username: openmptcprouter
		EOF
	fi
	#systemctl -q restart sshd
else
	echo '===================================================================================='
	echo "OpenMPTCProuter Server is now updated to version $OMR_VERSION !"
	echo 'Keys are not changed, shorewall rules files preserved'
	echo 'You need OpenMPTCProuter >= 0.30'
	echo '===================================================================================='
	echo 'Restarting systemd daemon...'
	systemctl -q daemon-reload
	echo 'done'
	echo 'Restarting systemd network...'
	systemctl -q restart systemd-networkd
	echo 'done'
	if [ "$MLVPN" = "yes" ]; then
		echo 'Restarting mlvpn...'
		systemctl -q restart mlvpn@mlvpn0
		echo 'done'
	fi
	if [ "$UBOND" = "yes" ]; then
		echo 'Restarting ubond...'
		systemctl -q restart ubond@ubond0
		echo 'done'
	fi
	if [ "$V2RAY" = "yes" ]; then
		echo 'Restarting v2ray...'
		systemctl -q restart v2ray
		echo 'done'
	fi
	if [ "$XRAY" = "yes" ]; then
		echo 'Restarting xray...'
		systemctl -q restart xray
		echo 'done'
	fi
	if [ "$DSVPN" = "yes" ]; then
		echo 'Restarting dsvpn...'
		systemctl -q start dsvpn-server@dsvpn0 || true
		systemctl -q restart 'dsvpn-server@*' || true
		echo 'done'
	fi
	if [ "$GLORYTUN_TCP" = "yes" ]; then
		echo 'Restarting glorytun tcp...'
		systemctl -q start glorytun-tcp@tun0 || true
		systemctl -q restart 'glorytun-tcp@*' || true
	fi
	if [ "$GLORYTUN_UDP" = "yes" ]; then
		systemctl -q start glorytun-udp@tun0 || true
		systemctl -q restart 'glorytun-udp@*' || true
		echo 'done'
	fi
	echo 'Restarting omr6in4...'
	systemctl -q start omr6in4@user0 || true
	systemctl -q restart omr6in4@* || true
	echo 'done'
	if [ "$OPENVPN" = "yes" ]; then
		echo 'Restarting OpenVPN'
		systemctl -q restart openvpn@tun0
		systemctl -q restart openvpn@tun1
		echo 'done'
	fi
	if [ "$WIREGUARD" = "yes" ]; then
		echo 'Restarting WireGuard'
		systemctl -q restart wg-quick@wg0
		echo 'done'
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		echo 'Restarting OpenMPTCProuter VPS admin'
		systemctl -q restart omr-admin
		echo 'done'
		if ! grep -q 'Server key' /root/openmptcprouter_config.txt ; then
			cat >> /root/openmptcprouter_config.txt <<-EOF
			Your OpenMPTCProuter Server key: $OMR_ADMIN_PASS
			Your OpenMPTCProuter Server username: openmptcprouter
			EOF
			echo '===================================================================================='
			echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
			echo 'OpenMPTCProuter Server key:'
			echo $OMR_ADMIN_PASS
			echo 'OpenMPTCProuter Server username:'
			echo 'openmptcprouter'
			echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
			echo '===================================================================================='
		else
			echo '!!! Keys are in /root/openmptcprouter_config.txt !!!'
		fi
	fi
	if [ "$VPS_CERT" = "0" ]; then
		echo 'No working domain detected, not able to generate certificate for v2ray.'
		echo 'You can set VPS_DOMAIN to a working domain if you want a certificate.'
	fi
	echo 'Apply latest sysctl...'
	sysctl -p /etc/sysctl.d/90-shadowsocks.conf > /dev/null 2>&1 || true
	echo 'done'
	echo 'Restarting omr...'
	systemctl -q restart omr
	echo 'done'
	if [ "$SHADOWSOCKS" = "yes" ]; then
		echo 'Restarting shadowsocks...'
		systemctl -q restart shadowsocks-libev-manager@manager
	fi
	if [ "$SHADOWSOCKS_GO" = "yes" ]; then
		echo 'Restarting shadowsocks-go...'
		systemctl -q restart shadowsocks-go
	fi
#	if [ $NBCPU -gt 1 ]; then
#		for i in $NBCPU; do
#			systemctl restart shadowsocks-libev-server@config$i
#		done
#	fi
	echo 'done'
	echo 'Restarting shorewall...'
	[ -n "$INTERFACE" ] && systemctl -q restart shorewall >/dev/null 2>&1 || true
	[ -n "$INTERFACE6" ] && systemctl -q restart shorewall6 >/dev/null 2>&1 || true
	echo 'done'
	echo '===================================================================================='
	echo '\033[1m  /!\ You need to reboot to use latest MPTCP kernel /!\ \033[0m'
	echo '===================================================================================='
fi
exit 0