#!/bin/sh
#
# Copyright (C) 2018-2026 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
#
# This is free software, licensed under the GNU General Public License v3 or later.
# See /LICENSE for more information.
#

KERNEL=${KERNEL:-6.18}
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
MQVPN_KEY=${MQVPN_KEY:-$(head -c 32 /dev/urandom | base64 -w0)}
UPDATE_OS=${UPDATE_OS:-yes}
FORCE_UPDATE_OS=${FORCE_UPDATE_OS:-yes}
UPDATE=${UPDATE:-yes}
TLS=${TLS:-yes}
OMR_ADMIN=${OMR_ADMIN:-yes}
OMR_ADMIN_PASS=${OMR_ADMIN_PASS:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
OMR_ADMIN_PASS_ADMIN=${OMR_ADMIN_PASS_ADMIN:-$(od -vN "32" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
OMR_METRICS=${OMR_METRICS:-no}
OMR_AI=${OMR_AI:-no}
MLVPN=${MLVPN:-yes}
MLVPN_PASS=${MLVPN_PASS:-$(head -c 32 /dev/urandom | base64 -w0)}
MQVPN=${MQVPN:-yes}
OPENVPN=${OPENVPN:-yes}
OPENVPN_BONDING=${OPENVPN_BONDING:-yes}
SOFTETHERVPN=${SOFTETHERVPN:-no}
SOFTETHERVPN_PASS_ADMIN=${SOFTETHERVPN_PASS_ADMIN:-$(od -vN "16" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
SOFTETHERVPN_PASS_USER=${SOFTETHERVPN_PASS_USER:-$(od -vN "16" -An -tx1 /dev/urandom | tr '[:lower:]' '[:upper:]' | tr -d " \n")}
DSVPN=${DSVPN:-yes}
WIREGUARD=${WIREGUARD:-yes}
FAIL2BAN=${FAIL2BAN:-yes}
BPFTUNE=${BPFTUNE:-no}
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
MPTCP_BPF_VERSION="1.3-1"
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
OBFS_VERSION="486bebd9208539058e57e23a12f23103016e09b4"
OBFS_BINARY_VERSION="0.0.5-1"
OMR_ADMIN_VERSION="27ddda7f6636d2b4869238b41a30d2bc65892783"
OMR_ADMIN_BINARY_VERSION="0.18+20261009"
DSVPN_VERSION="3b99d2ef6c02b2ef68b5784bec8adfdd55b29b1a"
DSVPN_BINARY_VERSION="0.1.4-2"
MQVPN_VERSION="0.17.0-1"
V2RAY_VERSION="5.32.0"
V2RAY_PLUGIN_VERSION="4.43.0"
XRAY_VERSION="26.7.11"
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
# Both come over plain HTTP and end up in acme.sh's arguments and in the
# WireGuard client config: only a host name and an IPv4 address are kept
printf '%s' "$VPS_DOMAIN" | grep -Eqx '[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+' || VPS_DOMAIN=""
printf '%s' "$VPS_PUBLIC_IP" | grep -Eqx '([0-9]{1,3}\.){3}[0-9]{1,3}' || VPS_PUBLIC_IP=""
VPSURL="https://www.openmptcprouter.com/"
REPO="repo.openmptcprouter.com"
CHINA=${CHINA:-no}

OMR_VERSION="0.1089-rolling-test"

DIR=$( pwd )
#"
set -e
# Tells the omr-server postinst that this script is already running. That
# postinst arms an omr-update run (which runs this script), and the
# "apt-get -y install omr-server" at the end of this script is one of the
# things that calls it -- without this, a fresh install would start a second
# run of itself on top of the first. /run is a tmpfs, so a lock left behind by
# a killed run is gone at the next boot.
OMR_INSTALL_LOCK=/run/omr-install.running
touch "$OMR_INSTALL_LOCK" 2>/dev/null || true
trap 'rm -f "$OMR_INSTALL_LOCK"' EXIT INT TERM
umask 0022
export LC_ALL=C
export PATH=$PATH:/sbin
export DEBIAN_FRONTEND=noninteractive

harden_secret_files() {
	for f in "$@"; do
		if [ -e "$f" ]; then
			chown root:root "$f" 2>/dev/null || true
			chmod 0600 "$f" 2>/dev/null || true
		fi
	done
}

# Rewrite a JSON file in place with jq: jq_rewrite FILE [jq options] FILTER
# `jq ... FILE > FILE.tmp; mv FILE.tmp FILE` replaced FILE with an empty file
# whenever jq failed (unparsable file, bad filter) and the script was not
# stopped by set -e, e.g. in the SoftEther part: an empty
# omr-admin-config.json makes omr-admin crash-loop. And the temp copy of these
# secret-bearing files was written with the default umask, world-readable.
# Only replace FILE when jq succeeded and produced output, write the temp copy
# owner-only and give it FILE's mode. Returns 1 (FILE unchanged) on failure.
jq_rewrite() {
	_jq_file="$1"
	shift
	_jq_tmp="$_jq_file.tmp.$$"
	if (umask 077 && jq "$@" "$_jq_file" > "$_jq_tmp") && [ -s "$_jq_tmp" ]; then
		chmod --reference="$_jq_file" "$_jq_tmp" 2>/dev/null || true
		mv -f "$_jq_tmp" "$_jq_file"
	else
		rm -f "$_jq_tmp"
		echo "Error: could not update $_jq_file with jq, left unchanged" >&2
		return 1
	fi
}

# Download a file of this repository into place: fetch_file URL DEST
# wget -O empties DEST before the download, so a failed one left it empty --
# an empty nftables.conf or omr.nft is a VPS with no firewall at the next boot.
# DEST is only replaced by a complete, non-empty download; returns 1 otherwise.
fetch_file() {
	_fetch_tmp="$2.tmp.$$"
	if wget -O "$_fetch_tmp" "$1" && [ -s "$_fetch_tmp" ]; then
		mv -f "$_fetch_tmp" "$2"
	else
		rm -f "$_fetch_tmp"
		echo "Error: could not download $1, $2 left unchanged" >&2
		return 1
	fi
}

# Install what the omr-vps-admin deb ships (omradmin.py, the config template,
# the unit) from the OMR_ADMIN_VERSION commit on GitHub: the deb pinned by
# OMR_ADMIN_BINARY_VERSION is not published yet when the pin is bumped here
# before the upload. Its dependencies are installed above it in the script.
# Called as an `if` condition, so set -e is off: every step is chained.
# Returns 1 when the archive could not be fetched or is incomplete.
omr_admin_from_github() {
	_admin_tmp=$(mktemp -d) || return 1
	_admin_src="$_admin_tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}"
	if wget -O "$_admin_tmp/admin.zip" "https://github.com/Ysurac/openmptcprouter-vps-admin/archive/${OMR_ADMIN_VERSION}.zip" &&
		unzip -q -o "$_admin_tmp/admin.zip" -d "$_admin_tmp" &&
		[ -s "$_admin_src/omradmin.py" ] && [ -s "$_admin_src/omr-admin-config.json" ] && [ -s "$_admin_src/debian/omr-admin.service" ] &&
		mkdir -p /usr/share/omr-admin &&
		install -m 0755 "$_admin_src/omradmin.py" /usr/bin/omradmin.py &&
		install -m 0644 "$_admin_src/omr-admin-config.json" /usr/share/omr-admin/omr-admin-config.json &&
		install -m 0644 "$_admin_src/debian/omr-admin.service" /lib/systemd/system/omr-admin.service; then
		rm -rf "$_admin_tmp"
		return 0
	fi
	rm -rf "$_admin_tmp"
	echo "Error: could not install omr-admin ${OMR_ADMIN_VERSION} from GitHub" >&2
	return 1
}

# Restart units at the end of an update. One that fails to restart is
# reported, not fatal: under set -e it ended the script there, before the
# nftables ruleset rewritten above was loaded and omr-admin resynced its chains.
restart_or_warn() {
	systemctl -q restart "$@" || echo "WARNING: restarting $* failed, see journalctl -u $1" >&2
}

# Self-signed certificate of the OMR API and of MQVPN
OMR_CERT_SUBJ="/C=US/ST=Oregon/L=Portland/O=OpenMPTCProuterVPS/OU=Org/CN=www.openmptcprouter.vps"
OMR_CERT_SAN="subjectAltName=DNS:www.openmptcprouter.vps"
omr_self_signed_cert() {
	_cert_key="$1"
	_cert_crt="$2"
	[ -L "$_cert_crt" ] && return 0
	if [ ! -f "$_cert_key" ]; then
		openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout "$_cert_key" -out "$_cert_crt" -subj "$OMR_CERT_SUBJ" -addext "$OMR_CERT_SAN" 2>/dev/null ||
			openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout "$_cert_key" -out "$_cert_crt" -subj "$OMR_CERT_SUBJ"
	elif [ ! -f "$_cert_crt" ] || ! openssl x509 -in "$_cert_crt" -noout -text 2>/dev/null | grep -q 'X509v3 Subject Alternative Name'; then
		_cert_new="$_cert_crt.new.$$"
		if openssl req -new -x509 -days 3650 -key "$_cert_key" -out "$_cert_new" -subj "$OMR_CERT_SUBJ" -addext "$OMR_CERT_SAN" 2>/dev/null ||
			{ [ ! -f "$_cert_crt" ] && openssl req -new -x509 -days 3650 -key "$_cert_key" -out "$_cert_new" -subj "$OMR_CERT_SUBJ"; }; then
			mv -f "$_cert_new" "$_cert_crt"
		else
			rm -f "$_cert_new"
		fi
	fi
}

# The pin a router keeps for this server (openmptcprouter.<server>.api_pin, curl
# --pinnedpubkey): base64 SHA-256 of the API certificate's public key, the
# certificate being $1 (default the API one). Nothing when there is none yet.
omr_api_pin() {
	_pin_crt="${1:-/etc/openmptcprouter-vps-admin/cert.pem}"
	[ -f "$_pin_crt" ] || return 0
	_pin_pubkey="$(openssl x509 -in "$_pin_crt" -pubkey -noout 2>/dev/null)" || return 0
	[ -n "$_pin_pubkey" ] || return 0
	printf '%s\n' "$_pin_pubkey" | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
}
# Routers that already pinned this server must be told when that key changes
# (acme.sh replacing the self-signed certificate, a lost key.pem).
OMR_API_PIN_BEFORE="$(omr_api_pin)"

echo "Check user..."
if [ "$(id -u)" -ne 0 ]; then echo 'Please run as root.' >&2; exit 1; fi

# Check Kernel
if [ "$KERNEL" != "5.4" ] && [ "$KERNEL" != "6.1" ] && [ "$KERNEL" != "6.6" ] && [ "$KERNEL" != "6.10" ] && [ "$KERNEL" != "6.11" ] && [ "$KERNEL" != "6.12" ] && [ "$KERNEL" != "6.18" ]; then
	echo "Only kernels 5.4, 6.1, 6.6, 6.10, 6.11, 6.12  and 6.18 are currently supported"
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

echo "Check virtualized environment"
VIRT="$(systemd-detect-virt 2>/dev/null || true)"
IS_CONTAINER="no"
if [ -n "$VIRT" ] && ([ "$VIRT" = "openvz" ] || [ "$VIRT" = "lxc" ] || [ "$VIRT" = "docker" ] || [ "$VIRT" = "podman" ] || [ "$VIRT" = "container-other" ]); then
	IS_CONTAINER="yes"
fi
if [ "$KERNEL" = "5.4" ] || [ "$KERNEL" = "5.15" ]; then
	if [ -z "$(uname -a | grep mptcp)" ] && [ "$IS_CONTAINER" = "yes" ]; then
		echo "Container detected: kernel can't be modified."
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
	# Nothing to do, and that is a success: this is the normal end of an
	# omr-update run on a VPS already at this version, and omr-update now
	# keeps its update-bin flag for a retry when this script exits non-zero.
	echo "This VPS already runs $OMR_VERSION, nothing to update"
	exit 0
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
	sed -i '/openmptcprouter/d' /etc/apt/sources.list
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
	if [ -f /etc/apt/sources.list.d/debian.sources ]; then
		sed -i 's:archive:deb:g' /etc/apt/sources.list.d/debian.sources
		sed -i 's:bullseye:bookworm:g' /etc/apt/sources.list.d/debian.sources
	elif [ -f /etc/apt/sources.list.d/bullseye.list ]; then
		sed -i 's:archive:deb:g' /etc/apt/sources.list.d/bullseye.list
		sed -i 's:bullseye:bookworm:g' /etc/apt/sources.list.d/bullseye.list
		mv -f /etc/apt/sources.list.d/bullseye.list /etc/apt/sources.list.d/bookworm.list
	fi
	apt-get update --allow-releaseinfo-change
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	VERSION_ID="12"
fi

# Update to Debian 13 only if FORCE_UPDATE_OS is set to yes. No problem to use Debian 12 if not.
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "12" ] && [ "$UPDATE_OS" = "yes" ] && [ "$FORCE_UPDATE_OS" = "yes" ]; then
	echo "Update Debian 12 Bookworm to Debian 13 Trixie"
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades upgrade
	apt-get -y -f --force-yes -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confnew" --allow-downgrades dist-upgrade
	sed -i 's:archive:deb:g' /etc/apt/sources.list
	sed -i 's:bookworm:trixie:g' /etc/apt/sources.list
	sed -i 's|Signed-By: /usr/share/keyrings/debian-deb-keyring.gpg|Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg|g' /etc/apt/sources.list
	if [ -f /etc/apt/sources.list.d/debian.sources ]; then
		sed -i 's:archive:deb:g' /etc/apt/sources.list.d/debian.sources
		sed -i 's:bookworm:trixie:g' /etc/apt/sources.list.d/debian.sources
		sed -i 's|Signed-By: /usr/share/keyrings/debian-deb-keyring.gpg|Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg|g' /etc/apt/sources.list.d/debian.sources
	elif [ -f /etc/apt/sources.list.d/bookworm.list ]; then
		sed -i 's:archive:deb:g' /etc/apt/sources.list.d/bookworm.list
		sed -i 's:bookworm:trixie:g' /etc/apt/sources.list.d/bookworm.list
		mv -f /etc/apt/sources.list.d/bookworm.list /etc/apt/sources.list.d/trixie.list
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
if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "20.04" ] && [ "$UPDATE_OS" = "yes" ]; then
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
	# apt-key is gone from Debian 13; the key is a binary keyring, as is the one
	# the non-China branch puts in trusted.gpg.d
	cp /var/lib/openmptcprouter-vps-debian/openmptcprouter.gpg.key /etc/apt/trusted.gpg.d/openmptcprouter.gpg
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
# nftables belongs in this early list, not only in the firewall section a
# thousand lines below: the omr-vps-admin deb Depends on it, and on a fresh VPS
# that dependency is unsatisfied by the time this script installs it, which
# leaves the package unconfigured and (set -e) ends the whole install
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "13" ]; then
	apt-get -y install dirmngr patch rename curl unzip pkg-config ipset bpftool nftables
else
	apt-get -y install dirmngr patch rename curl libcurl4 unzip pkg-config ipset nftables
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

# Print the path GRUB needs to select the menu entry matching $2 in the
# grub.cfg passed as $1. GRUB resolves "default" against the top level menu
# only: an entry buried in a submenu has to be named as the id (or index) of
# every submenu above it, separated by ">" (see GRUB_DEFAULT in grub.info).
# grub-mkconfig keeps only the highest version kernel at the top level and
# puts every other one under "Advanced options", so the bare entry id is
# almost never enough.
grub_menu_entry_path() {
	awk -v pat="$2" '
		function entry_id(l,   k, n, a) {
			k = index(l, "menuentry_id_option")
			if (k == 0)
				return ""
			n = split(substr(l, k), a, q)
			return (n >= 2) ? a[2] : ""
		}
		BEGIN {
			q = sprintf("%c", 39)
			depth = 0
			inentry = 0
			cnt[0] = 0
			npfx[0] = ""
			ipfx[0] = ""
		}
		{
			line = $0
			sub(/^[ \t]+/, "", line)
			if (!inentry && line ~ /^submenu[ \t]/) {
				id = entry_id(line)
				num = npfx[depth] cnt[depth]
				ids = (id == "") ? "" : ipfx[depth] id
				cnt[depth]++
				depth++
				cnt[depth] = 0
				npfx[depth] = num ">"
				ipfx[depth] = (ids == "") ? "" : ids ">"
				next
			}
			if (!inentry && line ~ /^menuentry[ \t]/) {
				inentry = 1
				if (line ~ pat && line !~ /recovery/) {
					id = entry_id(line)
					if (id != "" && (depth == 0 || ipfx[depth] != ""))
						print ipfx[depth] id
					else
						print npfx[depth] cnt[depth]
					exit
				}
				cnt[depth]++
				next
			}
			if (line ~ /^}/) {
				if (inentry)
					inentry = 0
				else if (depth > 0)
					depth--
			}
		}
	' "$1"
}

set_grub_default_kernel() {
	version="$1"
	name="$2"
	grub_cfg=""
	grub_deflt=""
	entry=""
	# grub.cfg is in /boot/grub on Debian and Ubuntu, /boot/grub2 elsewhere
	grub_cfg="$(find /boot/grub /boot/grub2 -maxdepth 1 -name grub.cfg 2>/dev/null | head -n 1)"
	grub_deflt="$(find /etc/default -maxdepth 1 \( -name grub -o -name grub2 \) 2>/dev/null | head -n 1)"
	if [ -z "$grub_cfg" ] || [ -z "$grub_deflt" ]; then
		echo "WARNING: no GRUB configuration found, can't set kernel ${version} ${name} as the default one" >&2
		echo "WARNING: set the default boot kernel by hand, else this VPS reboots on $(uname -r)" >&2
		return 1
	fi
	# The kernel package postinst already ran update-grub, but regenerate
	# anyway: an interrupted or skipped hook would leave the new kernel out.
	if [ -n "$(which grub-mkconfig)" ] && ! grub-mkconfig -o "$grub_cfg" >/dev/null 2>&1; then
		echo "WARNING: grub-mkconfig failed, ${grub_cfg} may not list kernel ${version} ${name}" >&2
	fi
	entry="$(grub_menu_entry_path "$grub_cfg" "${version}.*${name}")"
	if [ -z "$entry" ]; then
		echo "WARNING: kernel ${version} ${name} not found in ${grub_cfg}, GRUB default left untouched" >&2
		echo "WARNING: set the default boot kernel by hand, else this VPS reboots on $(uname -r)" >&2
		return 1
	fi
	if [ -n "$(grep -m1 '^[[:space:]]*GRUB_DEFAULT=' "$grub_deflt")" ]; then
		sed -i "s@^[[:space:]]*\(GRUB_DEFAULT=\).*@\1\"${entry}\"@" "$grub_deflt"
	else
		echo "GRUB_DEFAULT=\"${entry}\"" >> "$grub_deflt"
	fi
	if [ -n "$(which grub-mkconfig)" ] && ! grub-mkconfig -o "$grub_cfg" >/dev/null 2>&1; then
		echo "WARNING: grub-mkconfig failed, GRUB_DEFAULT=\"${entry}\" is not applied yet: run update-grub" >&2
		return 1
	fi
	echo "GRUB default boot entry is now ${entry}"
}

# Report which kernel the VPS runs and which one it is meant to run. Upstream
# MPTCP is in every mainline kernel since 5.6, so a distribution kernel can
# carry MPTCP too (Debian 13's own 6.12 does): what the OpenMPTCProuter kernel
# adds on top is the MPTCP BPF schedulers (the mptcp-bpf-* packages installed
# for KERNEL=6.18), which load on no other kernel. The out of tree 5.4 kernel
# is the exception, its MPTCP is the multipath-tcp.org fork and no distribution
# kernel has it.
check_running_kernel() {
	expected=""
	running=""
	running="$(uname -r)"
	expected="$(ls -1 /boot/vmlinuz-*-omr /boot/vmlinuz-*-xanmod* /boot/vmlinuz-*-mptcp 2>/dev/null | sed -e 's@.*/vmlinuz-@@' | sort -V | tail -n 1)"
	echo " Running kernel                    : ${running}"
	if [ -z "$expected" ]; then
		echo ' OpenMPTCProuter kernel installed  : none found in /boot'
		echo ' The MPTCP BPF schedulers need the OpenMPTCProuter kernel, they will not load.'
		return 1
	fi
	echo " OpenMPTCProuter kernel installed  : ${expected}"
	if [ "$running" = "$expected" ]; then
		echo ' The OpenMPTCProuter kernel is already running.'
		return 0
	fi
	echo " After the reboot, check with 'uname -r' that ${expected} is running."
	case "$expected" in
		*-mptcp)
			echo ' If it is not, MPTCP, shadowsocks and the VPN can not work: check'
			;;
		*)
			echo ' If it is not, MPTCP itself still works on any 5.6 or later kernel, but'
			echo ' the MPTCP BPF schedulers only load on the OpenMPTCProuter kernel: check'
			;;
	esac
	echo ' GRUB_DEFAULT in /etc/default/grub, run update-grub and reboot again.'
}

if [ "$IS_CONTAINER" = "yes" ]; then
	echo "Container detected: skipping kernel installation."
else
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
			# /tmp is a tmpfs on Debian 13: a kernel .deb left there costs
			# that much RAM until the next reboot (95 MB + 10 MB measured),
			# which on a 1 GB VPS is what makes the apt-get at the end of
			# this script get OOM-killed.
			rm -f /tmp/linux-headers-${KERNEL_RELEASE}_amd64.deb /tmp/linux-image-${KERNEL_RELEASE}_amd64.deb
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
		fetch_file ${VPSURL}${VPSPATH}/update-grub.sh /tmp/update-grub.sh
		cd /tmp
	else
		cd ${DIR}
	fi
	[ -f /boot/grub/grub.cfg ] && [ -z "$(grep ${KERNEL_VERSION}-mptcp /boot/grub/grub.cfg)" ] && [ -n "$(which grub-mkconfig)" ] && grub-mkconfig -o /boot/grub/grub.cfg
	rm -f /etc/grub.d/30_os-prober
	bash update-grub.sh ${KERNEL_VERSION}-mptcp
	bash update-grub.sh ${KERNEL_RELEASE}
	rm -f /tmp/update-grub.sh
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
	# tmpfs /tmp: keeping these costs their size in RAM until a reboot
	rm -f /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
	# By entry, not GRUB_DEFAULT="0": that is the newest kernel, Debian 13's
	# own 6.12 rather than this one
	set_grub_default_kernel "${KERNEL_VERSION}" "${PSABI}-xanmod" || true
elif [ "$KERNEL" = "6.10" ] && [ "$ARCH" = "amd64" ]; then
	# awk command from xanmod website
	PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
	#'
	if [ "$PSABI" = "x64v1" ]; then
		echo "psABI x86-64-v1 not supported by Xanmod kernel 6.10, use an older kernel"
		exit 1
	fi
	KERNEL_VERSION="6.10.2"
	KERNEL_REV="0~20240728.gae7b555"
	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1 source release"
	dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	# tmpfs /tmp: keeping these costs their size in RAM until a reboot
	rm -f /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
	# By entry, not GRUB_DEFAULT="0": that is the newest kernel, Debian 13's
	# own 6.12 rather than this one
	set_grub_default_kernel "${KERNEL_VERSION}" "${PSABI}-xanmod" || true
elif [ "$KERNEL" = "6.11" ] && [ "$ARCH" = "amd64" ]; then
	# awk command from xanmod website
	PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
	#'
	if [ "$PSABI" = "x64v1" ]; then
		echo "psABI x86-64-v1 not supported by Xanmod kernel 6.11, use an older kernel"
		exit 1
	fi
	KERNEL_VERSION="6.11.0"
	KERNEL_REV="0~20240916.g9c60408"
	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1 source release"
	dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	# tmpfs /tmp: keeping these costs their size in RAM until a reboot
	rm -f /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
	# By entry, not GRUB_DEFAULT="0": that is the newest kernel, Debian 13's
	# own 6.12 rather than this one
	set_grub_default_kernel "${KERNEL_VERSION}" "${PSABI}-xanmod" || true
elif [ "$KERNEL" = "6.12" ] && [ "$ARCH" = "amd64" ]; then
	# awk command from xanmod website
	PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
	#'
	if [ "$PSABI" = "x64v4" ]; then
		PSABI="x64v3"
	fi
	KERNEL_VERSION="6.12.67"
	KERNEL_REV="0~20260123.ga077982"
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
	# tmpfs /tmp: keeping these costs their size in RAM until a reboot
	rm -f /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb

#	wget -qO - https://dl.xanmod.org/archive.key | gpg --batch --yes --dearmor -vo /usr/share/keyrings/xanmod-archive-keyring.gpg
#	echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
#	apt-get update
#	apt-get -y install linux-xanmod-lts-x64v3
#	[ -f /etc/default/grub ] && {
#		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
#		if [ -f /boot/grub/grub.cfg ]; then 
#			BOOTNB=$(grep vmlinuz- /boot/grub/grub.cfg | tail -n +2 | grep -n -m 1 xanmod | sed -e 's/:.*//g' | tr -d '\n')
#			[ -n "$BOOTNB" ] && sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"${BOOTNB}\"@" /etc/default/grub >/dev/null 2>&1
#			grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
#		fi
#	}
	# Not fatal: the function printed how to set the default kernel by hand,
	# and a VPS that boots without GRUB (direct kernel, extlinux) has nothing
	# to set. Under set -e a bare call would end the install here.
	set_grub_default_kernel "${KERNEL_VERSION}" "${PSABI}-xanmod" || true
#elif [ "$KERNEL" = "6.18" ] && [ "$ARCH" = "amd64" ]; then
elif [ "$KERNEL" = "6.18" ]; then
	if [ "$ARCH" = "amd64" ]; then
		# awk command from xanmod website
		PSABI=$(awk 'BEGIN { while (!/flags/) if (getline < "/proc/cpuinfo" != 1) exit 1; if (/lm/&&/cmov/&&/cx8/&&/fpu/&&/fxsr/&&/mmx/&&/syscall/&&/sse2/) level = 1; if (level == 1 && /cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/) level = 2; if (level == 2 && /avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/) level = 3; if (level == 3 && /avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/) level = 4; if (level > 0) { print "x64v" level; exit level + 1 }; exit 1;}' | tr -d "\n")
		#'
		if [ "$PSABI" = "x64v4" ]; then
			PSABI="x64v3"
		fi
	else
		PSABI="generic"
	fi

	#KERNEL_VERSION="6.18.31"
	#KERNEL_REV="0~20260516.g54defdf"
	#if [ "$CHINA" = "yes" ]; then
	#	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb https://sourceforge.net/projects/xanmod/files/releases/lts/${KERNEL_VERSION}-xanmod1/${KERNEL_VERSION}-${PSABI}-xanmod1/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb https://sourceforge.net/projects/xanmod/files/releases/lts/${KERNEL_VERSION}-xanmod1/${KERNEL_VERSION}-${PSABI}-xanmod1/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#else
	#	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#fi
	#echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1 source release"
	#dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#set_grub_default_kernel "${KERNEL_VERSION}" "${PSABI}-xanmod"
	KERNEL_VERSION="6.18.41"
	KERNEL_REV="20260730"
	#if [ "$CHINA" = "yes" ]; then
	#	wget -O /tmp/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb https://sourceforge.net/projects/xanmod/files/releases/lts/${KERNEL_VERSION}-xanmod1/${KERNEL_VERSION}-${PSABI}-xanmod1/linux-image-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#	wget -O /tmp/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb https://sourceforge.net/projects/xanmod/files/releases/lts/${KERNEL_VERSION}-xanmod1/${KERNEL_VERSION}-${PSABI}-xanmod1/linux-headers-${KERNEL_VERSION}-${PSABI}-xanmod1_${KERNEL_VERSION}-${PSABI}-xanmod1-${KERNEL_REV}_amd64.deb
	#else
	wget -O /tmp/linux-image-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb ${VPSURL}kernel/linux-image-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb
	if [ "$ARCH" = "amd64" ]; then
		wget -O /tmp/linux-headers-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb ${VPSURL}kernel/linux-headers-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb
	fi
	echo "Install kernel linux-image-${KERNEL_VERSION}-${PSABI}-omr source release"
	if [ "$ARCH" = "amd64" ]; then
		dpkg --force-all -i -B /tmp/linux-headers-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb
	fi
	dpkg --force-all -i -B /tmp/linux-image-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb
	# tmpfs /tmp: keeping these costs their size in RAM until a reboot
	rm -f /tmp/linux-headers-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb /tmp/linux-image-${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${KERNEL_VERSION}-${KERNEL_REV}.${PSABI}-omr_${ARCH}.deb
	set_grub_default_kernel "${KERNEL_VERSION}" "${PSABI}-omr" || true
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
		latestkernel=$(apt-cache search linux-image-unsigned-6.1 | tail -n 1 | cut -d" " -f1)
		[ -n "$latestkernel" ] && apt-get -y install "$latestkernel"
	fi
	[ -f /etc/default/grub ] && {
		sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"0\"@" /etc/default/grub >/dev/null 2>&1
		[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
	}
fi
fi # IS_CONTAINER check

if [ "$KERNEL" = "6.18" ]; then
	
	echo "Install MPTCP BPF schedulers for kernel 6.18..."
	for pkg in mptcp-bpf-bkup mptcp-bpf-burst mptcp-bpf-first mptcp-bpf-red mptcp-bpf-rr mptcp-bpf-dscp mptcp-bpf-weight mptcp-bpf-weight-rr; do
		if ! apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y install ${pkg}=${MPTCP_BPF_VERSION}; then
			wget -O /tmp/${pkg}_${MPTCP_BPF_VERSION}_${ARCH}.deb ${VPSURL}debian/${pkg}_${MPTCP_BPF_VERSION}_${ARCH}.deb
			dpkg --force-confold --force-confdef --force-overwrite -i /tmp/${pkg}_${MPTCP_BPF_VERSION}_${ARCH}.deb
			rm -f /tmp/${pkg}_${MPTCP_BPF_VERSION}_${ARCH}.deb
		fi
	done
	# The managers are arch independent and depend on the exact same version
	# of their scheduler, so they share MPTCP_BPF_VERSION and install after it.
	echo "Install MPTCP BPF DSCP and weight scheduler managers..."
	for pkg in mptcp-dscp-manager mptcp-weight-manager; do
		if ! apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y install ${pkg}=${MPTCP_BPF_VERSION}; then
			wget -O /tmp/${pkg}_${MPTCP_BPF_VERSION}_all.deb ${VPSURL}debian/${pkg}_${MPTCP_BPF_VERSION}_all.deb
			dpkg --force-confold --force-confdef --force-overwrite -i /tmp/${pkg}_${MPTCP_BPF_VERSION}_all.deb
			rm -f /tmp/${pkg}_${MPTCP_BPF_VERSION}_all.deb
		fi
	done
fi

# tracebox is gone: the router runs its own to check a path for MPTCP, nothing
# used the VPS's copy, and on Debian 13 its libevent-2.1-7t64 dependency was
# swapped out by the MQVPN install. Remove what an earlier run installed.
if dpkg -s tracebox > /dev/null 2>&1; then
	echo "Remove tracebox"
	apt-get -y purge tracebox > /dev/null 2>&1 || true
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
		IPERFPASS=$(printf '%s' "{openmptcprouter}openmptcprouter" | sha256sum | awk '{ print $1 }')
		echo "openmptcprouter,$IPERFPASS" > /etc/iperf3/users.csv
	fi
	chown -Rf iperf3 /etc/iperf3 || true
	systemctl enable iperf3.service || true
	mkdir -p /etc/systemd/system/iperf3.service.d
	if [ "$LOCALFILES" = "no" ]; then
		fetch_file ${VPSURL}${VPSPATH}/iperf3.override.conf /etc/systemd/system/iperf3.service.d/override.conf
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
		# A run that died between clone and cleanup leaves the directory, and
		# git clone refuses to clone into it on every later run
		rm -rf /tmp/mptcpize
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
		rm -rf /tmp/iproute2
		git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git 
		cd iproute2
		git checkout "$IPROUTE2_VERSION"
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
	if [ "$SOURCES" = "yes" ] || [ "$ARCH" != "amd64" ]; then
		apt-get -y install git
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
		if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "13" ]; then
			apt-get -y --allow-downgrades install libmbedtls-dev=2.16.9-0.1 libmbedtls12=2.16.9-0.1 libmbedcrypto3=2.16.9-0.1 libmbedx509-0=2.16.9-0.1
		fi
		sleep 1
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		systemctl enable haveged >/dev/null 2>&1 || true
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
		if ! mk-build-deps --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"; then
			echo "Unable to install Shadowsocks-libev build dependencies."
		fi
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		# dpkg-buildpackage leaves the debs in /tmp: drop the ones of an earlier
		# build, else a failed build installs that stale package below
		rm -f /tmp/omr-shadowsocks-libev_*.deb
		if ! dpkg-buildpackage -b -us -uc; then
			echo "Unable to build Shadowsocks-libev package."
		fi
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		cd /tmp
		#dpkg -i shadowsocks-libev_*.deb
		if ls omr-shadowsocks-libev_*.deb >/dev/null 2>&1; then
			if ! dpkg -i omr-shadowsocks-libev_*.deb; then
				echo "Unable to install built Shadowsocks-libev package."
			fi
		else
			echo "No omr-shadowsocks-libev package produced."
		fi
		if ! command -v ss-manager >/dev/null 2>&1; then
			echo "Error: ss-manager was not installed." >&2
			exit 1
		fi
		#mkdir -p /usr/lib/shadowsocks-libev
		#cp -f /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}/src/*.ebpf /usr/lib/shadowsocks-libev
		#rm -rf /tmp/shadowsocks-libev-${SHADOWSOCKS_VERSION}
		rm -rf /tmp/shadowsocks-libev
	else
		apt-get -y install haveged >/dev/null 2>&1 || true
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
			rm -rf /tmp/Python-3.7.2 /tmp/Python-3.7.2.tgz
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
		apt-get -y install python3-jsonschema python3-fastapi python3-python-multipart python3-starlette
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
	mkdir -p /etc/openmptcprouter-vps-admin/omr-vxlan
	mkdir -p /etc/openmptcprouter-vps-admin/intf
	#[ ! -f "/etc/openmptcprouter-vps-admin/current-vpn" ] && echo "glorytun_tcp" > /etc/openmptcprouter-vps-admin/current-vpn
	[ ! -f "/etc/openmptcprouter-vps-admin/current-vpn" ] && echo "openvpn" > /etc/openmptcprouter-vps-admin/current-vpn
	mkdir -p /var/opt/openmptcprouter
	if [ "$SOURCES" = "yes" ]; then
		if [ "$LOCALFILES" = "no" ]; then
			fetch_file ${VPSURL}${VPSPATH}/omr-admin.service.in /lib/systemd/system/omr-admin.service
			#wget -O /lib/systemd/system/omr-admin-ipv6.service ${VPSURL}${VPSPATH}/omr-admin-ipv6.service.in
		else
			cp ${DIR}/omr-admin.service.in /lib/systemd/system/omr-admin.service
		fi
		wget -O /tmp/openmptcprouter-vps-admin.zip https://github.com/Ysurac/openmptcprouter-vps-admin/archive/${OMR_ADMIN_VERSION}.zip
		cd /tmp
		unzip -q -o openmptcprouter-vps-admin.zip
		rm -f /tmp/openmptcprouter-vps-admin.zip
		# Installed where the omr-vps-admin deb puts it, which is where
		# omr-admin.service runs it from
		cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omradmin.py /usr/bin/omradmin.py
		if [ -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
			OMR_ADMIN_PASS2=$(grep -Po '"'"pass"'"\s*:\s*"\K([^"]*)' /etc/openmptcprouter-vps-admin/omr-admin-config.json | tr -d  "\n")
			[ -z "$OMR_ADMIN_PASS2" ] && OMR_ADMIN_PASS2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.user_password | tr -d "\n")
			# Not the template's MySecretKey: sed would put it back in place of itself
			[ -n "$OMR_ADMIN_PASS2" ] && [ "$OMR_ADMIN_PASS2" != "null" ] && [ "$OMR_ADMIN_PASS2" != "MySecretKey" ] && OMR_ADMIN_PASS=$OMR_ADMIN_PASS2
			OMR_ADMIN_PASS_ADMIN2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].admin.user_password | tr -d "\n")
			[ -n "$OMR_ADMIN_PASS_ADMIN2" ] && [ "$OMR_ADMIN_PASS_ADMIN2" != "null" ] && [ "$OMR_ADMIN_PASS_ADMIN2" != "AdminMySecretKey" ] && OMR_ADMIN_PASS_ADMIN=$OMR_ADMIN_PASS_ADMIN2
		fi
		if [ ! -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ] || [ "$(grep user_password /etc/openmptcprouter-vps-admin/omr-admin-config.json)" = "" ]; then
			cp /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}/omr-admin-config.json /etc/openmptcprouter-vps-admin/
		fi
		rm -rf /tmp/openmptcprouter-vps-admin-${OMR_ADMIN_VERSION}
		chmod u+x /usr/bin/omradmin.py
	else
		if [ -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
			OMR_ADMIN_PASS2=$(grep -Po '"'"pass"'"\s*:\s*"\K([^"]*)' /etc/openmptcprouter-vps-admin/omr-admin-config.json | tr -d  "\n")
			[ -z "$OMR_ADMIN_PASS2" ] && OMR_ADMIN_PASS2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.user_password | tr -d "\n")
			[ -n "$OMR_ADMIN_PASS2" ] && [ "$OMR_ADMIN_PASS2" != "null" ] && [ "$OMR_ADMIN_PASS2" != "MySecretKey" ] && OMR_ADMIN_PASS=$OMR_ADMIN_PASS2
			OMR_ADMIN_PASS_ADMIN2=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].admin.user_password | tr -d "\n")
			[ -n "$OMR_ADMIN_PASS_ADMIN2" ] && [ "$OMR_ADMIN_PASS_ADMIN2" != "null" ] && [ "$OMR_ADMIN_PASS_ADMIN2" != "AdminMySecretKey" ] && OMR_ADMIN_PASS_ADMIN=$OMR_ADMIN_PASS_ADMIN2
		fi
		if ! apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y --allow-downgrades install omr-vps-admin=${OMR_ADMIN_BINARY_VERSION}; then
			if wget -O /tmp/omr-vps-admin_${OMR_ADMIN_BINARY_VERSION}_all.deb ${VPSURL}debian/omr-vps-admin_${OMR_ADMIN_BINARY_VERSION}_all.deb; then
				# Unlike the apt call above, dpkg resolves no dependency: pull
				# anything the deb needs and is missing (nftables, python3-*)
				# instead of leaving the package unconfigured
				dpkg --force-confold --force-confdef --force-overwrite -i /tmp/omr-vps-admin_${OMR_ADMIN_BINARY_VERSION}_all.deb || apt-get -y --fix-broken install
			else
				# The pinned deb is not published yet (the version is bumped
				# here before it is uploaded): install the same commit from
				# GitHub. Never another version: the rest of this script is
				# written against OMR_ADMIN_VERSION.
				echo "WARNING: omr-vps-admin ${OMR_ADMIN_BINARY_VERSION} is not available, installing omr-admin ${OMR_ADMIN_VERSION} from GitHub instead" >&2
				if ! omr_admin_from_github; then
					if [ -f /usr/bin/omradmin.py ] && [ -f /usr/share/omr-admin/omr-admin-config.json ]; then
						echo "WARNING: omr-admin ${OMR_ADMIN_VERSION} could not be installed, keeping the installed one" >&2
					else
						echo "ERROR: omr-admin ${OMR_ADMIN_VERSION} could not be installed, neither as omr-vps-admin ${OMR_ADMIN_BINARY_VERSION} nor from GitHub" >&2
						exit 1
					fi
				fi
			fi
			rm -f /tmp/omr-vps-admin_${OMR_ADMIN_BINARY_VERSION}_all.deb
		fi
		if [ ! -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
			cp /usr/share/omr-admin/omr-admin-config.json /etc/openmptcprouter-vps-admin/
		fi
		#OMR_ADMIN_PASS=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.user_password | tr -d "\n")
		#OMR_ADMIN_PASS_ADMIN=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].admin.user_password | tr -d "\n")
	fi
	# Owner-only before the passwords go in: a copy of the template is
	# created 0644, and sed -i and jq_rewrite keep the mode they find
	# (omr-admin would only tighten it at its next start).
	chmod 600 /etc/openmptcprouter-vps-admin/omr-admin-config.json
	omr_self_signed_cert /etc/openmptcprouter-vps-admin/key.pem /etc/openmptcprouter-vps-admin/cert.pem
	sed -i "s:openmptcptouter:${DEFAULT_USER}:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	sed -i "s:AdminMySecretKey:$OMR_ADMIN_PASS_ADMIN:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	sed -i "s:MySecretKey:$OMR_ADMIN_PASS:g" /etc/openmptcprouter-vps-admin/omr-admin-config.json
	[ "$NOINTERNET" = "yes" ] && {
		jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json '. + {internet: false}'
		#sed -i 's/"port": 65500,/"port": 65500,\n    "internet": false,/' /etc/openmptcprouter-vps-admin/omr-admin-config.json
	}
	[ "$GRETUNNELS" = "no" ] && {
		jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json '. + {gre_tunnels: false}'
		#sed -i 's/"port": 65500,/"port": 65500,\n    "gre_tunnels": false,/' /etc/openmptcprouter-vps-admin/omr-admin-config.json
	}
	[ "$LANROUTES" = "no" ] && {
		jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json '. + {lan_routes: false}'
	}

	# IPv6 give an error on uvicorn
	jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json '. + {host: "0.0.0.0"}'

	chmod 644 /lib/systemd/system/omr-admin.service
	#chmod 644 /lib/systemd/system/omr-admin-ipv6.service
	#[ "$(ip -6 a)" != "" ] && sed -i 's/0.0.0.0/::/g' /usr/local/bin/omr-admin.py
	#[ "$(ip -6 a)" != "" ] && {
	#	systemctl enable omr-admin-ipv6.service
	#}
	systemctl daemon-reload
	systemctl enable omr-admin.service
	#if [ "$KERNEL" != "5.4" ]; then
	#	mptcpize enable omr-admin.service >/dev/null 2>&1
		#[ "$(ip -6 a)" != "" ] && mptcpize enable omr-admin-ipv6.service >/dev/null 2>&1
	#fi
	# Best-effort: stop the unit before reconfiguring it, never fail the install
	# because of it. `systemctl stop` returns non-zero when its job is superseded
	# or cancelled, which happens when something else restarts the unit at the same
	# moment -- omr-admin's POST /mptcp restarts exactly the units these blocks stop
	# (shadowsocks-libev, shadowsocks-go, v2ray, xray, glorytun-tcp, openvpn), so a
	# router pushing its config during an install could trip `set -e` here. The run
	# then ended silently, the EXIT trap removing the lock on the way out and the
	# log simply stopping mid-section. The `is-active` test is an `if` condition and
	# so exempt from `set -e`; the commands in the body are not.
	if systemctl -q is-active omr-admin-ipv6.service 2>/dev/null; then
		systemctl -q stop omr-admin-ipv6 >/dev/null 2>&1 || true
		systemctl -q disable omr-admin-ipv6 >/dev/null 2>&1 || true
	fi
	if [ "$OMR_METRICS" = "yes" ]; then
		mkdir -p /usr/share/omr-admin
		wget -O /usr/share/omr-admin/omr_metrics.py https://raw.githubusercontent.com/Ysurac/openmptcprouter-vps-admin/${OMR_ADMIN_VERSION}/omr_metrics.py
	fi
	if [ "$OMR_AI" = "yes" ]; then
		wget -O /tmp/install_omr-ai.sh https://raw.githubusercontent.com/Ysurac/openmptcprouter-vps-admin/${OMR_ADMIN_VERSION}/install_omr-ai.sh
		OMR_ADMIN_VERSION="${OMR_ADMIN_VERSION}" bash /tmp/install_omr-ai.sh
		rm -f /tmp/install_omr-ai.sh
	fi
fi

# Get shadowsocks optimization
if [ "$LOCALFILES" = "no" ]; then
	if [ "$KERNEL" != "5.4" ]; then
		if [ "$KERNEL" != "6.12" ] && [ "$KERNEL" != "6.6" ]; then
			fetch_file ${VPSURL}${VPSPATH}/shadowsocks.6.18.conf /etc/sysctl.d/90-shadowsocks.conf
		else
			fetch_file ${VPSURL}${VPSPATH}/shadowsocks.6.1.conf /etc/sysctl.d/90-shadowsocks.conf
		fi
	else
		fetch_file ${VPSURL}${VPSPATH}/shadowsocks.conf /etc/sysctl.d/90-shadowsocks.conf
	fi
else
	# Same kernel split as the download branch above -- without the 6.18 case
	# here, every LOCALFILES=yes run (which is every SOURCES=yes run, see
	# above) installed the 6.1 sysctl set on a 6.18 kernel
	if [ "$KERNEL" != "5.4" ]; then
		if [ "$KERNEL" != "6.12" ] && [ "$KERNEL" != "6.6" ]; then
			cp ${DIR}/shadowsocks.6.18.conf /etc/sysctl.d/90-shadowsocks.conf
		else
			cp ${DIR}/shadowsocks.6.1.conf /etc/sysctl.d/90-shadowsocks.conf
		fi
	else
		cp ${DIR}/shadowsocks.conf /etc/sysctl.d/90-shadowsocks.conf
	fi
fi

if [ "$SHADOWSOCKS" = "yes" ]; then
	if [ "$update" != 0 ]; then
		# Keep the generated key unless the old config really has one: with
		# neither file (Shadowsocks was off) or no key in it, this read
		# nothing and manager.json got an empty key
		SHADOWSOCKS_PASS_OLD=""
		if [ ! -f /etc/shadowsocks-libev/manager.json ]; then
			[ -f /etc/shadowsocks-libev/config.json ] && SHADOWSOCKS_PASS_OLD=$(grep -Po '"'"key"'"\s*:\s*"\K([^"]*)' /etc/shadowsocks-libev/config.json | tr -d  "\n" | sed 's/-/+/g; s/_/\//g;')
		elif [ -f /etc/shadowsocks-libev/manager.json ]; then
			SHADOWSOCKS_PASS_OLD=$(grep -Po '"'"65101"'":\s*"\K([^"]*)' /etc/shadowsocks-libev/manager.json | tr -d  "\n" | sed 's/-/+/g; s/_/\//g;')
		fi
		[ -n "$SHADOWSOCKS_PASS_OLD" ] && SHADOWSOCKS_PASS="$SHADOWSOCKS_PASS_OLD"
	fi
	# Install shadowsocks config and add a shadowsocks by CPU
	if [ "$update" = "0" ] || [ ! -f /etc/shadowsocks-libev/manager.json ]; then
		mkdir -p /etc/shadowsocks-libev
		if [ "$LOCALFILES" = "no" ]; then
			fetch_file ${VPSURL}${VPSPATH}/manager.json /etc/shadowsocks-libev/manager.json
		else
			cp ${DIR}/manager.json /etc/shadowsocks-libev/manager.json
		fi
		SHADOWSOCKS_PASS_JSON=$(echo $SHADOWSOCKS_PASS | sed 's/+/-/g; s/\//_/g;')
		#sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/config.json
		sed -i "s:MySecretKey:$SHADOWSOCKS_PASS_JSON:g" /etc/shadowsocks-libev/manager.json
		[ "$(ip -6 a 2>/dev/null)" = "" ] && sed -i '/"\[::0\]"/d' /etc/shadowsocks-libev/manager.json
	elif [ "$update" != "0" ] && [ -f /etc/shadowsocks-libev/manager.json ] && [ "$(grep -c '65101' /etc/shadowsocks-libev/manager.json | tr -d '\n')" != "$NBCPU" ] && [ -z "$(grep port_conf /etc/shadowsocks-libev/manager.json)" ]; then
		echo "Keep a single Shadowsocks manager port entry"
	fi
	[ ! -f /etc/shadowsocks-libev/local.acl ] && touch /etc/shadowsocks-libev/local.acl
	#sed -i 's:aes-256-cfb:chacha20:g' /etc/shadowsocks-libev/config.json
	#sed -i 's:json:json --no-delay:g' /lib/systemd/system/shadowsocks-libev-server@.service
	if [ "$LOCALFILES" = "no" ]; then
		fetch_file ${VPSURL}${VPSPATH}/shadowsocks-libev-manager@.service.in /lib/systemd/system/shadowsocks-libev-manager@.service
	else
		cp ${DIR}/shadowsocks-libev-manager@.service.in /lib/systemd/system/shadowsocks-libev-manager@.service
	fi
	if systemctl -q is-enabled shadowsocks-libev 2>/dev/null; then
		systemctl -q disable --now shadowsocks-libev || true
	fi
	[ -f /etc/shadowsocks-libev/config.json ] && { systemctl disable shadowsocks-libev-server@config.service || true; }
	systemctl enable shadowsocks-libev-manager@manager.service
	if [ $NBCPU -gt 1 ]; then
		for i in $(seq 1 $NBCPU); do
			[ -f /etc/shadowsocks-libev/config$i.json ] && systemctl is-enabled shadowsocks-libev && { systemctl disable shadowsocks-libev-server@config$i.service || true; }
		done
	fi
	if systemctl -q is-active shadowsocks-libev-manager@manager 2>/dev/null; then
		systemctl -q stop shadowsocks-libev-manager@manager > /dev/null 2>&1 || true
	fi
fi
if ! grep -q 'DefaultLimitNOFILE=65536' /etc/systemd/system.conf ; then
	echo 'DefaultLimitNOFILE=65536' >> /etc/systemd/system.conf
fi

if [ "$LOCALFILES" = "no" ]; then
	fetch_file ${VPSURL}${VPSPATH}/omr-update.service.in /lib/systemd/system/omr-update.service
	fetch_file ${VPSURL}${VPSPATH}/omr-update /usr/bin/omr-update
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
	if [ "$SOURCES" = "yes" ] || [ "$ARCH" != "amd64" ]; then
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
	if [ "$SOURCES" = "yes" ] && [ "$ARCH" = "amd64" ]; then
		rm -rf /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		#wget -O /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz https://github.com/shadowsocks/v2ray-plugin/releases/download/${V2RAY_PLUGIN_VERSION}/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		#wget -O /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz ${VPSURL}${VPSPATH}/bin/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		wget -O /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz https://github.com/teddysun/v2ray-plugin/releases/download/v${V2RAY_PLUGIN_VERSION}/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		cd /tmp
		tar xzvf v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
		cp -f v2ray-plugin_linux_amd64 /usr/local/bin/v2ray-plugin
		cd /tmp
		rm -rf /tmp/v2ray-plugin_linux_amd64
		rm -rf /tmp/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz
	
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
	systemctl -q stop shadowsocks-go > /dev/null 2>&1 || true
	systemctl -q disable shadowsocks-go > /dev/null 2>&1 || true
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
		if ! apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y install shadowsocks-go=${SHADOWSOCKS_GO_VERSION}; then
			wget -O /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-${ARCH}.deb ${VPSURL}debian/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-${ARCH}.deb
			dpkg --force-confold --force-confdef --force-overwrite -i /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-${ARCH}.deb
			rm -f /tmp/shadowsocks-go-${SHADOWSOCKS_GO_VERSION}-${ARCH}.deb
		fi
	fi
	if [ -f /etc/shadowsocks-go/server.json ]; then
		PSK2=$(grep -Po '"'"psk"'"\s*:\s*"\K([^"]*)' /etc/shadowsocks-go/server.json | head -n 1 | tr -d "\n")
		[ -n "$PSK2" ] && [ "$PSK2" != "PSK" ] && [ "$PSK2" != "null" ] && PSK="$PSK2"
		UPSK2=$(grep -Po '"'"openmptcprouter"'"\s*:\s*"\K([^"]*)' /etc/shadowsocks-go/upsks.json | head -n 1 | tr -d "\n")
		[ -n "$UPSK2" ] && [ "$UPSK2" != "UPSK" ] && [ "$UPSK2" != "null" ] && UPSK="$UPSK2"
	fi
	if [ "$LOCALFILES" = "no" ]; then
		fetch_file ${VPSURL}${VPSPATH}/shadowsocks-go.server.json /etc/shadowsocks-go/server.json
	else
		cp ${DIR}/shadowsocks-go.server.json /etc/shadowsocks-go/server.json
	fi
	sed -i "s:\"PSK\":\"$PSK\":g" /etc/shadowsocks-go/server.json
	sed -i "s:UPSK:$UPSK:g" /etc/shadowsocks-go/upsks.json
	# Not there with OMR_ADMIN=no
	if [ -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
		cp -pf /etc/openmptcprouter-vps-admin/omr-admin-config.json /etc/openmptcprouter-vps-admin/omr-admin-config.json.bak
		jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json -M 'del(.users[0].openmptcprouter."shadowsocks-go")'
	fi

	chmod 644 /lib/systemd/system/shadowsocks-go.service
	systemctl daemon-reload
	systemctl enable shadowsocks-go.service
fi


if systemctl -q is-active v2ray.service 2>/dev/null; then
	systemctl -q stop v2ray > /dev/null 2>&1 || true
	systemctl -q disable v2ray > /dev/null 2>&1 || true
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
		if ! apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y install v2ray=${V2RAY_VERSION}; then
			wget -O /tmp/v2ray-${V2RAY_VERSION}-${ARCH}.deb ${VPSURL}debian/v2ray-${V2RAY_VERSION}-${ARCH}.deb
			dpkg --force-confold --force-confdef --force-overwrite -i /tmp/v2ray-${V2RAY_VERSION}-${ARCH}.deb
			rm -f /tmp/v2ray-${V2RAY_VERSION}-${ARCH}.deb
		fi
	fi
	if [ -f /etc/v2ray/v2ray-server.json ]; then
		V2RAY_UUID2=$(grep -Po '"'"id"'"\s*:\s*"\K([^"]*)' /etc/v2ray/v2ray-server.json | head -n 1 | tr -d "\n")
		[ -n "$V2RAY_UUID2" ] && V2RAY_UUID="$V2RAY_UUID2"
	fi
	# Copied from the template only when there is none: an existing config
	# holds what omr-admin added since (users of /add_user, port redirects,
	# reverse tunnels), which a copy on every run threw away. It only gets the
	# template inbounds and outbounds it lacks, and the rules that keep proxy
	# users off the VPS's loopback services when it has none.
	V2RAY_TEMPLATE="$(mktemp)"
	if [ "$LOCALFILES" = "no" ]; then
		wget -O "$V2RAY_TEMPLATE" ${VPSURL}${VPSPATH}/v2ray-server.json
	else
		cp ${DIR}/v2ray-server.json "$V2RAY_TEMPLATE"
	fi
	sed -i "s:V2RAY_UUID:$V2RAY_UUID:g" "$V2RAY_TEMPLATE"
	if [ ! -f /etc/v2ray/v2ray-server.json ]; then
		cp "$V2RAY_TEMPLATE" /etc/v2ray/v2ray-server.json
	else
		jq_rewrite /etc/v2ray/v2ray-server.json -M --slurpfile tmpl "$V2RAY_TEMPLATE" '[.inbounds[].tag] as $have | .inbounds += [$tmpl[0].inbounds[] | select(.tag as $t | $have | any(.[]; . == $t) | not)] | [.outbounds[]?.tag] as $haveout | .outbounds += [$tmpl[0].outbounds[] | select(.tag as $t | $haveout | any(.[]; . == $t) | not)] | if any(.routing.rules[]?; .outboundTag == "blocked") then . else .routing.rules += [$tmpl[0].routing.rules[] | select(.outboundTag == "blocked")] end'
	fi
	rm -f "$V2RAY_TEMPLATE"
	if [ "$KERNEL" != "5.4" ] && [ -z "$(grep mptcp /etc/v2ray/v2ray-server.json | grep true)" ]; then
		sed -i 's/"sockopt": {/&\n                    "mptcp": true,/' /etc/v2ray/v2ray-server.json
	fi
	rm -f /etc/v2ray/config.json
	ln -s /etc/v2ray/v2ray-server.json /etc/v2ray/config.json
	#if [ -f /etc/systemd/system/v2ray.service.dpkg-dist ]; then
	#	mv -f /etc/systemd/system/v2ray.service.dpkg-dist /etc/systemd/system/v2ray.service
	#fi
	if [ "$LOCALFILES" = "no" ]; then
		fetch_file ${VPSURL}${VPSPATH}/v2ray.service /lib/systemd/system/v2ray.service
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
	systemctl -q stop xray > /dev/null 2>&1 || true
	systemctl -q disable xray > /dev/null 2>&1 || true
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
		if ! apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y --allow-downgrades install xray=${XRAY_VERSION}; then
			wget -O /tmp/xray-${XRAY_VERSION}-${ARCH}.deb ${VPSURL}debian/xray-${XRAY_VERSION}-${ARCH}.deb
			dpkg --force-confold --force-confdef --force-overwrite -i /tmp/xray-${XRAY_VERSION}-${ARCH}.deb
			rm -f /tmp/xray-${XRAY_VERSION}-${ARCH}.deb
		fi
	fi
	if [ -f /etc/xray/xray-server.json ]; then
		XRAY_UUID2=$(grep -Po '"'"id"'"\s*:\s*"\K([^"]*)' /etc/xray/xray-server.json | head -n 1 | tr -d "\n")
		[ -n "$XRAY_UUID2" ] && [ "$XRAY_UUID2" != "XRAY_UUID" ] && [ "$XRAY_UUID2" != "V2RAY_UUID" ] && XRAY_UUID="$XRAY_UUID2"
		PSK2=$(jq -r '.inbounds[] | select(.tag=="omrin-shadowsocks-tunnel") | .settings.password' /etc/xray/xray-server.json | tr -d "\n")
		[ "$PSK2" != "null" ] && [ -n "$PSK2" ] && [ "$PSK2" != "XRAY_PSK" ] && PSK="$PSK2"
		UPSK2=$(jq -r '.inbounds[] | select(.tag=="omrin-shadowsocks-tunnel") | .settings.clients[] | select(.email=="openmptcprouter") | .password' /etc/xray/xray-server.json | tr -d "\n")
		[ "$UPSK2" != "null" ] && [ -n "$UPSK2" ] && [ "$UPSK2" != "XRAY_UPSK" ] && UPSK="$UPSK2"
		XRAY_X25519_PRIVATE_KEY2=$(grep -Po '"'"privateKey"'"\s*:\s*"\K([^"]*)' /etc/xray/xray-vless-reality.json | head -n 1 | tr -d "\n")
		[ -n "$XRAY_X25519_PRIVATE_KEY2" ] && [ "$XRAY_X25519_PRIVATE_KEY2" != "XRAY_X25519_PRIVATE_KEY" ] && XRAY_X25519_PRIVATE_KEY="$XRAY_X25519_PRIVATE_KEY2"
		XRAY_X25519_PUBLIC_KEY2=$(grep -Po '"'"publicKey"'"\s*:\s*"\K([^"]*)' /etc/xray/xray-vless-reality.json | head -n 1 | tr -d "\n")
		[ -n "$XRAY_X25519_PUBLIC_KEY2" ] && [ "$XRAY_X25519_PUBLIC_KEY2" != "XRAY_X25519_PUBLIC_KEY" ] && XRAY_X25519_PUBLIC_KEY="$XRAY_X25519_PUBLIC_KEY2"
		XRAY_REVERSE_UUID2=$(jq -r '.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients[] | select(.reverse.tag=="OMRLan") | .id' /etc/xray/xray-server.json 2>/dev/null | head -n 1 | tr -d "\n")
		[ -n "$XRAY_REVERSE_UUID2" ] && [ "$XRAY_REVERSE_UUID2" != "XRAY_REVERSE_UUID" ] && XRAY_REVERSE_UUID="$XRAY_REVERSE_UUID2"
		#jq -M 'del(.transport)' /etc/xray/xray-server.json > /etc/xray/xray-server.json.tmp
		#mv -f /etc/xray/xray-server.json.tmp /etc/xray/xray-server.json

	fi
	if [ -f /etc/openmptcprouter-vps-admin/omr-admin-config.json ]; then
		cp -pf /etc/openmptcprouter-vps-admin/omr-admin-config.json /etc/openmptcprouter-vps-admin/omr-admin-config.json.bak
		jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json -M 'del(.users[0].openmptcprouter.xray)'
	fi
	if [ -f /etc/xray/xray-server.json ]; then
		cp -pf /etc/xray/xray-server.json /etc/xray/xray-server.json.bak
		jq_rewrite /etc/xray/xray-server.json -M 'del(.api.listen)'
	fi
	if [ -f /etc/xray/xray-server.json ] && [ "$(jq -r '.reverse != null' /etc/xray/xray-server.json)" = "true" ]; then
		# xray 26+ removed legacy reverse: a config still carrying it prevents xray from starting
		cp -pf /etc/xray/xray-server.json /etc/xray/xray-server.json.bak
		jq_rewrite /etc/xray/xray-server.json -M 'del(.reverse) | if .routing.rules then .routing.rules |= map(select(.outboundTag != "OMRLan")) else . end'
	fi
	if [ -f /etc/xray/xray-server.json ] && [ "$(jq -r 'any(.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients[]; .reverse.tag=="OMRLan")' /etc/xray/xray-server.json)" = "false" ]; then
		# VLESS Reverse Proxy (replaces legacy reverse on xray 26+): the VPS->LAN port
		# forward feature needs a dedicated reverse client in the VLESS inbound
		XRAY_REVERSE_UUID=$(/usr/bin/xray uuid | tr -d "\n")
		jq_rewrite /etc/xray/xray-server.json -M --arg uuid "$XRAY_REVERSE_UUID" '(.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients) += [{"id": $uuid, "level": 0, "email": "omr-reverse", "reverse": {"tag": "OMRLan"}}]'
	fi
	if [ -f /etc/xray/xray-vless-reality.json ]; then
		# older installs parsed the new "xray x25519" output wrong and left an empty
		# privateKey, which makes xray refuse to start once the reality inbound is enabled
		XRAY_REALITY_PRIVATE=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' /etc/xray/xray-vless-reality.json)
		if [ -z "$XRAY_REALITY_PRIVATE" ] || [ "$XRAY_REALITY_PRIVATE" = "null" ] || [ "$XRAY_REALITY_PRIVATE" = "XRAY_X25519_PRIVATE_KEY" ]; then
			XRAY_X25519_KEYS=$(/usr/bin/xray x25519)
			XRAY_X25519_PRIVATE_KEY=$(echo "${XRAY_X25519_KEYS}" | grep Private | awk '{ print $NF }' | tr -d "\n")
			XRAY_X25519_PUBLIC_KEY=$(echo "${XRAY_X25519_KEYS}" | grep Public | awk '{ print $NF }' | tr -d "\n")
			if [ -n "$XRAY_X25519_PRIVATE_KEY" ] && [ -n "$XRAY_X25519_PUBLIC_KEY" ]; then
				jq_rewrite /etc/xray/xray-vless-reality.json -M --arg priv "$XRAY_X25519_PRIVATE_KEY" --arg pub "$XRAY_X25519_PUBLIC_KEY" '(.inbounds[] | select(.tag=="omrin-vless-reality") | .streamSettings.realitySettings) |= (.privateKey=$priv | .publicKey=$pub)'
				if [ -f /etc/xray/xray-server.json ] && [ "$(jq -r 'any(.inbounds[]; .tag=="omrin-vless-reality")' /etc/xray/xray-server.json)" = "true" ]; then
					jq_rewrite /etc/xray/xray-server.json -M --arg priv "$XRAY_X25519_PRIVATE_KEY" --arg pub "$XRAY_X25519_PUBLIC_KEY" '(.inbounds[] | select(.tag=="omrin-vless-reality") | .streamSettings.realitySettings) |= (.privateKey=$priv | .publicKey=$pub)'
				fi
			fi
		fi
	fi
	# Rebuilt from the template only when there is none, or it predates the
	# MPTCP one or still has the top-level "transport" xray 26 refuses. The
	# test used to be "no transport", true for every config since the template
	# lost it, so each run threw away what omr-admin added since: users'
	# settings of /xray, port redirects, reverse tunnels, GRE outbounds, and
	# the other users' uuids, the ones their routers have. Kept, a config only
	# gets the template inbounds and outbounds it lacks, and the loopback
	# blocking rules when it has none.
	if [ ! -f /etc/xray/xray-server.json ] || [ -z "$(grep -i mptcp /etc/xray/xray-server.json | grep true)" ] || [ "$(jq -r 'has("transport")' /etc/xray/xray-server.json 2>/dev/null)" = "true" ]; then
		XRAY_OLD_CONFIG=""
		if [ -f /etc/xray/xray-server.json ]; then
			XRAY_OLD_CONFIG=/etc/xray/xray-server.json.old
			cp -pf /etc/xray/xray-server.json "$XRAY_OLD_CONFIG"
		fi
		if [ "$LOCALFILES" = "no" ]; then
			fetch_file ${VPSURL}${VPSPATH}/xray-server.json /etc/xray/xray-server.json
		else
			cp ${DIR}/xray-server.json /etc/xray/xray-server.json
		fi
		sed -i "s:V2RAY_UUID:$XRAY_UUID:g" /etc/xray/xray-server.json
		sed -i "s:XRAY_PSK:$PSK:g" /etc/xray/xray-server.json
		sed -i "s:XRAY_UPSK:$UPSK:g" /etc/xray/xray-server.json
		[ -z "$XRAY_REVERSE_UUID" ] && XRAY_REVERSE_UUID=$(/usr/bin/xray uuid | tr -d "\n")
		sed -i "s:XRAY_REVERSE_UUID:$XRAY_REVERSE_UUID:g" /etc/xray/xray-server.json
		if [ "$LOCALFILES" = "no" ]; then
			fetch_file ${VPSURL}${VPSPATH}/xray-vless-reality.json /etc/xray/xray-vless-reality.json
		else
			cp ${DIR}/xray-vless-reality.json /etc/xray/xray-vless-reality.json
		fi
		if [ -z "$XRAY_X25519_PRIVATE_KEY" ]; then
			XRAY_X25519_KEYS=$(/usr/bin/xray x25519)
			# output format depends on xray version:
			#   old: "Private key: xxx" / "Public key: yyy"
			#   26+: "PrivateKey: xxx" / "Password (PublicKey): yyy"
			XRAY_X25519_PRIVATE_KEY=$(echo "${XRAY_X25519_KEYS}" | grep Private | awk '{ print $NF }' | tr -d "\n")
			XRAY_X25519_PUBLIC_KEY=$(echo "${XRAY_X25519_KEYS}" | grep Public | awk '{ print $NF }' | tr -d "\n")
		fi
		sed -i "s:XRAY_UUID:$XRAY_UUID:g" /etc/xray/xray-vless-reality.json
		sed -i "s:XRAY_X25519_PRIVATE_KEY:$XRAY_X25519_PRIVATE_KEY:g" /etc/xray/xray-vless-reality.json
		sed -i "s:XRAY_X25519_PUBLIC_KEY:$XRAY_X25519_PUBLIC_KEY:g" /etc/xray/xray-vless-reality.json
		for xrayuser in $(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r '.users[0][].username'); do
			if [ "$xrayuser" != "admin" ] && [ "$xrayuser" != "openmptcprouter" ]; then
				# The uuid and Shadowsocks 2022 key the old config gave this
				# user, so that its router keeps working
				xrayid=""
				shadowsockspass=""
				[ -n "$XRAY_OLD_CONFIG" ] && xrayid="$(jq -r --arg u "$xrayuser" 'first(.inbounds[]? | select(.tag=="omrin-tunnel") | .settings.clients[]? | select(.email==$u) | .id // empty)' "$XRAY_OLD_CONFIG" 2>/dev/null || true)"
				[ -z "$xrayid" ] && xrayid="$(/usr/bin/xray uuid)"
				jq_rewrite /etc/xray/xray-server.json --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients) += [{"level": 0, "alterId": 0, "email": $xrayuser,"id": $xrayid}]'
				jq_rewrite /etc/xray/xray-server.json --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-vmess-tunnel") | .settings.clients) += [{"level": 0, "alterId": 0, "email": $xrayuser,"id": $xrayid}]'
				jq_rewrite /etc/xray/xray-server.json --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-socks-tunnel") | .settings.accounts) += [{"user": $xrayuser,"pass": $xrayid}]'
				# Trojan authenticates by "password": with an "id" instead the
				# user had an empty one, which xray accepts from anyone
				jq_rewrite /etc/xray/xray-server.json --arg xrayuser "$xrayuser" --arg xrayid "$xrayid" '(.inbounds[] | select(.tag=="omrin-trojan-tunnel") | .settings.clients) += [{"level": 0, "email": $xrayuser,"password": $xrayid}]'
				[ -n "$XRAY_OLD_CONFIG" ] && shadowsockspass="$(jq -r --arg u "$xrayuser" 'first(.inbounds[]? | select(.tag=="omrin-shadowsocks-tunnel") | .settings.clients[]? | select(.email==$u) | .password // empty | select(. != "null"))' "$XRAY_OLD_CONFIG" 2>/dev/null || true)"
				[ -z "$shadowsockspass" ] && [ -e /etc/shadowsocks-go/upsks.json ] && shadowsockspass="$(jq --arg xrayuser "$xrayuser" -r '.[$xrayuser] // empty' /etc/shadowsocks-go/upsks.json)"
				[ -z "$shadowsockspass" ] && shadowsockspass=$(head -c 32 /dev/urandom | base64 -w0)
				jq_rewrite /etc/xray/xray-server.json --arg xrayuser "$xrayuser" --arg shadowsockspass "$shadowsockspass" '(.inbounds[] | select(.tag=="omrin-shadowsocks-tunnel") | .settings.clients) += [{"email": $xrayuser,"password": $shadowsockspass}]'
			fi
		done
		[ -n "$XRAY_OLD_CONFIG" ] && rm -f "$XRAY_OLD_CONFIG"
	else
		XRAY_TEMPLATE="$(mktemp)"
		if [ "$LOCALFILES" = "no" ]; then
			wget -O "$XRAY_TEMPLATE" ${VPSURL}${VPSPATH}/xray-server.json
		else
			cp ${DIR}/xray-server.json "$XRAY_TEMPLATE"
		fi
		sed -i "s:V2RAY_UUID:$XRAY_UUID:g; s:XRAY_PSK:$PSK:g; s:XRAY_UPSK:$UPSK:g" "$XRAY_TEMPLATE"
		[ -z "$XRAY_REVERSE_UUID" ] && XRAY_REVERSE_UUID=$(/usr/bin/xray uuid | tr -d "\n")
		sed -i "s:XRAY_REVERSE_UUID:$XRAY_REVERSE_UUID:g" "$XRAY_TEMPLATE"
		jq_rewrite /etc/xray/xray-server.json -M --slurpfile tmpl "$XRAY_TEMPLATE" '[.inbounds[].tag] as $have | .inbounds += [$tmpl[0].inbounds[] | select(.tag as $t | $have | any(.[]; . == $t) | not)] | [.outbounds[]?.tag] as $haveout | .outbounds += [$tmpl[0].outbounds[] | select(.tag as $t | $haveout | any(.[]; . == $t) | not)] | if any(.routing.rules[]?; .outboundTag == "blocked") then . else .routing.rules += [$tmpl[0].routing.rules[] | select(.outboundTag == "blocked")] end'
		rm -f "$XRAY_TEMPLATE"
	fi
	if [ -f /etc/xray/xray-server.json ] && [ "$(jq -r 'any(.inbounds[]? | select(.tag=="omrin-trojan-tunnel") | .settings.clients[]?; (.password // "") == "")' /etc/xray/xray-server.json)" = "true" ]; then
		# Trojan users this script added with an "id" and no "password": xray
		# took them as users of an empty password, anyone could connect
		jq_rewrite /etc/xray/xray-server.json -M '(.inbounds[] | select(.tag=="omrin-trojan-tunnel") | .settings.clients) |= map(if (.password // "") != "" then . elif (.id // "") != "" then (del(.id, .alterId) + {"password": .id}) else empty end)'
	fi
	if [ -f /etc/xray/xray-server.json ]; then
		# A user missing from upsks.json got the key "null", which xray refuses
		for ssuser in $(jq -r '.inbounds[]? | select(.tag=="omrin-shadowsocks-tunnel") | .settings.clients[]? | select((.password // "") == "" or .password == "null") | .email // empty' /etc/xray/xray-server.json); do
			ssfix=""
			[ -e /etc/shadowsocks-go/upsks.json ] && ssfix="$(jq -r --arg u "$ssuser" '.[$u] // empty' /etc/shadowsocks-go/upsks.json 2>/dev/null || true)"
			if [ -z "$ssfix" ] || [ "$ssfix" = "null" ]; then
				ssfix=$(head -c 32 /dev/urandom | base64 -w0)
			fi
			jq_rewrite /etc/xray/xray-server.json -M --arg u "$ssuser" --arg pass "$ssfix" '(.inbounds[] | select(.tag=="omrin-shadowsocks-tunnel") | .settings.clients[] | select(.email==$u)) |= (.password=$pass)'
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
		fetch_file ${VPSURL}${VPSPATH}/xray.service /lib/systemd/system/xray.service
	else
		cp ${DIR}/xray.service /lib/systemd/system/xray.service
	fi
	chmod 644 /lib/systemd/system/xray.service
	systemctl daemon-reload
	systemctl enable xray.service
fi

# mlvpn exits 1 on SIGTERM, so even this deliberate stop
# leaves the unit "failed" and the failed-services check at the end of the
# script would report it as broken by the install order
if systemctl -q is-active mlvpn@mlvpn0.service 2>/dev/null; then
	systemctl -q stop mlvpn@mlvpn0 > /dev/null 2>&1 || true
	systemctl reset-failed mlvpn@mlvpn0 > /dev/null 2>&1 || true
	systemctl -q disable mlvpn@mlvpn0 > /dev/null 2>&1 || true
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
	if [ "$SOURCES" = "yes" ] || [ "$ARCH" != "amd64" ]; then
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
			fetch_file ${VPSURL}${VPSPATH}/mlvpn.network /lib/systemd/network/mlvpn.network
			fetch_file ${VPSURL}${VPSPATH}/mlvpn@.service.in /lib/systemd/system/mlvpn@.service
		else
			cp ${DIR}/mlvpn.network /lib/systemd/network/mlvpn.network
			cp ${DIR}/mlvpn@.service.in /lib/systemd/system/mlvpn@.service
		fi
		if [ "$mlvpnupdate" = "0" ]; then
			if [ "$LOCALFILES" = "no" ]; then
				fetch_file ${VPSURL}${VPSPATH}/mlvpn0.conf /etc/mlvpn/mlvpn0.conf
			else
				cp ${DIR}/mlvpn0.conf /etc/mlvpn/mlvpn0.conf
			fi
			# Right here, not only in the chmod further down: mlvpn exits with
			# "[CRIT/config] file is group/other accessible" and the omr-mlvpn
			# deb installed below starts it before that later chmod runs
			chmod 0600 /etc/mlvpn/mlvpn0.conf
		fi
	else
		rm -f /var/lib/dpkg/lock
		rm -f /var/lib/dpkg/lock-frontend
		if ! apt-get -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" install omr-mlvpn=${MLVPN_BINARY_VERSION}; then
			wget -O /tmp/omr-mlvpn-${MLVPN_BINARY_VERSION}.deb ${VPSURL}debian/omr-mlvpn-${MLVPN_BINARY_VERSION}.deb
			dpkg --force-confold --force-confdef -i /tmp/omr-mlvpn-${MLVPN_BINARY_VERSION}.deb
			rm -f /tmp/omr-mlvpn-${MLVPN_BINARY_VERSION}.deb
		fi
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
# UBOND is gone: no OpenMPTCProuter router image has shipped it since it was
# disabled there for segfaulting (openmptcprouter-feeds e0b85427), and its
# UDP 65252 was also xray's Shadowsocks 2022 port. Remove what an earlier
# UBOND=yes run installed.
if [ -e /etc/ubond ] || [ -f /usr/local/sbin/ubond ]; then
	echo "Remove UBOND"
	systemctl -q disable --now ubond@ubond0 > /dev/null 2>&1 || true
	systemctl reset-failed ubond@ubond0 > /dev/null 2>&1 || true
	rm -f /lib/systemd/system/ubond@.service /lib/systemd/network/ubond.network
	rm -f /usr/local/sbin/ubond /usr/local/share/man/man1/ubond.1 /usr/local/share/man/man5/ubond.conf.5
	rm -rf /etc/ubond /var/opt/ubond
	deluser --quiet --system ubond > /dev/null 2>&1 || true
	systemctl daemon-reload
fi

if systemctl -q is-active wg-quick@wg0.service 2>/dev/null; then
	systemctl -q stop wg-quick@wg0 > /dev/null 2>&1 || true
	systemctl -q disable wg-quick@wg0 > /dev/null 2>&1 || true
fi

if [ "$WIREGUARD" = "yes" ]; then
	echo "Install WireGuard"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get -y install wireguard-tools --no-install-recommends
	# Keys and the configs holding them private, and only in this block: a
	# bare umask 077 here used to stay for the rest of the script, so a fresh
	# install made everything after it 0600/0700 (/etc/motd, speedtest...)
	umask 077
	if [ ! -f /etc/wireguard/wg0.conf ]; then
		cd /etc/wireguard
		wg genkey | tee vpn-server-private.key | wg pubkey > vpn-server-public.key
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
		wg genkey | tee vpn-client-private.key | wg pubkey > vpn-client-public.key
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
	umask 0022
	systemctl enable wg-quick@client-wg0
	echo "Install wireguard done"
fi

if systemctl -q is-active mqvpn.service 2>/dev/null; then
	systemctl -q stop mqvpn > /dev/null 2>&1 || true
	systemctl -q disable mqvpn > /dev/null 2>&1 || true
fi
if [ "$MQVPN" = "yes" ]; then
	echo "Install MQVPN"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	if [ "$ARCH" = "amd64" ]; then
		if ! apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" --allow-downgrades -y install mqvpn=${MQVPN_VERSION}; then
			wget -O /tmp/mqvpn_${MQVPN_VERSION}_${ARCH}.deb ${VPSURL}debian/mqvpn_${MQVPN_VERSION}_${ARCH}.deb
			wget -O /tmp/libmqvpn0_${MQVPN_VERSION}_${ARCH}.deb ${VPSURL}debian/libmqvpn0_${MQVPN_VERSION}_${ARCH}.deb
			apt-get -y install libevent-2.1-7
			dpkg --force-all -i -B /tmp/libmqvpn0_${MQVPN_VERSION}_${ARCH}.deb
			dpkg --force-all -i -B /tmp/mqvpn_${MQVPN_VERSION}_${ARCH}.deb
			apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y --fix-broken install
			rm -f /tmp/mqvpn_${MQVPN_VERSION}_${ARCH}.deb /tmp/libmqvpn0_${MQVPN_VERSION}_${ARCH}.deb
		fi
	elif [ "$ARCH" = "arm64" ]; then
		wget -O /tmp/mqvpn_${MQVPN_VERSION}_arm64.deb ${VPSURL}/debian/mqvpn_${MQVPN_VERSION}_arm64.deb
		wget -O /tmp/libmqvpn0_${MQVPN_VERSION}_arm64.deb ${VPSURL}/debian/libmqvpn0_${MQVPN_VERSION}_arm64.deb
		apt-get -y install libevent-2.1-7
		dpkg --force-all -i -B /tmp/libmqvpn0_${MQVPN_VERSION}_arm64.deb
		dpkg --force-all -i -B /tmp/mqvpn_${MQVPN_VERSION}_arm64.deb
		apt-get -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-overwrite" -y --fix-broken install
		rm -f /tmp/mqvpn_${MQVPN_VERSION}_arm64.deb
		rm -f /tmp/libmqvpn0_${MQVPN_VERSION}_arm64.deb
	fi
	mkdir -p /etc/mqvpn
	MQVPN_USERS=""
	if [ -f /etc/mqvpn/server.json ]; then
		MQVPN_KEY2=$(grep -Po '"key"\s*:\s*"\K([^"]*)' /etc/mqvpn/server.json | head -n 1 | tr -d "\n")
		[ -n "$MQVPN_KEY2" ] && [ "$MQVPN_KEY2" != "PSK" ] && [ "$MQVPN_KEY2" != "null" ] && MQVPN_KEY="$MQVPN_KEY2"
		MQVPN_USERS=$(jq -c '.users // empty' /etc/mqvpn/server.json 2>/dev/null)
	fi
	if [ "$LOCALFILES" = "no" ]; then
		fetch_file ${VPSURL}${VPSPATH}/mqvpn-server.json /etc/mqvpn/server.json
		fetch_file ${VPSURL}${VPSPATH}/mqvpn-server.service /lib/systemd/system/mqvpn.service
	else
		cp ${DIR}/mqvpn-server.json /etc/mqvpn/server.json
		cp ${DIR}/mqvpn-server.service /lib/systemd/system/mqvpn.service
	fi
	sed -i "s:PSK:$MQVPN_KEY:g" /etc/mqvpn/server.json
	if [ -n "$MQVPN_USERS" ] && [ "$MQVPN_USERS" != "null" ] && [ "$MQVPN_USERS" != "[]" ]; then
		jq_rewrite /etc/mqvpn/server.json --argjson users "$MQVPN_USERS" '.users = ($users + [.users[] | select(.name as $n | ($users | map(.name) | index($n)) == null)])' || true
	fi
	omr_self_signed_cert /etc/mqvpn/server.key /etc/mqvpn/server.crt
	chmod 644 /lib/systemd/system/mqvpn.service
	systemctl daemon-reload
	systemctl enable mqvpn.service
	echo "Install MQVPN done"
fi

if systemctl -q is-active fail2ban.service 2>/dev/null; then
	systemctl -q stop fail2ban > /dev/null 2>&1 || true
	systemctl -q disable fail2ban > /dev/null 2>&1 || true
fi
if [ "$FAIL2BAN" = "yes" ]; then
	echo "Install Fail2ban"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	apt-get -y install fail2ban python3-systemd
	systemctl enable fail2ban
	if [ "$LOCALFILES" = "no" ]; then
		fetch_file ${VPSURL}${VPSPATH}/fail2ban-jail-openmptcprouter.conf /etc/fail2ban/jail.d/openmptcprouter.conf
		fetch_file ${VPSURL}${VPSPATH}/fail2ban-filter-openvpn.conf /etc/fail2ban/filter.d/openvpn.conf
		fetch_file ${VPSURL}${VPSPATH}/fail2ban-filter-omradmin.conf /etc/fail2ban/filter.d/omradmin.conf
		fetch_file ${VPSURL}${VPSPATH}/fail2ban-filter-xray.conf /etc/fail2ban/filter.d/xray.conf
		fetch_file ${VPSURL}${VPSPATH}/fail2ban-filter-v2ray.conf /etc/fail2ban/filter.d/v2ray.conf
		fetch_file ${VPSURL}${VPSPATH}/fail2ban-filter-shadowsocks-go.conf /etc/fail2ban/filter.d/shadowsocks-go.conf
	else
		cp ${DIR}/fail2ban-jail-openmptcprouter.conf /etc/fail2ban/jail.d/openmptcprouter.conf
		cp ${DIR}/fail2ban-filter-openvpn.conf /etc/fail2ban/filter.d/openvpn.conf
		cp ${DIR}/fail2ban-filter-omradmin.conf /etc/fail2ban/filter.d/omradmin.conf
		cp ${DIR}/fail2ban-filter-xray.conf /etc/fail2ban/filter.d/xray.conf
		cp ${DIR}/fail2ban-filter-v2ray.conf /etc/fail2ban/filter.d/v2ray.conf
		cp ${DIR}/fail2ban-filter-shadowsocks-go.conf /etc/fail2ban/filter.d/shadowsocks-go.conf
	fi
	echo "Install Fail2ban done"
fi

if systemctl -q is-active openvpn-server@tun0.service 2>/dev/null; then
	systemctl -q stop openvpn-server@tun0 > /dev/null 2>&1 || true
	systemctl -q disable openvpn-server@tun0 > /dev/null 2>&1 || true
fi
if [ "$OPENVPN" = "yes" ]; then
	echo "Install OpenVPN"
	rm -f /var/lib/dpkg/lock
	rm -f /var/lib/dpkg/lock-frontend
	if [ "$VERSION_ID" = "13" ] && [ "$ID" = "debian" ]; then
		apt-get -y --allow-downgrades install openvpn easy-rsa
	else
		# Not --default-release: it takes a value, "install" became the
		# release and apt failed on "Invalid operation openvpn"
		apt-get -y install openvpn easy-rsa
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
		rm -f /tmp/EasyRSA-unix-v${EASYRSA_VERSION}.tgz
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
	# openvpn runs as nobody once started and re-reads the CRL when omr-admin
	# revokes a user: make-cadir creates /etc/openvpn/ca 0700, and then
	# openvpn can't reach crl.pem and keeps letting the revoked one in. Only
	# traversal, no listing; pki/private stays 0700.
	chmod 711 /etc/openvpn/ca /etc/openvpn/ca/pki >/dev/null 2>&1 || true
	if [ ! -f "/etc/openvpn/ca/pki/issued/openmptcprouter.crt" ]; then
		mv /etc/openvpn/ca/pki/issued/client.crt /etc/openvpn/ca/pki/issued/openmptcprouter.crt
		mv /etc/openvpn/ca/pki/private/client.key /etc/openvpn/ca/pki/private/openmptcprouter.key
	fi
	if [ ! -f "/etc/openvpn/server/dh2048.pem" ]; then
		openssl dhparam -out /etc/openvpn/server/dh2048.pem 2048
	fi
	# tun0.conf is written into place with a rename, never in place: omr-admin
	# rewrites this same file whenever it syncs client-to-client (and once at
	# every startup, which this script triggers), reading it line by line and
	# moving its own copy over it. Seen on a test VPS: wget logged
	# "'/etc/openvpn/tun0.conf' saved [770/770]" at 14:08:29 and omr-admin's
	# sync, one second later, left the file 0 bytes -- after which openvpn@tun0
	# only says "Options error: You must define TUN/TAP device (--dev)" and the
	# tunnel is down until someone looks. A rename is atomic, so omr-admin sees
	# either the old file or the new one, never a half-written one.
	if [ "$LOCALFILES" = "no" ]; then
		if [ "$KERNEL" != "5.4" ]; then
			wget -O /etc/openvpn/.tun0.conf.new ${VPSURL}${VPSPATH}/openvpn-tun0.6.1.conf && mv -f /etc/openvpn/.tun0.conf.new /etc/openvpn/tun0.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-tun1.6.1.conf /etc/openvpn/tun1.conf
		else
			wget -O /etc/openvpn/.tun0.conf.new ${VPSURL}${VPSPATH}/openvpn-tun0.conf && mv -f /etc/openvpn/.tun0.conf.new /etc/openvpn/tun0.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-tun1.conf /etc/openvpn/tun1.conf
		fi
		if [ "$OPENVPN_BONDING" = "yes" ]; then
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding1.conf /etc/openvpn/bonding1.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding2.conf /etc/openvpn/bonding2.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding3.conf /etc/openvpn/bonding3.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding4.conf /etc/openvpn/bonding4.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding5.conf /etc/openvpn/bonding5.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding6.conf /etc/openvpn/bonding6.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding7.conf /etc/openvpn/bonding7.conf
			fetch_file ${VPSURL}${VPSPATH}/openvpn-bonding8.conf /etc/openvpn/bonding8.conf
		fi
	else
		if [ "$KERNEL" != "5.4" ]; then
			cp ${DIR}/openvpn-tun0.6.1.conf /etc/openvpn/.tun0.conf.new && mv -f /etc/openvpn/.tun0.conf.new /etc/openvpn/tun0.conf
			cp ${DIR}/openvpn-tun1.6.1.conf /etc/openvpn/tun1.conf
		else
			cp ${DIR}/openvpn-tun0.conf /etc/openvpn/.tun0.conf.new && mv -f /etc/openvpn/.tun0.conf.new /etc/openvpn/tun0.conf
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
		# Everywhere but Debian 13, whose OpenMPTCProuter openvpn package has MPTCP
		if [ "$VERSION_ID" != "13" ] || [ "$ID" != "debian" ]; then
			mptcpize enable openvpn@tun0 >/dev/null 2>&1 || true
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
	systemctl -q stop 'glorytun-udp@*' > /dev/null 2>&1 || true
fi
if [ "$GLORYTUN_UDP" = "yes" ]; then
	if [ "$SOURCES" = "yes" ] || [ "$ARCH" != "amd64" ]; then
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
			fetch_file ${VPSURL}${VPSPATH}/glorytun-udp-run /usr/local/bin/glorytun-udp-run
		else
			cp ${DIR}/glorytun-udp-run /usr/local/bin/glorytun-udp-run
		fi
		chmod 755 /usr/local/bin/glorytun-udp-run
		if [ "$LOCALFILES" = "no" ]; then
			fetch_file ${VPSURL}${VPSPATH}/glorytun-udp%40.service.in /lib/systemd/system/glorytun-udp@.service
		else
			cp ${DIR}/glorytun-udp@.service.in /lib/systemd/system/glorytun-udp@.service
		fi
		chmod 644 /lib/systemd/system/glorytun-udp@.service
		#wget -O /lib/systemd/network/glorytun-udp.network ${VPSURL}${VPSPATH}/glorytun-udp.network
		rm -f /lib/systemd/network/glorytun-udp.network
		mkdir -p /etc/glorytun-udp
		if [ "$LOCALFILES" = "no" ]; then
			fetch_file ${VPSURL}${VPSPATH}/glorytun-udp-post.sh /etc/glorytun-udp/post.sh
			fetch_file ${VPSURL}${VPSPATH}/tun0.glorytun-udp /etc/glorytun-udp/tun0
		else
			cp ${DIR}/glorytun-udp-post.sh /etc/glorytun-udp/post.sh
			cp ${DIR}/tun0.glorytun-udp /etc/glorytun-udp/tun0
		fi
		chmod 755 /etc/glorytun-udp/post.sh
		# On an update that enables UDP, the key the router has is the TCP one:
		# test that first, the "no UDP key" case caught it before
		if [ "$update" != "0" ] && [ ! -f /etc/glorytun-udp/tun0.key ] && [ -f /etc/glorytun-tcp/tun0.key ]; then
			cp /etc/glorytun-tcp/tun0.key /etc/glorytun-udp/tun0.key
		elif [ "$update" = "0" ] || [ ! -f /etc/glorytun-udp/tun0.key ]; then
			echo "$GLORYTUN_PASS" > /etc/glorytun-udp/tun0.key
		fi
		harden_secret_files /etc/glorytun-udp/tun0.key
		systemctl enable glorytun-udp@tun0.service
		systemctl enable systemd-networkd.service
		cd /tmp
		rm -rf /tmp/glorytun-udp
	else
		rm -f /usr/local/bin/glorytun
		if ! apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-overwrite" install --reinstall omr-glorytun=${GLORYTUN_UDP_BINARY_VERSION}; then
			wget -O /tmp/omr-glorytun-${GLORYTUN_UDP_BINARY_VERSION}.deb ${VPSURL}debian/omr-glorytun_${GLORYTUN_UDP_BINARY_VERSION}_amd64.deb
			dpkg --force-confdef --force-confold --force-overwrite -i /tmp/omr-glorytun-${GLORYTUN_UDP_BINARY_VERSION}.deb
			rm -f /tmp/omr-glorytun-${GLORYTUN_UDP_BINARY_VERSION}.deb
		fi
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
		systemctl -q disable dsvpn-server > /dev/null 2>&1 || true
		systemctl -q stop dsvpn-server > /dev/null 2>&1 || true
	fi
	if [ "$SOURCES" = "yes" ] || [ "$ARCH" != "amd64" ]; then
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
			fetch_file ${VPSURL}${VPSPATH}/dsvpn-run /usr/local/bin/dsvpn-run
			fetch_file ${VPSURL}${VPSPATH}/dsvpn-server%40.service.in /lib/systemd/system/dsvpn-server@.service
			fetch_file ${VPSURL}${VPSPATH}/dsvpn0-config /etc/dsvpn/dsvpn0
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
		if ! apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-overwrite" install omr-dsvpn=${DSVPN_BINARY_VERSION}; then
			wget -O /tmp/omr-dsvpn-${DSVPN_BINARY_VERSION}.deb ${VPSURL}debian/omr-dsvpn_${DSVPN_BINARY_VERSION}_amd64.deb
			dpkg --force-confdef --force-confold --force-overwrite -i /tmp/omr-dsvpn-${DSVPN_BINARY_VERSION}.deb
			rm -f /tmp/omr-dsvpn-${DSVPN_BINARY_VERSION}.deb
		fi
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
	systemctl -q stop 'glorytun-tcp@*' > /dev/null 2>&1 || true
fi
if [ "$GLORYTUN_TCP" = "yes" ]; then
	echo "Install Glorytun-TCP..."
	if [ "$SOURCES" = "yes" ] || [ "$ARCH" != "amd64" ]; then
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
			rm -f /tmp/glorytun-0.0.35.tar.gz
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
			fetch_file ${VPSURL}${VPSPATH}/glorytun-tcp-run /usr/local/bin/glorytun-tcp-run
			fetch_file ${VPSURL}${VPSPATH}/glorytun-tcp%40.service.in /lib/systemd/system/glorytun-tcp@.service
			fetch_file ${VPSURL}${VPSPATH}/glorytun-tcp-post.sh /etc/glorytun-tcp/post.sh
			fetch_file ${VPSURL}${VPSPATH}/tun0.glorytun /etc/glorytun-tcp/tun0
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
		# Also on an update that enables TCP: glorytun-tcp can't start without
		# it. Same key as UDP when there is one, the router has a single key.
		if [ "$update" != "0" ] && [ ! -f /etc/glorytun-tcp/tun0.key ] && [ -f /etc/glorytun-udp/tun0.key ]; then
			cp /etc/glorytun-udp/tun0.key /etc/glorytun-tcp/tun0.key
		elif [ "$update" = "0" ] || [ ! -f /etc/glorytun-tcp/tun0.key ]; then
			echo "$GLORYTUN_PASS" > /etc/glorytun-tcp/tun0.key
		fi
		harden_secret_files /etc/glorytun-tcp/tun0.key
		systemctl enable glorytun-tcp@tun0.service
		#systemctl enable systemd-networkd.service
		cd /tmp
		rm -rf /tmp/glorytun-0.0.35
	else
		rm -f /usr/local/bin/glorytun-tcp
		if ! apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-overwrite" install --reinstall omr-glorytun-tcp=${GLORYTUN_TCP_BINARY_VERSION}; then
			wget -O /tmp/omr-glorytun-tcp-${GLORYTUN_TCP_BINARY_VERSION}.deb ${VPSURL}debian/omr-glorytun-tcp_${GLORYTUN_TCP_BINARY_VERSION}_amd64.deb
			dpkg --force-confdef --force-confold --force-overwrite -i /tmp/omr-glorytun-tcp-${GLORYTUN_TCP_BINARY_VERSION}.deb
			rm -f /tmp/omr-glorytun-tcp-${GLORYTUN_TCP_BINARY_VERSION}.deb
		fi
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
		# Check if SoftEther VPN is available... The command line comes as
		# one string, like $softetherrun is used everywhere: split it. As
		# "$@" it was one word, never a command, and this waited forever.
		_softether_wait=0
		# shellcheck disable=SC2086
		while ! $1 About >/dev/null 2>&1; do
			_softether_wait=$((_softether_wait+1))
			if [ "$_softether_wait" -ge 120 ]; then
				echo "WARNING: SoftEther VPN server not answering after 2 minutes" >&2
				return 1
			fi
			sleep 1
			printf '.'
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
		jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json --arg softether_password $softether_password '. + {softethervpn_admin_password: $softether_password}'
	else
		softetherdefault="vpncmd 127.0.0.1:65390 /SERVER /CSV /PASSWORD:$softether_password"
	fi

	softherether_user_name=$DEFAULT_USER
	softether_user_password=$(cat /etc/openmptcprouter-vps-admin/omr-admin-config.json | jq -r .users[0].openmptcprouter.softethervpn | tr -d "\n")
	#echo "softether user : $softether_user_password"
	if [ "$softether_user_password" = "null" ]; then
		#echo "Generate user password"
		softether_user_password=$SOFTETHERVPN_PASS_USER
		jq_rewrite /etc/openmptcprouter-vps-admin/omr-admin-config.json --arg softether_user_password $softether_user_password '(.users[0].openmptcprouter) += {softethervpn: $softether_user_password}'
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

# Post-install permission sweep: every secret-bearing config/key file the
# script above may have created or rewritten gets re-hardened to root:root
# 0600 here as a final safety net, regardless of which features were
# enabled. See https://github.com/Ysurac/openmptcprouter-vps/issues/132
harden_secret_files \
	/etc/openmptcprouter-vps-admin/omr-admin-config.json \
	/etc/openmptcprouter-vps-admin/omr-admin-config.json.bak \
	/etc/xray/xray-server.json \
	/etc/xray/xray-server.json.bak \
	/etc/xray/xray-vless-reality.json \
	/etc/v2ray/v2ray-server.json \
	/etc/mqvpn/server.json \
	/etc/mqvpn/server.key \
	/root/wireguard-client.conf \
	/root/openmptcprouter_config.txt \
	/var/log/omr-update.log \
	/etc/shadowsocks-libev/manager.json \
	/etc/shadowsocks-go/server.json \
	/etc/shadowsocks-go/upsks.json \
	/etc/glorytun-tcp/tun*.key \
	/etc/glorytun-udp/tun*.key \
	/etc/dsvpn/dsvpn*.key

# Load tun module at boot time
if ! grep -q tun /etc/modules ; then
	echo tun >> /etc/modules
fi

# Add multipath utility
if [ "$LOCALFILES" = "no" ]; then
	fetch_file ${VPSURL}${VPSPATH}/multipath /usr/local/bin/multipath
else
	cp ${DIR}/multipath /usr/local/bin/multipath
fi
chmod 755 /usr/local/bin/multipath

# Add omr-test-speed utility
if [ "$LOCALFILES" = "no" ]; then
	fetch_file ${VPSURL}${VPSPATH}/omr-test-speed /usr/local/bin/omr-test-speed
else
	cp ${DIR}/omr-test-speed /usr/local/bin/omr-test-speed
fi
chmod 755 /usr/local/bin/omr-test-speed

# Add OpenMPTCProuter service
if [ "$LOCALFILES" = "no" ]; then
	fetch_file ${VPSURL}${VPSPATH}/omr-service /usr/local/bin/omr-service
	fetch_file ${VPSURL}${VPSPATH}/omr.service.in /lib/systemd/system/omr.service
	fetch_file ${VPSURL}${VPSPATH}/omr-6in4-run /usr/local/bin/omr-6in4-run
	fetch_file ${VPSURL}${VPSPATH}/omr6in4%40.service.in /lib/systemd/system/omr6in4@.service
	fetch_file ${VPSURL}${VPSPATH}/omr-vxlan-run /usr/local/bin/omr-vxlan-run
	fetch_file ${VPSURL}${VPSPATH}/omr-vxlan%40.service.in /lib/systemd/system/omr-vxlan@.service
	fetch_file ${VPSURL}${VPSPATH}/omr-bypass /usr/local/bin/omr-bypass
	fetch_file ${VPSURL}${VPSPATH}/omr-bypass.service.in /lib/systemd/system/omr-bypass.service
	fetch_file ${VPSURL}${VPSPATH}/omr-bypass.timer.in /lib/systemd/system/omr-bypass.timer
	fetch_file ${VPSURL}${VPSPATH}/omr-reserved-ports /usr/local/bin/omr-reserved-ports
	fetch_file ${VPSURL}${VPSPATH}/omr-reserved-ports.service.in /lib/systemd/system/omr-reserved-ports.service
	fetch_file ${VPSURL}${VPSPATH}/omr-reserved-ports.path.in /lib/systemd/system/omr-reserved-ports.path
	fetch_file ${VPSURL}${VPSPATH}/omr-net-mem /usr/local/bin/omr-net-mem
	fetch_file ${VPSURL}${VPSPATH}/omr-net-mem.service.in /lib/systemd/system/omr-net-mem.service
else
	cp ${DIR}/omr-service /usr/local/bin/omr-service
	cp ${DIR}/omr.service.in /lib/systemd/system/omr.service
	cp ${DIR}/omr-6in4-run /usr/local/bin/omr-6in4-run
	cp ${DIR}/omr6in4@.service.in /lib/systemd/system/omr6in4@.service
	cp ${DIR}/omr-vxlan-run /usr/local/bin/omr-vxlan-run
	cp ${DIR}/omr-vxlan@.service.in /lib/systemd/system/omr-vxlan@.service
	cp ${DIR}/omr-bypass /usr/local/bin/omr-bypass
	cp ${DIR}/omr-bypass.service.in /lib/systemd/system/omr-bypass.service
	cp ${DIR}/omr-bypass.timer.in /lib/systemd/system/omr-bypass.timer
	cp ${DIR}/omr-reserved-ports /usr/local/bin/omr-reserved-ports
	cp ${DIR}/omr-reserved-ports.service.in /lib/systemd/system/omr-reserved-ports.service
	cp ${DIR}/omr-reserved-ports.path.in /lib/systemd/system/omr-reserved-ports.path
	cp ${DIR}/omr-net-mem /usr/local/bin/omr-net-mem
	cp ${DIR}/omr-net-mem.service.in /lib/systemd/system/omr-net-mem.service

fi
chmod 644 /lib/systemd/system/omr.service
chmod 644 /lib/systemd/system/omr6in4@.service
chmod 644 /lib/systemd/system/omr-vxlan@.service
chmod 755 /usr/local/bin/omr-service
chmod 755 /usr/local/bin/omr-bypass
chmod 755 /usr/local/bin/omr-6in4-run
chmod 755 /usr/local/bin/omr-vxlan-run
chmod 644 /lib/systemd/system/omr-bypass.service
chmod 644 /lib/systemd/system/omr-bypass.timer
chmod 755 /usr/local/bin/omr-reserved-ports
chmod 644 /lib/systemd/system/omr-reserved-ports.service
chmod 644 /lib/systemd/system/omr-reserved-ports.path
chmod 755 /usr/local/bin/omr-net-mem
chmod 644 /lib/systemd/system/omr-net-mem.service
systemctl daemon-reload
if systemctl -q is-active omr-6in4.service 2>/dev/null; then
	systemctl -q stop omr-6in4 > /dev/null 2>&1 || true
	systemctl -q disable omr-6in4 > /dev/null 2>&1 || true
fi
systemctl enable omr6in4@user0.service
systemctl enable omr-vxlan@user0.service
systemctl enable omr.service
systemctl enable omr-bypass.timer
systemctl enable omr-bypass.service
systemctl enable omr-reserved-ports.service
systemctl enable omr-reserved-ports.path
systemctl enable omr-net-mem.service

# Change SSH port to 65222. Only a "Port 22" line, commented or not, is
# changed, matched whole: 's:Port 22:...:g' also turned "Port 2222" into
# "Port 6522222", a config sshd refuses at the next boot. With no Port line at
# all sshd listens on 22, so one is added, at the top: after a Match block
# sshd would reject it.
cp -pf /etc/ssh/sshd_config /etc/ssh/sshd_config.omr-bak
sed -i -E 's/^#?[[:space:]]*Port[[:space:]]+22[[:space:]]*$/Port 65222/' /etc/ssh/sshd_config
grep -qE '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config || sed -i '1i Port 65222' /etc/ssh/sshd_config
# ...and make it effective now. The nftables ruleset loaded further down opens
# 65222 and rejects 22, so a running sshd left on port 22 until the next reboot
# means no new SSH connection can reach this VPS at all, while the summary
# printed at the end of this script already announces port 65222. The session
# running this script survives (conntrack keeps it established), which is
# precisely why the window went unnoticed; a dropped connection during it, or
# any second login, needed the provider's console to get back in. Restarting
# sshd never drops established sessions, only new connections use the new port.
if sshd -t >/dev/null 2>&1; then
	systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || echo "WARNING: could not restart sshd, SSH stays on port 22 until this VPS reboots" >&2
else
	echo "WARNING: sshd -t rejects /etc/ssh/sshd_config, not restarting sshd" >&2
	# Don't leave sshd a config it refuses to start with at the next boot
	if sshd -t -f /etc/ssh/sshd_config.omr-bak >/dev/null 2>&1; then
		cp -pf /etc/ssh/sshd_config.omr-bak /etc/ssh/sshd_config
		echo "WARNING: /etc/ssh/sshd_config restored as it was before this script" >&2
	fi
	echo "WARNING: SSH stays on its current port, and the firewall below only opens 65222" >&2
fi

# Remove Bind9 if available
#systemctl -q disable bind9

# Remove fail2ban if available
#systemctl -q disable fail2ban

# Install and configure the firewall using native nftables
apt-get -y install nftables
mkdir -p /etc/nftables
# Drop-in dir for the admin's own rules (see nftables.conf/nftables/omr.nft) --
# only ever created here, never written to or emptied, so anything already
# there survives every re-run of this installer, including on update.
mkdir -p /etc/nftables/custom.d
# Drop-in for the stock nftables.service: try-restarts omr-admin after every
# nftables start/reload (both re-run `flush ruleset`), so it repopulates its
# dynamic chains from omr-admin-config.json whoever reloaded the firewall,
# not only this script's update path (see nftables/omr-admin-resync.conf).
# Another one runs omr-bypass, which puts its inet omr_bypass table back (see
# nftables/omr-bypass-resync.conf).
mkdir -p /etc/systemd/system/nftables.service.d
# Drop-in for the stock systemd-networkd-wait-online.service: it blocks the boot
# until every managed link is up, so a VPS whose IPv6 never becomes routable
# waits out the full 90s unit timeout on every boot (see
# systemd/20-omr-wait-online-any.conf).
mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
if [ "$LOCALFILES" = "no" ]; then
	fetch_file ${VPSURL}${VPSPATH}/nftables.conf /etc/nftables.conf
	fetch_file ${VPSURL}${VPSPATH}/nftables/omr-vars.nft /etc/nftables/omr-vars.nft
	fetch_file ${VPSURL}${VPSPATH}/nftables/omr.nft /etc/nftables/omr.nft
	fetch_file ${VPSURL}${VPSPATH}/nftables/omr-admin-resync.conf /etc/systemd/system/nftables.service.d/omr-admin-resync.conf
	fetch_file ${VPSURL}${VPSPATH}/nftables/omr-bypass-resync.conf /etc/systemd/system/nftables.service.d/omr-bypass-resync.conf
	fetch_file ${VPSURL}${VPSPATH}/systemd/20-omr-wait-online-any.conf /etc/systemd/system/systemd-networkd-wait-online.service.d/20-omr-wait-online-any.conf
else
	cp ${DIR}/nftables.conf /etc/nftables.conf
	cp ${DIR}/nftables/omr-vars.nft /etc/nftables/omr-vars.nft
	cp ${DIR}/nftables/omr.nft /etc/nftables/omr.nft
	cp ${DIR}/nftables/omr-admin-resync.conf /etc/systemd/system/nftables.service.d/omr-admin-resync.conf
	cp ${DIR}/nftables/omr-bypass-resync.conf /etc/systemd/system/nftables.service.d/omr-bypass-resync.conf
	cp ${DIR}/systemd/20-omr-wait-online-any.conf /etc/systemd/system/systemd-networkd-wait-online.service.d/20-omr-wait-online-any.conf
fi
[ -n "$INTERFACE" ] && sed -i "/^define NET_IFACE6 /!s:eth0:$INTERFACE:g" /etc/nftables/omr-vars.nft
# The IPv6 WAN can be another NIC (openmptcprouter#3271); INTERFACE6 falls back to $INTERFACE.
[ -n "$INTERFACE6" ] && sed -i "/^define NET_IFACE6 /s:eth0:$INTERFACE6:" /etc/nftables/omr-vars.nft
# Static-IP optimization: replace the IPv4 masquerade with an explicit SNAT to
# the WAN source IP. The src token position varies with the route's proto
# field ("default via GW dev IF proto static src IP ..."), so walk the fields
# instead of hardcoding $7 -- that used to emit "snat ip to static" and make
# the whole nftables.conf fail to load. Skipped on dhcp-managed routes (the IP
# can change) and scoped to the "ip saddr" line so the IPv6 masquerade below
# it is left alone.
VPS_SRC_IP="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if ($i=="src") {print $(i+1); exit}}')"
if [ -n "$VPS_SRC_IP" ] && [ -z "$(ip -4 route show default 2>/dev/null | grep -w dhcp)" ]; then
	sed -i "/ip saddr/s/masquerade/snat ip to $VPS_SRC_IP/" /etc/nftables/omr.nft
fi
# nf_nat_ftp, the NAT half of omr.nft's FTP helper, now and at boot. Where it
# can't be loaded (a container), drop the FTP lines: the helper object would
# make the whole ruleset fail to load. A container can't modprobe, but can use
# the module when its host has already loaded it.
if modprobe nf_nat_ftp >/dev/null 2>&1 || [ -d /sys/module/nf_nat_ftp ]; then
	echo nf_nat_ftp > /etc/modules-load.d/omr-ftp.conf
else
	rm -f /etc/modules-load.d/omr-ftp.conf
	sed -i '/ct helper ftp \|ct helper set "ftp"/d' /etc/nftables/omr.nft
fi
systemctl mask --now shorewall shorewall6 >/dev/null 2>&1 || true
# Stopping shorewall leaves its stoppedrules in place (ADMINISABSENTMINDED=Yes),
# which drop every new WAN connection, SSH included. The nftables flush below
# only removes them when shorewall used the nft backend of iptables, not with
# iptables-legacy: clear them.
command -v shorewall >/dev/null 2>&1 && { shorewall clear >/dev/null 2>&1 || true; }
command -v shorewall6 >/dev/null 2>&1 && { shorewall6 clear >/dev/null 2>&1 || true; }
command -v ufw >/dev/null 2>&1 && ufw --force disable >/dev/null 2>&1 || true
systemctl mask --now ufw firewalld >/dev/null 2>&1 || true
systemctl daemon-reload
systemctl enable --now nftables
# With forwarding on, the kernel ignores RAs where accept_ra is 1 and drops
# the default routes they gave (openmptcprouter-vps#63). Keep them with 2 on
# the WAN where the kernel handles RAs, set before forwarding; 0 means a
# network manager handles them (networkd, NetworkManager), or none are wanted.
OMR_RA_IFACES=""
for intf in $(printf '%s\n%s\n' "$INTERFACE" "$INTERFACE6" | sort -u); do
	case "$(cat "/proc/sys/net/ipv6/conf/$intf/accept_ra" 2>/dev/null)" in
		1|2) OMR_RA_IFACES="$OMR_RA_IFACES $intf" ;;
	esac
done
for intf in $OMR_RA_IFACES; do
	echo "net.ipv6.conf.$(echo "$intf" | tr . /).accept_ra = 2"
done > /etc/sysctl.d/90-omr-forwarding.conf
cat >> /etc/sysctl.d/90-omr-forwarding.conf <<-EOF
	net.ipv4.ip_forward = 1
	net.ipv6.conf.all.forwarding = 1
EOF
# ifupdown sets accept_ra again at every ifup ("inet6 dhcp" sets 1).
if [ -d /etc/network/if-up.d ]; then
	cat > /etc/network/if-up.d/omr-accept-ra <<-'EOF'
	#!/bin/sh
	# OpenMPTCProuter VPS: put back the accept_ra 2 that ifup reset, on the
	# interfaces /etc/sysctl.d/90-omr-forwarding.conf gives it to.
	key="net.ipv6.conf.$(echo "$IFACE" | tr . /).accept_ra"
	grep -qxF "$key = 2" /etc/sysctl.d/90-omr-forwarding.conf 2>/dev/null || exit 0
	sysctl -q -e -w "$key=2" || true
	EOF
	chmod 755 /etc/network/if-up.d/omr-accept-ra
fi
sysctl -p /etc/sysctl.d/90-omr-forwarding.conf > /dev/null 2>&1 || true
[ -z "$(grep nf_conntrack_sip /etc/modprobe.d/blacklist.conf)" ] && echo 'blacklist nf_conntrack_sip' >> /etc/modprobe.d/blacklist.conf
if [ "$ID" = "debian" ] && [ "$VERSION_ID" = "10" ]; then
	apt-get -y install iptables
	update-alternatives --set iptables /usr/sbin/iptables-legacy
	update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
fi

# Limit /var/log/journal size
sed -i 's/#SystemMaxUse=/SystemMaxUse=100M/' /etc/systemd/journald.conf

if [ "$BPFTUNE" = "yes" ] && [ "$ARCH" = "amd64" ]; then
	apt-get -y install bpftune
	systemctl enable bpftune
fi

if [ "$TLS" = "yes" ]; then
	VPS_CERT=0
	apt-get -y install socat cron
	# ping prints to stdout even when nothing answers: test its exit status
	if [ "$VPS_DOMAIN" != "" ] && [ "$(getent hosts "$VPS_DOMAIN" | awk '{ print $1; exit }')" != "" ] && ping -q -c 1 -w 1 "$VPS_DOMAIN" >/dev/null 2>&1; then
		# acme.sh issues ECC certificates by default since 3.0.6, in
		# <domain>_ecc/: looking only in <domain>/ never found one, so the API
		# kept its self-signed certificate and every run issued a new one with
		# --force, into Let's Encrypt's duplicate certificate rate limit
		acme_dir() {
			for _acme_d in "/root/.acme.sh/${VPS_DOMAIN}_ecc" "/root/.acme.sh/${VPS_DOMAIN}"; do
				[ -f "$_acme_d/$VPS_DOMAIN.cer" ] && { echo "$_acme_d"; return 0; }
			done
			return 0
		}
		ACME_DIR="$(acme_dir)"
		# omr-admin reads its certificate once, at start: restart it on renewal
		ACME_RELOAD='systemctl try-restart omr-admin'
		if [ -z "$ACME_DIR" ]; then
			echo "Generate certificate for V2Ray"
			set +e
			curl https://get.acme.sh | sh
			~/.acme.sh/acme.sh --force --alpn --issue -d "$VPS_DOMAIN" --reloadcmd "$ACME_RELOAD" --pre-hook 'nft add rule inet omr install_tmp tcp dport 443 accept >/dev/null 2>&1' --post-hook 'nft flush chain inet omr install_tmp >/dev/null 2>&1' >/dev/null 2>&1
			set -e
			ACME_DIR="$(acme_dir)"
			if [ -n "$ACME_DIR" ]; then
				rm -f /etc/openmptcprouter-vps-admin/cert.pem
				ln -s "$ACME_DIR/fullchain.cer" /etc/openmptcprouter-vps-admin/cert.pem
				rm -f /etc/openmptcprouter-vps-admin/key.pem
				ln -s "$ACME_DIR/$VPS_DOMAIN.key" /etc/openmptcprouter-vps-admin/key.pem
			fi
#			mkdir -p /etc/ssl/v2ray
#			ln -f -s /root/.acme.sh/$reverse/$reverse.key /etc/ssl/v2ray/omr.key
#			ln -f -s /root/.acme.sh/$reverse/fullchain.cer /etc/ssl/v2ray/omr.cer
		elif [ "$(readlink /etc/openmptcprouter-vps-admin/cert.pem)" = "$ACME_DIR/$VPS_DOMAIN.cer" ]; then
			# Linked by an earlier run to the certificate alone: clients that
			# verify it need the intermediate too. Same key, so same pin.
			[ -f "$ACME_DIR/fullchain.cer" ] && ln -sfn "$ACME_DIR/fullchain.cer" /etc/openmptcprouter-vps-admin/cert.pem
			ACME_ECC=""
			[ "$ACME_DIR" = "/root/.acme.sh/${VPS_DOMAIN}_ecc" ] && ACME_ECC="--ecc"
			~/.acme.sh/acme.sh --install-cert -d "$VPS_DOMAIN" $ACME_ECC --reloadcmd "$ACME_RELOAD" >/dev/null 2>&1 || true
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
	# Not silent any more: when this does not install, the VPS is left with no
	# omr-server package and no version marker, and the two ways it fails look
	# identical from the outside -- an unresolvable version (a pin in
	# debian/control that drifted, or a version never published) and apt being
	# OOM-killed on a small VPS, which is what a kernel .deb left in the tmpfs
	# /tmp used to cause.
	if apt-cache madison omr-server 2>/dev/null | awk -F'|' -v v="$OMR_VERSION" '{gsub(/ /, "", $2)} $2 == v {f = 1} END {exit !f}'; then
		omr_server_install="$(apt-get -y install omr-server=${OMR_VERSION} 2>&1)" || {
			echo "WARNING: omr-server=${OMR_VERSION} was not installed, this VPS keeps no version marker:" >&2
			printf '%s\n' "$omr_server_install" | tail -n 5 >&2
		}
	else
		# This release has no omr-server deb (a rolling-test not published
		# yet): an older one left installed claims a version this VPS does not
		# run, and its /usr/share/omr-server holds an older copy of this script.
		echo "omr-server ${OMR_VERSION} is not in the repository, not installing it"
		if [ "$(dpkg-query -W -f='${Status}' omr-server 2>/dev/null)" = "install ok installed" ] && [ "$(dpkg-query -W -f='${Version}' omr-server)" != "$OMR_VERSION" ]; then
			echo "Removing omr-server $(dpkg-query -W -f='${Version}' omr-server), it is not this release"
			dpkg -r omr-server || echo "WARNING: omr-server could not be removed" >&2
		fi
	fi
	rm -f /etc/openmptcprouter-vps-admin/update-bin
fi

# Give one last start to every service left failed by the install order. A deb
# that ships its own configuration starts its daemon before this script has
# written the OpenMPTCProuter one (xray's upstream config.json carries
# "geoip:private" routing rules while no geoip.dat is installed, and mlvpn
# refuses a config file that is still group/other readable, chmod 0600 coming
# later), so the unit fails a few times, reaches StartLimitBurst and stays
# dead: from then on even `systemctl restart` is a silent no-op ("Start request
# repeated too quickly") until the counter is reset or the VPS reboots. The
# update path restarts everything at its end, a fresh install did not, which is
# how a brand new VPS ended up with xray and mlvpn failed while both their
# configuration files on disk were perfectly valid.
# Reserve the ports our own services listen on (the v2ray/xray API inbounds,
# the dokodemo-door inbounds of forwarded ports, VXLAN...) before the restarts
# below, so no outgoing connection can be sitting on one of them when a daemon
# binds it. The path unit keeps the list current from here on.
# Size tcp_mem/udp_mem from this VPS's RAM now, not at the next boot: the new
# 90-shadowsocks.conf no longer sets them, but the running kernel still has
# whatever the previous one did.
echo "Sizing TCP/UDP socket memory from RAM..."
/usr/local/bin/omr-net-mem --quiet || echo "WARNING: omr-net-mem failed" >&2

echo "Reserving the local ports of OpenMPTCProuter services..."
/usr/local/bin/omr-reserved-ports --quiet || echo "WARNING: omr-reserved-ports failed" >&2
systemctl -q restart omr-reserved-ports.path >/dev/null 2>&1 || true

echo "Check services left failed by the install order..."
for unit in shadowsocks-libev-manager@manager shadowsocks-go v2ray xray mlvpn@mlvpn0 mqvpn dsvpn-server@dsvpn0 glorytun-tcp@tun0 glorytun-udp@tun0 omr-admin omr; do
	systemctl is-enabled -q "$unit" 2>/dev/null || continue
	systemctl is-failed -q "$unit" 2>/dev/null || continue
	echo " ${unit} is failed, resetting its start counter and starting it again"
	systemctl reset-failed "$unit" >/dev/null 2>&1 || true
	systemctl start "$unit" >/dev/null 2>&1 || echo "WARNING: ${unit} still fails to start, see journalctl -u ${unit}" >&2
done

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
	if [ "$MQVPN" = "yes" ]; then
		echo 'MQVPN port: 65443'
		echo 'Your MQVPN key: '
		echo $MQVPN_KEY
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		echo "OpenMPTCProuter API Admin key (only for configuration via API, you don't need it): "
		echo $OMR_ADMIN_PASS_ADMIN
		echo 'OpenMPTCProuter Server key: '
		echo "\033[1m${OMR_ADMIN_PASS}\033[0m"
		echo 'OpenMPTCProuter Server username: '
		echo 'openmptcprouter'
		OMR_API_PIN="$(omr_api_pin)"
		if [ -n "$OMR_API_PIN" ]; then
			echo 'OpenMPTCProuter Server API certificate pin (optional, "Server API certificate pin" in the router wizard): '
			echo "$OMR_API_PIN"
		fi
	fi
	if [ "$VPS_CERT" = "0" ]; then
		echo 'No working domain detected, not able to generate certificate for v2ray.'
		echo 'You can set VPS_DOMAIN to a working domain if you want a certificate.'
	fi
	echo '===================================================================================='
	echo 'Keys are also saved in /root/openmptcprouter_config.txt, you are free to remove them'
	echo '===================================================================================='
	echo '\033[1m  /!\ You need to reboot to enable MPTCP, shadowsocks and glorytun /!\ \033[0m'
	echo '------------------------------------------------------------------------------------'
	check_running_kernel || true
	echo '===================================================================================='

	# Save info in file, readable by root only: it holds every key
	install -m 600 /dev/null /root/openmptcprouter_config.txt
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
	if [ "$MQVPN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		MQVPN port: 65443
		Your MQVPN key: $MQVPN_KEY
		EOF
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		cat >> /root/openmptcprouter_config.txt <<-EOF
		Your OpenMPTCProuter ADMIN API Server key (only for configuration via API access, you don't need it): $OMR_ADMIN_PASS_ADMIN
		Your OpenMPTCProuter Server key: $OMR_ADMIN_PASS
		Your OpenMPTCProuter Server username: openmptcprouter
		EOF
		[ -n "$OMR_API_PIN" ] && echo "Your OpenMPTCProuter Server API certificate pin: $OMR_API_PIN" >> /root/openmptcprouter_config.txt
	fi
	#systemctl -q restart sshd
else
	echo '===================================================================================='
	echo "OpenMPTCProuter Server is now updated to version $OMR_VERSION !"
	echo 'Keys are not changed'
	echo 'You need OpenMPTCProuter >= 0.30'
	echo '===================================================================================='
	echo 'Restarting systemd daemon...'
	systemctl -q daemon-reload
	echo 'done'
	echo 'Restarting systemd network...'
	restart_or_warn systemd-networkd
	echo 'done'
	if [ "$MLVPN" = "yes" ]; then
		echo 'Restarting mlvpn...'
		restart_or_warn mlvpn@mlvpn0
		echo 'done'
	fi
	if [ "$V2RAY" = "yes" ]; then
		echo 'Restarting v2ray...'
		restart_or_warn v2ray
		echo 'done'
	fi
	if [ "$XRAY" = "yes" ]; then
		echo 'Restarting xray...'
		restart_or_warn xray
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
	systemctl -q restart 'omr6in4@*' || true
	echo 'done'
	if [ "$OPENVPN" = "yes" ]; then
		echo 'Restarting OpenVPN'
		restart_or_warn openvpn@tun0
		restart_or_warn openvpn@tun1
		echo 'done'
	fi
	if [ "$WIREGUARD" = "yes" ]; then
		echo 'Restarting WireGuard'
		restart_or_warn wg-quick@wg0
		echo 'done'
	fi
	if [ "$OMR_ADMIN" = "yes" ]; then
		echo 'Restarting OpenMPTCProuter VPS admin'
		restart_or_warn omr-admin
		echo 'done'
		# Not when the file is gone: the summary says it can be removed, and
		# printing the key again would only put it in /var/log/omr-update.log
		if [ -f /root/openmptcprouter_config.txt ] && ! grep -q 'Server key' /root/openmptcprouter_config.txt ; then
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
		elif [ -f /root/openmptcprouter_config.txt ]; then
			echo '!!! Keys are in /root/openmptcprouter_config.txt !!!'
		fi
		OMR_API_PIN="$(omr_api_pin)"
		if [ -n "$OMR_API_PIN" ]; then
			if [ -n "$OMR_API_PIN_BEFORE" ] && [ "$OMR_API_PIN" != "$OMR_API_PIN_BEFORE" ]; then
				echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
				echo 'The OpenMPTCProuter API certificate key changed: routers that pinned the previous'
				echo 'one refuse this server. Enter the new pin as "Server API certificate pin" in the'
				echo 'router wizard, or empty that field:'
				echo "$OMR_API_PIN"
				echo '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
			fi
			if [ -f /root/openmptcprouter_config.txt ]; then
				sed -i '/^Your OpenMPTCProuter Server API certificate pin:/d' /root/openmptcprouter_config.txt
				echo "Your OpenMPTCProuter Server API certificate pin: $OMR_API_PIN" >> /root/openmptcprouter_config.txt
			fi
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
	restart_or_warn omr
	echo 'done'
	if [ "$SHADOWSOCKS" = "yes" ]; then
		echo 'Restarting shadowsocks...'
		restart_or_warn shadowsocks-libev-manager@manager
	fi
	if [ "$SHADOWSOCKS_GO" = "yes" ]; then
		echo 'Restarting shadowsocks-go...'
		restart_or_warn shadowsocks-go
	fi
#	if [ $NBCPU -gt 1 ]; then
#		for i in $NBCPU; do
#			systemctl restart shadowsocks-libev-server@config$i
#		done
#	fi
	echo 'done'
	echo 'Restarting nftables...'
	# Reloads the freshly-rewritten /etc/nftables.conf; that flushes the whole
	# ruleset including omr-vps-admin's dynamic chains (user_accept, etc.),
	# so restart omr-admin right after -- it repopulates them from its own
	# persisted state on startup (see omradmin.py's _nft_resync_all()). That
	# same startup resync also re-adds OpenVPN's client-to-client directive
	# to tun0.conf if needed, which the OpenVPN block above this also just
	# unconditionally regenerated from template.
	systemctl -q restart nftables >/dev/null 2>&1 || true
	systemctl -q restart omr-admin >/dev/null 2>&1 || true
	echo 'done'
	if [ "$FAIL2BAN" = "yes" ]; then
		echo 'Restarting fail2ban...'
		restart_or_warn fail2ban
		echo 'done'
	fi
	echo '===================================================================================='
	echo '\033[1m  /!\ You need to reboot to use latest MPTCP kernel /!\ \033[0m'
	echo '------------------------------------------------------------------------------------'
	check_running_kernel || true
	echo '===================================================================================='
fi
exit 0
