#!/bin/sh
set -e
umask 0022
export LC_ALL=C

#rm -f /var/lib/dpkg/lock
#rm -f /var/cache/apt/archives/lock

# Check Linux version
if test -f /etc/os-release ; then
	. /etc/os-release
else
	. /usr/lib/os-release
fi
if [ "$ID" = "debian" ] && [ "$VERSION_ID" != "9" ]; then
	echo "This script only work with Debian Stretch (9.x)"
	exit 1
elif [ "$ID" != "debian" ]; then
	echo "This script only work with Debian Stretch (9.x)"
	exit 1
fi

apt-get update
apt-get -y install apt-transport-https

echo 'deb https://repo.openmptcprouter.com stretch main' > /etc/apt/sources.list.d/openmptcprouter.list
cat <<EOF | tee /etc/apt/preferences.d/openmptcprouter.pref
Explanation: Prefer OpenMPTCProuter provided packages over the Debian native ones
Package: *
Pin: origin repo.openmptcprouter.com
Pin-Priority: 1001
EOF

echo 'deb http://deb.debian.org/debian stretch-backports main' > /etc/apt/sources.list.d/stretch-backports.list
wget -O - http://repo.openmptcprouter.com/openmptcprouter.gpg.key | apt-key add -
apt-get update
apt-get -y install dirmngr patch rename curl
# Rename bzImage to vmlinuz, needed when custom kernel was used
cd /boot
rename 's/^bzImage/vmlinuz/s' * >/dev/null 2>&1
#rm -f /var/lib/dpkg/lock
#rm -f /var/cache/apt/archives/lock
rm -f /etc/kernel-img.conf
echo "Install all"
DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-overwrite" -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install omr-vps

systemctl -q enable shorewall
systemctl -q enable shorewall6

# Change SSH port to 65222
sed -i 's:#Port 22:Port 65222:g' /etc/ssh/sshd_config
sed -i 's:Port 22:Port 65222:g' /etc/ssh/sshd_config

echo "OpenMPTCProuter VPS is now installed !"
cat /root/openmptcprouter_config.txt
