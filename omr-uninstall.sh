#!/bin/sh
#
# Copyright (C) 2018-2026 Ycarus (Yannick Chabanois) <ycarus@zugaina.org> for OpenMPTCProuter
#
# This is free software, licensed under the GNU General Public License v3 or later.
# See /LICENSE for more information.
#
# Remove what debian9-x86_64.sh installed: the OpenMPTCProuter services, their
# packages, configuration and keys, the firewall, the apt repository, the SSH
# port change and the OpenMPTCProuter kernel.
#
# Left in place, because they are not OpenMPTCProuter's alone or can't be
# undone: the Debian release upgrade the installer may have done, generic
# packages it installed (python3-*, jq, curl, chrony, fail2ban, wireguard-tools,
# nftables, easy-rsa...), acme.sh and its certificate, Pi-hole (omr-pihole.sh).
#
# Everything removed under /etc and /root is saved first in
# /root/omr-uninstall-backup-<date>.tar.gz (keys included, mode 0600).
#
# Options, as environment variables like the installer's:
#   ASSUME_YES=yes        don't ask for confirmation
#   BACKUP=no             don't save the configuration before removing it
#   RESTORE_SSH_PORT=no   keep sshd on port 65222
#   REMOVE_KERNEL=no      keep the OpenMPTCProuter kernel and the GRUB default
#
# The running kernel can't be removed safely: when the VPS runs the
# OpenMPTCProuter kernel, this script makes the distribution kernel the GRUB
# default and leaves the running one; reboot and run it again to remove it.
# Running it again is always safe, every step skips what is already gone.

ASSUME_YES=${ASSUME_YES:-no}
BACKUP=${BACKUP:-yes}
RESTORE_SSH_PORT=${RESTORE_SSH_PORT:-yes}
REMOVE_KERNEL=${REMOVE_KERNEL:-yes}

# No set -e: a removal that fails half way would leave the VPS in a state
# neither the installer nor this script expects. Each step reports its own
# failure and the next one runs anyway.
umask 0022
export LC_ALL=C
export PATH=$PATH:/sbin:/usr/sbin
export DEBIAN_FRONTEND=noninteractive

warn() {
	echo "WARNING: $*" >&2
}

if [ "$(id -u)" != "0" ]; then
	echo "This script must be run as root" >&2
	exit 1
fi

# Set by debian9-x86_64.sh while it runs (omr-update runs it too). Removing
# packages under a running install would have both fighting over dpkg.
if [ -e /run/omr-install.running ]; then
	echo "An OpenMPTCProuter install or update is running (/run/omr-install.running)." >&2
	echo "Wait for it to end, or reboot, then run this script again." >&2
	exit 1
fi

VIRT="$(systemd-detect-virt 2>/dev/null || true)"
IS_CONTAINER="no"
if [ -n "$VIRT" ] && ([ "$VIRT" = "openvz" ] || [ "$VIRT" = "lxc" ] || [ "$VIRT" = "docker" ] || [ "$VIRT" = "podman" ] || [ "$VIRT" = "container-other" ]); then
	IS_CONTAINER="yes"
fi

if [ "$ASSUME_YES" != "yes" ]; then
	echo '===================================================================================='
	echo 'This removes OpenMPTCProuter from this VPS: services, packages, keys, firewall,'
	echo 'apt repository and kernel. Routers using this VPS will lose their connection.'
	if [ "$RESTORE_SSH_PORT" = "yes" ]; then
		echo '\033[1m SSH goes back to port 22 (set RESTORE_SSH_PORT=no to keep 65222)\033[0m'
	fi
	echo '===================================================================================='
	# Read from the terminal: stdin is the script itself with "wget -O - ... | sh".
	# Tested in a subshell: a failed redirection of exec ends dash itself.
	if ! (: </dev/tty) 2>/dev/null; then
		echo "No terminal to confirm on: run with ASSUME_YES=yes" >&2
		exit 1
	fi
	printf 'Type "yes" to continue: '
	read -r answer </dev/tty
	if [ "$answer" != "yes" ]; then
		echo "Nothing done"
		exit 1
	fi
fi

# Print the installed packages matching the dpkg-query patterns given,
# including those removed with only their configuration left.
installed_pkgs() {
	dpkg-query -W -f='${db:Status-Status} ${Package}\n' "$@" 2>/dev/null | awk '$1 != "not-installed" { print $2 }'
}

# Purge packages, all in one go, or one by one when apt refuses the lot (a
# broken postrm in one of them must not keep the others installed).
purge_pkgs() {
	[ -n "$*" ] || return 0
	echo "Purging $*"
	apt-get -y purge "$@" && return 0
	for pkg in "$@"; do
		apt-get -y purge "$pkg" || warn "could not purge ${pkg}"
	done
}

# Remove files and directories no installed package owns. The installer
# overwrote some files that belong to a package it does not install (fail2ban's
# filter.d/openvpn.conf): those are left for that package.
rm_unowned() {
	for f in "$@"; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		if dpkg -S "$f" >/dev/null 2>&1; then
			echo " $f kept, it belongs to package $(dpkg -S "$f" 2>/dev/null | head -n 1 | cut -d: -f1)"
			continue
		fi
		rm -rf "$f"
	done
}

# Remove the directories given when empty and owned by no package
rmdir_unowned() {
	for d in "$@"; do
		[ -d "$d" ] || continue
		dpkg -S "$d" >/dev/null 2>&1 && continue
		rmdir "$d" 2>/dev/null || true
	done
}

# Print the units matching a glob that systemd knows of or that are enabled.
# Template instances (omr6in4@user1...) are only listed once loaded or by
# their symlinks in /etc/systemd/system/*.wants.
unit_instances() {
	{
		systemctl list-units --all --plain --no-legend "$1" 2>/dev/null | awk '{ print $1 }'
		systemctl list-unit-files --plain --no-legend "$1" 2>/dev/null | awk '{ print $1 }'
		find /etc/systemd/system -name "$1" 2>/dev/null | sed -e 's@.*/@@'
	} | grep -v '@\.' | sort -u
}

stop_units() {
	for pattern in "$@"; do
		for unit in $(unit_instances "$pattern"); do
			systemctl -q stop "$unit" >/dev/null 2>&1 || true
			systemctl -q disable "$unit" >/dev/null 2>&1 || true
			systemctl -q reset-failed "$unit" >/dev/null 2>&1 || true
		done
		# Symlinks left by a unit whose file is already gone, that disable can't find
		find /etc/systemd/system -name "$pattern" -type l -delete 2>/dev/null || true
	done
}

# Print the GRUB menu entry path for the entry matching regex $2 in grub.cfg $1.
# Same as in debian9-x86_64.sh, see there.
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

is_omr_kernel() {
	case "$1" in
		*-omr|*xanmod*|*-mptcp) return 0 ;;
	esac
	return 1
}

# Regex for the menu entry title of kernel $1 ("..., with Linux 6.12.48+deb13-amd64'"),
# its regex characters escaped and closed by the quote so that 6.12.4 is not 6.12.48
kernel_entry_regex() {
	echo "Linux $(echo "$1" | sed -e 's/[.+]/[&]/g')'"
}

# Highest version distribution kernel in /boot
stock_kernel() {
	for k in /boot/vmlinuz-*; do
		[ -f "$k" ] || continue
		k="${k#/boot/vmlinuz-}"
		is_omr_kernel "$k" || echo "$k"
	done | sort -V | tail -n 1
}

# Boot kernel $1 by default: entry 0 once it is the highest version one,
# else its entry under "Advanced options" (a running OpenMPTCProuter kernel
# still installed sorts above it).
set_grub_default() {
	grub_cfg="$(find /boot/grub /boot/grub2 -maxdepth 1 -name grub.cfg 2>/dev/null | head -n 1)"
	grub_deflt="$(find /etc/default -maxdepth 1 \( -name grub -o -name grub2 \) 2>/dev/null | head -n 1)"
	if [ -z "$grub_cfg" ] || [ -z "$grub_deflt" ] || [ -z "$(command -v grub-mkconfig)" ]; then
		warn "no GRUB configuration found, make sure this VPS boots kernel $1"
		return 1
	fi
	grub-mkconfig -o "$grub_cfg" >/dev/null 2>&1 || warn "grub-mkconfig failed"
	entry="0"
	if [ "$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed -e 's@.*/vmlinuz-@@' | sort -V | tail -n 1)" != "$1" ]; then
		entry="$(grub_menu_entry_path "$grub_cfg" "$(kernel_entry_regex "$1")")"
		if [ -z "$entry" ]; then
			warn "kernel $1 not found in ${grub_cfg}, GRUB default left untouched"
			return 1
		fi
	fi
	if grep -q '^[[:space:]]*GRUB_DEFAULT=' "$grub_deflt"; then
		sed -i "s@^[[:space:]]*\(GRUB_DEFAULT=\).*@\1\"${entry}\"@" "$grub_deflt"
	else
		echo "GRUB_DEFAULT=\"${entry}\"" >> "$grub_deflt"
	fi
	if ! grub-mkconfig -o "$grub_cfg" >/dev/null 2>&1; then
		warn "grub-mkconfig failed, GRUB_DEFAULT=\"${entry}\" is not applied yet: run update-grub"
		return 1
	fi
	echo "GRUB default boot entry is now ${entry} (kernel $1)"
}

KERNEL_LEFT=""
remove_kernel() {
	if [ "$IS_CONTAINER" = "yes" ]; then
		echo "Container detected: kernel left alone"
		return 0
	fi
	stock="$(stock_kernel)"
	if [ -z "$stock" ]; then
		. /etc/os-release
		if [ "$ID" = "ubuntu" ]; then
			meta="linux-image-generic"
		else
			meta="linux-image-$(dpkg --print-architecture)"
		fi
		echo "Install distribution kernel ${meta}"
		apt-get -y install "$meta" || warn "could not install ${meta}"
		stock="$(stock_kernel)"
	fi
	# Without another kernel, removing this one leaves nothing to boot
	if [ -z "$stock" ]; then
		warn "no distribution kernel installed, the OpenMPTCProuter kernel is left in place"
		KERNEL_LEFT="$(uname -r)"
		return 1
	fi
	running="$(uname -r)"
	purge_pkgs $(installed_pkgs 'linux-image-*-omr' 'linux-headers-*-omr' 'linux-image-*-mptcp' 'linux-headers-*-mptcp' 'linux-image-*xanmod*' 'linux-headers-*xanmod*' | grep -vxF "linux-image-${running}")
	is_omr_kernel "$running" && KERNEL_LEFT="$running"
	set_grub_default "$stock"
}

echo "Stop OpenMPTCProuter services..."
# omr-admin first: a router pushing its configuration restarts the services
# being stopped here, and GET /update starts omr-update, which reinstalls all.
stop_units omr-admin.service omr-admin-ipv6.service omr-update.service omr.service \
	omr-bypass.timer omr-bypass.service omr-reserved-ports.path omr-reserved-ports.service \
	omr-net-mem.service 'omr6in4@*' 'omr-vxlan@*' \
	'shadowsocks-libev-manager@*' 'shadowsocks-libev-server@*' shadowsocks-go.service \
	v2ray.service xray.service 'mlvpn@*' mqvpn.service mqvpn-server.service 'dsvpn-server@*' \
	'glorytun-tcp@*' 'glorytun-udp@*' openvpn@tun0.service openvpn@tun1.service 'openvpn@bonding*' \
	wg-quick@wg0.service wg-quick@client-wg0.service iperf3.service softether-vpnserver.service
if [ -n "$(installed_pkgs bpftune)" ]; then
	stop_units bpftune.service
fi
echo "done"

BACKUP_FILE=""
if [ "$BACKUP" = "yes" ]; then
	echo "Save configuration and keys..."
	BACKUP_FILE="/root/omr-uninstall-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
	backup_paths=""
	for p in etc/openmptcprouter-vps-admin etc/shadowsocks-libev etc/shadowsocks-go etc/v2ray etc/xray \
		etc/glorytun-tcp etc/glorytun-udp etc/dsvpn etc/mlvpn etc/mqvpn etc/openvpn etc/wireguard etc/iperf3 \
		etc/nftables.conf etc/nftables etc/fail2ban/jail.d/openmptcprouter.conf etc/ssh/sshd_config \
		etc/sysctl.d/90-shadowsocks.conf etc/sysctl.d/90-omr-forwarding.conf var/lib/softether \
		root/openmptcprouter_config.txt root/wireguard-client.conf; do
		[ -e "/$p" ] && backup_paths="$backup_paths $p"
	done
	if [ -n "$backup_paths" ] && (umask 077 && tar -C / -czf "$BACKUP_FILE" $backup_paths); then
		echo "Saved in ${BACKUP_FILE}"
	else
		warn "nothing saved"
		rm -f "$BACKUP_FILE"
		BACKUP_FILE=""
	fi
fi

echo "Reset the firewall..."
# The OpenMPTCProuter ruleset only opens 65222 for SSH: it goes first, before
# sshd moves back to 22. The installer overwrote /etc/nftables.conf without a
# copy, this is the nftables package's own default (accept everything).
rm -f /etc/systemd/system/nftables.service.d/omr-admin-resync.conf /etc/systemd/system/nftables.service.d/omr-bypass-resync.conf
rmdir_unowned /etc/systemd/system/nftables.service.d
systemctl daemon-reload
if [ -f /etc/nftables/omr.nft ] || grep -q 'OpenMPTCProuter' /etc/nftables.conf 2>/dev/null; then
	cat > /etc/nftables.conf <<-'EOF'
	#!/usr/sbin/nft -f

	flush ruleset

	table inet filter {
		chain input {
			type filter hook input priority filter;
		}
		chain forward {
			type filter hook forward priority filter;
		}
		chain output {
			type filter hook output priority filter;
		}
	}
	EOF
fi
rm -f /etc/nftables/omr.nft /etc/nftables/omr-vars.nft
# The admin's own rules: never removed, but nothing includes them any more
if [ -n "$(ls -A /etc/nftables/custom.d 2>/dev/null)" ]; then
	echo " /etc/nftables/custom.d is kept: it holds your own rules, no longer loaded"
else
	rmdir /etc/nftables/custom.d 2>/dev/null || true
	rmdir /etc/nftables 2>/dev/null || true
fi
if [ -f /etc/nftables.conf ] && command -v nft >/dev/null 2>&1; then
	nft -f /etc/nftables.conf || warn "could not load /etc/nftables.conf"
fi
rm -f /etc/modules-load.d/omr-ftp.conf
# Masked by the installer; not started again, whether they ran before is unknown
systemctl unmask shorewall shorewall6 ufw firewalld >/dev/null 2>&1 || true
echo "done"

SSH_MOVED="no"
if [ "$RESTORE_SSH_PORT" = "yes" ] && grep -qE '^[[:space:]]*Port[[:space:]]+65222[[:space:]]*$' /etc/ssh/sshd_config 2>/dev/null; then
	echo "Move SSH back to port 22..."
	# The installer turned "#Port 22" or "Port 22" into "Port 65222", or added
	# it on top when there was no Port line: "#Port 22" is sshd's default.
	cp -pf /etc/ssh/sshd_config /etc/ssh/sshd_config.omr-uninstall
	sed -i -E 's/^[[:space:]]*Port[[:space:]]+65222[[:space:]]*$/#Port 22/' /etc/ssh/sshd_config
	if sshd -t >/dev/null 2>&1; then
		# Established sessions survive the restart, only new ones use port 22
		systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || warn "could not restart sshd, SSH stays on port 65222 until this VPS reboots"
		rm -f /etc/ssh/sshd_config.omr-uninstall
		SSH_MOVED="yes"
	else
		cp -pf /etc/ssh/sshd_config.omr-uninstall /etc/ssh/sshd_config
		rm -f /etc/ssh/sshd_config.omr-uninstall
		warn "sshd -t rejects the changed configuration, SSH stays on port 65222"
	fi
	echo "done"
fi
rm -f /etc/ssh/sshd_config.omr-bak

echo "Remove OpenMPTCProuter packages..."
if command -v mptcpize >/dev/null 2>&1; then
	mptcpize disable iperf3 >/dev/null 2>&1 || true
fi
# The OpenMPTCProuter OpenVPN is an MPTCP build from its repository, a
# distribution one is left: it may serve something else.
OPENVPN_PKG=""
case "$(dpkg-query -W -f='${Version}' openvpn 2>/dev/null)" in
	*mptcp*) OPENVPN_PKG="openvpn" ;;
esac
purge_pkgs $(installed_pkgs 'omr-*' 'mptcp-bpf-*' mptcp-dscp-manager mptcp-weight-manager \
	shadowsocks-go v2ray v2ray-plugin xray mqvpn 'libmqvpn*' softether-vpnserver bpftune) $OPENVPN_PKG
echo "done"

echo "Remove OpenMPTCProuter files..."
rm_unowned /usr/local/bin/omr-service /usr/local/bin/omr-6in4-run /usr/local/bin/omr-vxlan-run \
	/usr/local/bin/omr-bypass /usr/local/bin/omr-reserved-ports /usr/local/bin/omr-net-mem \
	/usr/local/bin/omr-test-speed /usr/local/bin/multipath /usr/local/bin/glorytun-tcp \
	/usr/local/bin/glorytun-tcp-run /usr/local/bin/glorytun-udp-run /usr/local/bin/dsvpn-run \
	/usr/local/bin/v2ray-plugin /usr/local/bin/obfs-server \
	/usr/bin/omr-update /usr/bin/omradmin.py /usr/share/omr-admin /usr/share/omr-server \
	/usr/share/omr-server-git /var/lib/openmptcprouter-vps-debian /var/opt/openmptcprouter \
	/var/log/omr-update.log
for unit in omr.service omr6in4@.service omr-vxlan@.service omr-bypass.service omr-bypass.timer \
	omr-reserved-ports.service omr-reserved-ports.path omr-net-mem.service omr-update.service \
	omr-admin.service omr-admin-ipv6.service glorytun-tcp@.service glorytun-udp@.service \
	mlvpn@.service dsvpn-server@.service mqvpn.service shadowsocks-libev-manager@.service \
	v2ray.service xray.service; do
	rm_unowned /lib/systemd/system/$unit
done
rm_unowned /lib/systemd/network/mlvpn.network /lib/systemd/network/glorytun.network \
	/lib/systemd/network/glorytun-udp.network /lib/systemd/network/glorytun-tcp.network \
	/lib/systemd/network/openvpn.network
rm -f /etc/systemd/system/iperf3.service.d/override.conf \
	/etc/systemd/system/systemd-networkd-wait-online.service.d/20-omr-wait-online-any.conf
rmdir_unowned /etc/systemd/system/iperf3.service.d /etc/systemd/system/systemd-networkd-wait-online.service.d

rm_unowned /etc/openmptcprouter-vps-admin /etc/shadowsocks-libev /etc/shadowsocks-go /etc/v2ray /etc/xray \
	/etc/glorytun-tcp /etc/glorytun-udp /etc/dsvpn /etc/mlvpn /etc/mqvpn /etc/iperf3 /var/lib/softether \
	/usr/share/bpf/scheduler
rm -rf /etc/openvpn/tun0.conf /etc/openvpn/tun1.conf /etc/openvpn/.tun0.conf.new /etc/openvpn/bonding?.conf \
	/etc/openvpn/ca /etc/openvpn/ccd /etc/openvpn/server/ca.crt /etc/openvpn/server/ca.key \
	/etc/openvpn/server/crl.pem /etc/openvpn/server/dh2048.pem /etc/openvpn/server/server.crt \
	/etc/openvpn/server/server.key /etc/openvpn/server/static.key /etc/openvpn/client/client.crt \
	/etc/openvpn/client/client.key
rmdir_unowned /etc/openvpn/server /etc/openvpn/client /etc/openvpn
rm -f /etc/wireguard/wg0.conf /etc/wireguard/client-wg0.conf /etc/wireguard/vpn-server-private.key \
	/etc/wireguard/vpn-server-public.key /etc/wireguard/vpn-client-private.key /etc/wireguard/vpn-client-public.key
rmdir_unowned /etc/wireguard
rm -f /root/openmptcprouter_config.txt /root/wireguard-client.conf

if [ -f /etc/fail2ban/jail.d/openmptcprouter.conf ]; then
	rm_unowned /etc/fail2ban/jail.d/openmptcprouter.conf /etc/fail2ban/filter.d/omradmin.conf \
		/etc/fail2ban/filter.d/xray.conf /etc/fail2ban/filter.d/v2ray.conf \
		/etc/fail2ban/filter.d/shadowsocks-go.conf
	systemctl -q try-restart fail2ban >/dev/null 2>&1 || true
fi

if getent passwd mlvpn >/dev/null 2>&1; then
	deluser --quiet --system mlvpn >/dev/null 2>&1 || warn "could not remove user mlvpn"
fi
rm -rf /var/opt/mlvpn

# System settings. The sysctl values stay in effect until the reboot.
rm -f /etc/sysctl.d/90-shadowsocks.conf /etc/sysctl.d/90-omr-forwarding.conf \
	/etc/sysctl.d/99-omr-net-mem.conf /etc/sysctl.d/99-omr-reserved-ports.conf \
	/etc/default/omr-net-mem /etc/network/if-up.d/omr-accept-ra
[ -f /etc/modules ] && sed -i -E '/^(tcp_bbr|tcp_bbr2|mptcp_olia|mptcp_wvegas|mptcp_balia|mctcp_desync|mptcp_ndiffports|mptcp_redundant|mptcp_rr|mptcp_ecf|mptcp_blest)$/d' /etc/modules
[ -f /etc/modprobe.d/blacklist.conf ] && sed -i '/^blacklist nf_conntrack_sip$/d' /etc/modprobe.d/blacklist.conf
[ -f /etc/systemd/system.conf ] && sed -i '/^DefaultLimitNOFILE=65536$/d' /etc/systemd/system.conf
[ -f /etc/systemd/journald.conf ] && sed -i 's/^SystemMaxUse=100M$/#SystemMaxUse=/' /etc/systemd/journald.conf
for motd in /etc/motd /etc/motd.head; do
	[ -f "$motd" ] && sed -i '/^< OpenMPTCProuter VPS .* >$/d' "$motd"
done
systemctl daemon-reload
echo "done"

echo "Remove the OpenMPTCProuter apt repository..."
rm -f /etc/apt/sources.list.d/openmptcprouter.list /etc/apt/sources.list.d/openmptcprouter-test.list \
	/etc/apt/preferences.d/openmptcprouter.pref /etc/apt/trusted.gpg.d/openmptcprouter.gpg
apt-get update >/dev/null 2>&1 || warn "apt-get update failed"
echo "done"

if [ "$REMOVE_KERNEL" = "yes" ]; then
	echo "Remove the OpenMPTCProuter kernel..."
	remove_kernel
	echo "done"
fi

echo '===================================================================================='
echo 'OpenMPTCProuter is removed from this VPS.'
[ -n "$BACKUP_FILE" ] && echo "Configuration and keys saved in ${BACKUP_FILE}"
if [ "$SSH_MOVED" = "yes" ]; then
	echo '\033[1m SSH port: 22 (instead of port 65222)\033[0m'
fi
echo 'Packages the installer added that are not OpenMPTCProuter specific are left'
echo 'installed, "apt-get autoremove" lists what nothing depends on any more.'
if [ -d /root/.acme.sh ]; then
	echo 'acme.sh is left installed, "/root/.acme.sh/acme.sh --uninstall" removes it.'
fi
echo '------------------------------------------------------------------------------------'
echo '\033[1m  /!\ Reboot to drop the OpenMPTCProuter network settings /!\ \033[0m'
if [ -n "$KERNEL_LEFT" ]; then
	echo " The running kernel ${KERNEL_LEFT} is still installed: after the reboot, check"
	echo ' with "uname -r" that it is not running any more, and run this script again.'
fi
echo '===================================================================================='
exit 0
