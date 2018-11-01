#!/bin/bash
kernel=$1
[ -z "$kernel" ] && exit 0

config_file="$(find /boot/grub* -maxdepth 1 -name grub.cfg 2>/dev/null)"
[ $config_file ] || exit 0

deflt_file="$(find /etc/default \( -name grub -o -name grub2 \) 2>/dev/null)"
[ $deflt_file ] || exit 0

if [ -z "$(grep -m 1 vmlinuz $config_file | grep $kernel)" ]; then
	x=0
	sed -n -e 's@\([^'\"\'']*\)['\"\'']\([^'\"\'']*\).*@\1\2@' -e '/\(menuentry\) /p' <$config_file | \
		while IFS= read ln
		do
			if [ -n "$(echo $ln | grep $kernel)" ]; then
				x=$(expr $x - 1)
				sed -i "s@^\(GRUB_DEFAULT=\).*@\1\"1>$x\"@" $deflt_file
				[ -f /boot/grub/grub.cfg ] && grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1
				exit 0
			fi
			x=$(expr $x + 1)
		done | sed 's@\(menuentry\) @@'
fi