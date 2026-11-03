#!/bin/bash
# Checks omr-uninstall.sh against debian9-x86_64.sh, on a plain checkout:
#   1. it parses as POSIX sh (dash or busybox sh when installed, else sh -n)
#   2. its copy of grub_menu_entry_path is the installer's, byte for byte
#   3. every script, unit, network, sysctl and drop-in file the installer puts
#      in place is named in it: a file added to the installer and forgotten
#      here would survive an uninstall
#   4. kernel_entry_regex selects a distribution kernel whose version holds
#      regex characters (6.12.94+deb13-amd64), and not a longer version
#      sharing its prefix
#   5. is_omr_kernel tells the OpenMPTCProuter kernels from distribution ones
#
# Functions are extracted from the scripts, so the tests exercise the shipped
# code. Requires: bash, awk.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"
UNINSTALLER="$ROOT/omr-uninstall.sh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0

pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL %s\n    expected=%s\n    got=%s\n' "$desc" "$expected" "$actual"
    fi
}

extract_fn() {
    awk -v name="$1" '$0 ~ "^" name "\\(\\) \\{" , /^\}/' "$2"
}

# ── 1. syntax ───────────────────────────────────────────────────────────────
if command -v dash >/dev/null 2>&1; then
    checker="dash -n"
elif command -v busybox >/dev/null 2>&1; then
    checker="busybox sh -n"
else
    checker="sh -n"
fi
if $checker "$UNINSTALLER" 2>"$TMPDIR/syntax.err"; then
    pass "parses with $checker"
else
    fail "parses with $checker: $(cat "$TMPDIR/syntax.err")"
fi

# ── 2. grub_menu_entry_path is the installer's ──────────────────────────────
extract_fn grub_menu_entry_path "$INSTALLER" > "$TMPDIR/grub.installer"
extract_fn grub_menu_entry_path "$UNINSTALLER" > "$TMPDIR/grub.uninstaller"
if [ -s "$TMPDIR/grub.installer" ] && cmp -s "$TMPDIR/grub.installer" "$TMPDIR/grub.uninstaller"; then
    pass "grub_menu_entry_path matches the installer's"
else
    fail "grub_menu_entry_path differs from the installer's"
fi

# ── 3. every installed file is removed ──────────────────────────────────────
# The last word of each fetch_file/copy_file/cp line is where the installer
# puts a file; keep those under the paths OpenMPTCProuter owns outright.
grep -vE '^[[:space:]]*#' "$INSTALLER" |
    grep -E '^[[:space:]]*(fetch_file|copy_file|cp)[[:space:]]' |
    awk '{ print $NF }' |
    grep -E '^/(usr/local/bin|lib/systemd/(system|network)|etc/sysctl\.d|etc/systemd/system|etc/nftables|etc/fail2ban/jail\.d|usr/bin/omr)' |
    sort -u > "$TMPDIR/installed"
if [ ! -s "$TMPDIR/installed" ]; then
    fail "no installed file found in the installer"
fi
# Units are removed by name in a loop over /lib/systemd/system/$unit: only
# that loop counts, the same names are also in the list of units to stop.
awk '/^for unit in /, /; do$/' "$UNINSTALLER" | tr -s ' \t\\;' '\n' > "$TMPDIR/unit_loop"
while read -r f; do
    if grep -qF "$f" "$UNINSTALLER" || { [ "${f%/*}" = "/lib/systemd/system" ] && grep -qxF "${f##*/}" "$TMPDIR/unit_loop"; }; then
        pass "removes $f"
    else
        fail "does not remove $f"
    fi
done < "$TMPDIR/installed"

# ── 4. kernel_entry_regex ───────────────────────────────────────────────────
extract_fn grub_menu_entry_path "$UNINSTALLER" > "$TMPDIR/fn.sh"
extract_fn kernel_entry_regex "$UNINSTALLER" >> "$TMPDIR/fn.sh"
extract_fn is_omr_kernel "$UNINSTALLER" >> "$TMPDIR/fn.sh"
. "$TMPDIR/fn.sh"

UUID="77a07ccf-4a94-4ae3-9afd-2da099f4882a"
CFG="$TMPDIR/debian13.cfg"
cat > "$CFG" <<EOF
menuentry 'Debian GNU/Linux' --class debian --class gnu-linux --class gnu --class os \$menuentry_id_option 'gnulinux-simple-$UUID' {
	linux	/boot/vmlinuz-6.18.57-20261018.x64v3-omr root=UUID=$UUID ro
}
submenu 'Advanced options for Debian GNU/Linux' \$menuentry_id_option 'gnulinux-advanced-$UUID' {
	menuentry 'Debian GNU/Linux, with Linux 6.18.57-20261018.x64v3-omr' --class debian \$menuentry_id_option 'gnulinux-6.18.57-20261018.x64v3-omr-advanced-$UUID' {
		linux	/boot/vmlinuz-6.18.57-20261018.x64v3-omr root=UUID=$UUID ro
	}
	menuentry 'Debian GNU/Linux, with Linux 6.12.948+deb13-amd64' --class debian \$menuentry_id_option 'gnulinux-6.12.948+deb13-amd64-advanced-$UUID' {
		linux	/boot/vmlinuz-6.12.948+deb13-amd64 root=UUID=$UUID ro
	}
	menuentry 'Debian GNU/Linux, with Linux 6.12.94+deb13-amd64 (recovery mode)' --class debian \$menuentry_id_option 'gnulinux-6.12.94+deb13-amd64-recovery-$UUID' {
		linux	/boot/vmlinuz-6.12.94+deb13-amd64 root=UUID=$UUID ro single
	}
	menuentry 'Debian GNU/Linux, with Linux 6.12.94+deb13-amd64' --class debian \$menuentry_id_option 'gnulinux-6.12.94+deb13-amd64-advanced-$UUID' {
		linux	/boot/vmlinuz-6.12.94+deb13-amd64 root=UUID=$UUID ro
	}
}
EOF
assert_eq "selects the distribution kernel, not a longer version or its recovery entry" \
    "gnulinux-advanced-$UUID>gnulinux-6.12.94+deb13-amd64-advanced-$UUID" \
    "$(grub_menu_entry_path "$CFG" "$(kernel_entry_regex 6.12.94+deb13-amd64)")"
assert_eq "a kernel not in the menu gives no entry" "" \
    "$(grub_menu_entry_path "$CFG" "$(kernel_entry_regex 6.12.9+deb13-amd64)")"

# ── 5. is_omr_kernel ────────────────────────────────────────────────────────
for k in 6.18.57-20261018.x64v3-omr 6.6.30-x64v3-xanmod1 5.4.207-mptcp; do
    if is_omr_kernel "$k"; then pass "$k is an OpenMPTCProuter kernel"; else fail "$k is an OpenMPTCProuter kernel"; fi
done
for k in 6.12.94+deb13-amd64 6.12.94+deb13-cloud-amd64 5.15.0-91-generic; do
    if is_omr_kernel "$k"; then fail "$k is a distribution kernel"; else pass "$k is a distribution kernel"; fi
done

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
