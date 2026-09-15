#!/bin/bash
# Tests for grub_menu_entry_path in debian9-x86_64.sh, the helper
# set_grub_default_kernel uses to build the GRUB_DEFAULT value:
#   1. the Debian/Ubuntu layout (newest kernel promoted to the top level,
#      every other one plus the recovery entries under "Advanced options")
#   2. a menu whose entries all sit at the top level (GRUB_DISABLE_SUBMENU)
#   3. a grub.cfg whose entries carry no $menuentry_id_option at all, where
#      the answer has to be a menu index instead of an id
#   4. submenus nested more than one level deep, and an id-less submenu
#      holding entries with ids (the whole path then has to be numeric)
#   5. recovery mode entries never being selected
#   6. a kernel that is not in the menu at all
#
# GRUB resolves "default" against the top level menu only, so an entry inside
# a submenu has to be named as the id (or index) of every submenu above it,
# separated by ">" (see GRUB_DEFAULT in grub.info) -- getting that wrong makes
# GRUB silently boot entry 0 instead.
#
# The function is extracted from the installer, so the tests exercise the
# shipped code. Requires: bash, awk.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="$SCRIPT_DIR/../debian9-x86_64.sh"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        PASS=$((PASS+1)); printf '  PASS %s\n' "$desc"
    else
        FAIL=$((FAIL+1))
        printf '  FAIL %s\n    expected=%s\n    got=%s\n' "$desc" "$expected" "$actual"
    fi
}

# Extract the function under test (definition line to the closing brace in
# column 0) straight out of the installer and load it.
awk '/^grub_menu_entry_path\(\) \{/,/^\}/' "$INSTALLER" > "$TMPDIR/fn.sh"
if [ ! -s "$TMPDIR/fn.sh" ]; then
    echo "FAIL could not extract grub_menu_entry_path from $INSTALLER"
    exit 1
fi
. "$TMPDIR/fn.sh"

UUID="77a07ccf-4a94-4ae3-9afd-2da099f4882a"

# ── 1. Debian 13 / Ubuntu layout, as grub-mkconfig writes it ─────────────────
# Only the highest version kernel gets a top level entry, and its title does
# not carry the release; everything else lives in the "Advanced options"
# submenu, each kernel followed by its recovery variant.

DEBIAN_CFG="$TMPDIR/debian13.cfg"
cat > "$DEBIAN_CFG" <<EOF
menuentry 'Debian GNU/Linux' --class debian --class gnu-linux --class gnu --class os \$menuentry_id_option 'gnulinux-simple-$UUID' {
	load_video
	linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr root=UUID=$UUID ro
}
submenu 'Advanced options for Debian GNU/Linux' \$menuentry_id_option 'gnulinux-advanced-$UUID' {
	menuentry 'Debian GNU/Linux, with Linux 6.18.41-20260730.x64v3-omr' --class debian --class gnu-linux \$menuentry_id_option 'gnulinux-6.18.41-20260730.x64v3-omr-advanced-$UUID' {
		linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr root=UUID=$UUID ro
	}
	menuentry 'Debian GNU/Linux, with Linux 6.18.41-20260730.x64v3-omr (recovery mode)' --class debian \$menuentry_id_option 'gnulinux-6.18.41-20260730.x64v3-omr-recovery-$UUID' {
		linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr root=UUID=$UUID ro single
	}
	menuentry 'Debian GNU/Linux, with Linux 6.12.94+deb13-amd64' --class debian --class gnu-linux \$menuentry_id_option 'gnulinux-6.12.94+deb13-amd64-advanced-$UUID' {
		linux	/boot/vmlinuz-6.12.94+deb13-amd64 root=UUID=$UUID ro
	}
	menuentry 'Debian GNU/Linux, with Linux 6.12.94+deb13-amd64 (recovery mode)' --class debian \$menuentry_id_option 'gnulinux-6.12.94+deb13-amd64-recovery-$UUID' {
		linux	/boot/vmlinuz-6.12.94+deb13-amd64 root=UUID=$UUID ro single
	}
}
if [ "\$vt_handoff" = 1 ]; then
	menuentry 'UEFI Firmware Settings' \$menuentry_id_option 'uefi-firmware' {
		fwsetup
	}
fi
EOF

echo "== Debian 13 layout =="
assert_eq "OMR kernel is named through its submenu" \
    "gnulinux-advanced-$UUID>gnulinux-6.18.41-20260730.x64v3-omr-advanced-$UUID" \
    "$(grub_menu_entry_path "$DEBIAN_CFG" "6.18.41.*x64v3-omr")"
assert_eq "distribution kernel is named through its submenu" \
    "gnulinux-advanced-$UUID>gnulinux-6.12.94+deb13-amd64-advanced-$UUID" \
    "$(grub_menu_entry_path "$DEBIAN_CFG" "6.12.94.*amd64")"
assert_eq "the xanmod naming set_grub_default_kernel passes for KERNEL=6.12 resolves the same way" \
    "gnulinux-advanced-$UUID>gnulinux-6.12.94+deb13-amd64-advanced-$UUID" \
    "$(grub_menu_entry_path "$DEBIAN_CFG" "6.12.94.*deb13")"
assert_eq "a kernel that is not installed gives nothing" "" \
    "$(grub_menu_entry_path "$DEBIAN_CFG" "6.6.99.*x64v3-omr")"

# ── 2. every entry at the top level (GRUB_DISABLE_SUBMENU=y) ─────────────────

FLAT_CFG="$TMPDIR/flat.cfg"
cat > "$FLAT_CFG" <<EOF
menuentry 'Ubuntu' --class ubuntu \$menuentry_id_option 'gnulinux-simple-$UUID' {
	linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
}
menuentry 'Ubuntu, with Linux 6.18.41-20260730.x64v3-omr' \$menuentry_id_option 'gnulinux-6.18.41-20260730.x64v3-omr-advanced-$UUID' {
	linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
}
menuentry 'Ubuntu, with Linux 6.18.41-20260730.x64v3-omr (recovery mode)' \$menuentry_id_option 'gnulinux-6.18.41-20260730.x64v3-omr-recovery-$UUID' {
	linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr single
}
EOF

echo "== no submenu =="
assert_eq "top level entry is named by its bare id, with no > prefix" \
    "gnulinux-6.18.41-20260730.x64v3-omr-advanced-$UUID" \
    "$(grub_menu_entry_path "$FLAT_CFG" "6.18.41.*x64v3-omr")"

# ── 3. no entry ids anywhere: the answer is a menu index ─────────────────────
# grub.cfg from an older grub-mkconfig, or a hand written one.

NOID_CFG="$TMPDIR/noid.cfg"
cat > "$NOID_CFG" <<'EOF'
menuentry 'Some other OS' {
	chainloader +1
}
menuentry 'Linux 5.4.230-mptcp' {
	linux	/boot/vmlinuz-5.4.230-mptcp
}
menuentry 'Linux 6.18.41-20260730.x64v3-omr' {
	linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
}
EOF

echo "== no entry ids =="
assert_eq "third top level entry is index 2, not 2>00" "2" \
    "$(grub_menu_entry_path "$NOID_CFG" "6.18.41.*x64v3-omr")"
assert_eq "first top level entry is index 0" "0" \
    "$(grub_menu_entry_path "$NOID_CFG" "Some other OS")"

NOID_SUB_CFG="$TMPDIR/noid-submenu.cfg"
cat > "$NOID_SUB_CFG" <<'EOF'
menuentry 'Debian GNU/Linux' {
	linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
}
submenu 'Advanced options' {
	menuentry 'Linux 5.4.230-mptcp' {
		linux	/boot/vmlinuz-5.4.230-mptcp
	}
	menuentry 'Linux 6.18.41-20260730.x64v3-omr' {
		linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
	}
}
EOF

assert_eq "second entry of the second submenu is 1>1, not 1>01" "1>1" \
    "$(grub_menu_entry_path "$NOID_SUB_CFG" "6.18.41.*x64v3-omr")"
assert_eq "first entry of that submenu is 1>0" "1>0" \
    "$(grub_menu_entry_path "$NOID_SUB_CFG" "5.4.230-mptcp")"

# ── 4. nesting, and mixed id/no-id ───────────────────────────────────────────

NESTED_CFG="$TMPDIR/nested.cfg"
cat > "$NESTED_CFG" <<EOF
menuentry 'Debian GNU/Linux' \$menuentry_id_option 'gnulinux-simple-$UUID' {
	linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
}
submenu 'Advanced options' \$menuentry_id_option 'advanced' {
	menuentry 'Linux 6.12.94+deb13-amd64' \$menuentry_id_option 'deb13' {
		linux	/boot/vmlinuz-6.12.94+deb13-amd64
	}
	submenu 'OpenMPTCProuter kernels' \$menuentry_id_option 'omr-kernels' {
		menuentry 'Linux 6.18.41-20260730.x64v3-omr' \$menuentry_id_option 'omr-6.18' {
			linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
		}
	}
}
EOF

echo "== nested submenus =="
assert_eq "two levels deep, every submenu above the entry is named" \
    "advanced>omr-kernels>omr-6.18" \
    "$(grub_menu_entry_path "$NESTED_CFG" "6.18.41.*x64v3-omr")"
assert_eq "sibling entry one level up keeps its own shorter path" "advanced>deb13" \
    "$(grub_menu_entry_path "$NESTED_CFG" "6.12.94.*amd64")"

MIXED_CFG="$TMPDIR/mixed.cfg"
cat > "$MIXED_CFG" <<EOF
submenu 'Advanced options' {
	menuentry 'Linux 5.4.230-mptcp' \$menuentry_id_option 'mptcp-5.4' {
		linux	/boot/vmlinuz-5.4.230-mptcp
	}
	menuentry 'Linux 6.18.41-20260730.x64v3-omr' \$menuentry_id_option 'omr-6.18' {
		linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
	}
}
EOF

assert_eq "an id-less submenu forces the whole path to indexes" "0>1" \
    "$(grub_menu_entry_path "$MIXED_CFG" "6.18.41.*x64v3-omr")"

# ── 5. recovery entries are never selected ───────────────────────────────────

RECOVERY_FIRST_CFG="$TMPDIR/recovery-first.cfg"
cat > "$RECOVERY_FIRST_CFG" <<EOF
submenu 'Advanced options' \$menuentry_id_option 'advanced' {
	menuentry 'Linux 6.18.41-20260730.x64v3-omr (recovery mode)' \$menuentry_id_option 'omr-recovery' {
		linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr single
	}
	menuentry 'Linux 6.18.41-20260730.x64v3-omr' \$menuentry_id_option 'omr-normal' {
		linux	/boot/vmlinuz-6.18.41-20260730.x64v3-omr
	}
}
EOF

echo "== recovery entries =="
assert_eq "a recovery entry matching first is skipped for the normal one" \
    "advanced>omr-normal" \
    "$(grub_menu_entry_path "$RECOVERY_FIRST_CFG" "6.18.41.*x64v3-omr")"
assert_eq "and it still counts as a menu index" "advanced>omr-normal" \
    "$(grub_menu_entry_path "$RECOVERY_FIRST_CFG" "x64v3-omr'")"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
