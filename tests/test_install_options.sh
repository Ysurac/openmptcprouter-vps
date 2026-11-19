#!/bin/bash
# The feature switches the installer saves at the end of a run and reads back
# at the start of the next one (/etc/openmptcprouter-vps-admin/install-options).
# omr-update runs the installer with no environment at all: without this file
# every update a router triggers turned a service the admin left out
# (OPENVPN=no, WIREGUARD=no...) back on.
#
# Both blocks are taken from the installer itself and run with sh against a
# temporary file. Requires: bash, sh, sed.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="$SCRIPT_DIR/../debian9-x86_64.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

PASS=0
FAIL=0
assert_eq() {
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '  PASS %s\n' "$1"
    else
        FAIL=$((FAIL+1)); printf '  FAIL %s\n    expected=%s\n    got=%s\n' "$1" "$2" "$3"
    fi
}

# From the OMR_INSTALL_OPTIONS= line to the fi closing the read loop, and the
# loop that writes the file back
sed -n '/^OMR_INSTALL_OPTIONS=/,/^fi$/p' "$INSTALLER" \
    | sed "s|^OMR_INSTALL_OPTIONS=.*|OMR_INSTALL_OPTIONS=$T/install-options|" > "$T/read.sh"
sed -n '/^for _opt_name in \$OMR_OPTION_NAMES; do$/,/^done > "\$OMR_INSTALL_OPTIONS"$/p' "$INSTALLER" > "$T/write.sh"

echo "== the blocks are found in the installer =="
assert_eq "read block extracted" "yes" "$(grep -q 'done < "$OMR_INSTALL_OPTIONS"' "$T/read.sh" && echo yes)"
assert_eq "write block extracted" "3" "$(wc -l < "$T/write.sh" | tr -d ' ')"

# Run the read block, then the installer's own defaults for two switches, in
# the environment given, and print the result
run() {
    env -i PATH="$PATH" "$@" sh -c ". '$T/read.sh'; OPENVPN=\${OPENVPN:-yes}; WIREGUARD=\${WIREGUARD:-yes}; echo \"\$OPENVPN \$WIREGUARD\""
}

echo
echo "== no file: the defaults =="
assert_eq "first install" "yes yes" "$(run)"

echo
echo "== the saved switches survive a run with no environment =="
printf 'OPENVPN=no\nWIREGUARD=yes\n' > "$T/install-options"
assert_eq "OPENVPN=no kept by an omr-update run" "no yes" "$(run)"
assert_eq "the environment still wins" "yes yes" "$(run OPENVPN=yes)"

echo
echo "== only known names, only yes/no =="
cat > "$T/install-options" <<'EOF'
OPENVPN=maybe
WIREGUARD=$(touch PWNED)
PATH=no
OPENVPN WIREGUARD=no
=no
EOF
assert_eq "invalid values and names ignored" "yes yes" "$(cd "$T" && run)"
assert_eq "nothing in the file is run" "no" "$([ -e "$T/PWNED" ] && echo yes || echo no)"

echo
echo "== written back as read =="
env -i PATH="$PATH" sh -c ". '$T/read.sh'; OPENVPN=no; WIREGUARD=yes; OMR_INSTALL_OPTIONS='$T/out'; . '$T/write.sh'"
assert_eq "OPENVPN saved" "OPENVPN=no" "$(grep '^OPENVPN=' "$T/out")"
assert_eq "WIREGUARD saved" "WIREGUARD=yes" "$(grep '^WIREGUARD=' "$T/out")"
mv "$T/out" "$T/install-options"
assert_eq "and read back" "no yes" "$(run)"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
