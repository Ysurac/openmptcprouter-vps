#!/bin/bash
# Reference integrity of debian9-x86_64.sh against the repository and against
# debian/. Everything here runs on a plain checkout -- no build, no VPS -- so
# the class of breakage that only shows up halfway through an install on a
# customer's machine is caught at commit time.
#
# The installer reads every one of its companion files twice over: once as a
# URL under ${VPSURL}${VPSPATH}/ (a fresh install, LOCALFILES=no) and once as
# a path under ${DIR}/ (LOCALFILES=yes, which SOURCES=yes forces on). Both
# branches run under `set -e` with no guard of their own:
#
#   - a wget of a file that was renamed or deleted exits non-zero and ends the
#     install right there, on a VPS that is now half configured
#   - a cp of a file that debian/rules never packaged does the same to any run
#     that takes that branch (0.1082: systemd/20-omr-wait-online-any.conf was
#     in no package at all). Note that the packaged installer is not one of
#     them today: debian/postinst rewrites its LOCALFILES/SOURCES defaults to
#     plain "no", which beats the environment omr-update passes it
#   - a file added to only one of the two branches installs on a fresh VPS and
#     silently does not on an updated one, or the reverse (0.1080: the 6.18
#     sysctl set was missing from the LOCALFILES branch, so every update
#     re-installed the 6.1 set on a 6.18 kernel)
#
# and the package's dependency pins mirror the installer's own *_VERSION
# constants, where a single stale pin makes the last step of the install,
# "apt-get -y install omr-server=${OMR_VERSION} >/dev/null 2>&1 || true",
# resolve to nothing without a word in the log.
#
# tests/test_deb_contents.sh checks the built artifact; this one checks the
# sources it is built from. Requires: bash.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"
CONTROL="$ROOT/debian/control"
RULES="$ROOT/debian/rules"
CHANGELOG="$ROOT/debian/changelog"

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

# Lines whose first non-blank character is # are commented-out install steps
# (several wget lines are kept that way on purpose) and reference nothing.
uncommented() { grep -vE '^[[:space:]]*#' "$INSTALLER"; }

# A path still holding a $ is built from a variable at run time
# (bin/v2ray-plugin-linux-amd64-v${V2RAY_PLUGIN_VERSION}.tar.gz); its name
# cannot be resolved here, so it is left to the human.
#
# %40 is "@": the systemd template units are fetched URL-encoded
# (glorytun-udp%40.service.in) and copied under their real name.
refs_local() {
    uncommented | grep -oE '\$\{DIR\}/[^[:space:];"'"'"'`)]+' \
        | sed 's|\${DIR}/||' | grep -v '\$' | sort -u
}
refs_remote() {
    uncommented | grep -oE '\$\{VPSURL\}\$\{VPSPATH\}/[^[:space:];"'"'"'`)]+' \
        | sed 's|.*VPSPATH}/||; s/%40/@/g' | grep -v '\$' | sort -u
}

refs_local  > "$TMPDIR/local"
refs_remote > "$TMPDIR/remote"
sort -u "$TMPDIR/local" "$TMPDIR/remote" > "$TMPDIR/all"

# ── 1. every referenced file exists ────────────────────────────────────────

echo "== every file the installer reads exists in the repository =="
missing=""
while read -r f; do
    [ -z "$f" ] && continue
    [ -e "$ROOT/$f" ] || missing="$missing $f"
done < "$TMPDIR/all"
if [ -z "$missing" ]; then
    pass "all $(wc -l < "$TMPDIR/all" | tr -d ' ') referenced files are present"
else
    fail "referenced by the installer but not in the repository:"
    printf '         %s\n' $missing
fi

# ── 2. the two branches install the same set of files ──────────────────────
# update-grub.sh is the one legitimate asymmetry: the remote branch downloads
# it to /tmp and cds there, the local branch just cds to ${DIR} and runs it by
# bare name, so it never appears as a ${DIR}/ path.

echo
echo "== fresh install (wget) and update (cp) install the same files =="
ALLOWED_REMOTE_ONLY="update-grub.sh"
remote_only="$(comm -13 "$TMPDIR/local" "$TMPDIR/remote")"
for a in $ALLOWED_REMOTE_ONLY; do
    remote_only="$(printf '%s\n' $remote_only | grep -vFx "$a")"
done
local_only="$(comm -23 "$TMPDIR/local" "$TMPDIR/remote")"

if [ -z "$(printf '%s' "$remote_only" | tr -d '[:space:]')" ]; then
    pass "nothing is downloaded on a fresh install that an update does not copy"
else
    fail "downloaded by the LOCALFILES=no branch only (an update will not install these):"
    printf '         %s\n' $remote_only
fi
if [ -z "$(printf '%s' "$local_only" | tr -d '[:space:]')" ]; then
    pass "nothing is copied on an update that a fresh install does not download"
else
    fail "copied by the LOCALFILES=yes branch only (a fresh install will not install these):"
    printf '         %s\n' $local_only
fi

# ── 3. what the installer reads out of a subdirectory must be packaged ─────
# debian/rules sweeps the repository root file by file and then copies each
# subdirectory by name, so a new top level *directory* is invisible to it
# until that list is extended -- which is exactly how
# systemd/20-omr-wait-online-any.conf shipped nowhere for a release.

echo
echo "== subdirectories the installer reads are copied by debian/rules =="
dirs="$(sed -n 's|^\([^/]*\)/.*|\1|p' "$TMPDIR/all" | sort -u)"
for d in $dirs; do
    if grep -qE "^[[:space:]]*cp -r \./$d[[:space:]]" "$RULES"; then
        pass "$d/ is copied into the package"
    else
        fail "$d/ is read by the installer but debian/rules never copies it"
    fi
done
# and the reverse: a directory dropped from the repository but left in rules
# fails the build with a cp error
for d in $(grep -oE '^[[:space:]]*cp -r \./[A-Za-z0-9._-]+' "$RULES" | sed 's|.*\./||'); do
    if [ -d "$ROOT/$d" ]; then
        pass "debian/rules copies $d/, which exists"
    else
        fail "debian/rules copies $d/, which does not exist"
    fi
done

# ── 3b. debian/rules stages everything inside the package ──────────────────
# Anything written under $(CURDIR)/debian/ that is not under the package's own
# staging directory is built and then left behind: it ends up in no package at
# all, silently. That is how the update-bin flag spent its life in
# debian/etc/openmptcprouter-vps-admin/ (instead of
# debian/omr-server/etc/...), which meant every deb install ran omr-update
# against a flag that was not there and changed nothing on the VPS.

echo
echo "== debian/rules writes only into the package staging directory =="
stray="$(grep -oE '\$\(CURDIR\)/debian/[A-Za-z0-9._/-]+' "$RULES" \
    | grep -v '^\$(CURDIR)/debian/omr-server' | sort -u)"
if [ -z "$stray" ]; then
    pass "every \$(CURDIR)/debian/ path is under debian/omr-server/"
else
    fail "written under debian/ but outside the package staging directory:"
    printf '         %s\n' $stray
fi

# ── 3c. nothing is left behind in /tmp ─────────────────────────────────────
# /tmp is a tmpfs on Debian 13, so every byte the installer leaves there is a
# byte of RAM gone until the next reboot. The kernel .deb alone is 95 MB: on a
# 1 GB VPS that is the difference between the installer's last step,
# "apt-get -y install omr-server=${OMR_VERSION}", completing and being
# OOM-killed -- silently, since that line's output goes to /dev/null.

echo
echo "== every file downloaded into /tmp is removed again =="
removals="$(uncommented | grep -oE 'rm -[rf]+ [^;&|]*' || true)"
leaked=""
for f in $(uncommented | grep -oE 'wget -O /tmp/[^[:space:]]+' | sed 's|wget -O /tmp/||' | sort -u); do
    printf '%s\n' "$removals" | grep -qF "/tmp/$f" || leaked="$leaked $f"
done
if [ -z "$leaked" ]; then
    pass "every /tmp download is cleaned up"
else
    fail "downloaded into the tmpfs /tmp and never removed:"
    printf '         %s\n' $leaked
fi

# ── 3d. the lock the omr-server postinst reads ─────────────────────────────
# That postinst asks omr-update to run this installer, and this installer's
# last step can call that postinst: without the lock, a fresh install starts a
# second copy of itself on top of the first.

echo
echo "== the installer marks itself as running =="
if uncommented | grep -q 'touch "\$OMR_INSTALL_LOCK"'; then
    pass "the installer creates its run lock"
else
    fail "the installer no longer creates /run/omr-install.running, which debian/postinst checks before arming an update"
fi
if uncommented | grep -q "trap 'rm -f \"\$OMR_INSTALL_LOCK\"'"; then
    pass "the lock is removed on exit"
else
    fail "nothing removes the run lock on exit: every later package install would skip its update run"
fi

# ── 4. dependency pins mirror the installer's constants ────────────────────
# Same table as tests/test_deb_contents.sh, read from a different place: that
# one checks the fields of a built package, this one the source they are
# generated from, so a stale pin is visible without a build.

echo
echo "== debian/control pins vs the installer's *_VERSION constants =="
installer_version() { grep -m1 "^$1=" "$INSTALLER" | cut -d'"' -f2; }
control_version() {
    sed -n "s|^ *$1 *([<>=]* *\([^)]*\)).*|\1|p" "$CONTROL" | head -n 1
}

while read -r pkg var; do
    [ -z "$pkg" ] && continue
    want="$(installer_version "$var")"
    got="$(control_version "$pkg")"
    if [ -z "$want" ]; then
        fail "$var not found in $(basename "$INSTALLER")"
    elif [ -z "$got" ]; then
        fail "$pkg is not pinned in debian/control (installer installs $want)"
    else
        assert_eq "$pkg pinned at the installed version" "$want" "$got"
    fi
done <<'DEPS'
omr-shadowsocks-libev SHADOWSOCKS_BINARY_VERSION
omr-simple-obfs OBFS_BINARY_VERSION
omr-vps-admin OMR_ADMIN_BINARY_VERSION
omr-mlvpn MLVPN_BINARY_VERSION
omr-glorytun GLORYTUN_UDP_BINARY_VERSION
omr-glorytun-tcp GLORYTUN_TCP_BINARY_VERSION
omr-dsvpn DSVPN_BINARY_VERSION
mqvpn MQVPN_VERSION
v2ray V2RAY_VERSION
xray XRAY_VERSION
shadowsocks-go SHADOWSOCKS_GO_VERSION
v2ray-plugin V2RAY_PLUGIN_VERSION
DEPS

# ── 5. versions ────────────────────────────────────────────────────────────
# The build is stamped with OMR_VERSION (.github/workflows/build-deb.yml), so
# the changelog does not have to carry the suffix a test build asks for -- but
# it does have to carry the release the installer is asking apt for, or the
# top changelog entry describes a version nobody will ever install.

echo
echo "== versions =="
OMR_VERSION="$(installer_version OMR_VERSION)"
CHANGELOG_VERSION="$(sed -n '1s|^omr-server (\([^)]*\)).*|\1|p' "$CHANGELOG")"
if [ -z "$OMR_VERSION" ]; then
    fail "OMR_VERSION not found in $(basename "$INSTALLER")"
elif [ -z "$CHANGELOG_VERSION" ]; then
    fail "the first line of debian/changelog is not a version header"
elif [ "$OMR_VERSION" = "$CHANGELOG_VERSION" ]; then
    pass "OMR_VERSION and debian/changelog are both $OMR_VERSION"
elif [ "${OMR_VERSION#$CHANGELOG_VERSION}" != "$OMR_VERSION" ]; then
    pass "OMR_VERSION ($OMR_VERSION) extends the changelog release ($CHANGELOG_VERSION)"
else
    fail "OMR_VERSION is $OMR_VERSION but debian/changelog's newest entry is $CHANGELOG_VERSION"
fi

# The line that ties the two together. Without it nothing installs the package
# at the end of a run and the version marker on the VPS is never written.
if uncommented | grep -q 'apt-get -y install omr-server=\${OMR_VERSION}'; then
    pass "the install ends with apt-get install omr-server=\${OMR_VERSION}"
else
    fail "no 'apt-get -y install omr-server=\${OMR_VERSION}' in the installer"
fi

# ── 6. the postinst's in-place edits still match ───────────────────────────
# debian/postinst rewrites the installed copy so the packaged installer never
# builds from source or reads files from a directory the package does not own.
# Both are ^-anchored: rename or indent either assignment and the sed becomes
# a silent no-op that changes how every installed VPS updates itself.

echo
echo "== debian/postinst edits still match the installer =="
for pat in $(grep -oE 's/\^[A-Z_]+=' "$ROOT/debian/postinst" | sed 's|^s/\^||; s|=$||'); do
    if grep -qE "^$pat=" "$INSTALLER"; then
        pass "postinst's ^$pat= rewrite matches a line in the installer"
    else
        fail "postinst rewrites ^$pat=, which no line of the installer matches"
    fi
done

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
