#!/bin/bash
# Checks a built omr-server .deb against the installer it ships, catching the
# two ways this package silently rots:
#
#   1. a file the installer copies out of its own directory that debian/rules
#      never packaged. debian/rules copies the repo root file by file, then
#      each subdirectory by name, so a new top level *directory* is invisible
#      to it: 0.1080 added systemd/20-omr-wait-online-any.conf and the package
#      shipped it nowhere, while the LOCALFILES path does an unguarded
#      "cp ${DIR}/systemd/..." that ends any run taking that branch under
#      set -e, halfway through the firewall section
#   2. a version pin in debian/control that no longer matches the version the
#      installer asks apt for. The install ends with
#      "apt-get -y install omr-server=${OMR_VERSION} >/dev/null 2>&1 || true",
#      so one unresolvable dependency means no package, no version marker and
#      not a word in the log
#
# It also checks the package version itself against OMR_VERSION, the version
# that same apt-get line asks for -- a .deb built straight from
# debian/changelog carries the bare "0.1082" and can never answer it.
#
# Usage: tests/test_deb_contents.sh [path/to/omr-server_*.deb]
# Without an argument it takes the newest omr-server_*.deb found next to the
# repository or in ./dist. Requires: bash, dpkg-deb.
# EXPECT_VERSION=x.y overrides the version the package is expected to carry.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "FAIL dpkg-deb is required to inspect the package"
    exit 1
fi

DEB="$1"
if [ -z "$DEB" ]; then
    DEB="$(ls -t "$ROOT"/../omr-server_*.deb "$ROOT"/dist/omr-server_*.deb 2>/dev/null | head -n 1)"
fi
if [ -z "$DEB" ] || [ ! -f "$DEB" ]; then
    # 77 is "skipped" to tests/run_all.sh: there is nothing to inspect yet.
    echo "SKIP no .deb given and none found (build one with: dpkg-buildpackage -us -uc -b)"
    exit 77
fi
echo "Package: $DEB"

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

# Paths inside the package, relative to /usr/share/omr-server
dpkg-deb --contents "$DEB" | awk '{print $6}' \
    | sed -n 's|^\./usr/share/omr-server/||p' | sed '/\/$/d' | sort -u > "$TMPDIR/packaged"

# ── 1. every file the installer reads from its own directory ────────────────
# Which callers reach this branch is worth being exact about. The packaged
# installer is not one of them: debian/postinst rewrites its own
# "LOCALFILES=${LOCALFILES:-no}" and "SOURCES=${SOURCES:-no}" into plain "no",
# and a bare assignment beats the environment, so it takes the download branch
# -- which is why omr-update stopped passing those two variables at all. What
# is left reading ${DIR} is a run from a checkout and the SOURCES=yes branch
# (DIR=/usr/share/omr-server-git), plus the package itself the day that pin
# changes. The package is what claims to carry these files, so one missing
# from it is a packaging bug either way.

echo "== files the installer copies from \${DIR} =="
grep -oE '\$\{DIR\}/[A-Za-z0-9._@/-]+' "$INSTALLER" | sed 's|\${DIR}/||' | sort -u > "$TMPDIR/referenced"
missing="$(comm -23 "$TMPDIR/referenced" "$TMPDIR/packaged")"
if [ -z "$missing" ]; then
    pass "all $(wc -l < "$TMPDIR/referenced" | tr -d ' ') referenced files are packaged"
else
    fail "referenced by the installer but not in the package:"
    printf '         %s\n' $missing
fi

# The postinst rewrites this one in place, and omr-update executes it.
if grep -qx 'debian9-x86_64.sh' "$TMPDIR/packaged"; then
    pass "debian9-x86_64.sh is packaged (postinst seds it, omr-update runs it)"
else
    fail "debian9-x86_64.sh is missing from the package"
fi

echo
echo "== nothing that should stay out =="
leaked="$(grep -E '^(\.git|debian)/' "$TMPDIR/packaged")"
if [ -z "$leaked" ]; then
    pass "no .git/ or debian/ content shipped under /usr/share/omr-server"
else
    fail "packaging internals leaked into the package:"
    printf '         %s\n' $leaked
fi

# ── 1b. the flag that makes an install do anything at all ───────────────────
# Installing this package only refreshes /usr/share/omr-server; the installer
# is what puts those files where they belong. The postinst arms that by
# creating /etc/openmptcprouter-vps-admin/update-bin and restarting
# omr-update, which takes its "update-bin" branch and removes the flag when
# done. Two ways that stops working silently, both seen on this package:
#   - debian/rules once touched the flag into $(CURDIR)/debian/etc/ instead of
#     $(CURDIR)/debian/omr-server/etc/, outside the staging directory, so it
#     was in no package at all and every install's omr-update run exited in
#     the same second
#   - shipping it as a package file makes it a conffile (dpkg flags everything
#     under /etc), and a conffile the runtime deletes is never restored by a
#     later upgrade, so the update would be armed on the first install only

echo
echo "== the update-bin flag =="
POSTINST="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -xOf - ./postinst 2>/dev/null)"
if printf '%s' "$POSTINST" | grep -q 'touch /etc/openmptcprouter-vps-admin/update-bin'; then
    pass "the postinst creates /etc/openmptcprouter-vps-admin/update-bin"
else
    fail "nothing in the postinst creates the update-bin flag; installing this package would refresh /usr/share/omr-server and change nothing on the VPS"
fi
if printf '%s' "$POSTINST" | grep -qE 'systemctl (-q )?restart omr-update'; then
    pass "the postinst restarts omr-update"
else
    fail "the postinst never restarts omr-update, so the flag above is never acted on"
fi
# The installer that run executes ends with "apt-get -y install
# omr-server=${OMR_VERSION}", which can bring this very script back.
if printf '%s' "$POSTINST" | grep -q 'is-active omr-update' \
   && printf '%s' "$POSTINST" | grep -q '/run/omr-install.running'; then
    pass "the postinst skips the restart during an installer run and during an omr-update run"
else
    fail "the postinst arms omr-update unconditionally: called from the installer's own apt-get, that starts a second install on top of the running one"
fi
if dpkg-deb --ctrl-tarfile "$DEB" | tar -tf - | grep -q '^\./conffiles$'; then
    fail "the package declares conffiles:"
    dpkg-deb --ctrl-tarfile "$DEB" | tar -xOf - ./conffiles | sed 's/^/         /'
else
    pass "the package declares no conffiles (nothing under /etc is shipped)"
fi

# ── 1c. archive members the apt repository can read ────────────────────────
# dpkg-deb's default compression follows the distribution doing the build:
# Debian writes xz, Ubuntu writes zstd, and .github/workflows/build-deb.yml
# builds on ubuntu-latest. reprepro reads gzip and xz only, so a zstd package
# is refused at the door with
#   Could not find a suitable control.tar file within '...omr-server_....deb'!
# and never reaches the repository the installer's own
# "apt-get -y install omr-server=${OMR_VERSION}" pulls from.

echo
echo "== archive members =="
members="$(ar t "$DEB" | tr '\n' ' ')"
bad="$(printf '%s\n' $members | grep -vE '^(debian-binary|(control|data)\.tar\.(gz|xz))$' || true)"
if [ -z "$bad" ]; then
    pass "members are $members(reprepro reads all of these)"
else
    fail "members reprepro will refuse:"
    printf '         %s\n' $bad
    printf '         (debian/rules pins this with "dh_builddeb -- -Zxz")\n'
fi

# ── 2. dependency pins against the installer's own constants ────────────────
# debian/control mirrors the versions the installer asks apt for; it is never
# the source of truth, so every pin has to be checked against the constant it
# mirrors.

echo
echo "== dependency pins vs the installer's *_VERSION constants =="
# One field at a time: dpkg-deb prefixes the output with the field name as
# soon as more than one is asked for, which would glue "Recommends:" onto the
# last dependency of Depends.
RELATIONS="$(for f in Depends Recommends Suggests; do
    dpkg-deb --field "$DEB" "$f" | tr '\n' ' '; printf ','
done)"

installer_version() {
    grep -m1 "^$1=" "$INSTALLER" | cut -d'"' -f2
}
control_version() {
    printf '%s' "$RELATIONS" | tr ',' '\n' \
        | sed -n "s|^ *$1 *([<>=]* *\([^)]*\)).*|\1|p" | head -n 1
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

# Dependencies the installer removes or never installs must not be declared:
# apt removing omr-iperf3 (which the installer does on amd64) would take
# omr-server with it, and libcurl4 does not exist on Debian 13.
echo
echo "== dependencies that must not come back =="
for pkg in omr-iperf3 libcurl4 linux-image-5.4.100-mptcp; do
    if printf '%s' "$RELATIONS" | grep -qE "(^| )$pkg( |,|\(|$)"; then
        fail "$pkg is declared again (see debian/changelog 0.1082)"
    else
        pass "$pkg not declared"
    fi
done

# ── 3. the version the installer will ask apt for ───────────────────────────

echo
echo "== package version =="
EXPECT_VERSION="${EXPECT_VERSION:-$(installer_version OMR_VERSION)}"
GOT_VERSION="$(dpkg-deb --field "$DEB" Version)"
assert_eq "version matches OMR_VERSION, the version apt is asked for" \
    "$EXPECT_VERSION" "$GOT_VERSION"
if [ "$EXPECT_VERSION" != "$GOT_VERSION" ]; then
    printf '    (debian/changelog carries the bare version; stamp the build with\n'
    printf '     sed -i "1s/^omr-server ([^)]*)/omr-server (%s)/" debian/changelog\n' "$EXPECT_VERSION"
    printf '     as .github/workflows/build-deb.yml does, or set EXPECT_VERSION)\n'
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
