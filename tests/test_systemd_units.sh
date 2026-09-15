#!/bin/bash
# Tests for every systemd unit, drop-in and .network file this repository
# ships, plus the way the installer puts them on the VPS.
#
# systemd does not fail loudly on most of what goes wrong here:
#
#   - a %i in a unit that is not a template expands to nothing, so the service
#     starts against the wrong path and stays "active"
#   - a drop-in that adds an ExecStart= without first clearing the stock one
#     leaves the unit with two, which systemd refuses for Type=simple -- the
#     unit then fails at boot only
#   - a unit installed under a name nothing enables is simply never started,
#     and the feature it carries is silently absent
#   - an ExecStart naming a path the installer no longer writes leaves a unit
#     that fails at every start with status=203/EXEC
#
# Requires: bash, python3.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
    echo "FAIL python3 is required"
    exit 1
fi

python3 - "$ROOT" <<'PY'
import os, re, sys

root = sys.argv[1]
os.chdir(root)
installer = open('debian9-x86_64.sh', encoding='utf-8', errors='replace').read().splitlines()
# Commented-out install steps reference nothing.
live = [l for l in installer if not l.lstrip().startswith('#')]
live_text = "\n".join(live)

passed = failed = 0
def ok(d):
    global passed; passed += 1; print("  PASS %s" % d)
def ko(d, extra=""):
    global failed; failed += 1; print("  FAIL %s%s" % (d, extra))
def note(d):
    print("  note %s" % d)

UNIT_FILES = sorted(f for f in os.listdir('.')
                    if f.endswith(('.service', '.service.in', '.timer.in', '.network')))
DROPINS = ['systemd/20-omr-wait-online-any.conf',
           'nftables/omr-admin-resync.conf',
           'iperf3.override.conf']
UNIT_SECTIONS = {'Unit', 'Service', 'Install', 'Timer', 'Socket'}
# systemd-networkd's own vocabulary; anything outside it is a typo that
# networkd ignores in silence.
NETWORK_SECTIONS = {'Match', 'Link', 'Network', 'Address', 'Route', 'DHCP',
                    'DHCPv4', 'DHCPv6', 'DHCPServer', 'IPv6AcceptRA',
                    'IPv6SendRA', 'Neighbor', 'NextHop', 'RoutingPolicyRule',
                    'BridgeVLAN', 'QDisc', 'Tunnel', 'Peer', 'VLAN', 'Bridge'}

def parse(path):
    """[(section, key, value)] plus the section list, in file order."""
    entries, sections, section = [], [], None
    for n, raw in enumerate(open(path, encoding='utf-8', errors='replace'), 1):
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
            sections.append(section)
            continue
        if '=' not in line:
            entries.append((section, None, line, n))
            continue
        k, v = line.split('=', 1)
        entries.append((section, k.strip(), v.strip(), n))
    return entries, sections

# ── 1. syntax ──────────────────────────────────────────────────────────────
print("== unit syntax ==")
for f in UNIT_FILES + DROPINS:
    entries, sections = parse(f)
    bad = ["line %d: %s" % (n, v) for (s, k, v, n) in entries if k is None]
    allowed = NETWORK_SECTIONS if f.endswith('.network') else UNIT_SECTIONS
    unknown = [s for s in sections if s not in allowed]
    orphan = [("line %d: %s=%s" % (n, k, v)) for (s, k, v, n) in entries if s is None]
    problems = bad + ["unknown section [%s]" % s for s in unknown] + \
               ["outside any section, %s" % o for o in orphan]
    if problems:
        ko("%s" % f, "\n    " + "\n    ".join(problems))
    else:
        ok("%s parses (%s)" % (f, ", ".join("[%s]" % s for s in sections)))

# ── 2. templates and specifiers ────────────────────────────────────────────
print("\n== template specifiers ==")
for f in UNIT_FILES:
    if f.endswith('.network'):
        continue
    entries, _ = parse(f)
    body = "\n".join("%s=%s" % (k, v) for (s, k, v, n) in entries if k)
    uses = re.search(r'%[iI]', body)
    if '@' in f:
        if uses:
            ok("%s is a template and uses %%i/%%I" % f)
        else:
            ko("%s is a template unit that never uses its instance name" % f)
    else:
        if uses:
            ko("%s is not a template but uses %%i/%%I, which expands to nothing" % f)
        else:
            ok("%s uses no instance specifier" % f)

# ── 3. Exec= lines ─────────────────────────────────────────────────────────
# systemd requires an absolute path; the optional "-", "@", "+", "!" prefixes
# change error handling, not the path.
print("\n== Exec= commands ==")
EXEC_KEYS = ('ExecStart', 'ExecStop', 'ExecStartPre', 'ExecStartPost',
             'ExecReload', 'ExecStopPost')
repo_files = set(os.listdir('.'))
for f in UNIT_FILES + DROPINS:
    entries, _ = parse(f)
    execs = [(k, v, n) for (s, k, v, n) in entries if k in EXEC_KEYS]
    drop_in = f in DROPINS
    for k, v, n in execs:
        if v == '':
            if drop_in:
                continue        # the required reset before a replacement
            ko("%s line %d: empty %s= outside a drop-in" % (f, n, k))
            continue
        cmd = v.split()[0].lstrip('-@+!:')
        if not cmd.startswith('/'):
            ko("%s line %d: %s=%s is not an absolute path" % (f, n, k, cmd))
            continue
        base = os.path.basename(cmd)
        # Only what this repository ships can be checked against the installer;
        # /usr/bin/xray and friends come from their own packages.
        if base in repo_files:
            if re.search(r'(^|\s)%s(\s|$)' % re.escape(cmd), live_text):
                ok("%s: %s=%s is installed there by the installer" % (f, k, cmd))
            else:
                ko("%s: %s=%s, but the installer never writes that path "
                   "(the repo ships ./%s)" % (f, k, cmd, base))

# ── 4. drop-ins replace rather than append ────────────────────────────────
# ExecStart= in a drop-in appends to the stock list; the empty assignment
# first is what turns it into a replacement.
print("\n== drop-ins ==")
for f in DROPINS:
    entries, _ = parse(f)
    execs = [(k, v) for (s, k, v, n) in entries if k == 'ExecStart']
    if not execs:
        note("%s sets no ExecStart" % f)
    elif execs[0][1] == '' and len(execs) >= 2:
        ok("%s clears ExecStart before setting its own" % f)
    else:
        ko("%s sets ExecStart without the empty reset first (systemd would run both)" % f)

# The two fixes 0.1080/0.1081 turn on, spelled out so a reformat cannot drop
# one silently: --any alone is satisfied by a link-local address, and without
# --timeout an ifupdown-managed VPS waits out wait-online's own 120s default
# on every boot.
wait_online = open('systemd/20-omr-wait-online-any.conf').read()
for needle, why in (('--any', 'returns on the first routable link'),
                    ('-o routable', 'does not settle for a link-local address'),
                    ('--timeout=', 'caps the wait on a VPS networkd does not manage')):
    if needle in wait_online:
        ok("wait-online drop-in keeps %s (%s)" % (needle, why))
    else:
        ko("wait-online drop-in lost %s (%s)" % (needle, why))

# nftables.service reloads run `flush ruleset`, which empties the chains
# omr-admin owns; the restart hook is what replays them from
# omr-admin-config.json. --no-block because omr-admin is ordered after
# nftables.service, so a blocking restart from inside ExecStartPost deadlocks.
resync = open('nftables/omr-admin-resync.conf').read()
for key in ('ExecStartPost', 'ExecReload'):
    line = [l for l in resync.splitlines() if l.startswith(key + '=')]
    if not line:
        ko("the nftables drop-in has no %s (omr-admin's chains stay empty after a %s)"
           % (key, 'start' if key == 'ExecStartPost' else 'reload'))
        continue
    val = line[0].split('=', 1)[1]
    problems = []
    if 'try-restart omr-admin.service' not in val:
        problems.append("does not try-restart omr-admin.service")
    if '--no-block' not in val:
        problems.append("is not --no-block (it would deadlock against After=nftables.service)")
    if not val.startswith('-'):
        problems.append("has no leading '-' (a failed hook would fail the firewall load)")
    if problems:
        ko("nftables drop-in %s=: %s" % (key, "; ".join(problems)))
    else:
        ok("nftables drop-in %s= restarts omr-admin safely" % key)

# ── 5. ordering that another file depends on ──────────────────────────────
print("\n== ordering ==")
admin = open('omr-admin.service.in').read()
after = " ".join(l.split('=', 1)[1] for l in admin.splitlines() if l.startswith('After='))
if 'nftables.service' in after:
    ok("omr-admin.service is ordered After=nftables.service")
else:
    ko("omr-admin.service is no longer ordered after nftables.service, which the "
       "--no-block restart hook in nftables/omr-admin-resync.conf relies on")

# ── 6. installed units are enabled by something ───────────────────────────
# A unit copied into /lib/systemd/system that nothing enables or starts is
# dead weight, and the feature it carries never runs.
print("\n== every installed unit is enabled or started ==")
postinst = open('debian/postinst').read()
dests = sorted(set(re.findall(r'/lib/systemd/system/([A-Za-z0-9@._-]+\.(?:service|timer))',
                              live_text)))
for unit in dests:
    name = unit.rsplit('.', 1)[0]           # omr-bypass.timer -> omr-bypass
    stem = name[:-1] if name.endswith('@') else name
    pat = r'systemctl\b[^\n]*\b(enable|start|restart|reload-or-restart)\b[^\n]*\b%s\b' % re.escape(stem)
    if re.search(pat, live_text) or re.search(pat, postinst):
        ok("%s is enabled or started" % unit)
    else:
        ko("%s is installed but nothing ever enables or starts it" % unit)

# ── 7. networkd files ─────────────────────────────────────────────────────
print("\n== .network files ==")
for f in sorted(x for x in UNIT_FILES if x.endswith('.network')):
    entries, sections = parse(f)
    if 'Match' not in sections:
        ko("%s has no [Match] section, so it applies to no link" % f)
        continue
    names = [v for (s, k, v, n) in entries if s == 'Match' and k == 'Name']
    if names:
        ok("%s matches %s" % (f, ", ".join(names)))
    else:
        ko("%s has a [Match] section with no Name=" % f)

print("\n%d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
