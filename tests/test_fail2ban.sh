#!/bin/bash
# Tests for the shipped fail2ban jail and filters.
#
# A fail2ban filter fails in two directions and neither is visible on the VPS:
#
#   - too loose: it counts something that is not a failed login, and bans a
#     router out of the API it is being set up from (0.1079: "POST /token" 400
#     and "GET /login_basic" 401 are logged when a router polls with no key
#     yet, and a browser opening /docs draws the 401 Basic challenge). Worse,
#     an unanchored regex reading an access log lets the request path -- which
#     the attacker writes -- forge a matching line and ban any address they
#     name
#   - too tight, or aimed at the wrong daemon name: it silently matches
#     nothing and the jail bans no one, which looks exactly like "no attacks"
#
# The regexes are read out of the shipped filter files and exercised here
# against journal lines of both kinds. common.conf is not available outside a
# fail2ban install, so its __prefix_line is approximated: an optional
# timestamp and hostname, the filter's own _daemon, an optional [pid], a colon
# and whitespace. That is the shape the systemd backend feeds a filter
# (SYSLOG_IDENTIFIER[PID]: MESSAGE), which is the backend this jail uses.
#
# Requires: bash, python3.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"
JAIL="$ROOT/fail2ban-jail-openmptcprouter.conf"
cd "$ROOT" || exit 1

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }

uncommented() { grep -vE '^[[:space:]]*#' "$INSTALLER"; }

# Section-scoped ini lookup: jail_get <section> <key>
jail_get() {
    awk -v sect="[$1]" -v key="$2" '
        $0 ~ /^\[/ { in_sect = ($0 == sect); next }
        in_sect && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/, ""); print; exit
        }' "$JAIL"
}
jail_sections() { sed -n 's/^\[\(.*\)\]$/\1/p' "$JAIL" | grep -v '^DEFAULT$'; }

# ── 1. filters are installed, and under the name the jail asks for ─────────
# The jail names a filter, fail2ban resolves it in /etc/fail2ban/filter.d/,
# and the installer is the only thing that puts one there -- under a name it
# chooses on the wget/cp line, not the name of the file in this repository.

echo "== every shipped filter is installed, under the name the jail uses =="
installed_filters=""
for line in $(uncommented | grep -oE '/etc/fail2ban/filter\.d/[A-Za-z0-9_.-]+\.conf'); do
    installed_filters="$installed_filters $(basename "$line" .conf)"
done
installed_filters="$(printf '%s\n' $installed_filters | sort -u | tr '\n' ' ')"

for f in fail2ban-filter-*.conf; do
    name="${f#fail2ban-filter-}"; name="${name%.conf}"
    wget_count=$(uncommented | grep -cE "wget -O /etc/fail2ban/filter\.d/$name\.conf .*$f\$")
    cp_count=$(uncommented | grep -cE "cp \\\$\{DIR\}/$f /etc/fail2ban/filter\.d/$name\.conf\$")
    if [ "$wget_count" -ge 1 ] && [ "$cp_count" -ge 1 ]; then
        pass "$f is installed as filter.d/$name.conf by both branches"
    else
        fail "$f: fresh install installs it $wget_count time(s), an update $cp_count time(s) (both must be 1)"
    fi
done

echo
echo "== every jail resolves to a filter that exists =="
# sshd ships with fail2ban itself; everything else has to come from this repo.
STOCK_FILTERS="sshd"
for jail in $(jail_sections); do
    filter="$(jail_get "$jail" filter)"
    [ -z "$filter" ] && filter="$jail"
    if printf '%s' " $installed_filters " | grep -q " $filter "; then
        pass "jail [$jail] uses filter $filter, installed by the installer"
    elif printf '%s' " $STOCK_FILTERS " | grep -q " $filter "; then
        pass "jail [$jail] uses filter $filter, shipped by fail2ban itself"
    else
        fail "jail [$jail] uses filter $filter, which nothing installs"
    fi
done

# ── 2. jail settings that have bitten before ──────────────────────────────

echo
echo "== jail settings =="
ignoreip="$(jail_get DEFAULT ignoreip)"
# omr-service probes https://127.0.0.1:65500 every 10 seconds and restarts
# omr-admin when a probe fails; fail2ban's own ignoreself does not cover
# loopback and Debian comments its ignoreip out.
case "$ignoreip" in
    *127.0.0.1/8*) pass "[DEFAULT] ignoreip covers IPv4 loopback" ;;
    *) fail "[DEFAULT] ignoreip does not cover 127.0.0.1/8 (omr-service probes the API from there)" ;;
esac
case "$ignoreip" in
    *::1*) pass "[DEFAULT] ignoreip covers IPv6 loopback" ;;
    *) fail "[DEFAULT] ignoreip does not cover ::1" ;;
esac

backend="$(jail_get DEFAULT backend)"
if [ "$backend" = "systemd" ]; then
    pass "[DEFAULT] backend is systemd"
    # Without python3-systemd the systemd backend cannot start at all.
    if uncommented | grep -q 'apt-get -y install fail2ban python3-systemd'; then
        pass "the installer installs python3-systemd alongside fail2ban"
    else
        fail "backend = systemd but the installer does not install python3-systemd"
    fi
else
    fail "[DEFAULT] backend is '$backend'; the journalmatch lines below assume systemd"
fi

# The omradmin jail protects an API whose only clients are the operator's own
# routers, on a port nothing else talks to, while a false positive costs a
# router its VPS ("can ping server vps, no server API answer"). Disabled on
# purpose in 0.1081 -- if that decision is reversed, this check is the place
# to record it.
if [ "$(jail_get omradmin enabled)" = "false" ]; then
    pass "[omradmin] is disabled by default (0.1081)"
else
    fail "[omradmin] is enabled again; see debian/changelog 0.1081 for why it was not"
fi

for jail in $(jail_sections); do
    missing=""
    [ -z "$(jail_get "$jail" enabled)" ] && missing="$missing enabled"
    # sshd takes fail2ban's own port/filter/journalmatch/maxretry defaults.
    if [ "$jail" != "sshd" ]; then
        for key in port protocol journalmatch maxretry; do
            [ -z "$(jail_get "$jail" "$key")" ] && missing="$missing $key"
        done
    fi
    if [ -z "$missing" ]; then
        pass "jail [$jail] declares everything it needs"
    else
        fail "jail [$jail] is missing:$missing"
    fi
done

# A journalmatch naming a unit that does not exist reads an empty stream for
# ever, and the jail is a no-op nobody notices.
echo
echo "== journalmatch units are units this VPS runs =="
for jail in $(jail_sections); do
    jm="$(jail_get "$jail" journalmatch)"
    [ -z "$jm" ] && continue
    unit="${jm#_SYSTEMD_UNIT=}"
    if [ "$unit" = "$jm" ]; then
        fail "jail [$jail] journalmatch is '$jm', not a _SYSTEMD_UNIT= match"
        continue
    fi
    base="${unit%.service}"
    if uncommented | grep -qE "(^|[^a-zA-Z0-9_.-])${base}(\.service|[^a-zA-Z0-9_.-]|$)"; then
        pass "jail [$jail] watches $unit, a unit the installer sets up"
    else
        fail "jail [$jail] watches $unit, which the installer never mentions"
    fi
done

# ── 3. what the regexes actually match ────────────────────────────────────

echo
echo "== filter regexes =="
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 is required for the regex checks"
    echo
    echo "$PASS passed, $FAIL failed"
    exit 1
fi

python3 - <<'PY'
import re, sys, configparser, os

passed = failed = 0
def ok(d):
    global passed; passed += 1; print("  PASS %s" % d)
def ko(d, extra=""):
    global failed; failed += 1; print("  FAIL %s%s" % (d, extra))
def note(d):
    print("  note %s" % d)

# fail2ban's <HOST> is an address or a hostname; the surrounding regex decides
# whether brackets are part of it. Close enough for these lines.
HOST = r'(?P<host>[0-9a-fA-F:.]+)'

def load(name):
    cp = configparser.RawConfigParser(strict=False)
    cp.read('fail2ban-filter-%s.conf' % name)
    daemon = cp.get('Definition', '_daemon', fallback=name)
    fail = cp.get('Definition', 'failregex')
    return daemon, [l for l in fail.splitlines() if l.strip()]

def compile_filter(name):
    daemon, lines = load(name)
    # Approximation of common.conf's __prefix_line for the systemd backend.
    prefix = r'(?:\S+\s+\d+\s+\d\d:\d\d:\d\d\s+)?(?:\S+\s+)?(?:%s)(?:\[\d+\])?:?\s+' % daemon
    out = []
    for line in lines:
        rx = line.replace('%(__prefix_line)s', prefix).replace('<HOST>', HOST)
        out.append(re.compile(rx))
    return out

def check(name, line, expect, why):
    try:
        rxs = compile_filter(name)
    except re.error as e:
        ko("%s: failregex does not compile (%s)" % (name, e))
        return
    hit = None
    for rx in rxs:
        m = rx.search(line)
        if m:
            hit = m
            break
    if bool(hit) == expect:
        if expect:
            ok("%s matches %s (banning %s)" % (name, why, hit.group('host')))
        else:
            ok("%s ignores %s" % (name, why))
    else:
        ko("%s %s %s" % (name, "should match but does not:" if expect else
                         "matches what it must not:", why),
           "\n    line: %s" % line)

# Structure first: one <HOST> per alternative, or fail2ban refuses the filter.
for name in sorted(f[len('fail2ban-filter-'):-len('.conf')]
                   for f in os.listdir('.')
                   if f.startswith('fail2ban-filter-') and f.endswith('.conf')):
    daemon, lines = load(name)
    bad = [l for l in lines if l.count('<HOST>') != 1]
    if bad:
        ko("%s: every failregex alternative needs exactly one <HOST>" % name,
           "\n    " + "\n    ".join(bad))
    else:
        ok("%s: %d failregex alternative(s), one <HOST> each" % (name, len(lines)))
    try:
        compile_filter(name)
        ok("%s: failregex compiles" % name)
    except re.error as e:
        ko("%s: failregex does not compile (%s)" % (name, e))

# omr-admin logs the line below itself, at WARNING, only for a credential pair
# that was actually rejected (omr-admin 0.18+20260908 and later).
check('omradmin', 'omradmin.py[1234]: omr-admin: authentication failure from 203.0.113.7',
      True, 'a rejected credential pair')
check('omradmin', 'omradmin.py[1234]: WARNING: omr-admin: authentication failure from 203.0.113.7',
      True, 'the same line with uvicorn\'s WARNING prefix')
check('omradmin', 'omradmin.py[1234]: omr-admin: authentication failure from 2001:db8::1',
      True, 'an IPv6 client')
# The attack the anchors exist for: the request path is written by the client
# and access-logged verbatim, so an unanchored regex would ban 198.51.100.1 --
# an address of the attacker's choosing -- on demand.
check('omradmin',
      'omradmin.py[1234]: 203.0.113.9:44 - "GET /omr-admin:%20authentication%20failure%20from%20198.51.100.1 HTTP/1.1" 404',
      False, 'a request path forging the failure line')
check('omradmin',
      'omradmin.py[1234]: 203.0.113.9:44 - "GET /omr-admin: authentication failure from 198.51.100.1 HTTP/1.1" 404',
      False, 'the same forgery, unencoded')
# The two false positives 0.1079 removed: a router with no VPS key yet polls
# /token, and a browser opening /docs draws the Basic challenge.
check('omradmin', 'omradmin.py[1234]: 203.0.113.9:44 - "POST /token HTTP/1.1" 400',
      False, 'a router polling /token with no key yet')
check('omradmin', 'omradmin.py[1234]: 203.0.113.9:44 - "GET /login_basic HTTP/1.1" 401',
      False, 'the Basic challenge a browser draws on /docs')
# The trailing $ is the other half of the anchoring: omr-admin logs the peer
# address and nothing else after it, on purpose (a username echoed there could
# carry a newline), so a line that continues past the address did not come
# from it and must not ban anyone.
check('omradmin',
      'omradmin.py[1234]: omr-admin: authentication failure from 203.0.113.7 for user admin',
      False, 'a line that continues past the address')
# _daemon exists so another service's log cannot feed this filter.
check('omradmin', 'sshd[1234]: omr-admin: authentication failure from 198.51.100.1',
      False, 'the same text logged by another daemon')

for proxy in ('xray', 'v2ray'):
    check(proxy, '%s[1234]: 2026/01/02 15:04:05 from 203.0.113.7:56789 rejected  proxy/vmess/inbound: invalid user' % proxy,
          True, 'a rejected proxy connection')
    check(proxy, '%s[1234]: from [2001:db8::1]:56789 rejected  proxy/vless/inbound: invalid user' % proxy,
          True, 'a rejected IPv6 connection')
    check(proxy, '%s[1234]: 2026/01/02 15:04:05 from 203.0.113.7:56789 accepted tcp:1.1.1.1:443' % proxy,
          False, 'an accepted connection')

# The filter expects the message to start the journal line, with zap's
# structured fields after it (shadowsocks-go's "systemd" logger preset, which
# leaves the timestamp to the journal).
check('shadowsocks-go',
      'shadowsocks-go[1234]: Failed to complete handshake with client\t{"server": "ss", "listenAddress": "[::]:65280", "clientAddress": "203.0.113.7:44444", "error": "bad header"}',
      True, 'a failed handshake')
check('shadowsocks-go',
      'shadowsocks-go[1234]: Failed to complete handshake with client\t{"clientAddress": "[2001:db8::1]:44444"}',
      True, 'a failed handshake from IPv6')
check('shadowsocks-go',
      'shadowsocks-go[1234]: Accepted connection\t{"clientAddress": "203.0.113.7:44444"}',
      False, 'a normal accepted connection')
# Which zap preset the shipped shadowsocks-go.service runs with decides
# whether the message starts the line or sits inside a JSON object; a filter
# that only handles one of the two bans no one under the other, and on a VPS
# that looks exactly like "no attacks".
check('shadowsocks-go',
      'shadowsocks-go[1234]: {"level":"warn","ts":"2026-01-02T15:04:05Z","msg":"Failed to '
      'complete handshake with client","clientAddress":"203.0.113.7:44444"}',
      True, 'the same failure logged as zap JSON')
check('shadowsocks-go',
      'shadowsocks-go[1234]: 2026-01-02T15:04:05.000Z\tWARN\tFailed to complete handshake '
      'with client\t{"clientAddress": "203.0.113.7:44444"}',
      True, 'the same failure with a console timestamp in front')
# zap escapes every quote inside a field value, so client-controlled text can
# carry \"clientAddress\" but never an unescaped one: the address banned is
# always the one shadowsocks-go itself logged.
check('shadowsocks-go',
      'shadowsocks-go[1234]: Failed to open connection\t{"clientAddress": "203.0.113.7:44444", '
      '"error": "lookup Failed to complete handshake with client \\"clientAddress\\": '
      '\\"198.51.100.1:1\\": no such host"}',
      False, 'an error string echoing the pattern with escaped quotes')

check('openvpn', 'ovpn-server[1234]: 203.0.113.7:1194 TLS Auth Error: Auth Username/Password verification failed',
      True, 'a TLS auth error')
check('openvpn', 'ovpn-server[1234]: 203.0.113.7:1194 VERIFY ERROR: depth=0, error=self signed certificate',
      True, 'a certificate verification error')
check('openvpn', 'ovpn-server[1234]: TLS Error: cannot locate HMAC in incoming packet from [AF_INET]203.0.113.7:1194',
      True, 'a packet with no HMAC')
check('openvpn', 'ovpn-server[1234]: 203.0.113.7:1194 [client] Peer Connection Initiated',
      False, 'a successful connection')

print("  -- %d regex checks passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PY
rc=$?
[ "$rc" -eq 0 ] || fail "one or more regex checks above failed"

echo
echo "$PASS passed, $FAIL failed (the regex checks report their own counts above)"
[ "$FAIL" -eq 0 ]
