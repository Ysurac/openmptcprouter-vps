#!/bin/bash
# Content sanity of the files the installer ships, in the state they are
# shipped in. Each check stands for a way one of these files has broken a VPS
# without breaking the install itself -- the run succeeds, the damage shows up
# at the next boot or the next API call:
#
#   - a template placeholder the installer no longer substitutes stays in the
#     deployed config verbatim, so the service comes up with the literal
#     string as its key or password
#   - a file the runtime appends to that does not end with a newline glues the
#     appended line onto the last one (0.1080: "...tcp_slow_start_after_idle=0"
#     + "net.mptcp.checksum_enabled=0" on one line, which systemd-sysctl
#     treats as a fatal error, so nothing in that file was applied any more)
#   - an inbound tag the installer's jq selects but no template declares means
#     the per-user accounts are silently never added
#   - a sysctl key set twice with two different values: the second one wins,
#     the first is dead text nobody notices
#
# Requires: bash, jq.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"
cd "$ROOT" || exit 1

if ! command -v jq >/dev/null 2>&1; then
    echo "FAIL jq is required"
    exit 1
fi

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
note() { printf '  note %s\n' "$1"; }

uncommented() { grep -vE '^[[:space:]]*#' "$INSTALLER"; }

# Files tracked by git, minus the ones that are not shipped configuration.
# Outside a git checkout (an unpacked source tarball), walk the tree instead --
# an empty list here would let every check below pass on nothing.
shipped_files() {
    local files
    files="$(git ls-files 2>/dev/null)"
    if [ -z "$files" ]; then
        files="$(find . -type f -not -path './.git/*' | sed 's|^\./||')"
    fi
    printf '%s\n' "$files" | grep -vE '^(tests|docs|\.github)/'
}

# ── 1. shell syntax ────────────────────────────────────────────────────────
# Every one of these is executed on a VPS, most of them by systemd with no one
# watching; a syntax error is a service that never starts.

echo "== shell syntax =="
syntax_bad=""
checked=0
for f in $(shipped_files); do
    [ -f "$f" ] || continue
    case "$f" in
        *.tar.gz|*.gz|*.json) continue ;;
    esac
    head -n 1 "$f" | grep -qE '^#!.*(bash|/bin/sh|dash)' || continue
    checked=$((checked+1))
    bash -n "$f" 2>/dev/null || syntax_bad="$syntax_bad $f"
done
if [ -z "$syntax_bad" ]; then
    pass "$checked shell scripts parse"
else
    fail "shell scripts with a syntax error:"
    printf '         %s\n' $syntax_bad
fi

# The per-distribution entry points are symlinks to debian9-x86_64.sh and are
# what the download server actually serves (debian.sh, ubuntu20.04-x86_64.sh,
# ...). A dangling one is a 404 at the very first step of an install.
broken_links=""
for f in $(shipped_files); do
    [ -L "$f" ] || continue
    [ -e "$f" ] || broken_links="$broken_links $f"
done
if [ -z "$broken_links" ]; then
    pass "every shipped symlink resolves"
else
    fail "dangling symlinks:"
    printf '         %s\n' $broken_links
fi

# ── 2. JSON validity ───────────────────────────────────────────────────────
# These are installed as-is and parsed by xray/v2ray/shadowsocks-go at
# startup, after a chain of sed substitutions -- a file that is already
# invalid here has no chance of being valid there.

echo
echo "== JSON templates parse =="
json_bad=""
json_count=0
for f in $(shipped_files | grep '\.json$'); do
    json_count=$((json_count+1))
    jq -e . "$f" >/dev/null 2>&1 || json_bad="$json_bad $f"
done
if [ -z "$json_bad" ]; then
    pass "$json_count JSON files parse"
else
    fail "invalid JSON:"
    printf '         %s\n' $json_bad
fi

# ── 3. placeholders the installer substitutes ──────────────────────────────
# Build the map of "installed file" -> "template(s) it comes from" out of the
# installer's own wget/cp lines, then check every literal `sed -i s/X/.../`
# token against the templates behind the file it edits. A token that matches
# nothing leaves the placeholder in place (XRAY_PSK as the actual key) or
# silently skips a fixup the config still needs.

echo
echo "== every sed placeholder exists in the template it edits =="
declare -A TEMPLATES
while IFS= read -r line; do
    src="$(printf '%s' "$line" | sed -nE 's|.*\$\{VPSURL\}\$\{VPSPATH\}/([^[:space:];"]+).*|\1|p' | sed 's/%40/@/g')"
    dst="$(printf '%s' "$line" | sed -nE 's|.*wget -O ([^[:space:]]+).*|\1|p')"
    [ -n "$src" ] && [ -n "$dst" ] && TEMPLATES[$dst]="${TEMPLATES[$dst]} $src"
done < <(uncommented | grep -E 'wget -O')
while IFS= read -r line; do
    src="$(printf '%s' "$line" | sed -nE 's|.*\$\{DIR\}/([^[:space:];"]+).*|\1|p')"
    dst="$(printf '%s' "$line" | sed -nE 's|.*cp \$\{DIR\}/[^[:space:]]+ ([^[:space:];"]+).*|\1|p')"
    [ -n "$src" ] && [ -n "$dst" ] && TEMPLATES[$dst]="${TEMPLATES[$dst]} $src"
done < <(uncommented | grep -E 'cp \$\{DIR\}/')

sed_checked=0
while IFS= read -r line; do
    dst="$(printf '%s' "$line" | awk '{print $NF}')"
    [ -n "${TEMPLATES[$dst]:-}" ] || continue
    expr="$(printf '%s' "$line" | sed -E "s/.*sed -i +(-e +)?[\"']?//")"
    case "$expr" in
        s:*) token="$(printf '%s' "${expr#s:}" | cut -d: -f1)" ;;
        s/*) token="$(printf '%s' "${expr#s/}" | cut -d/ -f1)" ;;
        *)   continue ;;
    esac
    # \" is a literal quote once the shell is done with the line; a token
    # still holding a $ is built at run time and cannot be checked here.
    token="$(printf '%s' "$token" | sed 's/\\"/"/g')"
    case "$token" in ''|*'$'*) continue ;; esac
    sed_checked=$((sed_checked+1))
    found=no
    for s in ${TEMPLATES[$dst]}; do
        grep -qF -- "$token" "$s" 2>/dev/null && found=yes
    done
    if [ "$found" = no ]; then
        fail "sed replaces '$token' in $dst, which no template behind it contains:"
        printf '         templates: %s\n' "$(printf '%s' "${TEMPLATES[$dst]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    fi
done < <(uncommented | grep -E 'sed -i')
pass "$sed_checked literal sed substitutions checked against their templates"

# ── 4. tags the installer selects with jq ──────────────────────────────────
# Per-user accounts are added, and the reverse proxy repaired, by selecting an
# inbound (or an outbound, or a client's reverse portal) by tag; rename a tag
# in a template and the jq expression matches nothing, silently, leaving every
# user but the default one without access.

echo
echo "== jq tags exist in a shipped template =="
shipped_tags="$(for f in xray-server.json v2ray-server.json xray-vless-reality.json; do
    [ -f "$f" ] && jq -r '[(.inbounds[]?.tag), (.outbounds[]?.tag), (.reverse?.portals[]?.tag),
                           (.inbounds[]?.settings?.clients[]?.reverse?.tag),
                           (.routing?.rules[]?.outboundTag)] | map(select(. != null)) | .[]' "$f"
done | sort -u)"
for tag in $(uncommented | grep -oE '\.tag=="[^"]+"' | sed 's/.*=="//; s/"//' | sort -u); do
    if printf '%s\n' "$shipped_tags" | grep -qx "$tag"; then
        pass "tag $tag is declared by a template"
    else
        fail "the installer selects tag $tag, which no shipped template declares"
    fi
done

# ── 4b. proxy users and the VPS's loopback ────────────────────────────────
# A proxy user's freedom outbound dials from the VPS itself, so 127.0.0.1 is
# the VPS: the xray/v2ray gRPC API (10086/10085), OpenVPN's management socket
# (65302, no password), ss-manager (8839/udp), the MQVPN control API (9090),
# shadowsocks-go's API (65279) and the omr-admin API seen from loopback
# (exempt from fail2ban). Routers never send loopback through the proxy (their
# transparent proxy bypasses it), and the VPS->LAN port forwards are
# dokodemo-door inbounds of their own, so the block is scoped to the inbounds
# the users connect to. omr-admin's xray_del_routing/v2ray_del_routing read
# rule['outboundTag'] on every rule, so none may lack one.

echo
echo "== proxy users can't reach the VPS's loopback =="
REALITY_TAGS="$(jq -r '.inbounds[]?.tag' xray-vless-reality.json 2>/dev/null)"
for f in xray-server.json v2ray-server.json; do
    [ -f "$f" ] || continue
    extra=""
    [ "$f" = xray-server.json ] && extra="$REALITY_TAGS"
    if [ "$(jq -r '.outbounds[0].protocol' "$f")" = freedom ]; then
        pass "$f: the first (default) outbound is still freedom"
    else
        fail "$f: the first outbound is no longer freedom, it is what every unmatched connection takes"
    fi
    if jq -e '[.routing.rules[] | select(has("outboundTag") | not)] | length == 0' "$f" >/dev/null; then
        pass "$f: every routing rule has an outboundTag (omr-admin's *_del_routing index it)"
    else
        fail "$f: a routing rule has no outboundTag; omr-admin's *_del_routing raise KeyError on it"
    fi
    out=$(jq -r --arg extra "$extra" '
        ([.outbounds[] | select(.protocol == "blackhole") | .tag]) as $bh |
        ([.outbounds[] | select(.protocol == "freedom") | .tag]) as $free |
        ([.inbounds[] | select(.protocol != "dokodemo-door") | .tag] + ($extra | split("\n") | map(select(. != "")))) as $users |
        (.routing.rules | to_entries) as $r |
        ([$r[] | select((.value.outboundTag as $o | $bh | index($o)) and ((.value.ip // []) | index("127.0.0.0/8")) and ((.value.ip // []) | index("::1/128")))]) as $ipr |
        ([$r[] | select((.value.outboundTag as $o | $bh | index($o)) and ((.value.domain // []) | index("domain:localhost")))]) as $dnr |
        if ($bh | length) == 0 then "no blackhole outbound"
        elif ($ipr | length) == 0 then "no rule sends 127.0.0.0/8 and ::1/128 to a blackhole outbound"
        elif ($dnr | length) == 0 then "no rule sends domain:localhost to a blackhole outbound"
        elif ([$users[] | select(. as $u | ($ipr[0].value.inboundTag | index($u)) == null)] | length) > 0 then
            "the loopback ip rule misses inbound(s) " + ([$users[] | select(. as $u | ($ipr[0].value.inboundTag | index($u)) == null)] | join(","))
        elif ([$users[] | select(. as $u | ($dnr[0].value.inboundTag | index($u)) == null)] | length) > 0 then
            "the localhost domain rule misses inbound(s) " + ([$users[] | select(. as $u | ($dnr[0].value.inboundTag | index($u)) == null)] | join(","))
        elif ($ipr[0].value.inboundTag + $dnr[0].value.inboundTag | index("api")) != null then
            "the loopback block applies to the api inbound, which is how omr-admin reaches the proxy"
        elif ([$r[] | select(.key < ([$ipr[0].key, $dnr[0].key] | max)) | select(.value.outboundTag as $o | $free | index($o)) | select((.value.inboundTag // []) as $i | [$users[] | select(. as $u | $i | index($u))] | length > 0)] | length) > 0 then
            "a rule ahead of the loopback block already sends user traffic to freedom"
        else "ok" end' "$f")
    if [ "$out" = ok ]; then
        pass "$f: loopback (127.0.0.0/8, ::1, localhost) from every user inbound goes to a blackhole outbound"
    else
        fail "$f: $out"
    fi
done

# ── 5. files the runtime appends to ────────────────────────────────────────
# omr-admin rewrites /etc/sysctl.d/90-shadowsocks.conf (POST /settings, the
# MPTCP block) and /etc/openvpn/tun0.conf (the client2client sync) by reading
# the file and writing extra lines after it. Both take the file exactly as it
# was installed from the templates below.

echo
echo "== templates the runtime appends to end with a newline =="
for f in shadowsocks.conf shadowsocks.6.1.conf shadowsocks.6.18.conf \
         openvpn-tun0.conf openvpn-tun0.6.1.conf openvpn-tun0.6.1-ipv6.conf; do
    [ -f "$f" ] || continue
    if [ "$(tail -c 1 "$f" | wc -l)" -eq 1 ]; then
        pass "$f ends with a newline"
    else
        fail "$f has no final newline: the first appended line will be glued to its last line"
    fi
done

# ── 5b. the update path ────────────────────────────────────────────────────
# omr-update is started by the omr-server postinst, i.e. from inside the apt
# run that is installing that very package, and the installer it launches
# gives up a few lines in if the dpkg lock is still held:
#   E: Unable to acquire the dpkg frontend lock ... process 1926128 (apt-get)
#   E: `apt-get check` failed, you may have broken packages. Aborting...
# which took one second and removed the flag on the way out, so the update was
# lost with nothing but that line in a log nobody reads.

echo
echo "== omr-update =="
if grep -qE 'pgrep .*(apt|dpkg)' omr-update; then
    pass "omr-update waits for the package manager before running the installer"
else
    fail "omr-update runs the installer without waiting for apt/dpkg: started from the omr-server postinst it aborts on the dpkg lock"
fi
if grep -qE 'if .*debian9-x86_64\.sh; then' omr-update; then
    pass "omr-update keeps the update-bin flag when the installer fails"
else
    fail "omr-update removes the update-bin flag whether or not the installer worked, so a failed update is never retried"
fi
# ... which only works because "nothing to update" is not a failure:
if grep -A8 'CURRENT_OMR" = "\$OMR_VERSION"' "$INSTALLER" | grep -qE '^\s*exit 0'; then
    pass "the installer exits 0 when the VPS already runs this version"
else
    fail "the installer still exits non-zero when there is nothing to update, which omr-update now reads as a failed run"
fi

# omr-admin rewrites /etc/openvpn/tun0.conf itself (the client-to-client sync,
# and once at every startup). Writing that file in place races with it: the
# sync reads it line by line and moves its own copy over the result, so a read
# that lands mid-write leaves an empty file behind and openvpn@tun0 stops with
# "Options error: You must define TUN/TAP device (--dev)".
echo
echo "== /etc/openvpn/tun0.conf is written atomically =="
inplace="$(uncommented | grep -E '(wget -O|cp \$\{DIR\}/[^ ]+) /etc/openvpn/tun0\.conf( |$)' || true)"
if [ -z "$inplace" ]; then
    pass "nothing writes /etc/openvpn/tun0.conf in place"
else
    fail "written in place, where omr-admin's sync can read it half-written:"
    printf '         %s\n' "$inplace"
fi
if uncommented | grep -q 'mv -f /etc/openvpn/\.tun0\.conf\.new /etc/openvpn/tun0\.conf'; then
    pass "the new file is renamed into place"
else
    fail "no rename of a temporary file onto /etc/openvpn/tun0.conf"
fi

# ── 6. line endings ────────────────────────────────────────────────────────
# A CR survives into /etc/sysctl.d, into a systemd unit and into an openvpn
# config, where it is part of the value.

echo
echo "== no CRLF line endings =="
crlf=""
for f in $(shipped_files); do
    [ -f "$f" ] || continue
    case "$f" in *.tar.gz|*.gz) continue ;; esac
    grep -qU $'\r' "$f" 2>/dev/null && crlf="$crlf $f"
done
if [ -z "$crlf" ]; then
    pass "no shipped file carries a carriage return"
else
    fail "CRLF line endings in:"
    printf '         %s\n' $crlf
fi

# ── 7. sysctl sets ─────────────────────────────────────────────────────────

echo
echo "== sysctl templates =="
for f in shadowsocks.conf shadowsocks.6.1.conf shadowsocks.6.18.conf; do
    [ -f "$f" ] || continue
    bad="$(grep -nvE '^[[:space:]]*(#|;|$)' "$f" | grep -vE '^[0-9]+:[[:space:]]*[-a-zA-Z0-9_./*]+[[:space:]]*=' )"
    if [ -z "$bad" ]; then
        pass "$f holds only comments and key=value lines"
    else
        fail "$f has lines systemd-sysctl cannot parse:"
        printf '         %s\n' "$bad"
    fi

    # Two values for one key: the last one silently wins. Same value twice is
    # only redundant, and is reported without failing.
    conflicting=""
    redundant=""
    while read -r key; do
        [ -z "$key" ] && continue
        values="$(grep -E "^[[:space:]]*$(printf '%s' "$key" | sed 's/\./\\./g')[[:space:]]*=" "$f" \
            | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//' | sort -u | tr '\n' '/')"
        case "$values" in
            */*/*) conflicting="$conflicting $key" ;;
            *)     redundant="$redundant $key" ;;
        esac
    done <<< "$(grep -vE '^[[:space:]]*(#|;|$)' "$f" | sed 's/[[:space:]]*=.*//; s/^[[:space:]]*//' | sort | uniq -d)"
    if [ -z "$conflicting" ]; then
        pass "$f sets no key to two different values"
    else
        fail "$f sets these keys twice with different values (the last wins):"
        printf '         %s\n' $conflicting
    fi
    [ -n "$redundant" ] && note "$f repeats$redundant with the same value"
done

# The out of tree net.mptcp.mptcp_* namespace only exists on the v0.95 kernel,
# which is KERNEL=5.4 and shadowsocks.conf alone. On the upstream MPTCP kernels
# the other two files are installed for (6.6/6.12 and 6.18) every one of these
# keys produces a systemd-sysctl warning per boot and sets nothing: dropped
# from shadowsocks.6.18.conf in 0.1080 and from shadowsocks.6.1.conf in 0.1082.
for f in shadowsocks.6.1.conf shadowsocks.6.18.conf; do
    if grep -q 'net\.mptcp\.mptcp_' "$f"; then
        fail "$f carries out of tree net.mptcp.mptcp_* keys again"
    else
        pass "$f carries no out of tree net.mptcp.mptcp_* key"
    fi
done

# ── 8. OpenVPN socket buffers ──────────────────────────────────────────────
# On a TCP tunnel a non-zero sndbuf/rcvbuf sets SO_SNDBUF/SO_RCVBUF, which pins
# the socket (the kernel doubles the value) and turns TCP autotuning off. The
# 6.1 templates had "sndbuf 262144"/"rcvbuf 262144" and pushed them to every
# router, holding the TCP tunnel's window at 512 KB - ~200 Mbit/s at 20 ms
# RTT, ~80 Mbit/s at 50 ms - whatever the links. UDP never autotunes, so a UDP
# tunnel should set a real size, but one the kernel does not clamp: SO_RCVBUF
# is silently capped at net.core.rmem_max.

echo
echo "== OpenVPN socket buffers =="
RMEM_MAX=$(sed -e 's/#.*//' shadowsocks.6.18.conf | sed -n 's/^[[:space:]]*net\.core\.rmem_max[[:space:]]*=[[:space:]]*//p' | tail -1)
for f in openvpn-*.conf; do
    [ -f "$f" ] || continue
    body=$(sed -e 's/#.*//' "$f")
    bufs=$(echo "$body" | grep -nE '^[[:space:]]*(push[[:space:]]+"?)?(sndbuf|rcvbuf)[[:space:]]+[1-9]')
    if echo "$body" | grep -qE '^[[:space:]]*proto[[:space:]]+tcp'; then
        if [ -n "$bufs" ]; then
            fail "$f (TCP) pins a socket buffer, which disables autotuning: $bufs"
        else
            pass "$f (TCP) leaves its socket buffers to autotuning"
        fi
    else
        too_big=$(echo "$bufs" | awk -v m="${RMEM_MAX:-0}" '{ v = $NF; gsub(/"/, "", v); if (m > 0 && v + 0 > m + 0) print }')
        if [ -n "$too_big" ]; then
            fail "$f (UDP) asks for more than net.core.rmem_max ($RMEM_MAX), which the kernel clamps: $too_big"
        else
            pass "$f (UDP) buffer requests fit under net.core.rmem_max"
        fi
    fi
done
if sed -e 's/#.*//' openvpn-tun1.6.1.conf | grep -qE '^[[:space:]]*rcvbuf[[:space:]]+([1-9][0-9]{6,})'; then
    pass "openvpn-tun1.6.1.conf (UDP) sets a receive buffer of at least 1 MB"
else
    fail "openvpn-tun1.6.1.conf (UDP) sets under 1 MB of receive buffer, or none (rmem_default, 208 KB): UDP does not autotune"
fi

# ── 9. tcp_mtu_probing ─────────────────────────────────────────────────────
# 1 = blackhole detection. With 0, an MPTCP subflow over a path filtering ICMP
# "fragmentation needed" never recovered on the bench and the connection lost
# that WAN; 2 would start every connection at 1024-byte segments.
echo
echo "== tcp_mtu_probing =="
for f in shadowsocks.conf shadowsocks.6.1.conf shadowsocks.6.18.conf; do
    v=$(sed -e 's/#.*//' "$f" | sed -n 's/^[[:space:]]*net\.ipv4\.tcp_mtu_probing[[:space:]]*=[[:space:]]*//p' | tail -1)
    if [ "$v" = "1" ]; then pass "$f sets tcp_mtu_probing = 1"; else fail "$f sets tcp_mtu_probing = '${v:-unset}', expected 1"; fi
done

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
