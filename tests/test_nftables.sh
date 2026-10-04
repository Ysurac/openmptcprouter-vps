#!/bin/bash
# Tests for the nftables ruleset that replaced Shorewall in 0.1068.
#
# This ruleset is loaded by nftables.service at boot, and /etc/nftables.conf
# starts with `flush ruleset`: whatever it cannot parse, it takes the whole
# firewall down with it, and a VPS that boots with an empty ruleset looks
# healthy right up to the moment someone scans it. A `jump` to a chain that
# was renamed, or a $VARIABLE that is not defined, is enough:
#
#   /etc/nftables/omr.nft:86:12-24: Error: Could not process rule: No such
#   file or directory
#
# and nftables.service just fails, at boot, on a machine nobody is watching.
#
# The chains omr-admin owns are the other half: omradmin.py adds and flushes
# rules in user_accept, user_dnat, gre_snat, client2client, dscp_mark and
# ct_helpers by name, so those six have to exist here, empty, for the API's
# port openings and per-user redirects to land anywhere at all.
#
# `nft -c -f` (a real parse, if nft is installed and permitted) runs on top of
# the static checks rather than instead of them, and is reported as skipped
# where it cannot run.
#
# Requires: bash. Optional: nft.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"
CONF="$ROOT/nftables.conf"
RULES="$ROOT/nftables/omr.nft"
VARS="$ROOT/nftables/omr-vars.nft"
cd "$ROOT" || exit 1

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
note() { printf '  note %s\n' "$1"; }

uncommented() { grep -vE '^[[:space:]]*#' "$INSTALLER"; }
# nft comments run to end of line and start with #.
nft_body() { sed 's/#.*//' "$1"; }

# ── 1. the includes ───────────────────────────────────────────────────────

echo "== /etc/nftables.conf includes =="
if grep -q '^flush ruleset' "$CONF"; then
    pass "nftables.conf starts from a flushed ruleset"
else
    fail "nftables.conf no longer flushes the ruleset; the omr-admin resync drop-in exists because it does"
fi

for inc in $(grep -oE '^include "[^"]+"' "$CONF" | cut -d'"' -f2); do
    case "$inc" in
        */\*.nft)
            # A glob include is a no-op when the directory is empty or absent,
            # which is what makes custom.d optional.
            dir="$(dirname "$inc")"
            if uncommented | grep -q "mkdir -p $dir"; then
                pass "$inc: the installer creates $dir"
            else
                fail "$inc: nothing creates $dir"
            fi
            ;;
        *)
            src="$(basename "$inc")"
            if [ ! -f "nftables/$src" ]; then
                fail "$inc is included but nftables/$src does not exist"
            elif uncommented | grep -q "$inc"; then
                pass "$inc is shipped as nftables/$src and installed there"
            else
                fail "nftables/$src exists but the installer never writes it to $inc"
            fi
            ;;
    esac
done

# ── 2. variables ──────────────────────────────────────────────────────────
# An undefined variable is a load-time error for the whole file.

echo
echo "== every \$variable is defined =="
defined="$(grep -hoE '^[[:space:]]*define[[:space:]]+[A-Za-z0-9_]+' "$VARS" "$RULES" \
    | awk '{print $2}' | sort -u)"
used="$(nft_body "$RULES" | grep -oE '\$[A-Za-z0-9_]+' | sed 's/\$//' | sort -u)"
undefined=""
for v in $used; do
    printf '%s\n' "$defined" | grep -qx "$v" || undefined="$undefined \$$v"
done
if [ -z "$undefined" ]; then
    pass "all $(printf '%s\n' $used | wc -l | tr -d ' ') variables used in omr.nft are defined"
else
    fail "used in omr.nft but never defined:$undefined"
fi

# The installer rewrites these three per install; omr-vps-admin's /vpnips
# rewrites them again at run time. Losing one leaves the ruleset pointing at
# the shipped placeholder.
for v in NET_IFACE NET_IFACE6 VPS_IFACE VPS_ADDR OMR_ADDR OMR_ADDR6 VPN_IFACES VPNCL_IFACES; do
    if printf '%s\n' "$defined" | grep -qx "$v"; then
        pass "\$$v is defined in omr-vars.nft"
    else
        fail "\$$v is gone from omr-vars.nft"
    fi
done

# ── 3. chains ─────────────────────────────────────────────────────────────

echo
echo "== chains =="
declared="$(grep -oE '^[[:space:]]*chain[[:space:]]+[A-Za-z0-9_]+' "$RULES" | awk '{print $2}' | sort -u)"
jumped="$(nft_body "$RULES" | grep -oE '\b(jump|goto)[[:space:]]+[A-Za-z0-9_]+' | awk '{print $2}' | sort -u)"
dangling=""
for c in $jumped; do
    printf '%s\n' "$declared" | grep -qx "$c" || dangling="$dangling $c"
done
if [ -z "$dangling" ]; then
    pass "every jump target is a declared chain"
else
    fail "jumped to but never declared:$dangling"
fi

# omradmin.py adds and flushes rules in these by name (_nft_flush_chain);
# against a chain that does not exist, every one of those calls fails and the
# API's port openings, redirects and DSCP marks land nowhere.
for c in user_accept user_dnat gre_snat client2client dscp_mark ct_helpers; do
    if printf '%s\n' "$declared" | grep -qx "$c"; then
        pass "chain $c exists for omr-admin to fill"
    else
        fail "chain $c is gone; omr-admin writes into it by name"
    fi
done
# The installer's own one-off access (ACME challenge) and the admin's
# custom.d escape hatches.
for c in install_tmp custom_accept custom_dnat_bypass; do
    if printf '%s\n' "$declared" | grep -qx "$c"; then
        pass "chain $c exists"
    else
        fail "chain $c is gone"
    fi
done

# Every base chain needs its hook spelled out, or it is just an unused
# regular chain that nothing ever traverses.
echo
echo "== base chains declare a hook =="
for c in input forward output nat_prerouting nat_postrouting mangle_post raw_prerouting raw_output; do
    if awk -v c="$c" '
        $1 == "chain" && $2 == c { inside = 1 }
        inside && /type .* hook .* priority .*;/ { found = 1 }
        inside && /^\t\}/ { exit }
        END { exit !found }' "$RULES"; then
        pass "chain $c declares type/hook/priority"
    else
        fail "chain $c has no base chain declaration, so the kernel never calls it"
    fi
done

# ── 4. the rules that have already broken a VPS ──────────────────────────

echo
echo "== rules with a history =="
# 0.1080: the output chain rejected everything not leaving $NET_IFACE, which
# takes DNS away from any VPS whose resolver sits on a second NIC (DigitalOcean
# hands out 10.114.x.x on eth1) the moment the firewall loads.
if nft_body "$RULES" | grep -qE 'oifname[[:space:]]*!=[[:space:]]*\$NET_IFACE[^\n]*reject'; then
    fail "the output chain rejects everything not leaving \$NET_IFACE again (see 0.1080: DNS over a second NIC dies with it)"
else
    pass "the output chain does not reject by 'not \$NET_IFACE'"
fi
if nft_body "$RULES" | grep -qE 'oifname[[:space:]]+\$VPNCL_IFACES[^\n]*reject'; then
    pass "the output chain's reject is scoped to \$VPNCL_IFACES"
else
    fail "the output chain no longer rejects fw->vpncl, the one thing the source policy withheld"
fi
if nft_body "$RULES" | grep -qE 'oifname[[:space:]]+"lo"[[:space:]]+accept'; then
    pass "the output chain accepts loopback (omr-service probes the API on 127.0.0.1)"
else
    fail "the output chain no longer accepts loopback; omr-service's health check would be rejected"
fi

# 0.1080 again: sshd is moved to 65222 during the install and the ruleset is
# loaded a few lines later. If the two disagree, the VPS is unreachable from
# the next reboot and the only survivor is the session running the installer.
SSH_PORT="$(uncommented | sed -nE 's|.*sed -i .s:#?Port 22:Port ([0-9]+):g.*|\1|p' | head -n 1)"
if [ -z "$SSH_PORT" ]; then
    fail "cannot tell which port the installer moves sshd to"
elif nft_body "$RULES" | grep -qE "tcp dport $SSH_PORT accept"; then
    pass "the input chain accepts tcp/$SSH_PORT, where the installer puts sshd"
else
    fail "the installer moves sshd to $SSH_PORT but the input chain never accepts it"
fi

# #4381: 0.1068 dropped what Shorewall6 accepted for IPv6 on the link. A DHCPv6
# Advertise/Reply comes back to our link-local address from the server's, not
# as the reply to the multicast Solicit, so conntrack calls it NEW: without an
# explicit accept the VPS never gets or renews a lease. MLD is untracked, and
# an unanswered query lets an MLD-snooping switch stop forwarding neighbour
# solicitations to us. MLD carries a hop-by-hop header, so a rule spelled
# `ip6 nexthdr icmpv6 ... mld-listener-query` loads fine and never matches.
if nft_body "$RULES" | grep -qE 'udp dport 546 accept'; then
    pass "the input chain accepts DHCPv6 replies (udp/546)"
else
    fail "the input chain no longer accepts udp/546; DHCPv6 replies are rejected and the lease is lost (#4381)"
fi
mld="$(nft_body "$RULES" | grep -E 'icmpv6 type[^#]*mld-listener-query[^#]*accept')"
if [ -z "$mld" ]; then
    fail "the input chain no longer accepts MLD queries; snooping switches drop our multicast groups (#4381)"
elif printf '%s\n' "$mld" | grep -q 'nexthdr'; then
    fail "the MLD rule matches on ip6 nexthdr, which is the hop-by-hop header for MLD: it never matches (#4381)"
else
    pass "the input chain accepts MLD queries without an ip6 nexthdr match"
fi

# #4382: the router's IPv6 arrives through the omr-6in4-user* sit tunnel, a
# vpn interface in shorewall6/interfaces. Left out of VPN_IFACES, everything
# the router routes into it hits the forward chain's trailing reject.
if nft_body "$VARS" | grep -E '^define VPN_IFACES' | grep -q '"omr-6in4-user\*"'; then
    pass "VPN_IFACES includes the 6in4 tunnel (omr-6in4-user*)"
else
    fail "VPN_IFACES lacks omr-6in4-user*; the router's IPv6 is rejected in forward (#4382)"
fi
# With the tunnel in VPN_IFACES, an unrestricted net->vpn accept lets any new
# IPv6 connection from the internet reach a LAN using a public prefix.
# shorewall6 only let DNAT'd connections through (net all DROP).
if nft_body "$RULES" | grep -E 'iifname \$NET_IFACE6? oifname \$VPN_IFACES' | grep -v 'meta nfproto ipv4' | grep -vq 'ct status dnat'; then
    fail "IPv6 from the internet into a tunnel is accepted without ct status dnat; a public LAN prefix is open (#4382)"
elif nft_body "$RULES" | grep -q 'meta nfproto ipv6 iifname \$NET_IFACE6 oifname \$VPN_IFACES ct status dnat accept'; then
    pass "IPv6 net->vpn forwarding is limited to redirected (DNAT'd) connections"
else
    fail "the IPv6 net->vpn rule for redirected ports is gone; IPv6 port redirects to the router are rejected (#4382)"
fi
if nft_body "$RULES" | grep -E 'ip6 saddr[^#]*masquerade' | grep -q 'oifname \$NET_IFACE6 '; then
    pass "the NAT66 masquerade follows the IPv6 WAN (\$NET_IFACE6)"
else
    fail "the NAT66 masquerade is not on \$NET_IFACE6; with IPv6 on another NIC the LAN's ULA leaves unmasqueraded (#3271)"
fi

# The installer's own sed lines, run against the shipped omr-vars.nft. The
# second case is the trap: an IPv6 NIC named eth0 next to an IPv4 NIC with
# another name must not be rewritten to the IPv4 one by the first sed.
uncommented | grep -E 'sed -i .*/etc/nftables/omr-vars\.nft' > "$TMPDIR/vars-seds.sh"
for case in "ens3 ens3" "enx5 enx4" "enx5 eth0" "eth0 enx4"; do
    set -- $case
    cp "$VARS" "$TMPDIR/omr-vars.nft"
    INTERFACE="$1" INTERFACE6="$2" bash -c "$(sed "s|/etc/nftables/omr-vars.nft|$TMPDIR/omr-vars.nft|" "$TMPDIR/vars-seds.sh")"
    got4="$(sed -nE 's/^define NET_IFACE += *//p' "$TMPDIR/omr-vars.nft")"
    got6="$(sed -nE 's/^define NET_IFACE6 += *//p' "$TMPDIR/omr-vars.nft")"
    if [ "$got4" = "$1" ] && [ "$got6" = "$2" ]; then
        pass "INTERFACE=$1 INTERFACE6=$2 gives NET_IFACE=$got4 NET_IFACE6=$got6"
    else
        fail "INTERFACE=$1 INTERFACE6=$2 gives NET_IFACE=$got4 NET_IFACE6=$got6"
    fi
done

# The management rule and the dynamic chains have to be evaluated before the
# trailing reject, or they are dead rules.
awk '
    $1 == "chain" && $2 == "input" { inside = 1; n = 0; next }
    inside && /^\t\}/ { inside = 0 }
    inside { n++; if ($0 ~ /reject/) rej = n; if ($0 ~ /jump user_accept/) ua = n;
             if ($0 ~ /dport 65222/) ssh = n }
    END { exit !(ssh && ua && rej && ssh < rej && ua < rej) }' "$RULES" \
    && pass "the SSH rule and jump user_accept come before the trailing reject" \
    || fail "the input chain's trailing reject now comes before the SSH rule or jump user_accept"

# ── 5. a real parse ──────────────────────────────────────────────────────

echo
echo "== nft -c -f =="
if ! command -v nft >/dev/null 2>&1; then
    note "nft is not installed; skipping the parse (the CI job installs nftables)"
else
    mkdir -p "$TMPDIR/nftables"
    cp "$VARS" "$RULES" "$TMPDIR/nftables/"
    sed "s|/etc/nftables/|$TMPDIR/nftables/|" "$CONF" > "$TMPDIR/nftables.conf"
    out="$(nft -c -f "$TMPDIR/nftables.conf" 2>&1)"
    rc=$?
    if [ $rc -eq 0 ]; then
        pass "nft parses the full ruleset"
    elif printf '%s' "$out" | grep -qiE 'not permitted|permission denied'; then
        note "nft cannot check the ruleset without CAP_NET_ADMIN; run this test as root for a real parse"
    else
        fail "nft rejects the ruleset:"
        printf '%s\n' "$out" | sed 's/^/         /'
    fi
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
