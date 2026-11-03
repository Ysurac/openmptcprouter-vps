#!/bin/bash
# Tests for the xray config migrations in debian9-x86_64.sh:
#   1. legacy "reverse" removal (xray 26+ refuses to start on it)
#   2. VLESS Reverse Proxy client injection (VPS->LAN port forwarding)
#   3. reality x25519 key repair (empty privateKey from old output parsing)
#   4. "xray x25519" output parsing (old and 26+ formats)
#
# The jq expressions are extracted from the installer itself, so the tests
# exercise the shipped code. Requires: bash, jq.

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

# Extract the single-quoted jq program from the installer line matching $1.
# The installer runs it as `jq_rewrite /etc/xray/FILE -M [--arg ...] 'PROGRAM'`:
# the program is the single-quoted string closing the line.
extract_jq() {
    grep -F "$1" "$INSTALLER" | grep -E "jq_rewrite /etc/xray/[^ ]+ -M" | head -n 1 | sed "s/^[^']*'//; s/'[[:space:]]*\$//"
}

# ── Fixtures ──────────────────────────────────────────────────────────────────

LEGACY_CONFIG="$TMPDIR/legacy.json"
cat > "$LEGACY_CONFIG" <<'EOF'
{
  "inbounds": [
    {
      "tag": "omrin-tunnel",
      "port": 65248,
      "protocol": "vless",
      "settings": {"clients": [{"id": "user-uuid", "email": "openmptcprouter"}]}
    }
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["omrin-tunnel"], "outboundTag": "OMRLan", "domain": ["full:omr.lan"]},
      {"type": "field", "inboundTag": ["user_redir_tcp_8080"], "outboundTag": "OMRLan"},
      {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}
    ]
  },
  "reverse": {"portals": [{"tag": "OMRLan", "domain": "omr.lan"}]}
}
EOF

VR_FILE="$TMPDIR/xray-vless-reality.json"
cat > "$VR_FILE" <<'EOF'
{
  "inbounds": [
    {
      "tag": "omrin-vless-reality",
      "protocol": "vless",
      "streamSettings": {
        "security": "reality",
        "realitySettings": {"privateKey": "", "publicKey": "stale-public"}
      }
    }
  ]
}
EOF

# ── 1. legacy reverse removal ─────────────────────────────────────────────────

echo "== legacy reverse removal =="

JQ_REVERSE="$(extract_jq 'del(.reverse)')"
assert_eq "installer contains the del(.reverse) migration" "0" "$([ -n "$JQ_REVERSE" ]; echo $?)"

jq -M "$JQ_REVERSE" "$LEGACY_CONFIG" > "$TMPDIR/migrated.json"
assert_eq "jq migration exits cleanly" "0" "$?"
assert_eq "reverse section removed" "null" "$(jq -r '.reverse' "$TMPDIR/migrated.json")"
assert_eq "OMRLan routing rules removed" "0" \
    "$(jq '[.routing.rules[] | select(.outboundTag=="OMRLan")] | length' "$TMPDIR/migrated.json")"
assert_eq "api routing rule preserved" "1" \
    "$(jq '[.routing.rules[] | select(.outboundTag=="api")] | length' "$TMPDIR/migrated.json")"

# a config without routing must survive the same expression
echo '{"reverse": {"portals": []}, "inbounds": []}' > "$TMPDIR/noroute.json"
jq -M "$JQ_REVERSE" "$TMPDIR/noroute.json" > "$TMPDIR/noroute-out.json"
assert_eq "config without routing survives migration" "0" "$?"
assert_eq "reverse removed without routing" "null" "$(jq -r '.reverse' "$TMPDIR/noroute-out.json")"

# the trigger condition must fire only when a reverse section exists
assert_eq "trigger true on legacy config" "true" "$(jq -r '.reverse != null' "$LEGACY_CONFIG")"
assert_eq "trigger false after migration" "false" "$(jq -r '.reverse != null' "$TMPDIR/migrated.json")"

# ── 2. reverse client injection ───────────────────────────────────────────────

echo "== VLESS Reverse Proxy client injection =="

JQ_CLIENT="$(extract_jq '"reverse": {"tag": $uuid')"
[ -z "$JQ_CLIENT" ] && JQ_CLIENT="$(extract_jq 'omr-reverse')"
assert_eq "installer contains the reverse-client migration" "0" "$([ -n "$JQ_CLIENT" ]; echo $?)"

jq -M --arg uuid "11111111-2222-3333-4444-555555555555" "$JQ_CLIENT" "$TMPDIR/migrated.json" \
    > "$TMPDIR/with-client.json"
assert_eq "client injection exits cleanly" "0" "$?"
assert_eq "reverse client appended with uuid" "11111111-2222-3333-4444-555555555555" \
    "$(jq -r '.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients[] | select(.reverse.tag=="OMRLan") | .id' "$TMPDIR/with-client.json")"
assert_eq "existing user client untouched" "user-uuid" \
    "$(jq -r '.inbounds[0].settings.clients[0].id' "$TMPDIR/with-client.json")"

# idempotence guard used by the installer
GUARD='any(.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients[]; .reverse.tag=="OMRLan")'
assert_eq "guard false before injection" "false" "$(jq -r "$GUARD" "$TMPDIR/migrated.json")"
assert_eq "guard true after injection" "true" "$(jq -r "$GUARD" "$TMPDIR/with-client.json")"

# ── 3. reality key repair ─────────────────────────────────────────────────────

echo "== reality x25519 key repair =="

JQ_REALITY="$(extract_jq '.privateKey=$priv')"
assert_eq "installer contains the reality key repair" "0" "$([ -n "$JQ_REALITY" ]; echo $?)"

jq -M --arg priv "NEWPRIV" --arg pub "NEWPUB" "$JQ_REALITY" "$VR_FILE" > "$TMPDIR/vr-fixed.json"
assert_eq "key repair exits cleanly" "0" "$?"
assert_eq "privateKey replaced" "NEWPRIV" \
    "$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$TMPDIR/vr-fixed.json")"
assert_eq "publicKey replaced" "NEWPUB" \
    "$(jq -r '.inbounds[0].streamSettings.realitySettings.publicKey' "$TMPDIR/vr-fixed.json")"

# repair trigger: empty and placeholder keys must be detected
for broken in "" "null" "XRAY_X25519_PRIVATE_KEY"; do
    case "$broken" in
        "") desc="empty" ;;
        "null") desc="null" ;;
        *) desc="placeholder" ;;
    esac
    if [ -z "$broken" ] || [ "$broken" = "null" ] || [ "$broken" = "XRAY_X25519_PRIVATE_KEY" ]; then
        rc=0
    else
        rc=1
    fi
    assert_eq "repair trigger fires on $desc privateKey" "0" "$rc"
done

# ── 4. xray x25519 output parsing ─────────────────────────────────────────────

echo "== x25519 output parsing =="

# installer must use $NF (last field), which handles both output formats
NF_COUNT="$(grep -c "grep Private | awk '{ print \$NF }'" "$INSTALLER")"
assert_eq "installer parses private key with \$NF (2 call sites)" "2" "$NF_COUNT"

NEW_OUT=$'PrivateKey: NEWFORMATPRIV\nPassword (PublicKey): NEWFORMATPUB\nHash32: HASH'
OLD_OUT=$'Private key: OLDFORMATPRIV\nPublic key: OLDFORMATPUB'

assert_eq "new format private key" "NEWFORMATPRIV" \
    "$(echo "$NEW_OUT" | grep Private | awk '{ print $NF }' | tr -d '\n')"
assert_eq "new format public key" "NEWFORMATPUB" \
    "$(echo "$NEW_OUT" | grep Public | awk '{ print $NF }' | tr -d '\n')"
assert_eq "old format private key" "OLDFORMATPRIV" \
    "$(echo "$OLD_OUT" | grep Private | awk '{ print $NF }' | tr -d '\n')"
assert_eq "old format public key" "OLDFORMATPUB" \
    "$(echo "$OLD_OUT" | grep Public | awk '{ print $NF }' | tr -d '\n')"

# preservation greps must read the real file name (hyphen, not underscore)
assert_eq "no reference to the wrong xray-vless_reality.json filename" "0" \
    "$(grep -c 'xray-vless_reality.json' "$INSTALLER")"

# ── 5. template sanity ────────────────────────────────────────────────────────

echo "== template sanity =="

TEMPLATE="$SCRIPT_DIR/../xray-server.json"
assert_eq "template has no legacy reverse section" "null" "$(jq -r '.reverse' "$TEMPLATE")"
assert_eq "template has no OMRLan routing rule" "0" \
    "$(jq '[.routing.rules[] | select(.outboundTag=="OMRLan")] | length' "$TEMPLATE")"
assert_eq "template ships the reverse client placeholder" "XRAY_REVERSE_UUID" \
    "$(jq -r '.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients[] | select(.reverse.tag=="OMRLan") | .id' "$TEMPLATE")"
assert_eq "template keeps a default direct outbound (required so the reverse tag never becomes the default route)" "freedom" \
    "$(jq -r '.outbounds[0].protocol' "$TEMPLATE")"
assert_eq "installer substitutes XRAY_REVERSE_UUID" "0" \
    "$(grep -q 's:XRAY_REVERSE_UUID:\$XRAY_REVERSE_UUID:g' "$INSTALLER"; echo $?)"

# ── 6. existing configs are kept, not rebuilt ─────────────────────────────────

echo "== existing config kept =="

# The rebuild test used to be `-z "$(grep -i transport ...)"`, true for every
# config since the template lost "transport": each run threw away the users,
# redirects and outbounds omr-admin had added.
assert_eq "no rebuild on a config merely lacking \"transport\"" "0" \
    "$(grep -c 'grep -i transport /etc/xray/xray-server.json' "$INSTALLER")"
assert_eq "rebuild only on a legacy top-level transport" "1" \
    "$(grep -c "jq -r 'has(\"transport\")' /etc/xray/xray-server.json" "$INSTALLER")"
assert_eq "v2ray config no longer copied over on every run" "0" \
    "$(grep -c '^	#if \[ ! -f /etc/v2ray/v2ray-server.json \]; then' "$INSTALLER")"

MERGE_PROG="$(grep -F 'jq_rewrite /etc/xray/xray-server.json -M --slurpfile tmpl' "$INSTALLER" | head -n 1 | sed "s/^[^']*'//; s/'[[:space:]]*\$//")"
KEPT="$TMPDIR/kept.json"
cat > "$KEPT" <<'EOF'
{
  "inbounds": [
    {"tag": "omrin-tunnel", "settings": {"clients": [{"id": "main", "email": "openmptcprouter"}, {"id": "u2-uuid", "email": "u2"}]}},
    {"tag": "user_redir_tcp_8080_u2", "port": 8080, "protocol": "dokodemo-door"}
  ],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "freedom", "tag": "output-192.0.2.10"}],
  "routing": {"rules": [{"type": "field", "inboundTag": ["omrin-tunnel"], "user": ["u2"], "outboundTag": "output-192.0.2.10"}]}
}
EOF
MERGED="$(jq -M --slurpfile tmpl "$TEMPLATE" "$MERGE_PROG" "$KEPT")"
assert_eq "merge exits cleanly" "0" "$?"
assert_eq "other user's uuid kept" "u2-uuid" \
    "$(echo "$MERGED" | jq -r '.inbounds[] | select(.tag=="omrin-tunnel") | .settings.clients[] | select(.email=="u2") | .id')"
assert_eq "port redirect inbound kept" "1" \
    "$(echo "$MERGED" | jq '[.inbounds[] | select(.tag=="user_redir_tcp_8080_u2")] | length')"
assert_eq "GRE outbound and rule kept, rule still first" "output-192.0.2.10" \
    "$(echo "$MERGED" | jq -r '.routing.rules[0].outboundTag')"
assert_eq "missing template inbounds added once" "1" \
    "$(echo "$MERGED" | jq '[.inbounds[] | select(.tag=="omrin-trojan-tunnel")] | length')"
assert_eq "omrin-tunnel not duplicated" "1" \
    "$(echo "$MERGED" | jq '[.inbounds[] | select(.tag=="omrin-tunnel")] | length')"
assert_eq "blackhole outbound added" "blackhole" \
    "$(echo "$MERGED" | jq -r '.outbounds[] | select(.tag=="blocked") | .protocol')"
assert_eq "outbounds[0] still freedom" "freedom" "$(echo "$MERGED" | jq -r '.outbounds[0].protocol')"
assert_eq "loopback blocking rules added" "$(jq '[.routing.rules[] | select(.outboundTag=="blocked")] | length' "$TEMPLATE")" \
    "$(echo "$MERGED" | jq '[.routing.rules[] | select(.outboundTag=="blocked")] | length')"
assert_eq "merge is idempotent" "$(echo "$MERGED" | jq -cS .)" \
    "$(echo "$MERGED" | jq -M --slurpfile tmpl "$TEMPLATE" "$MERGE_PROG" | jq -cS .)"

# ── 7. trojan users without a password ───────────────────────────────────────

echo "== trojan password repair =="

assert_eq "extra users are added to trojan with a password" "0" \
    "$(grep -F 'omrin-trojan-tunnel") | .settings.clients) +=' "$INSTALLER" | grep -c '"id": \$xrayid')"
TROJAN_PROG="$(extract_jq 'omrin-trojan-tunnel") | .settings.clients) |= map')"
TROJAN="$TMPDIR/trojan.json"
cat > "$TROJAN" <<'EOF'
{"inbounds": [{"tag": "omrin-trojan-tunnel", "settings": {"clients": [
  {"password": "main", "email": "openmptcprouter", "level": 0},
  {"level": 0, "alterId": 0, "email": "u2", "id": "u2-uuid"},
  {"email": "nothing"}
]}}]}
EOF
FIXED="$(jq -M "$TROJAN_PROG" "$TROJAN")"
assert_eq "trojan repair exits cleanly" "0" "$?"
assert_eq "id moved to password" "u2-uuid" \
    "$(echo "$FIXED" | jq -r '.inbounds[0].settings.clients[] | select(.email=="u2") | .password')"
assert_eq "no id/alterId left" "0" \
    "$(echo "$FIXED" | jq '[.inbounds[0].settings.clients[] | select(has("id") or has("alterId"))] | length')"
assert_eq "client with no credential dropped" "0" \
    "$(echo "$FIXED" | jq '[.inbounds[0].settings.clients[] | select(.email=="nothing")] | length')"
assert_eq "valid client untouched" "main" \
    "$(echo "$FIXED" | jq -r '.inbounds[0].settings.clients[] | select(.email=="openmptcprouter") | .password')"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
