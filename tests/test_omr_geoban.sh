#!/bin/bash
# Tests for omr-geoban, which filters the new connections arriving from the
# internet by the country of their source address, from an nftables table of
# its own (inet omr_geoban) loaded from the DB-IP country list.
#
# 1. Without nft: the country groups (the continents split the list's codes
#    between them, once each), the merged ranges, the country and network
#    lookup and the exempt ranges, the network search, the download (this
#    month, last month, a broken file), the configuration file. Two small
#    lists stand in for DB-IP's, through file://. MaxMind's GeoLite2 as the
#    source: zips of small CSVs behind a fake curl that wants the account ID
#    and license key (on its standard input, never its command line), their
#    conversion to DB-IP's format, the checksum, the errors, the switch back.
# 2. The real nft in a network namespace of its own (root, or an unprivileged
#    user namespace): the table allow and deny load, with countries, networks
#    and networks taken out, the exempt addresses and open ports, off, a
#    reload of the ruleset, the refusal to block a peer connected now (ss
#    replaced by a fake).
# 3. Same namespace: packets. A second namespace on the other side of a veth
#    named eth0 (the WAN) and one named tun0 (a tunnel) sends from an allowed
#    and a denied country; what is dropped, what is not.
#
# Requires: bash, awk, gzip, curl. Optional: unzip, python3 (MaxMind), nft,
# unshare, nsenter, ping.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPT="$ROOT/omr-geoban"
cd "$ROOT" || exit 1

for c in awk gzip curl; do
    command -v $c > /dev/null 2>&1 || { echo "SKIP $c is not installed"; exit 77; }
done

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf '  PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  FAIL %s\n' "$1"; }
note() { printf '  note %s\n' "$1"; }
assert_eq() {
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1"
        printf '         expected: %s\n         got:      %s\n' "$(printf '%s' "$2" | tr '\n' ' ')" "$(printf '%s' "$3" | tr '\n' ' ')"
    fi
}
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
check_not() { local d="$1"; shift; if "$@"; then fail "$d"; else pass "$d"; fi; }
# A command whose output is noise: "check d quiet cmd", not "check d cmd > /dev/null",
# which would hide the PASS/FAIL line too.
quiet() { "$@" > /dev/null 2>&1; }

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# A list in DB-IP's format: FR, DE and FR again side by side (merged for
# "fr de", not for "fr"), IPv6 FR and DE adjacent across a carry
# (2000:ffff:...:ffff + 1 = 2001::).
CUR="$(date -u +%Y-%m)"
PREV="$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m)"
mkdir -p "$T/mirror"
cat > "$T/list.csv" << 'EOF'
0.0.0.0,1.255.255.255,ZZ
2.0.0.0,2.0.0.255,FR
2.0.1.0,2.0.1.255,DE
2.0.2.0,2.0.2.255,FR
2.0.3.0,2.255.255.255,US
3.0.0.0,3.255.255.255,US
4.0.0.0,4.255.255.255,RU
5.0.0.0,255.255.255.255,ZZ
::,1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ
2000::,2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff,FR
2001::,2001:0:ffff:ffff:ffff:ffff:ffff:ffff,DE
2001:1::,2001:1:ffff:ffff:ffff:ffff:ffff:ffff,US
2001:2::,ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff,ZZ
EOF
gzip -c "$T/list.csv" > "$T/mirror/dbip-country-lite-$CUR.csv.gz"
# Networks: AS100 the first French range and France's IPv6, AS200 the German
# range and the second French one (adjacent: one range), AS300 part of the
# US. Organisation names are quoted, with commas, as DB-IP writes them.
cat > "$T/asn.csv" << 'EOF'
2.0.0.0,2.0.0.255,100,"Orange S.A."
2.0.1.0,2.0.1.255,200,"Free SAS"
2.0.2.0,2.0.2.255,200,"Free SAS"
3.0.0.0,3.0.255.255,300,"Big Cloud, Inc."
2000::,2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff,100,"Orange S.A."
2001:1::,2001:1:ffff:ffff:ffff:ffff:ffff:ffff,300,"Big Cloud, Inc."
EOF
gzip -c "$T/asn.csv" > "$T/mirror/dbip-asn-lite-$CUR.csv.gz"

export OMR_GEOBAN_URL="file://$T/mirror"
export OMR_GEOBAN_MIN_ROWS=1

# A fresh root for omr-geoban: config, state, lock under it.
new_root() {
    R="$T/root.$1"
    rm -rf "$R"
    mkdir -p "$R/etc/nftables" "$R/run"
    cp "$ROOT/nftables/omr-vars.nft" "$R/etc/nftables/"
    export OMR_GEOBAN_ROOT="$R"
}
geoban() { "$SCRIPT" "$@"; }

# ── 1. without nft ───────────────────────────────────────────────────────
fake_tests() {
echo "== groups =="
# The codes of DB-IP's list (2026-11), ZZ (no country) aside.
CODES="AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW"
groups="$(geoban groups)"
continents="$(printf '%s\n' "$groups" | grep -v '^eu:' | sed 's/^[^:]*: //' | tr ' ' '\n' | sort)"
assert_eq "the continents hold every country exactly once" \
    "$(echo $CODES | tr ' ' '\n' | sort)" "$continents"
eu="$(printf '%s\n' "$groups" | sed -n 's/^eu: //p')"
check "eu holds the 27 members and 7 outermost regions or Aland (34 codes)" [ "$(echo $eu | wc -w)" -eq 34 ]
bad=""
for c in $eu; do case " $CODES " in *" $c "*) ;; *) bad="$bad $c" ;; esac; done
assert_eq "every code of eu is in the list" "" "$bad"

echo
echo "== download =="
new_root dl
geoban update; rc=$?
assert_eq "update does nothing while off" "0 no" "$rc $([ -f "$R/var/lib/omr-geoban/dbip-country-lite.csv.gz" ] && echo yes || echo no)"
geoban update --force 2> "$T/err"; rc=$?
assert_eq "update --force stores this month's list" "0 $CUR" "$rc $(cat "$R/var/lib/omr-geoban/dbip-country-month" 2> /dev/null)"
geoban update --force 2> "$T/err"
check "the attribution is logged" grep -q 'IP Geolocation by DB-IP' "$T/err"

new_root prev
mv "$T/mirror/dbip-country-lite-$CUR.csv.gz" "$T/mirror/dbip-country-lite-$PREV.csv.gz"
geoban update --force 2> /dev/null; rc=$?
assert_eq "last month's list while this month's isn't out" "0 $PREV" "$rc $(cat "$R/var/lib/omr-geoban/dbip-country-month" 2> /dev/null)"
geoban update --force 2> /dev/null
mkdir -p "$R/etc/openmptcprouter-vps-admin"
printf 'MODE="deny"\nCOUNTRIES="ru"\n' > "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
mkdir -p "$T/fakebin"
printf '#!/bin/sh\necho "nft $*" >> "%s/nft.log"\n' "$T" > "$T/fakebin/nft"
chmod 755 "$T/fakebin/nft"
rm -f "$T/nft.log"
PATH="$T/fakebin:$PATH" geoban update; rc=$?
if [ "$rc" = 0 ] && [ ! -s "$T/nft.log" ]; then pass "an update with nothing new does not reload the table"; else fail "an update with nothing new does not reload the table"; fi
mv "$T/mirror/dbip-country-lite-$PREV.csv.gz" "$T/mirror/dbip-country-lite-$CUR.csv.gz"

new_root both
mkdir -p "$R/etc/openmptcprouter-vps-admin"
printf 'MODE="deny"\nCOUNTRIES="ru as300"\n' > "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
rm -f "$T/nft.log"
PATH="$T/fakebin:$PATH" geoban update 2> /dev/null; rc=$?
assert_eq "with a network configured, update fetches both lists" "0 $CUR $CUR" \
    "$rc $(cat "$R/var/lib/omr-geoban/dbip-country-month" "$R/var/lib/omr-geoban/dbip-asn-month" 2> /dev/null | tr '\n' ' ' | sed 's/ $//')"
check "and applies them" grep -q '^nft -f ' "$T/nft.log"
new_root asnonly
mkdir -p "$R/etc/openmptcprouter-vps-admin"
printf 'MODE="allow"\nCOUNTRIES="as300"\n' > "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
PATH="$T/fakebin:$PATH" geoban update 2> /dev/null
if [ ! -f "$R/var/lib/omr-geoban/dbip-country-lite.csv.gz" ] && [ -f "$R/var/lib/omr-geoban/dbip-asn-lite.csv.gz" ]; then pass "with networks only, the country list is not fetched"; else fail "with networks only, the country list is not fetched"; fi

new_root broken
echo '<html>Service unavailable</html>' | gzip -c > "$T/mirror/bad.gz"
OMR_GEOBAN_URL="file://$T/nonexistent" geoban update --force 2> /dev/null; rc=$?
check "update fails without a list anywhere" [ "$rc" != 0 ]
mkdir -p "$T/mirror-bad"
cp "$T/mirror/bad.gz" "$T/mirror-bad/dbip-country-lite-$CUR.csv.gz"
geoban update --force 2> /dev/null
before="$(md5sum < "$R/var/lib/omr-geoban/dbip-country-lite.csv.gz")"
OMR_GEOBAN_URL="file://$T/mirror-bad" geoban update --force 2> "$T/err"
after="$(md5sum < "$R/var/lib/omr-geoban/dbip-country-lite.csv.gz")"
check "an error page never replaces a good list" [ "$before" = "$after" ]
check "and says so" grep -q 'not a DB-IP country list' "$T/err"

echo
echo "== ranges =="
new_root ranges
assert_eq "fr: its two ranges, unmerged, and its IPv6" \
    "2.0.0.0-2.0.0.255 2.0.2.0-2.0.2.255 2000:0000:0000:0000:0000:0000:0000:0000-2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff" \
    "$(geoban ranges fr 2> /dev/null | tr '\n' ' ' | sed 's/ $//')"
assert_eq "fr de: adjacent ranges merged, IPv6 across the carry" \
    "2.0.0.0-2.0.2.255 2000:0000:0000:0000:0000:0000:0000:0000-2001:0000:ffff:ffff:ffff:ffff:ffff:ffff" \
    "$(geoban ranges fr,DE 2> /dev/null | tr '\n' ' ' | sed 's/ $//')"
assert_eq "europe -fr -ru: what is left" \
    "2.0.1.0-2.0.1.255 2001:0000:0000:0000:0000:0000:0000:0000-2001:0000:ffff:ffff:ffff:ffff:ffff:ffff" \
    "$(geoban ranges europe -fr '!ru' 2> /dev/null | tr '\n' ' ' | sed 's/ $//')"
geoban ranges uk 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'is GB' "$T/err"; then pass "UK is refused, pointing at GB"; else fail "UK is refused, pointing at GB"; fi
geoban ranges fr xx 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'group: xx' "$T/err"; then pass "an unknown code is refused, naming it"; else fail "an unknown code is refused, naming it"; fi

echo
echo "== check, without the table =="
out="$(PATH="$T/fakebin:$PATH" geoban check 2.0.1.7 3.1.2.3 2000::1 2001:1::5 ::ffff:2.0.0.1 2> /dev/null | awk '{ print $1, $2 }' | tr '\n' ' ')"
assert_eq "the country of each address (IPv4-mapped read as IPv4)" \
    "2.0.1.7 DE 3.1.2.3 US 2000::1 FR 2001:1::5 US 2.0.0.1 FR " "$out"
geoban check 1.2.3 2> /dev/null; rc=$?
check "a non-address is refused" [ "$rc" != 0 ]

echo
echo "== networks =="
new_root asn
assert_eq "as200: its ranges, merged" "2.0.1.0-2.0.2.255" "$(geoban ranges as200 2> /dev/null | tr '\n' ' ' | sed 's/ $//')"
assert_eq "fr AS300: the countries' then the networks' ranges" \
    "2.0.0.0-2.0.0.255 2.0.2.0-2.0.2.255 3.0.0.0-3.0.255.255 2000:0000:0000:0000:0000:0000:0000:0000-2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff 2001:0001:0000:0000:0000:0000:0000:0000-2001:0001:ffff:ffff:ffff:ffff:ffff:ffff" \
    "$(geoban ranges fr AS300 2> /dev/null | tr '\n' ' ' | sed 's/ $//')"
assert_eq "as alone is American Samoa, not a network" "unknown country code or group: as" \
    "$(geoban ranges as 2>&1 | sed 's/^omr-geoban: //; s/ (.*//')"
geoban ranges as1x 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'not an AS number: as1x' "$T/err"; then pass "as1x is refused"; else fail "as1x is refused"; fi
out="$(PATH="$T/fakebin:$PATH" geoban check 2.0.1.7 3.0.0.5 4.0.0.1 2> /dev/null)"
assert_eq "check names the network and its organisation" \
    "2.0.1.7 DE AS200 (Free SAS) not filtered (omr-geoban is not applied)|3.0.0.5 US AS300 (Big Cloud, Inc.) not filtered (omr-geoban is not applied)|4.0.0.1 RU AS?? not filtered (omr-geoban is not applied)" \
    "$(printf '%s' "$out" | tr '\n' '|')"
assert_eq "asn: by name, the largest first, with its country" \
    "AS300 US 65536|AS200 DE 512" \
    "$(geoban asn 'big cloud' free 2> /dev/null | awk '{ print $1, $2, $3 }' | tr '\n' '|' | sed 's/|$//')"
assert_eq "asn: by number, with or without AS" "AS200 DE 512 Free SAS|AS100 FR 256 Orange S.A." \
    "$(geoban asn 100 AS200 2> /dev/null | awk '{ $4 = ""; print }' | sed 's/  / /' | tr '\n' '|' | sed 's/|$//')"
geoban asn nothingmatches 2> /dev/null; rc=$?
check "asn: nothing found is an error" [ "$rc" != 0 ]

echo
echo "== exempt ranges =="
# Through the awk of the script itself: the boundaries of a prefix, both
# families, a range, a nibble-unaligned IPv6 prefix.
eval "$(sed -n "/^AWK_LIB='/,/^'\$/p" "$SCRIPT")"
LIST="$T/mirror/dbip-country-lite-$CUR.csv.gz"
eval "$(sed -n '/^lookup() {/,/^}/p' "$SCRIPT")"
ex="100.64.0.0/10 192.0.2.10-192.0.2.20 2a01:e00::/26 fe80::/10 203.0.113.7"
out="$(lookup "$LIST" "$ex" 100.63.255.255 100.64.0.0 100.127.255.255 100.128.0.0 \
    192.0.2.9 192.0.2.10 192.0.2.20 192.0.2.21 2a01:e00::1 2a01:e3f:ffff::1 2a01:e40::1 \
    febf:ffff::1 fec0::1 203.0.113.7 203.0.113.8 | awk '{ printf "%s", $3 }')"
assert_eq "exempt: prefix and range bounds" "011001101101010" "$out"

echo
echo "== configuration =="
new_root conf
mkdir -p "$R/etc/openmptcprouter-vps-admin"
printf '# mine\nMODE="off"\n# keep me\nEXEMPT="1.2.3.4"\n' > "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
eval "$(sed -n '/^get_conf() {/,/^}/p; /^write_default_conf() {/,/^}/p; /^set_conf() {/,/^}/p; /^log() /p; /^die() /p' "$SCRIPT")"
CONF="$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
set_conf COUNTRIES "europe -ru"
set_conf MODE allow
assert_eq "set_conf changes one line, keeps the comments, appends a new key" \
    '# mine|MODE="allow"|# keep me|EXEMPT="1.2.3.4"|COUNTRIES="europe -ru"|' "$(tr '\n' '|' < "$CONF")"
assert_eq "get_conf reads it back" "europe -ru" "$(get_conf COUNTRIES)"
assert_eq "get_conf default" "off" "$(get_conf NOPE off)"

maxmind_tests
}

# GeoLite2's CSVs, zipped in a directory named after the edition and its date,
# with the checksum file MaxMind serves next to each zip.
mkzip() {
    python3 -I -c 'import sys, os, zipfile
z = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)
for f in sys.argv[3:]:
    z.write(f, sys.argv[2] + "/" + os.path.basename(f))' "$T/mm/$1.zip" "$1_$2" "$T/mmsrc/$1"/*.csv
    (cd "$T/mm" && sha256sum "$1.zip" | awk -v n="$1_$2.zip" '{ print $1 "  " n }' > "$1.zip.sha256")
}

maxmind_tests() {
echo
echo "== maxmind =="
for c in unzip python3 sha256sum; do
    command -v $c > /dev/null 2>&1 || { note "$c is not installed; skipping"; return; }
done
mkdir -p "$T/mm" "$T/mmsrc/GeoLite2-Country-CSV" "$T/mmsrc/GeoLite2-ASN-CSV" "$T/mmbin"
# Unsorted, CRLF ends on one file; 4.0.0.0/24 is located to Europe only
# (registered in DE), 4.0.1.0/24 nowhere (an anonymous proxy: ZZ);
# 2a01:e00::/26 is not on a nibble boundary.
cat > "$T/mmsrc/GeoLite2-Country-CSV/GeoLite2-Country-Locations-en.csv" << 'EOF'
geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
3017382,en,EU,Europe,FR,France,1
2921044,en,EU,Europe,DE,Germany,1
6252001,en,NA,"North America",US,"United States",0
6255148,en,EU,Europe,,,0
EOF
printf '%s\r\n' network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast \
    2.0.2.0/24,3017382,3017382,,0,0, 2.0.0.0/24,3017382,3017382,,0,0, 2.0.1.0/24,2921044,2921044,,0,0, \
    4.0.1.0/24,,,,1,0, 3.0.0.0/8,6252001,6252001,,0,0, 4.0.0.0/24,6255148,2921044,,0,0, \
    > "$T/mmsrc/GeoLite2-Country-CSV/GeoLite2-Country-Blocks-IPv4.csv"
cat > "$T/mmsrc/GeoLite2-Country-CSV/GeoLite2-Country-Blocks-IPv6.csv" << 'EOF'
network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider,is_anycast
2a01:e00::/26,3017382,3017382,,0,0,
2001::/32,2921044,2921044,,0,0,
2000::/16,3017382,3017382,,0,0,
2001:1::/32,6252001,6252001,,0,0,
EOF
cat > "$T/mmsrc/GeoLite2-ASN-CSV/GeoLite2-ASN-Blocks-IPv4.csv" << 'EOF'
network,autonomous_system_number,autonomous_system_organization
2.0.0.0/24,100,"Orange S.A."
2.0.1.0/24,200,Free SAS
2.0.2.0/24,200,Free SAS
3.0.0.0/16,300,"Big Cloud, Inc."
EOF
cat > "$T/mmsrc/GeoLite2-ASN-CSV/GeoLite2-ASN-Blocks-IPv6.csv" << 'EOF'
network,autonomous_system_number,autonomous_system_organization
2000::/16,100,"Orange S.A."
EOF
mkzip GeoLite2-Country-CSV 20261103
mkzip GeoLite2-ASN-CSV 20261103
# download.maxmind.com: /<edition>/download?suffix=<zip|zip.sha256>, with
# HTTP basic auth 42:goodkey; 429 while $T/mm/429 exists. Any other URL goes
# to the real curl.
cat > "$T/mmbin/curl" << EOF
#!/bin/sh
case "\$*" in *https://mm.test/*) ;; *) exec $(command -v curl) "\$@" ;; esac
echo "argv \$*" >> "$T/curl.log"
cfg=""; out=""; url=""
while [ \$# -gt 0 ]; do
    case "\$1" in
    -K) [ "\$2" = - ] && cfg="\$(cat)"; shift ;;
    -o) out="\$2"; shift ;;
    -w | --retry | --connect-timeout | --max-time) shift ;;
    -*) ;;
    *) url="\$1" ;;
    esac
    shift
done
echo "stdin \$cfg" >> "$T/curl.log"
[ "\$cfg" = 'user = "42:goodkey"' ] || { printf 401; exit 22; }
[ -f "$T/mm/429" ] && { printf 429; exit 22; }
e="\${url#https://mm.test/geoip/databases/}"; e="\${e%%/*}"
f="$T/mm/\$e.\${url##*suffix=}"
[ -f "\$f" ] || { printf 404; exit 22; }
cp "\$f" "\$out"
printf 200
EOF
chmod 755 "$T/mmbin/curl"
export OMR_GEOBAN_MAXMIND_URL="https://mm.test/geoip/databases"
mm() { PATH="$T/mmbin:$T/fakebin:$PATH" geoban "$@"; }
C="$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
S="$R/var/lib/omr-geoban"

new_root mm
C="$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
S="$R/var/lib/omr-geoban"
geoban update --force 2> /dev/null
mm source maxmind 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'needs an account ID and a license key' "$T/err"; then pass "maxmind without credentials is refused"; else fail "maxmind without credentials is refused"; fi
assert_eq "and the source stays dbip" "dbip" "$(geoban source | awk '{ print $1 }')"
mm source maxmind 42 badkey 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'refused the account ID and license key (HTTP 401)' "$T/err"; then pass "a wrong license key is refused, saying so"; else fail "a wrong license key is refused, saying so"; fi
check_not "and is not saved" grep -qs badkey "$C"
mm source maxmind 42 'bad key!' 2> /dev/null; rc=$?
check "a license key with other characters is refused" [ "$rc" != 0 ]

rm -f "$T/curl.log"
mm source maxmind 42 goodkey 2> "$T/err"; rc=$?
assert_eq "source maxmind <account> <key>: switched and saved" '0 SOURCE="maxmind" MAXMIND_ACCOUNT_ID="42" MAXMIND_LICENSE_KEY="goodkey"' \
    "$rc $(grep -E '^(SOURCE|MAXMIND_[A-Z_]*)=' "$C" | tr '\n' ' ' | sed 's/ $//')"
assert_eq "the configuration is readable by root only" "600" "$(stat -c %a "$C")"
check "the key goes to curl on its standard input" grep -q '^stdin user = "42:goodkey"' "$T/curl.log"
check_not "never on its command line" grep -q '^argv .*goodkey' "$T/curl.log"
check "the attribution is logged" grep -q 'GeoLite2 data created by MaxMind' "$T/err"
assert_eq "the DB-IP list is deleted, the GeoLite2 one stored with its date" "maxmind-country-version maxmind-country.csv.gz 2026-11-03" \
    "$(cd "$S" && LC_ALL=C ls | grep -v applied | tr '\n' ' ')$(awk '{ print $1 }' "$S/maxmind-country-version")"
assert_eq "GeoLite2 converted: DB-IP's format, sorted, continent-only ranges by registration, ZZ, IPv6 unaligned" \
    "2.0.0.0,2.0.0.255,FR 2.0.1.0,2.0.1.255,DE 2.0.2.0,2.0.2.255,FR 3.0.0.0,3.255.255.255,US 4.0.0.0,4.0.0.255,DE 4.0.1.0,4.0.1.255,ZZ 2000:0000:0000:0000:0000:0000:0000:0000,2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff,FR 2001:0000:0000:0000:0000:0000:0000:0000,2001:0000:ffff:ffff:ffff:ffff:ffff:ffff,DE 2001:0001:0000:0000:0000:0000:0000:0000,2001:0001:ffff:ffff:ffff:ffff:ffff:ffff,US 2a01:0e00:0000:0000:0000:0000:0000:0000,2a01:0e3f:ffff:ffff:ffff:ffff:ffff:ffff,FR" \
    "$(gzip -dc "$S/maxmind-country.csv.gz" | tr '\n' ' ' | sed 's/ $//')"
assert_eq "fr de from GeoLite2: merged as with DB-IP" \
    "2.0.0.0-2.0.2.255 4.0.0.0-4.0.0.255 2000:0000:0000:0000:0000:0000:0000:0000-2001:0000:ffff:ffff:ffff:ffff:ffff:ffff 2a01:0e00:0000:0000:0000:0000:0000:0000-2a01:0e3f:ffff:ffff:ffff:ffff:ffff:ffff" \
    "$(mm ranges fr de 2> /dev/null | tr '\n' ' ' | sed 's/ $//')"
assert_eq "check reads both GeoLite2 lists" \
    "3.0.0.5 US AS300 (Big Cloud, Inc.)|2.0.1.9 DE AS200 (Free SAS)|4.0.0.1 DE AS??|2a01:e3f::1 FR AS??" \
    "$(mm check 3.0.0.5 2.0.1.9 4.0.0.1 2a01:e3f::1 2> /dev/null | sed 's/ not filtered.*//' | tr '\n' '|' | sed 's/|$//')"
assert_eq "asn searches GeoLite2's names" "AS300 US 65536 IPv4 Big Cloud, Inc." \
    "$(mm asn cloud 2> /dev/null | tr -s ' ')"
check "status names the source" grep -q '^Source: maxmind (GeoLite2 data created by MaxMind' <<< "$(geoban status)"

printf 'MODE="deny"\nCOUNTRIES="de as300"\n' >> "$C"
rm -f "$T/curl.log" "$T/nft.log"
mm update 2> /dev/null; rc=$?
assert_eq "update with the same checksum: only the checksums are fetched, nothing re-applied" "0 2 0" \
    "$rc $(grep -c '^argv .*suffix=zip.sha256' "$T/curl.log") $(grep -c '^argv .*suffix=zip$' "$T/curl.log")"
check "and the table is not reloaded" [ ! -s "$T/nft.log" ]
mkzip GeoLite2-Country-CSV 20261106
mm update 2> /dev/null; rc=$?
assert_eq "a new edition is fetched and applied" "0 2026-11-06" "$rc $(awk '{ print $1 }' "$S/maxmind-country-version")"
check "the table is reloaded" grep -q '^nft -f ' "$T/nft.log"
assert_eq "status names the lists applied" "from maxmind" "$(mm status | sed -n 's/.*lists of [^ ]* [^ ]* \(from [a-z]*\).*/\1/p')"

before="$(md5sum < "$S/maxmind-country.csv.gz")"
cp "$T/mm/GeoLite2-Country-CSV.zip.sha256" "$T/sha.keep"
sed -i 's/^./0/; s/_20261106/_20261110/' "$T/mm/GeoLite2-Country-CSV.zip.sha256"
mm update 2> "$T/err"; rc=$?
check "a zip that does not match its checksum fails the update" [ "$rc" != 0 ]
check "and says so" grep -q 'does not match its checksum' "$T/err"
check "and the list stays" [ "$before" = "$(md5sum < "$S/maxmind-country.csv.gz")" ]
cp "$T/sha.keep" "$T/mm/GeoLite2-Country-CSV.zip.sha256"
echo 'not a zip' > "$T/mm/bad.zip"
cp "$T/mm/GeoLite2-Country-CSV.zip" "$T/zip.keep"
cp "$T/mm/bad.zip" "$T/mm/GeoLite2-Country-CSV.zip"
(cd "$T/mm" && sha256sum GeoLite2-Country-CSV.zip | awk '{ print $1 "  GeoLite2-Country-CSV_20261110.zip" }' > GeoLite2-Country-CSV.zip.sha256)
mm update 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'not a GeoLite2 CSV zip' "$T/err" && [ "$before" = "$(md5sum < "$S/maxmind-country.csv.gz")" ]; then pass "a zip without the CSVs never replaces the list"; else fail "a zip without the CSVs never replaces the list"; fi
check "nor leaves its files behind" [ -z "$(ls "$S" | grep download)" ]
cp "$T/zip.keep" "$T/mm/GeoLite2-Country-CSV.zip"
cp "$T/sha.keep" "$T/mm/GeoLite2-Country-CSV.zip.sha256"
touch "$T/mm/429"
mm update --force 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'daily download limit' "$T/err"; then pass "MaxMind's download limit is named"; else fail "MaxMind's download limit is named"; fi
rm -f "$T/mm/429"

mm source dbip 2> /dev/null; rc=$?
assert_eq "source dbip: back, the GeoLite2 lists deleted" "0 dbip dbip-asn-lite.csv.gz dbip-asn-month dbip-country-lite.csv.gz dbip-country-month" \
    "$rc $(geoban source | awk '{ print $1 }') $(cd "$S" && LC_ALL=C ls | grep -v applied | tr '\n' ' ' | sed 's/ $//')"
check "the MaxMind credentials stay, for a switch back" grep -q '^MAXMIND_LICENSE_KEY="goodkey"' "$C"
geoban source nope 2> /dev/null; rc=$?
check "an unknown source is refused" [ "$rc" != 0 ]
sed -i 's/^SOURCE=.*/SOURCE="nope"/' "$C"
geoban status > /dev/null 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'SOURCE must be dbip or maxmind' "$T/err"; then pass "a SOURCE set by hand to nothing known stops the commands"; else fail "a SOURCE set by hand to nothing known stops the commands"; fi
mm source dbip 2> /dev/null; rc=$?
check "but source fixes it" [ "$rc" = 0 ]
unset OMR_GEOBAN_MAXMIND_URL
}

# ── 2. and 3. the real nft, in a network namespace ───────────────────────
netns_tests() {
PATH="$PATH:/usr/sbin:/sbin"
echo "== the table =="
new_root nft
mkdir -p "$T/ssbin"
# ss: a router WAN (Shadowsocks) from the US, one from France, an SSH session
# from the US (open to every country by default), the VPS's own outgoing
# connection to the US (not to a port it listens on: not a peer).
cat > "$T/ssbin/ss" << 'EOF'
#!/bin/sh
case "$*" in
"-Htln")
    echo "LISTEN 0 128 0.0.0.0:65222 0.0.0.0:*"
    echo "LISTEN 0 128 0.0.0.0:65101 0.0.0.0:*" ;;
"-Htn state established")
    echo "0 0 198.51.100.1:65101 3.0.0.9:51000"
    echo "0 0 198.51.100.1:65101 2.0.0.9:51001"
    echo "0 0 198.51.100.1:65222 3.0.0.11:51002"
    echo "0 0 198.51.100.1:40000 3.0.0.10:443" ;;
esac
EOF
chmod 755 "$T/ssbin/ss"
SS="$T/ssbin"
mkdir -p "$T/nossbin"
printf '#!/bin/sh\nexit 0\n' > "$T/nossbin/ss"
chmod 755 "$T/nossbin/ss"
NOSS="$T/nossbin"

PATH="$SS:$PATH" geoban allow fr 2> "$T/err"; rc=$?
check "allow fr is refused while a router WAN from the US is up" [ "$rc" != 0 ]
check "naming the peer, its country, network and port" grep -q '3.0.0.9 (US, AS300 Big Cloud, Inc.), to port 65101' "$T/err"
check_not "not the French one, the SSH session, nor the VPS's own connection" grep -q '2.0.0.9\|3.0.0.11\|3.0.0.10' "$T/err"
check_not "and nothing is loaded" quiet nft list table inet omr_geoban
check "nor configured" [ ! -f "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf" ]

PATH="$SS:$PATH" geoban deny us 2> /dev/null; rc=$?
check "deny us is refused for the same reason" [ "$rc" != 0 ]
PATH="$SS:$PATH" geoban deny ru 2> /dev/null; rc=$?
check "deny ru is not" [ "$rc" = 0 ]

PATH="$SS:$PATH" geoban exempt add 3.0.0.9 2> /dev/null
PATH="$SS:$PATH" geoban allow fr 2> /dev/null; rc=$?
check "allow fr goes through once the peer is exempt" [ "$rc" = 0 ]
PATH="$SS:$PATH" geoban exempt del 3.0.0.9 2> /dev/null
check "exempt del re-applies, without the peer check" quiet nft list set inet omr_geoban exempt4
check_not "and it is out of the set" quiet nft get element inet omr_geoban exempt4 '{ 3.0.0.9 }'

PATH="$SS:$PATH" geoban allow fr --force 2> /dev/null; rc=$?
check "--force applies anyway" [ "$rc" = 0 ]
assert_eq "the configuration" 'MODE="allow" COUNTRIES="fr"' \
    "$(grep -E '^(MODE|COUNTRIES)=' "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf" | sort -r | tr '\n' ' ' | sed 's/ $//')"
check "FR's IPv4 is in the set" quiet nft get element inet omr_geoban geo4 '{ 2.0.2.9 }'
check_not "DE's is not" quiet nft get element inet omr_geoban geo4 '{ 2.0.1.9 }'
check "FR's IPv6 is in the set" quiet nft get element inet omr_geoban geo6 '{ 2000:1::1 }'
chain="$(nft list chain inet omr_geoban prerouting)"
check "the chain hooks prerouting at mangle - 10" grep -q 'hook prerouting priority mangle - 10' <<< "$chain"
check "it skips the tunnels" grep -q 'iifname { .*"tun\*"' <<< "$chain"
check "allow ends with a drop" grep -q 'drop comment "omr-geoban: not from an allowed country or network"' <<< "$chain"
status="$(geoban status)"
check "status reports the mode, the codes and the list" grep -q "^Applied: allow FR" <<< "$status"

PATH="$NOSS:$PATH" geoban exempt add 300.1.1.1 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'not an address' "$T/err"; then pass "an exempt entry nft can't read is refused"; else fail "an exempt entry nft can't read is refused"; fi
PATH="$NOSS:$PATH" geoban exempt add 2001:db8::/32 192.0.2.10-192.0.2.20 2> /dev/null; rc=$?
check "a prefix and a range are taken" [ "$rc" = 0 ]
check "and loaded" quiet nft get element inet omr_geoban exempt6 '{ 2001:db8::5 }'
assert_eq "exempt lists them" "2001:db8::/32 192.0.2.10-192.0.2.20" "$(geoban exempt | tr '\n' ' ' | sed 's/ $//')"
PATH="$NOSS:$PATH" geoban exempt del 2001:db8::/32 192.0.2.10-192.0.2.20 2> /dev/null
PATH="$NOSS:$PATH" geoban allow fr -as100 as300 2> /dev/null; rc=$?
check "allow fr -as100 as300 loads" [ "$rc" = 0 ]
check "the network is in net4" quiet nft get element inet omr_geoban net4 '{ 3.0.0.9 }'
check "the network taken out is in except4" quiet nft get element inet omr_geoban except4 '{ 2.0.0.9 }'
check "and except6" quiet nft get element inet omr_geoban except6 '{ 2000::9 }'
chain="$(nft list chain inet omr_geoban prerouting)"
check "allow drops a network taken out before accepting its country" \
    test "$(grep -n '@except4 counter' <<< "$chain" | cut -d: -f1)" -lt "$(grep -n '@geo4 accept' <<< "$chain" | cut -d: -f1)"
assert_eq "status names them" "Applied: allow FR AS300, but AS100" "$(geoban status | grep '^Applied')"
PATH="$NOSS:$PATH" geoban allow as999 2> "$T/err"; rc=$?
if [ "$rc" != 0 ] && grep -q 'no address range for AS999' "$T/err"; then pass "an AS number with no range is refused"; else fail "an AS number with no range is refused"; fi
check "and the table stays" quiet nft get element inet omr_geoban net4 '{ 3.0.0.9 }'
PATH="$NOSS:$PATH" geoban deny ru -as300 2> /dev/null
chain="$(nft list chain inet omr_geoban prerouting)"
check "deny accepts a network taken out before dropping" \
    test "$(grep -n '@except4 accept' <<< "$chain" | cut -d: -f1)" -lt "$(grep -n '@geo4 counter' <<< "$chain" | cut -d: -f1)"
check "SSH open to every country by default" grep -q 'tcp dport 65222 accept' <<< "$chain"
sed -i '/^OPEN_PORTS=/d' "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
geoban apply 2> /dev/null
chain="$(nft list chain inet omr_geoban prerouting)"
check "and without an OPEN_PORTS line" grep -q 'tcp dport 65222 accept' <<< "$chain"
printf 'OPEN_PORTS=""\n' >> "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
geoban apply 2> /dev/null
chain="$(nft list chain inet omr_geoban prerouting)"
if grep -q 'dport' <<< "$chain"; then fail "OPEN_PORTS=\"\" filters SSH too"; else pass "OPEN_PORTS=\"\" filters SSH too"; fi
printf 'OPEN_PORTS="tcp/65222 udp/1194 tcp/8000-8100"\n' >> "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
geoban apply 2> /dev/null
chain="$(nft list chain inet omr_geoban prerouting)"
check "OPEN_PORTS tcp" grep -q 'tcp dport { 8000-8100, 65222 } accept' <<< "$chain"
check "OPEN_PORTS udp" grep -q 'udp dport 1194 accept' <<< "$chain"

# nftables.conf begins with flush ruleset: apply (omr-geoban.service, run
# by the nftables.service.d hook) puts the table back from the stored list,
# without the network.
nft flush ruleset
OMR_GEOBAN_URL="file://$T/nonexistent" geoban apply 2> /dev/null; rc=$?
if [ "$rc" = 0 ] && nft get element inet omr_geoban geo4 '{ 4.1.1.1 }' > /dev/null 2>&1; then pass "apply restores the table after a flush, offline"; else fail "apply restores the table after a flush, offline"; fi

PATH="$NOSS:$PATH" geoban deny ru us 2> /dev/null
chain="$(nft list chain inet omr_geoban prerouting)"
check "deny drops the listed countries" grep -q 'ip saddr @geo4 counter packets 0 bytes 0 drop' <<< "$chain"
check_not "and has no final drop" grep -q 'not from an allowed country' <<< "$chain"

# A hand-edited EXEMPT nft refuses: the previous table stays.
sed -i 's/^EXEMPT=.*/EXEMPT="300.1.1.1"/' "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"
geoban apply 2> /dev/null; rc=$?
check "a ruleset nft refuses fails the run" [ "$rc" != 0 ]
check "and leaves the previous table" quiet nft get element inet omr_geoban geo4 '{ 4.1.1.1 }'
sed -i 's/^EXEMPT=.*/EXEMPT=""/' "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf"

geoban off 2> /dev/null
check_not "off removes the table" quiet nft list table inet omr_geoban
assert_eq "and configures off" 'MODE="off"' "$(grep '^MODE=' "$R/etc/openmptcprouter-vps-admin/omr-geoban.conf")"
geoban apply; rc=$?
if [ "$rc" = 0 ] && ! nft list table inet omr_geoban > /dev/null 2>&1; then pass "apply while off succeeds and loads nothing"; else fail "apply while off succeeds and loads nothing"; fi

packet_tests
}

packet_tests() {
echo
echo "== packets =="
for c in nsenter ping; do
    command -v $c > /dev/null 2>&1 || { note "$c is not installed; skipping"; return; }
done
# The internet: a namespace behind eth0 (the WAN) and tun0 (a tunnel),
# sending from 2.0.0.1 (FR), 3.0.0.1 (US), 2000::1 (FR) and 2001:1::1 (US).
unshare -n sleep 600 &
NET=$!
sleep 0.3
inet() { nsenter -t "$NET" -n "$@"; }
if ! ip link add eth0 type veth peer name weth netns "$NET" 2> /dev/null ||
    ! ip link add tun0 type veth peer name wtun netns "$NET" 2> /dev/null; then
    note "cannot move a veth into another namespace here; skipping"
    kill "$NET"
    return
fi
ip link set lo up; ip link set eth0 up; ip link set tun0 up
ip addr add 198.51.100.1/32 dev eth0
ip addr add 198.51.100.2/32 dev tun0
ip addr add 2400::1/128 dev eth0 nodad
ip route add default dev eth0
ip route add 3.0.0.2/32 dev tun0
ip -6 route add default dev eth0
inet ip link set lo up; inet ip link set weth up; inet ip link set wtun up
for a in 2.0.0.1 3.0.0.1; do inet ip addr add $a/32 dev weth; done
inet ip addr add 3.0.0.2/32 dev wtun
for a in 2000::1 2001:1::1; do inet ip addr add $a/128 dev weth nodad; done
inet ip route add 198.51.100.1/32 dev weth
inet ip route add 198.51.100.2/32 dev wtun
inet ip -6 route add 2400::1/128 dev weth
sleep 1
from() { inet ping -c 1 -W 1 -I "$1" "$2" > /dev/null 2>&1; }
quiet_not_from() { ! from "$@"; }

PATH="$T/nossbin:$PATH" geoban allow fr 2> /dev/null
check "allow fr: France reaches the VPS over IPv4" quiet from 2.0.0.1 198.51.100.1
check_not "the US does not" quiet from 3.0.0.1 198.51.100.1
check "France over IPv6" quiet from 2000::1 2400::1
check_not "the US over IPv6 does not" quiet from 2001:1::1 2400::1
dropped="$(nft list chain inet omr_geoban prerouting | sed -n 's/.*counter packets \([0-9]*\).*/\1/p' | awk '{ n += $1 } END { print n + 0 }')"
check "the drops are counted ($dropped)" [ "${dropped:-0}" -ge 2 ]
check "a tunnel is never filtered" quiet from 3.0.0.2 198.51.100.2
check "the VPS still gets its answers from the US (established)" quiet ping -c 1 -W 1 -I 198.51.100.1 3.0.0.1

PATH="$T/nossbin:$PATH" geoban deny us 2> /dev/null
check "deny us: France reaches the VPS" quiet from 2.0.0.1 198.51.100.1
check_not "the US does not" quiet from 3.0.0.1 198.51.100.1
check_not "the US over IPv6 does not" quiet from 2001:1::1 2400::1

PATH="$T/nossbin:$PATH" geoban exempt add 3.0.0.1 2> /dev/null
check "an exempt address gets through" quiet from 3.0.0.1 198.51.100.1
PATH="$T/nossbin:$PATH" geoban exempt del 3.0.0.1 2> /dev/null

PATH="$T/nossbin:$PATH" geoban allow as300 2> /dev/null
check "allow as300: its address in the US gets through" quiet from 3.0.0.1 198.51.100.1
check "France does not" quiet_not_from 2.0.0.1 198.51.100.1
check "its IPv6 gets through" quiet from 2001:1::1 2400::1
PATH="$T/nossbin:$PATH" geoban allow fr -as100 2> /dev/null
check "allow fr -as100: AS100's French address does not get through" quiet_not_from 2.0.0.1 198.51.100.1
check "nor its IPv6" quiet_not_from 2000::1 2400::1

geoban off 2> /dev/null
check "off: the US reaches the VPS again" quiet from 2001:1::1 2400::1
kill "$NET" 2> /dev/null
}

section_netns() {
echo
echo "== the real nft, in a network namespace =="
if ! command -v nft > /dev/null 2>&1 && ! [ -x /usr/sbin/nft ]; then
    note "nft is not installed; skipping"
elif ! command -v unshare > /dev/null 2>&1; then
    note "unshare is not installed; skipping"
else
    if [ "$(id -u)" = 0 ]; then ns_cmd="unshare -n"; else ns_cmd="unshare -rn"; fi
    if ! $ns_cmd sh -c 'PATH="$PATH:/usr/sbin:/sbin"; nft list tables' > /dev/null 2>&1; then
        note "cannot create a network namespace with nft in it here; run this test as root"
    else
        out="$($ns_cmd bash "$SCRIPT_DIR/$(basename "$0")" --in-netns 2>&1)"
        printf '%s\n' "$out" | grep -v '^netns-counts '
        counts="$(printf '%s\n' "$out" | sed -n 's/^netns-counts //p')"
        if [ -n "$counts" ]; then
            set -- $counts
            PASS=$((PASS + $1)); FAIL=$((FAIL + $2))
        else
            fail "the namespace run did not finish"
        fi
    fi
fi
}

if [ "${1:-}" = "--in-netns" ]; then
    netns_tests
    echo "netns-counts $PASS $FAIL"
    exit 0
fi
fake_tests
section_netns

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
