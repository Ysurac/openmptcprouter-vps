#!/bin/bash
# omr_self_signed_cert() and omr_api_pin(), the installer's certificates for
# the OMR API and MQVPN (GHSA-qq6x-5r9f-2w3m).
#
# The router pins the public key of the API certificate, so the installer must
# never replace an existing key, and the pin it prints must be the one curl
# --pinnedpubkey checks. The certificates had only a CN, which TLS clients that
# verify the name ignore: a CN-only certificate is reissued with a
# subjectAltName from the same key.
#
# The functions are taken from the installer itself and run with /bin/sh, as
# the installer is. Requires: bash, openssl.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$ROOT/debian9-x86_64.sh"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

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

if ! command -v openssl > /dev/null 2>&1; then
    echo "openssl not installed; skipping"
    exit 77
fi

{
    grep '^OMR_CERT_SUBJ=\|^OMR_CERT_SAN=' "$INSTALLER"
    sed -n '/^omr_self_signed_cert() {/,/^}/p' "$INSTALLER"
    sed -n '/^omr_api_pin() {/,/^}/p' "$INSTALLER"
} > "$T/fn.sh"
for f in omr_self_signed_cert omr_api_pin OMR_CERT_SUBJ OMR_CERT_SAN; do
    grep -q "^$f" "$T/fn.sh" || { echo "  FAIL $f not found in $INSTALLER"; exit 1; }
done

cert() { sh -c '. "$1"; shift; omr_self_signed_cert "$@"' sh "$T/fn.sh" "$@" 2> "$T/stderr"; }
api_pin() { sh -c '. "$1"; shift; omr_api_pin "$@"' sh "$T/fn.sh" "$@"; }
# What curl --pinnedpubkey sha256// compares, computed independently
curl_pin() {
    openssl x509 -in "$1" -noout -pubkey | openssl pkey -pubin -outform der |
        openssl dgst -sha256 -binary | base64
}
has_san() { openssl x509 -in "$1" -noout -text | grep -q 'DNS:www.openmptcprouter.vps' && echo yes || echo no; }
sum() { md5sum "$1" | cut -d' ' -f1; }

echo "== a fresh install =="
cert "$T/key.pem" "$T/cert.pem"
assert_eq "key created" yes "$([ -s "$T/key.pem" ] && echo yes || echo no)"
assert_eq "certificate has the subjectAltName" yes "$(has_san "$T/cert.pem")"
assert_eq "CN kept" yes "$(openssl x509 -in "$T/cert.pem" -noout -subject | grep -q 'CN *= *www.openmptcprouter.vps' && echo yes || echo no)"
PIN="$(curl_pin "$T/cert.pem")"
assert_eq "the printed pin is curl's" "$PIN" "$(api_pin "$T/cert.pem")"

echo
echo "== a certificate with a subjectAltName is left alone =="
before="$(sum "$T/cert.pem")"
cert "$T/key.pem" "$T/cert.pem"
assert_eq "certificate unchanged" "$before" "$(sum "$T/cert.pem")"

echo
echo "== an older CN-only certificate is reissued from its key =="
rm -f "$T/key.pem" "$T/cert.pem"
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout "$T/key.pem" -out "$T/cert.pem" \
    -subj "/C=US/ST=Oregon/L=Portland/O=OpenMPTCProuterVPS/OU=Org/CN=www.openmptcprouter.vps" 2>/dev/null
OLD_PIN="$(curl_pin "$T/cert.pem")"
key_before="$(sum "$T/key.pem")"
assert_eq "precondition: no subjectAltName" no "$(has_san "$T/cert.pem")"
cert "$T/key.pem" "$T/cert.pem"
assert_eq "now has the subjectAltName" yes "$(has_san "$T/cert.pem")"
assert_eq "key untouched" "$key_before" "$(sum "$T/key.pem")"
assert_eq "so the routers' pin still matches" "$OLD_PIN" "$(curl_pin "$T/cert.pem")"
assert_eq "no temp file left" 0 "$(ls "$T"/cert.pem.new.* 2>/dev/null | wc -l)"

echo
echo "== a lost certificate is recreated from the key =="
rm -f "$T/cert.pem"
cert "$T/key.pem" "$T/cert.pem"
assert_eq "same key, same pin" "$OLD_PIN" "$(curl_pin "$T/cert.pem")"

echo
echo "== an acme.sh symlink is left alone =="
openssl req -new -newkey rsa:2048 -days 30 -nodes -x509 -keyout "$T/acme.key" -out "$T/acme.cer" \
    -subj "/CN=vps.example.com" 2>/dev/null
ln -s "$T/acme.cer" "$T/link.pem"
before="$(sum "$T/acme.cer")"
cert "$T/acme.key" "$T/link.pem"
assert_eq "still a symlink" yes "$([ -L "$T/link.pem" ] && echo yes || echo no)"
assert_eq "its target unchanged" "$before" "$(sum "$T/acme.cer")"
assert_eq "the pin follows the symlink" "$(curl_pin "$T/acme.cer")" "$(api_pin "$T/link.pem")"

echo
echo "== no certificate, no pin =="
assert_eq "nothing printed" "" "$(api_pin "$T/missing.pem")"
echo garbage > "$T/garbage.pem"
assert_eq "nothing for an unreadable certificate" "" "$(api_pin "$T/garbage.pem")"

echo
echo "== the installer creates both certificates through the function =="
assert_eq "no openssl req left outside omr_self_signed_cert" 4 "$(grep -c 'openssl req ' "$INSTALLER")"
for pair in "/etc/openmptcprouter-vps-admin/key.pem /etc/openmptcprouter-vps-admin/cert.pem" \
            "/etc/mqvpn/server.key /etc/mqvpn/server.crt"; do
    if grep -q "^[[:space:]]*omr_self_signed_cert $pair\$" "$INSTALLER"; then
        pass "omr_self_signed_cert $pair"
    else
        fail "omr_self_signed_cert $pair not called"
    fi
done

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
