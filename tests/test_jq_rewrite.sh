#!/bin/bash
# jq_rewrite(), the installer's in-place JSON rewrite, and the guarantee that
# no `jq ... > FILE.tmp; mv FILE.tmp FILE` is left in debian9-x86_64.sh.
#
# That pattern replaced FILE with an empty file whenever jq failed (an
# unparsable file, a bad filter) and set -e did not stop the script, as in the
# SoftEther part (set +e): an empty omr-admin-config.json makes omr-admin
# crash-loop (Ysurac/openmptcprouter#2487, #4385). Its temp copy of these
# secret-bearing files (user passwords, VPN keys) was also written with the
# default umask, world-readable.
#
# The function is taken from the installer itself and run with /bin/sh, as the
# installer is. Requires: bash, jq, GNU stat/chmod (Linux).

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

if ! command -v jq > /dev/null 2>&1; then
    echo "jq not installed; skipping"
    exit 77
fi

sed -n '/^jq_rewrite() {/,/^}/p' "$INSTALLER" > "$T/fn.sh"
if [ ! -s "$T/fn.sh" ]; then
    echo "  FAIL jq_rewrite() not found in $INSTALLER"
    exit 1
fi

# Run jq_rewrite with /bin/sh; RC gets its exit code.
run() {
    sh -c '. "$1"; shift; jq_rewrite "$@"' sh "$T/fn.sh" "$@" 2> "$T/stderr"
    RC=$?
}
mode() { stat -c %a "$1"; }
leftovers() { ls "$T"/cfg.json.tmp.* 2> /dev/null | wc -l; }

GOOD='{"users":[{"openmptcprouter":{"userid":0,"user_password":"s"}}]}'

echo "== a successful rewrite =="
printf '%s\n' "$GOOD" > "$T/cfg.json"
chmod 600 "$T/cfg.json"
run "$T/cfg.json" -M '. + {host: "0.0.0.0"}'
assert_eq "exit 0" 0 "$RC"
assert_eq "the change is written" "0.0.0.0" "$(jq -r .host "$T/cfg.json")"
assert_eq "the rest is kept" "s" "$(jq -r '.users[0].openmptcprouter.user_password' "$T/cfg.json")"
assert_eq "the file stays 0600" 600 "$(mode "$T/cfg.json")"
assert_eq "no temp copy left" 0 "$(leftovers)"

echo
echo "== jq options and --arg pass through =="
run "$T/cfg.json" --arg p 'a b"c' '. + {softethervpn_admin_password: $p}'
assert_eq "exit 0" 0 "$RC"
assert_eq "--arg value with spaces and quotes" 'a b"c' "$(jq -r .softethervpn_admin_password "$T/cfg.json")"

echo
echo "== the file's own mode is kept =="
chmod 640 "$T/cfg.json"
run "$T/cfg.json" '. + {x: 1}'
assert_eq "a 0640 file stays 0640" 640 "$(mode "$T/cfg.json")"
chmod 600 "$T/cfg.json"

echo
echo "== the temp copy is owner-only from the start =="
# A jq that records the mode of the file its stdout goes to, then runs jq.
mkdir -p "$T/bin"
cat > "$T/bin/jq" <<EOF
#!/bin/sh
stat -L -c %a /proc/self/fd/1 > "$T/tmpmode"
exec "$(command -v jq)" "\$@"
EOF
chmod +x "$T/bin/jq"
( umask 022; PATH="$T/bin:$PATH" run "$T/cfg.json" '. + {y: 1}'; echo "$RC" > "$T/rc" )
assert_eq "exit 0" 0 "$(cat "$T/rc")"
assert_eq "temp copy created 0600 under umask 022" 600 "$(cat "$T/tmpmode" 2> /dev/null)"

echo
echo "== jq fails on an unparsable file: nothing is replaced =="
printf '{"users": [,\n' > "$T/cfg.json"
chmod 600 "$T/cfg.json"
cp -p "$T/cfg.json" "$T/orig"
run "$T/cfg.json" '. + {host: "0.0.0.0"}'
assert_eq "exit 1" 1 "$RC"
assert_eq "the file is left as it was (not emptied)" "" "$(cmp -s "$T/orig" "$T/cfg.json" || echo changed)"
assert_eq "no temp copy left" 0 "$(leftovers)"
assert_eq "the failure is reported" yes "$(grep -q 'left unchanged' "$T/stderr" && echo yes)"

echo
echo "== a bad filter: nothing is replaced =="
printf '%s\n' "$GOOD" > "$T/cfg.json"
cp -p "$T/cfg.json" "$T/orig"
run "$T/cfg.json" '. + {'
assert_eq "exit 1" 1 "$RC"
assert_eq "the file is left as it was" "" "$(cmp -s "$T/orig" "$T/cfg.json" || echo changed)"
assert_eq "no temp copy left" 0 "$(leftovers)"

echo
echo "== a filter with no output: nothing is replaced =="
run "$T/cfg.json" 'empty'
assert_eq "exit 1" 1 "$RC"
assert_eq "the file is not emptied" "" "$(cmp -s "$T/orig" "$T/cfg.json" || echo changed)"
assert_eq "no temp copy left" 0 "$(leftovers)"

echo
echo "== a missing file =="
run "$T/missing.json" '.'
assert_eq "exit 1" 1 "$RC"
assert_eq "nothing is created" no "$([ -e "$T/missing.json" ] && echo yes || echo no)"

echo
echo "== under set -e a failure still stops the installer, as before =="
printf '{"users": [,\n' > "$T/cfg.json"
sh -c 'set -e; . "$1"; jq_rewrite "$2" "."; echo continued' sh "$T/fn.sh" "$T/cfg.json" > "$T/out" 2> /dev/null
assert_eq "set -e: the script stops at the failed rewrite" "" "$(cat "$T/out")"
sh -c 'set +e; . "$1"; jq_rewrite "$2" "."; echo continued' sh "$T/fn.sh" "$T/cfg.json" > "$T/out" 2> /dev/null
assert_eq "set +e: the script goes on, with the file intact" continued "$(cat "$T/out")"

echo
echo "== the installer uses it everywhere =="
uncommented() { grep -vE '^[[:space:]]*#' "$INSTALLER"; }
# jq writing straight to FILE.tmp / FILE.new, renamed over FILE afterwards.
raw="$(uncommented | grep -E '^[[:space:]]*jq .*>[[:space:]]*[^ ]+\.(tmp|new)[[:space:]]*$')"
if [ -z "$raw" ]; then
    pass "no 'jq ... > FILE.tmp; mv' rewrite left"
else
    fail "rewrites not going through jq_rewrite:"
    printf '%s\n' "$raw" | sed 's/^/      /'
fi
for f in /etc/openmptcprouter-vps-admin/omr-admin-config.json.bak /etc/xray/xray-server.json.bak; do
    if sed -n '/^harden_secret_files \\$/,/^$/p' "$INSTALLER" | grep -q "^[[:space:]]*$f"; then
        pass "the final permission sweep hardens $f"
    else
        fail "the final permission sweep does not harden $f"
    fi
done

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
