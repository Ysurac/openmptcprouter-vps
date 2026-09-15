#!/bin/bash
# Runs every tests/test_*.sh and reports one line per test.
#
# A test that cannot run for want of its subject -- test_deb_contents.sh with
# no built .deb around -- exits 77 and is counted as skipped, not as a pass:
# the point is that "0 failed" never quietly means "nothing ran".
#
# Usage: tests/run_all.sh [name ...]   (substring match on the test file name)
# DEB=path/to/omr-server_*.deb selects the package for test_deb_contents.sh.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

PASSED=0
FAILED=0
SKIPPED=0
failed_names=""
skipped_names=""

for t in "$SCRIPT_DIR"/test_*.sh; do
    name="$(basename "$t")"
    if [ $# -gt 0 ]; then
        wanted=no
        for arg in "$@"; do
            case "$name" in *"$arg"*) wanted=yes ;; esac
        done
        [ "$wanted" = yes ] || continue
    fi

    printf '\n\033[1m=== %s\033[0m\n' "$name"
    case "$name" in
        test_deb_contents.sh) bash "$t" ${DEB:+"$DEB"} ;;
        *)                    bash "$t" ;;
    esac
    rc=$?
    case $rc in
        0)  PASSED=$((PASSED+1)) ;;
        77) SKIPPED=$((SKIPPED+1)); skipped_names="$skipped_names $name" ;;
        *)  FAILED=$((FAILED+1)); failed_names="$failed_names $name" ;;
    esac
done

echo
echo "────────────────────────────────────────────────────────"
printf '%d test file(s) passed, %d failed, %d skipped\n' "$PASSED" "$FAILED" "$SKIPPED"
[ -n "$failed_names" ]  && printf 'failed: %s\n' "$failed_names"
[ -n "$skipped_names" ] && printf 'skipped:%s\n' "$skipped_names"
[ "$FAILED" -eq 0 ]
