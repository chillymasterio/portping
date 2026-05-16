#!/bin/bash
# Basic integration tests for portping
set -e

PORTPING=./portping
PASS=0
FAIL=0

run_test() {
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
        echo "  PASS: $desc"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL: $desc"
    fi
}

echo "Running portping integration tests..."
echo

run_test "Connect to localhost:22" $PORTPING localhost 22 -c 1
run_test "Version flag" $PORTPING --version
run_test "Help flag" $PORTPING --help
run_test "Timeout works" timeout 5 $PORTPING 192.0.2.1 9999 -c 1 -w 2 || true
run_test "Compact mode" $PORTPING localhost 22 -c 3 --compact

echo
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
