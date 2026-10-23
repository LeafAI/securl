#!/bin/sh
# Read-only smoke test of a securl that is already running (the daemon). It runs only commands that read: it closes no session,
# changes no database, submits no ticket, sends no request to a website, changes no configuration and does not start, stop or
# reload anything. It never opens the vault: with the vault locked it says so and stops (securl unlock is the person's step).
#
#   scripts/smoke-readonly.sh [-config FILE] [securl-binary]
#
# Commands that could reach a person or a site are NOT in it: a login (`session open`), `archery ...` (needs a session, and asks
# for one when there is none), `request`, `db query`, `db exec`, `session close`, `unlock`. The test in smoke_test.go fails if one
# is ever added here.
set -u

CONFIG=""
if [ "${1:-}" = "-config" ]; then
	CONFIG="$2"
	shift 2
fi
BIN="${1:-securl}"
if ! command -v "$BIN" >/dev/null 2>&1; then
	echo "smoke: $BIN not found" >&2
	exit 2
fi

fail=0
pass=0
# check NAME EXPECT COMMAND...: runs the command, prints ok/FAIL, and keeps the first line of its answer for the log.
check() {
	name="$1"
	expect="$2"
	shift 2
	out="$("$@" 2>&1)"
	code=$?
	if [ "$code" -eq 0 ] && printf '%s' "$out" | grep -q -- "$expect"; then
		printf 'ok    %s\n' "$name"
		pass=$((pass + 1))
	else
		printf 'FAIL  %s (exit %s, wanted %s)\n' "$name" "$code" "$expect"
		printf '%s\n' "$out" | head -5 | sed 's/^/      /'
		fail=$((fail + 1))
	fi
}

run() { # run SUBCOMMAND...: the binary with the optional -config at the end, as securl takes it anywhere
	if [ -n "$CONFIG" ]; then "$BIN" "$@" -config "$CONFIG"; else "$BIN" "$@"; fi
}

echo "securl smoke test (read-only)"
status="$(run daemon status 2>&1)"
printf '%s\n' "$status" | sed 's/^/  /'
case "$status" in
*"daemon: running"*) ;;
*)
	echo "smoke: no daemon is running; nothing was run" >&2
	exit 3
	;;
esac
case "$status" in
*"vault unlocked"*) ;;
*)
	echo "smoke: the vault is locked. Open it with: securl unlock   (nothing was run)" >&2
	exit 3
	;;
esac

check "vault status reads the files"      "vault:"      run vault status
check "site list names the websites"      '"sites"'     run site list
check "session list shows names, no secret" '"sessions"' run session list
check "db targets lists the targets"      '"targets"'   run db targets
check "version"                           "securl"      "$BIN" version

echo
printf '%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
