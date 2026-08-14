#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Regression test: reloadfirewall must capture a nonzero firewall exit code
## instead of aborting under errexit before the status is read.
##
## The buggy version ran the firewall on one line and read "$?" on the next:
##   sudo /usr/bin/whonix_firewall
##   firewall_status="$?"
## Under `set -o errexit` a failing firewall aborted the script at the first
## line, so the ERROR branch never ran and no diagnostic was shown.
##
## This test stubs a failing firewall on PATH and asserts the ERROR branch is
## still reached. Non-destructive: touches only a temporary PATH stub directory.

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## Run from the repository root regardless of the caller's working directory.
script_dir="$(dirname -- "$(readlink --canonicalize -- "$0")")"
cd -- "${script_dir}/.."

reloadfirewall="usr/libexec/whonix-firewall/reloadfirewall"

tests_failed=0

pass() {
  printf '%s\n' "$0: PASS: ${1}"
}

fail() {
  tests_failed=$((tests_failed + 1))
  printf '%s\n' "$0: FAIL: ${1}" >&2
}

cleanup() {
  safe-rm --recursive --force -- "${stub_dir}"
}

stub_dir="$(mktemp --directory)"
trap cleanup EXIT

## Create an executable PATH stub with a fixed exit code.
make_stub() {
  local name
  local exit_code
  name="${1}"
  exit_code="${2}"
  printf '%s\n' "#!/bin/bash" "exit ${exit_code}" > "${stub_dir}/${name}"
  chmod -- +x "${stub_dir}/${name}"
}

## Neutralize the `cat /etc/motd` read and the trailing `sleep 86400`.
make_stub cat 0
make_stub sleep 0

## Case 1: failing firewall. `sudo` (and therefore the firewall run) exits 7.
make_stub sudo 7
run_exit=0
run_output="$(PATH="${stub_dir}:${PATH}" bash "${reloadfirewall}" 2>&1)" || run_exit="$?"

if [ "${run_exit}" = "7" ]; then
  pass "failing firewall: reloadfirewall exits with the captured code 7"
else
  fail "failing firewall: expected exit 7, got ${run_exit}"
fi

if printf '%s' "${run_output}" \
  | grep --quiet -- "ERROR: Whonix firewall reload failed with exit code '7'"; then
  pass "failing firewall: ERROR branch reached"
else
  fail "failing firewall: ERROR branch not reached (aborted under errexit before capturing status)"
fi

## Case 2: successful firewall. Sanity check the OK path still works.
make_stub sudo 0
run_exit=0
run_output="$(PATH="${stub_dir}:${PATH}" bash "${reloadfirewall}" 2>&1)" || run_exit="$?"

if [ "${run_exit}" = "0" ]; then
  pass "successful firewall: reloadfirewall exits 0"
else
  fail "successful firewall: expected exit 0, got ${run_exit}"
fi

if printf '%s' "${run_output}" \
  | grep --quiet -- "OK: Whonix firewall reload completed successfully."; then
  pass "successful firewall: OK branch reached"
else
  fail "successful firewall: OK branch not reached"
fi

if [ "${tests_failed}" -gt 0 ]; then
  printf '%s\n' "$0: ${tests_failed} test(s) failed" >&2
  exit 1
fi

printf '%s\n' "$0: all reloadfirewall regression tests passed"
