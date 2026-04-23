#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## WARNING: DO NOT RUN THIS ON A NON-DISPOSABLE SYSTEM. It intentionally
## deletes important files as part of the test process, and therefore *will*
## damage the system it runs on.

## Dry-run test suite for Whonix firewall scripts.
## Runs each firewall script with --dry-run under various configurations,
## verifies exit codes, and checks the generated nft script for expected
## rules. Does not require a running nftables kernel module.
##
## Usage:
##   sudo ./tests/test_firewall_dry_run.sh [output_dir]
##
## The generated nft scripts are saved to output_dir (default: ./test-output)
## for manual review and diffing against baselines.

set -o errexit
set -o nounset
set -o errtrace
set -o pipefail

if ! [ "${CI:-}" = "true" ]; then
  printf '%s\n' "$0: These tests are only supposed to run on CI." >&2
  exit 1
fi

## ---------------------------------------------------------------------------
## Helpers
## ---------------------------------------------------------------------------

## Timeout wrapper for all privileged commands.
## Prevents hangs from accidentally loading firewall rules that block
## the connection, or from other unexpected blocking operations.
timeout_wrapper=(timeout --kill-after=5 30)

tests_run=0
tests_passed=0
tests_failed=0

pass() {
  tests_passed=$((tests_passed + 1))
  printf '%s\n' "$0: PASS: ${1}"
}

fail() {
  tests_failed=$((tests_failed + 1))
  printf '%s\n' "$0: FAIL: ${1}" >&2
}

assert_file_not_empty() {
  local label
  local file
  label="${1}"
  file="${2}"
  if [ -s "${file}" ]; then
    pass "${label}: nft script non-empty"
  else
    fail "${label}: nft script is empty or missing"
  fi
}

## Check that a pattern exists in the generated nft script.
assert_contains() {
  local label
  local file
  local pattern
  label="${1}"
  file="${2}"
  pattern="${3}"
  if grep --quiet -- "${pattern}" "${file}" 2>/dev/null; then
    pass "${label}: contains '${pattern}'"
  else
    fail "${label}: missing '${pattern}'"
  fi
}

## Check that a pattern does NOT exist in the generated nft script.
assert_not_contains() {
  local label
  local file
  local pattern
  label="${1}"
  file="${2}"
  pattern="${3}"
  if grep --quiet -- "${pattern}" "${file}" 2>/dev/null; then
    fail "${label}: unexpectedly contains '${pattern}'"
  else
    pass "${label}: correctly omits '${pattern}'"
  fi
}

## ---------------------------------------------------------------------------
## Setup
## ---------------------------------------------------------------------------

output_dir="${1:-./test-output}"
mkdir --parents -- "${output_dir}"

nft_script="/var/lib/whonix-firewall/firewall.nft"

## Install files to system paths (required because scripts use absolute paths).
install_files() {
  printf '%s\n' "$0: Installing firewall files to system paths..."
  cp --archive -- usr/bin/whonix_firewall /usr/bin/
  cp --archive -- usr/bin/whonix-gateway-firewall /usr/bin/
  cp --archive -- usr/bin/whonix-workstation-firewall /usr/bin/
  cp --archive -- usr/bin/whonix-host-firewall /usr/bin/
  chmod -- +x /usr/bin/whonix_firewall /usr/bin/whonix-gateway-firewall \
    /usr/bin/whonix-workstation-firewall /usr/bin/whonix-host-firewall

  mkdir --parents -- /usr/libexec/whonix-firewall
  cp --archive -- usr/libexec/whonix-firewall/firewall-common /usr/libexec/whonix-firewall/

  mkdir --parents -- /etc/whonix_firewall.d
  ## Start with no config files to avoid interference.
  safe-rm --force -- /etc/whonix_firewall.d/*.conf

  mkdir --parents -- /var/lib/whonix-firewall
  mkdir --parents -- /run/whonix_firewall
}

create_users() {
  printf '%s\n' "$0: Creating system users..."
  local user_account
  for user_account in clearnet tunnel notunnel systemcheck sdwdate updatesproxycheck; do
    if ! id -- "${user_account}" >/dev/null 2>&1; then
      adduser --home "/run/${user_account}" --no-create-home --quiet --system \
        --group --shell /bin/false "${user_account}" 2>/dev/null || true
    fi
  done
}

cleanup_markers() {
  safe-rm --force -- /usr/share/anon-gw-base-files/gateway
  safe-rm --force -- /usr/share/anon-ws-base-files/workstation
  safe-rm --force -- /usr/share/libvirt-dist/marker
  safe-rm --recursive --force -- /run/sdwdate
  safe-rm --force -- /run/whonix_firewall/first_run_current_boot.status
  safe-rm --force -- /run/whonix_firewall/consecutive_run.status
}

set_gateway_marker() {
  mkdir --parents -- /usr/share/anon-gw-base-files
  touch -- /usr/share/anon-gw-base-files/gateway
}

set_workstation_marker() {
  mkdir --parents -- /usr/share/anon-ws-base-files
  touch -- /usr/share/anon-ws-base-files/workstation
}

set_host_marker() {
  mkdir --parents -- /usr/share/libvirt-dist
  touch -- /usr/share/libvirt-dist/marker
}

set_sdwdate_success() {
  mkdir --parents -- /run/sdwdate
  touch -- /run/sdwdate/first_success
}

write_config() {
  printf '%s\n' "${1}" > /etc/whonix_firewall.d/50_test.conf
}

clear_config() {
  safe-rm --force -- /etc/whonix_firewall.d/50_test.conf
}

save_nft_script() {
  local name
  name="${1}"
  if [ -f "${nft_script}" ]; then
    cp -- "${nft_script}" "${output_dir}/${name}.nft"
  fi
}

## Validate nft script syntax without loading into kernel.
nft_syntax_check() {
  local name
  local check_exit
  name="${1}"
  if [ ! -f "${nft_script}" ]; then
    fail "${name}: nft script not found for syntax check"
    return 0
  fi
  check_exit=0
  "${timeout_wrapper[@]}" nft --check --file "${nft_script}" 2>/dev/null || check_exit=$?
  if [ "${check_exit}" -eq 0 ]; then
    pass "${name}: nft --check passed"
  else
    fail "${name}: nft --check failed (exit ${check_exit})"
  fi
}

## ---------------------------------------------------------------------------
## Test runner
## ---------------------------------------------------------------------------

run_test() {
  local name
  local cmd
  local cmd_exit
  name="${1}"
  cmd="${2}"
  tests_run=$((tests_run + 1))
  printf '\n%s\n' "$0: --- Test: ${name} ---"
  safe-rm --force -- "${nft_script}"
  safe-rm --force -- /run/whonix_firewall/first_run_current_boot.status
  safe-rm --force -- /run/whonix_firewall/consecutive_run.status
  cmd_exit=0
  "${timeout_wrapper[@]}" bash -c "${cmd}" >/dev/null 2>&1 || cmd_exit=$?
  if [ "${cmd_exit}" -eq 0 ]; then
    pass "${name}: exit 0"
  else
    fail "${name}: exited ${cmd_exit}"
  fi
  save_nft_script "${name}"
  nft_syntax_check "${name}"
}

## ---------------------------------------------------------------------------
## Test cases
## ---------------------------------------------------------------------------

test_gateway_default() {
  cleanup_markers
  set_gateway_marker
  write_config "firewall_mode=full"

  run_test "gateway-default" "whonix-gateway-firewall --dry-run"
  local f
  f="${output_dir}/gateway-default.nft"
  assert_file_not_empty "gateway-default" "${f}"
  assert_contains "gateway-default" "${f}" "add table inet filter"
  assert_contains "gateway-default" "${f}" "add table inet nat"
  assert_contains "gateway-default" "${f}" "policy drop"
  assert_contains "gateway-default" "${f}" "iifname lo counter accept"
  assert_contains "gateway-default" "${f}" "oifname lo counter accept"
  assert_contains "gateway-default" "${f}" "ct state established counter accept"
  assert_contains "gateway-default" "${f}" "counter reject"
  ## Transparent proxy rules (full mode).
  assert_contains "gateway-default" "${f}" "redirect to :9040"
  assert_contains "gateway-default" "${f}" "redirect to :5300"
  ## SOCKS ports input rules.
  assert_contains "gateway-default" "${f}" "tcp dport 9050 counter accept"
  assert_contains "gateway-default" "${f}" "tcp dport 9150 counter accept"
  ## ICMPv6 ND.
  assert_contains "gateway-default" "${f}" "nd-neighbor-solicit"
}

test_gateway_vpn() {
  cleanup_markers
  set_gateway_marker
  write_config "firewall_mode=full
VPN_FIREWALL=1"

  run_test "gateway-vpn" "whonix-gateway-firewall --dry-run"
  local f
  f="${output_dir}/gateway-vpn.nft"
  assert_file_not_empty "gateway-vpn" "${f}"
  assert_contains "gateway-vpn" "${f}" "oifname tun0 counter accept"
}

test_gateway_timesync() {
  cleanup_markers
  set_gateway_marker
  safe-rm --recursive --force -- /run/sdwdate
  write_config "firewall_mode=timesync-fail-closed"

  run_test "gateway-timesync" "whonix-gateway-firewall --dry-run"
  local f
  f="${output_dir}/gateway-timesync.nft"
  assert_file_not_empty "gateway-timesync" "${f}"
  ## In timesync-fail-closed, SOCKS ports should be rejected (except 9108).
  assert_contains "gateway-timesync" "${f}" "tcp dport 9050 counter reject"
  assert_not_contains "gateway-timesync" "${f}" "tcp dport 9108 counter reject"
  ## Transparent proxy rules should NOT be present (skipped in timesync-fail-closed).
  assert_not_contains "gateway-timesync" "${f}" "redirect to :9040"
}

test_gateway_timesync_sdwdate_success() {
  cleanup_markers
  set_gateway_marker
  set_sdwdate_success
  write_config "firewall_mode=timesync-fail-closed"

  run_test "gateway-timesync-sdwdate-ok" "whonix-gateway-firewall --dry-run"
  local f
  f="${output_dir}/gateway-timesync-sdwdate-ok.nft"
  assert_file_not_empty "gateway-timesync-sdwdate-ok" "${f}"
  ## After sdwdate success, should be in full mode.
  assert_contains "gateway-timesync-sdwdate-ok" "${f}" "redirect to :9040"
  assert_not_contains "gateway-timesync-sdwdate-ok" "${f}" "tcp dport 9050 counter reject"
}

test_gateway_socksified_disabled() {
  cleanup_markers
  set_gateway_marker
  write_config "firewall_mode=full
WORKSTATION_ALLOW_SOCKSIFIED=0"

  run_test "gateway-no-socks" "whonix-gateway-firewall --dry-run"
  local f
  f="${output_dir}/gateway-no-socks.nft"
  assert_file_not_empty "gateway-no-socks" "${f}"
  ## Should still have basic rules (loopback, established).
  assert_contains "gateway-no-socks" "${f}" "oifname lo counter accept"
  ## Transparent proxy should still work.
  assert_contains "gateway-no-socks" "${f}" "redirect to :9040"
}

test_workstation_default() {
  cleanup_markers
  set_workstation_marker
  write_config "firewall_mode=full"

  run_test "workstation-default" "whonix-workstation-firewall --dry-run"
  local f
  f="${output_dir}/workstation-default.nft"
  assert_file_not_empty "workstation-default" "${f}"
  assert_contains "workstation-default" "${f}" "add table inet filter"
  assert_contains "workstation-default" "${f}" "policy drop"
  assert_contains "workstation-default" "${f}" "oifname lo counter accept"
  assert_contains "workstation-default" "${f}" "ct state established counter accept"
  ## DNS to gateway.
  assert_contains "workstation-default" "${f}" "udp dport 53 counter accept"
  ## Non-TCP reject (IPv4).
  assert_contains "workstation-default" "${f}" "ip protocol != tcp counter reject"
  ## Accept all in full mode.
  assert_contains "workstation-default" "${f}" "counter accept"
  ## Final reject.
  assert_contains "workstation-default" "${f}" "counter reject"
}

test_workstation_tunnel() {
  cleanup_markers
  set_workstation_marker
  write_config "firewall_mode=full
TUNNEL_FIREWALL_ENABLE=true"

  run_test "workstation-tunnel" "whonix-workstation-firewall --dry-run"
  local f
  f="${output_dir}/workstation-tunnel.nft"
  assert_file_not_empty "workstation-tunnel" "${f}"
  assert_contains "workstation-tunnel" "${f}" "oifname tun0 counter accept"
  ## Final reject should be present even in tunnel mode.
  assert_contains "workstation-tunnel" "${f}" "counter reject"
}

test_workstation_timesync() {
  cleanup_markers
  set_workstation_marker
  safe-rm --recursive --force -- /run/sdwdate
  write_config "firewall_mode=timesync-fail-closed"

  run_test "workstation-timesync" "whonix-workstation-firewall --dry-run"
  local f
  f="${output_dir}/workstation-timesync.nft"
  assert_file_not_empty "workstation-timesync" "${f}"
  ## SOCKS ports rejected (except 9108).
  assert_contains "workstation-timesync" "${f}" "tcp dport 9050 counter reject"
  assert_not_contains "workstation-timesync" "${f}" "tcp dport 9108 counter reject"
  ## DNS should NOT be allowed.
  assert_not_contains "workstation-timesync" "${f}" "udp dport 53 counter accept"
}

test_workstation_outgoing_ip_list() {
  cleanup_markers
  set_workstation_marker
  write_config 'firewall_mode=full
outgoing_allow_ip_list="198.51.100.1 203.0.113.5"'

  run_test "workstation-ip-list" "whonix-workstation-firewall --dry-run"
  local f
  f="${output_dir}/workstation-ip-list.nft"
  assert_file_not_empty "workstation-ip-list" "${f}"
  assert_contains "workstation-ip-list" "${f}" "ip daddr 198.51.100.1 counter accept"
  assert_contains "workstation-ip-list" "${f}" "ip daddr 203.0.113.5 counter accept"
}

test_host_default() {
  cleanup_markers
  set_host_marker
  write_config "firewall_mode=full"

  run_test "host-default" "whonix-host-firewall --dry-run"
  local f
  f="${output_dir}/host-default.nft"
  assert_file_not_empty "host-default" "${f}"
  assert_contains "host-default" "${f}" "add table inet filter"
  assert_contains "host-default" "${f}" "policy drop"
  assert_contains "host-default" "${f}" "oifname lo counter accept"
  assert_contains "host-default" "${f}" "nd-neighbor-solicit"
  assert_contains "host-default" "${f}" "counter reject"
}

test_host_vpn() {
  cleanup_markers
  set_host_marker
  write_config "firewall_mode=full
VPN_FIREWALL=1"

  run_test "host-vpn" "whonix-host-firewall --dry-run"
  local f
  f="${output_dir}/host-vpn.nft"
  assert_file_not_empty "host-vpn" "${f}"
  assert_contains "host-vpn" "${f}" "oifname tun0 counter accept"
}

test_cli_mode_full() {
  cleanup_markers
  set_gateway_marker
  safe-rm --recursive --force -- /run/sdwdate
  write_config "firewall_mode=timesync-fail-closed"

  ## --mode full should override config.
  run_test "cli-mode-full" "whonix-gateway-firewall --dry-run --mode full"
  local f
  f="${output_dir}/cli-mode-full.nft"
  assert_file_not_empty "cli-mode-full" "${f}"
  ## Should be in full mode despite config saying timesync-fail-closed.
  assert_contains "cli-mode-full" "${f}" "redirect to :9040"
  assert_not_contains "cli-mode-full" "${f}" "tcp dport 9050 counter reject"
}

test_cli_mode_timesync() {
  cleanup_markers
  set_gateway_marker
  safe-rm --recursive --force -- /run/sdwdate
  write_config "firewall_mode=full"

  ## --mode timesync-fail-closed should override config.
  run_test "cli-mode-timesync" "whonix-gateway-firewall --dry-run --mode timesync-fail-closed"
  local f
  f="${output_dir}/cli-mode-timesync.nft"
  assert_file_not_empty "cli-mode-timesync" "${f}"
  ## Should be in timesync-fail-closed despite config saying full.
  assert_contains "cli-mode-timesync" "${f}" "tcp dport 9050 counter reject"
  assert_not_contains "cli-mode-timesync" "${f}" "redirect to :9040"
}

## ---------------------------------------------------------------------------
## Main
## ---------------------------------------------------------------------------

printf '%s\n' "$0: ============================================="
printf '%s\n' "$0: Whonix Firewall Dry-Run Test Suite"
printf '%s\n' "$0: ============================================="

install_files
create_users

test_gateway_default
test_gateway_vpn
test_gateway_timesync
test_gateway_timesync_sdwdate_success
test_gateway_socksified_disabled
test_workstation_default
test_workstation_tunnel
test_workstation_timesync
test_workstation_outgoing_ip_list
test_host_default
test_host_vpn
test_cli_mode_full
test_cli_mode_timesync

cleanup_markers
clear_config

printf '\n%s\n' "$0: ============================================="
printf '%s\n' "$0: Results: ${tests_passed} passed, ${tests_failed} failed (${tests_run} tests)"
printf '%s\n' "$0: Generated nft scripts saved to: ${output_dir}/"
printf '%s\n' "$0: ============================================="

if [ "${tests_failed}" -gt 0 ]; then
  exit 1
fi
