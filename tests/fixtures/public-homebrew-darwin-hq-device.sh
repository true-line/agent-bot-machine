#!/bin/bash
# Qualify the public formula on a fresh hosted runner without starting either service.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "$(uname -sm)" == 'Darwin arm64' && "$(id -u)" != 0 &&
   "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
source "$(dirname "$0")/stage-darwin-hq-device.sh"
brew=/opt/homebrew/bin/brew
prefix=/opt/homebrew
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tap_homebrew_device_release "$brew" "$prefix"
recipe="$("$brew" --repository true-line/agent-bot-machine)/Formula/managed-machine.rb"
pin="$(python3 "$(dirname "$0")/homebrew-device-pin.py" "$recipe")"
if [[ -n "${MM_HQ_TAP_REVISION:-}" && "$pin" != "${MM_HQ_DEVICE_VERSION:-} ${MM_HQ_DEVICE_SHA256:-}" ]]; then
    echo 'The event revision does not install the selected formula pin' >&2
    exit 1
fi
read -r version digest <<< "$pin"
asset="managed-machine_${version}_darwin_arm64.tar.gz"
fetch_public_device_archive "$version" "$work" "$digest"
unpack_signed_device_release "$work/$asset" "$digest" "$work/unpacked"
install_homebrew_device_release "$brew" "$version" "$digest"
verify_homebrew_device_install "$prefix" "$version" "$work/unpacked"
echo 'PASS: both Homebrew executables match the signed public release, active keg and installed modes'
