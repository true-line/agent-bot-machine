#!/bin/bash
# Qualify the public formula on a fresh PR runner without starting either service.
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
version="$(sed -nE 's/^  version "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' "$recipe")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
asset="managed-machine_${version}_darwin_arm64.tar.gz"
url="https://github.com/true-line/agent-bot-machine/releases/download/v$version"
download=(curl -qfsSL --proto '=https' --proto-redir '=https' --retry 3)
"${download[@]}" "$url/SHA256SUMS" -o "$work/SHA256SUMS"
digest="$(awk -v asset="$asset" 'NF == 2 && $2 == asset {print $1}' "$work/SHA256SUMS")"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]]
"${download[@]}" "$url/$asset" -o "$work/$asset"
unpack_signed_device_release "$work/$asset" "$digest" "$work/unpacked"
install_homebrew_device_release "$brew" "$version" "$digest"
verify_homebrew_device_install "$prefix" "$version" "$work/unpacked"
echo 'PASS: both Homebrew executables match the signed public release, active keg and installed modes'
