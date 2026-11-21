#!/bin/bash
# Qualify the public formula on a fresh hosted runner and exercise the lifecycle after publication.
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
tapdir="$("$brew" --repository true-line/agent-bot-machine)"
recipe="$tapdir/Formula/managed-machine.rb"
source_commit=
if [[ "$#" == 1 && "$1" == --published-formula ]]; then
    [[ "${MM_HQ_TAP_REVISION:-}" =~ ^[0-9a-f]{40}$ ]] || exit 1
    source_commit="$MM_HQ_TAP_REVISION"
    use_published_device_formula "$MM_HQ_DEVICE_VERSION" "$MM_HQ_FORMULA_SHA256" "$work/managed-machine.rb" "$recipe"
elif [[ "$#" != 0 ]]; then
    exit 1
fi
pin="$(python3 "$(dirname "$0")/homebrew-device-pin.py" "$recipe")"
if [[ -n "${MM_HQ_TAP_REVISION:-}" && "$pin" != "${MM_HQ_DEVICE_VERSION:-} ${MM_HQ_DEVICE_SHA256:-}" ]]; then
    echo 'The event revision does not install the selected formula pin' >&2
    exit 1
fi
read -r version digest <<< "$pin"
asset="managed-machine_${version}_darwin_arm64.tar.gz"
fetch_public_device_archive "$version" "$work" "$digest"
unpack_signed_device_release "$work/$asset" "$digest" "$work/unpacked"
qualify_homebrew_device_release "$brew" "$prefix" "$version" "$digest" "$work/unpacked" "$source_commit"
if [[ "$#" == 1 ]]; then
    qualify_published_device_lifecycle "$work/managed-machine.rb" "$version" "$work/unpacked" "$source_commit" "$tapdir"
    cmp "$work/managed-machine.rb" "$recipe" || { echo 'The release formula changed during qualification' >&2; exit 1; }
fi
