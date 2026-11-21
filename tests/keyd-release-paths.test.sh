#!/usr/bin/env bash
# Build the release helper twice with different source, dependency and output paths.
set -euo pipefail
[[ $# == 1 ]] || { echo "usage: tests/keyd-release-paths.test.sh <destination>" >&2; exit 2; }
root="$(cd "$(dirname "$0")/.." && pwd)"
scratch="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/keyd-path-test.XXXXXXXX")"
trap 'rm -rf "$scratch"' EXIT
source_copy="$scratch/second checkout"
cache="${CARGO_HOME:-$HOME/.cargo}/registry"
mkdir -p "$source_copy" "$scratch/second cache/registry" "$scratch/second target"

# Build from the working tree so local changes and the checked-out CI revision
# are tested alike. Copy only the tracked build inputs, excluding Cargo output.
git -C "$root" ls-files -z -- keyd scripts/build-darwin-keyd |
    tar -C "$root" -cf - --null -T - | tar -C "$source_copy" -xf -

CARGO_TARGET_DIR="$scratch/alternate-target" "$root/scripts/build-darwin-keyd" "$scratch/first"
# Reuse Cargo's downloaded archives and index. A separate registry/src forces
# rustc to compile dependencies from different absolute filenames.
ln -s "$(cd "$cache/index" && pwd -P)" "$scratch/second cache/registry/index"
ln -s "$(cd "$cache/cache" && pwd -P)" "$scratch/second cache/registry/cache"
CARGO_HOME="$scratch/second cache" CARGO_NET_OFFLINE=true RUNNER_TEMP="$scratch/second target" \
    "$source_copy/scripts/build-darwin-keyd" "$scratch/second"
cmp -s "$scratch/first" "$scratch/second" || {
    echo "release keyd bytes differ across build paths" >&2; exit 1;
}
install -m 0700 "$scratch/first" "$1"
