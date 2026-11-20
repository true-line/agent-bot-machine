#!/bin/bash
# A private throwaway copy of this commit's native crate. The production crate,
# issuer manifest and release target are never written by this test build.
set -euo pipefail
[[ "$#" == 2 && "$(uname -sm)" == 'Darwin arm64' ]] || exit 1
build=$1
manifest=$2
root="$(cd "$(dirname "$0")/../.." && pwd -P)"
[[ "$build" == /* && "$manifest" == /* && -f "$manifest" && ! -L "$manifest" ]] || exit 1
mkdir -m 0700 "$build" # exclusive, before extracting or creating target
mkdir -m 0700 "$build/source"
git -C "$root" archive HEAD:keyd | tar -xf - -C "$build/source"
install -m 0600 "$manifest" "$build/source/trusted/server-keys.json"
(cd "$build/source" && CARGO_TARGET_DIR="$build/target" cargo build --release --locked)
