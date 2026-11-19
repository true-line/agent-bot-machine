#!/usr/bin/env bash
# Build a disposable software provider for cross-repo protocol tests. No test
# file, fake key, issuer override, or compiler flag is added to release keyd.
set -euo pipefail
if [[ "$#" != 2 || ! -f "$1" || -e "$2" || -L "$2" ]]; then
    echo 'usage: build-keyd-device-interop.sh SYNTHETIC_PUBLIC_MANIFEST NEW_EXECUTABLE' >&2
    exit 2
fi
umask 077
root="$(cd "$(dirname "$0")/../.." && pwd)"
issuer="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
destination="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT
mkdir "$build/src" "$build/trusted"
cp "$root/keyd/Cargo.toml" "$root/keyd/Cargo.lock" "$root/keyd/rust-toolchain.toml" "$build/"
cp "$root/keyd/src/hq_device.rs" "$build/src/"
cp "$root"/tests/fixtures/keyd-device-interop/{main.rs,software.mjs} "$build/src/"
cp "$issuer" "$build/trusted/server-keys.json"
node_bin="$(node -p 'process.execPath')"
[[ "$node_bin" == /* && -x "$node_bin" ]]
(
    cd "$build"
    KEYD_FIXTURE_NODE="$node_bin" CARGO_TARGET_DIR="$build/target" cargo build --locked --quiet
)
# Never replace a previously built executable. Copy next to the destination so
# the final link is atomic even if the temporary Cargo tree is on another disk.
out="$(mktemp "$(dirname "$destination")/.keyd-fixture.XXXXXXXX")"
trap 'rm -rf "$build"; rm -f "$out"' EXIT
install -m 0700 "$build/target/debug/agent-bot-keyd" "$out"
ln "$out" "$destination"
