#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
    echo 'skipped native keyd host-report guard outside macOS'
    exit 0
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
stage="$(mktemp -d "${TMPDIR:-/tmp}/keyd-host-report-guard.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT

/usr/bin/xcrun swiftc -parse-as-library \
    "$root/keyd/native/DeviceEnclave.swift" \
    "$root/tests/fixtures/keyd-host-report-guard.swift" \
    -o "$stage/guard-test"
"$stage/guard-test"
