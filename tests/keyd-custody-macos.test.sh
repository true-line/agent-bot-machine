#!/usr/bin/env bash
# Exercise the Rust entry point as two macOS UIDs, on a disposable hosted runner.
set -euo pipefail

[[ "${MM_KEYD_CUSTODY_TEST:-}" == 1 ]] || exit 0
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "$(uname -sm)" == 'Darwin arm64' && "$(id -u)" != 0 && "$(id -u)" == "$(stat -f %u /opt/homebrew)" ]] || exit 1
root="$(cd "$(dirname "$0")/.." && pwd)"
temp="$(mktemp -d /private/tmp/mm-custody.XXXXXXXX)"
trap 'rm -rf "$temp"' EXIT
chmod 0755 "$temp"
helper="$temp/agent-bot-keyd"
case "${1:-enrollment}" in
enrollment)
    whoami_test=0
    [[ "$#" == 0 ]] || exit 1
    (cd "$root/keyd" && cargo build --release --locked)
    install -m 0700 "$root/keyd/target/release/agent-bot-keyd" "$helper"
    ;;
--whoami)
    whoami_test=1
    [[ "$#" == 1 ]] || exit 1
    mkdir -m 0700 "$temp/issuer"
    node "$root/tests/fixtures/hosted-whoami.mjs" create-issuer "$temp/issuer"
    bash "$root/tests/fixtures/build-native-whoami-keyd.sh" "$temp/whoami-build" "$temp/issuer/server-keys.json"
    install -m 0700 "$temp/whoami-build/target/release/agent-bot-keyd" "$helper"
    install -m 0644 "$root/tests/fixtures/hosted-whoami.mjs" "$temp/hosted-whoami.mjs"
    ;;
*) exit 1 ;;
esac
owner="$(stat -f %Su /opt/homebrew)"
sudo -n chown "$owner" "$helper"
sudo -n -u "$owner" "$helper" --version | grep -E '^agent-bot-keyd [0-9]+\.[0-9]+\.[0-9]+$'

# Nobody is a real unprivileged UID. First check installed-file access. Then
# make this disposable copy executable as if the account extracted the archive.
if sudo -n -u nobody test -r "$helper" || sudo -n -u nobody test -x "$helper"; then
    echo "another UID can read or execute the installed custody helper" >&2
    exit 1
fi
sudo -n chmod 0755 "$helper"
refused() {
    local caller="$1" rc
    shift
    if sudo -n -u "$caller" "$helper" "$@" >"$temp/denied-out" 2>"$temp/denied-err"; then
        echo "custody helper accepted a foreign UID" >&2
        exit 1
    else
        rc=$?
    fi
    [[ "$rc" == 1 && ! -s "$temp/denied-out" ]]
    [[ "$(cat "$temp/denied-err")" == 'agent-bot-keyd: custody requires the nonroot administrator who owns the Homebrew prefix' ]]
}
refused nobody --version
refused nobody serve --state-dir "$temp/state"
refused nobody presence-key --keychain "$temp/absent.keychain-db"
refused nobody mcp --state-dir "$temp/state"
refused root --version
[[ ! -e "$temp/state" && ! -e "$temp/absent.keychain-db" ]]

refused nobody hq-device-init
refused nobody hq-device
refused root hq-device-init
refused root hq-device

# A missing hardware capability is a distinct failed native gate. This
# probe only queries availability; the real key and proof are made by keyd.
if ! /usr/bin/xcrun swift -e 'import CryptoKit; import Darwin; exit(SecureEnclave.isAvailable ? 0 : 1)' >/dev/null 2>&1; then
    echo 'FAIL hosted Secure Enclave unavailable' >&2
    exit 1
fi
echo 'Hosted Secure Enclave available'
[[ "$(id -u)" == "$(stat -f %u /opt/homebrew)" ]]
role=_agent-bot-hq
if dscl . -read "/Users/$role" >/dev/null 2>&1; then
    echo 'FAIL disposable HQ account already exists' >&2; exit 1
fi
role_uid=590
while dscl . -list /Users UniqueID | awk -v u="$role_uid" '$2 == u { found=1 } END { exit !found }'; do
    role_uid=$((role_uid + 1))
    [[ "$role_uid" -lt 700 ]]
done
sudo -n dscl . -create "/Users/$role"
trap 'sudo -n dscl . -delete "/Users/$role" >/dev/null; sudo -n rm -rf "$temp/role-home"; rm -rf "$temp"' EXIT
sudo -n dscl . -create "/Users/$role" UniqueID "$role_uid"
sudo -n dscl . -create "/Users/$role" PrimaryGroupID 20
sudo -n dscl . -create "/Users/$role" UserShell /usr/bin/false
sudo -n install -d -m 0700 -o "$role_uid" -g 20 "$temp/role-home"
sudo -n dscl . -create "/Users/$role" NFSHomeDirectory "$temp/role-home"
sudo -n dscl . -create "/Users/$role" IsHidden 1
[[ "$(id -u "$role")" == "$role_uid" ]]
refused "$role" hq-device-init
refused "$role" hq-device
sudo -n chmod 0700 "$helper"

# The prefix owner negotiates on the release binary's actual same-UID MCP
# socket. The handshake requires no enrollment, keys or credential operations.
python3 - "$helper" "$temp" <<'PY'
import json
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

helper, stage = sys.argv[1:]
version = subprocess.check_output([helper, "--version"], text=True).strip().split()[-1]
with TemporaryDirectory(dir=stage) as state:
    endpoint = Path(state, "keyd", "keyd.sock")
    keychain = Path(state, "unused.keychain-db")
    process = subprocess.Popen([helper, "serve", "--state-dir", state, "--keychain", keychain])
    try:
        deadline = time.monotonic() + 10
        # keyd binds the MCP listener before its owner listener.
        while not endpoint.with_name("owner.sock").is_socket():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("staged keyd did not publish its MCP socket")
            time.sleep(0.05)
        for requested, expected in [("2025-03-26", "2025-03-26"), ("2025-06-18", "2025-06-18"),
                                    ("2099-01-01", "2025-06-18"), (None, "2025-06-18")]:
            params = {"capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}
            if requested is not None:
                params["protocolVersion"] = requested
            message = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params}
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(5)
                client.connect(str(endpoint))
                client.sendall(json.dumps(message).encode() + b"\n")
                with client.makefile("rb") as replies:
                    reply = json.loads(replies.readline(8192))
            assert reply["jsonrpc"] == "2.0" and reply["id"] == 1 and "error" not in reply
            assert reply["result"]["protocolVersion"] == expected, requested
            assert reply["result"]["serverInfo"] == {"name": "agent-bot-keyd", "version": version}
        assert not keychain.exists()
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
print("Release keyd negotiated supported, unknown and omitted MCP revisions over its socket.")
PY
# The production launcher still requires the Team's Developer ID signature.
# PRs exercise the same signed request gate and native helper via a Go test
# binary. A published signed pair is exercised separately on dispatch.
(cd "$root" && go test -c -o "$temp/machine-test" ./internal/daemon && go build -o "$temp/managed-machine" ./cmd/managed-machine)
install -m 0755 "$(command -v node)" "$temp/node"
install -m 0644 "$root/tests/fixtures/paired-darwin-hq-device.mjs" "$temp/role-check.mjs"
MM_NATIVE_WHOAMI_TEST="$whoami_test" bash "$root/tests/fixtures/with-keyd-test-keychain.sh" node "$root/tests/fixtures/keyd-device-native.mjs" "$helper" "$role_uid"
