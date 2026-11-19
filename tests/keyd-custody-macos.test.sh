#!/usr/bin/env bash
# Exercise the Rust entry point as two macOS UIDs, on a disposable hosted runner.
set -euo pipefail

[[ "${MM_KEYD_CUSTODY_TEST:-}" == 1 ]] || exit 0
[[ "$(uname -s)" == Darwin && "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]
root="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$root/keyd" && cargo build --release --locked)
temp="$(mktemp -d /private/tmp/mm-custody.XXXXXXXX)"
trap 'rm -rf "$temp"' EXIT
chmod 0755 "$temp"
helper="$temp/agent-bot-keyd"
install -m 0700 "$root/keyd/target/release/agent-bot-keyd" "$helper"
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
role=_mm_keyd_ci_hq
if dscl . -read "/Users/$role" >/dev/null 2>&1; then
    echo 'FAIL disposable HQ account already exists' >&2; exit 1
fi
role_uid=590
while dscl . -list /Users UniqueID | awk -v u="$role_uid" '$2 == u { found=1 } END { exit !found }'; do
    role_uid=$((role_uid + 1))
    [[ "$role_uid" -lt 700 ]]
done
sudo -n dscl . -create "/Users/$role"
trap 'sudo -n dscl . -delete "/Users/$role" >/dev/null; rm -rf "$temp"' EXIT
sudo -n dscl . -create "/Users/$role" UniqueID "$role_uid"
sudo -n dscl . -create "/Users/$role" PrimaryGroupID 20
sudo -n dscl . -create "/Users/$role" UserShell /usr/bin/false
sudo -n dscl . -create "/Users/$role" NFSHomeDirectory /var/empty
sudo -n dscl . -create "/Users/$role" IsHidden 1
[[ "$(id -u "$role")" == "$role_uid" ]]
refused "$role" hq-device-init
refused "$role" hq-device
sudo -n chmod 0700 "$helper"
bash "$root/tests/fixtures/with-keyd-test-keychain.sh" node "$root/tests/fixtures/keyd-device-native.mjs" "$helper" "$role_uid"
