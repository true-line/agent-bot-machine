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
role=_agent-bot-hq
role_home=/private/var/agent-bot-hq
channel=/opt/homebrew/var/agent-machine
if dscl . -read "/Users/$role" >/dev/null 2>&1 || dscl . -read "/Groups/$role" >/dev/null 2>&1 ||
    [[ -e "$role_home" || -L "$role_home" || -e "$channel" || -L "$channel" ]]; then
    echo 'FAIL dedicated role, home or Machine channel already exists'; exit 1
fi
# Use the production dedicated-account layout. Allocate an unused UID/GID
# pair on this host, independently of the prefix administrator.
users="$(dscl . -list /Users UniqueID)"
groups="$(dscl . -list /Groups PrimaryGroupID)"
for candidate in {300..399}; do
    if ! awk -v n="$candidate" '$NF == n { taken=1 } END { exit !taken }' <<<"$users
$groups"; then role_uid="$candidate"; break; fi
done
: "${role_uid:?no free macOS service UID/GID}"
mkdir -m 0755 "$channel"
made_group=false; made_role=false; made_home=false
cleanup_role() {
    "$made_role" && sudo -n dscl . -delete "/Users/$role"
    "$made_group" && sudo -n dscl . -delete "/Groups/$role"
    "$made_home" && sudo -n rm -rf "$role_home"
    rmdir "$channel"
    rm -rf "$temp"
}
trap cleanup_role EXIT
sudo -n dscl . -create "/Groups/$role"
made_group=true
sudo -n dscl . -create "/Groups/$role" PrimaryGroupID "$role_uid"
sudo -n dscl . -create "/Users/$role"
made_role=true
sudo -n dscl . -create "/Users/$role" UniqueID "$role_uid"
sudo -n dscl . -create "/Users/$role" PrimaryGroupID "$role_uid"
sudo -n dscl . -create "/Users/$role" UserShell /usr/bin/false
sudo -n mkdir -m 0700 "$role_home"
made_home=true
sudo -n chown "$role_uid:$role_uid" "$role_home"
sudo -n dscl . -create "/Users/$role" NFSHomeDirectory "$role_home"
sudo -n dscl . -create "/Users/$role" IsHidden 1
[[ "$(id -u "$role")" == "$role_uid" && "$(id -g "$role")" == "$role_uid" ]]
refused "$role" hq-device-init
refused "$role" hq-device
sudo -n chmod 0700 "$helper"
# The production launcher still requires the Team's Developer ID signature.
# PRs exercise the same signed request gate and native helper via a Go test
# binary. A published signed pair is exercised separately on dispatch.
(cd "$root" && go test -c -o "$temp/machine-test" ./internal/daemon && go build -o "$temp/managed-machine" ./cmd/managed-machine)
command -v gtar >/dev/null || HOMEBREW_NO_AUTO_UPDATE=1 brew install gnu-tar
mkdir -m 0700 "$temp/artifact"
bash "$root/tests/fixtures/prepare-real-darwin-hq.sh" "$temp/artifact" --paired-device
install -m 0755 "$temp/artifact/bin/node" "$temp/node"
tar --no-same-owner -xf "$temp/artifact/approved.tar" -C "$temp"
install -m 0644 "$root/tests/fixtures/packaged-darwin-hq-device.mjs" "$temp/packaged-device.mjs"
install -m 0644 "$root/tests/fixtures/paired-darwin-hq-device.mjs" "$temp/role-check.mjs"
bash "$root/tests/fixtures/with-keyd-test-keychain.sh" node "$root/tests/fixtures/keyd-device-native.mjs" "$helper" "$role_uid"
