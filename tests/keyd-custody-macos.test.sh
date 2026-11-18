#!/usr/bin/env bash
# Exercise the Rust entry point as two macOS UIDs, on a disposable hosted runner.
set -euo pipefail

[[ "${MM_KEYD_CUSTODY_TEST:-}" == 1 ]] || exit 0
[[ "$(uname -s)" == Darwin && "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]
root="$(cd "$(dirname "$0")/.." && pwd)"
(cd "$root/keyd" && cargo build --locked)
temp="$(mktemp -d /private/tmp/mm-custody.XXXXXXXX)"
trap 'rm -rf "$temp"' EXIT
chmod 0755 "$temp"
helper="$temp/agent-bot-keyd"
install -m 0700 "$root/keyd/target/debug/agent-bot-keyd" "$helper"
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
    local caller="$1" result
    shift
    if result="$(sudo -n -u "$caller" "$helper" "$@" 2>&1)"; then
        echo "custody helper accepted $caller $1" >&2
        exit 1
    fi
    [[ "$result" == *"custody requires the nonroot administrator who owns the Homebrew prefix"* ]]
}
refused nobody --version
refused nobody serve --state-dir "$temp/state"
refused nobody presence-key --keychain "$temp/absent.keychain-db"
refused nobody mcp --state-dir "$temp/state"
refused root --version
[[ ! -e "$temp/state" && ! -e "$temp/absent.keychain-db" ]]
