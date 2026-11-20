#!/bin/bash
# Exercise an installed source fixture through its public CLI on a disposable runner.
set -euo pipefail
[[ "$#" == 2 && "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "$(uname -sm)" == 'Darwin arm64' &&
   "$(id -u)" != 0 && "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
version=$1 unpack=$2
prefix=/opt/homebrew
brew=$prefix/bin/brew
mm=$prefix/bin/managed-machine
formula=true-line/agent-bot-machine/managed-machine
channel=$prefix/var/agent-machine
private=$HOME/.config/agent-machine
keyd=$HOME/.local/state/agent-bot/keyd
agents=$HOME/Library/LaunchAgents
endpoints=("$channel/daemon.sock" "$keyd/keyd.sock" "$keyd/owner.sock")
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
absent() { [[ ! -e "$1" && ! -L "$1" ]]; }
units() {
    python3 "$(dirname "$0")/homebrew-launch-agents.py" "$1" "$agents" "$prefix/Cellar/managed-machine/$version" "$work"
}
endpoints_absent() {
    local endpoint
    for endpoint in "${endpoints[@]}"; do absent "$endpoint" || return 1; done
}
services_absent() { endpoints_absent && units absent; }
endpoints_listening() {
    python3 - "${endpoints[@]}" <<'PY'
import socket, sys
for path in sys.argv[1:]:
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(1)
        client.connect(path)
PY
}
signed_and_listening() {
    "$mm" daemon status --json | python3 -c 'import json,sys; sys.exit(json.load(sys.stdin).get("channel") != "signed")' &&
        endpoints_listening
}
terminal_revoked() {
    local marker="$private/peers/terminal.revoked"
    [[ -f "$marker" && ! -L "$marker" ]] && cmp "$work/revoked" "$marker" &&
        absent "$private/client.key" && cmp "$work/terminal.pub" "$private/peers/terminal.pub"
}
wait_for() {
    local i
    for ((i=0;i<100;i++)); do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 0.1; done
    fail "timed out waiting for $1"
}

[[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ && "${HOMEBREW_NO_AUTO_UPDATE:-}" == 1 ]] || exit 1
verify_package() {
    local keg="$prefix/Cellar/managed-machine/$version"
    [[ "$("$mm" --version)" == "$version" ]] &&
        cmp "$unpack/managed-machine" "$keg/bin/managed-machine" &&
        cmp "$unpack/agent-bot-keyd" "$keg/bin/agent-bot-keyd" &&
        cmp "$unpack/RELEASE_COMMIT" "$keg/libexec/RELEASE_COMMIT"
}
verify_package >/dev/null 2>&1 || fail 'installed package identity'
reinstall_package() {
    (umask 022; "$brew" install --formula "$formula") || fail 'reinstalling the same formula'
    verify_package >/dev/null 2>&1 || fail 'reinstalled package identity'
    "$mm" daemon start >/dev/null
}
units before
endpoints_absent && absent "$private" && absent "$keyd" && absent "$channel/daemon.pub" || fail 'expected an unused runner'
"$mm" daemon install --debug >/dev/null
"$mm" daemon pair >/dev/null
wait_for signed_and_listening
units active
# Only the public keys leave the service state. A second pairing would invalidate this test.
cmp "$private/daemon.pub" "$channel/daemon.pub"
for file in "$channel/daemon.pub" "$private/peers/terminal.pub"; do
    [[ -f "$file" && ! -L "$file" && "$(wc -c < "$file")" -eq 32 ]] || fail 'missing public pairing'
    cp "$file" "$work/$(basename "$file")"
done
"$mm" uninstall
wait_for services_absent
for file in "$prefix/Cellar/managed-machine/$version" "$prefix/opt/managed-machine" "$mm" "$prefix/bin/agent-machine" "$prefix/bin/agent-bot-keyd"; do
    absent "$file" || fail 'package files remain after uninstall'
done
"$brew" list --formula --full-name > "$work/formulae"
if grep -Fxq "$formula" "$work/formulae"; then fail 'Homebrew still lists the removed formula'; fi
cmp "$work/daemon.pub" "$channel/daemon.pub"
cmp "$work/terminal.pub" "$private/peers/terminal.pub"
reinstall_package
wait_for signed_and_listening
units active
cmp "$work/daemon.pub" "$channel/daemon.pub"
cmp "$work/terminal.pub" "$private/peers/terminal.pub"
"$mm" daemon unpair --client terminal >/dev/null
printf 'revoked\n' > "$work/revoked"
terminal_revoked || fail 'terminal unpair did not retain its revocation'
"$mm" uninstall
wait_for services_absent
terminal_revoked || fail 'uninstall lost the revoked terminal record'
reinstall_package
wait_for endpoints_listening
units active
cmp "$work/daemon.pub" "$channel/daemon.pub"
"$mm" daemon status --json | python3 -c 'import json,sys; s=json.load(sys.stdin); sys.exit(s.get("state") != "running" or "channel" in s)' ||
    fail 'expected a running daemon with no signed terminal status after reinstall'
terminal_revoked || fail 'reinstall or status restored the revoked terminal'
"$mm" uninstall
wait_for services_absent
echo 'PASS: verified removal of both LaunchAgents and three sockets, active pairing across reinstall, and continued revocation across a second reinstall'
