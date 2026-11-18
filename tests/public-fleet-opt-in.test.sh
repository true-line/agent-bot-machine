#!/usr/bin/env bash
# Exercise the public bootstrap and update entry points with inert installation
# steps. The sibling fixture used to activate fleet setup without selection.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
sandbox="$(mktemp -d)"
trap 'rm -rf "$sandbox"' EXIT
fixture="$sandbox/machine/legacy"
mkdir -p "$fixture/scripts" "$sandbox/home" "$sandbox/bin" "$sandbox/managed-machine-config"
git init --quiet "$sandbox/managed-machine-config"
cp -R "$root/legacy/lib" "$fixture/lib"
cp "$root/legacy/scripts/"{bootstrap,update} "$fixture/scripts/"
for tool in git gh curl brew; do
    cat >"$sandbox/bin/$tool" <<'STUB'
#!/bin/sh
if [ "$(basename "$0")" = brew ] && [ "$*" = 'list --versions managed-machine' ]; then exit 1; fi
echo "unexpected $(basename "$0") $*" >>"$CALLS"
exit 91
STUB
    chmod +x "$sandbox/bin/$tool"
done
for name in hostname zsh brew nvm git-hooks gh bin zsh-functions rust; do
    cat >"$fixture/setup-$name" <<'STUB'
#!/bin/sh
basename "$0" >>"$STEPS"
STUB
    chmod +x "$fixture/setup-$name"
done
cat >"$fixture/../install.sh" <<'STUB'
#!/bin/sh
[ "$#" = 1 ] && [ "$1" = --update ] || exit 90
echo public-update >>"$STEPS"
exit "${UPDATE_RESULT:-0}"
STUB
run() {
    env -i HOME="$sandbox/home" XDG_DATA_HOME="$sandbox/data" \
        PATH="$sandbox/bin:/usr/bin:/bin" CALLS="$sandbox/calls" STEPS="$sandbox/steps" \
        UPDATE_RESULT="${UPDATE_RESULT:-0}" "$@"
}

run "$fixture/scripts/bootstrap" --non-interactive >"$sandbox/bootstrap.log"
expected="$(printf '%s\n' setup-brew setup-nvm setup-git-hooks setup-rust)"
[[ "$(cat "$sandbox/steps")" == "$expected" ]]
grep -qx $'skipped\tmigrations\tno fleet configuration selected' "$sandbox/home/.config/managed-machine/bootstrap.manifest"
[[ ! -e "$sandbox/data" && ! -e "$sandbox/calls" ]]
: >"$sandbox/steps"
manifest="$sandbox/home/.config/managed-machine/update.manifest"
if UPDATE_RESULT=42 run "$fixture/scripts/update" >"$sandbox/fail.log"; then exit 1; else [[ $? == 42 ]]; fi
[[ ! -e "$manifest" ]]
run "$fixture/scripts/update" >"$sandbox/update.log"
[[ "$(cat "$sandbox/steps")" == "$(printf '%s\n' public-update public-update)" ]]
grep -qx $'skipped\tfleet-setup\tno fleet configuration selected' "$manifest"
[[ ! -e "$sandbox/data" && ! -e "$sandbox/calls" ]]

# A clean roster lookup must stay local even when a gh binary is available.
if run "$root/legacy/scripts/add-agent" --all >"$sandbox/roster.log" 2>&1; then exit 1; fi
grep -q 'no roster source found' "$sandbox/roster.log"
[[ ! -e "$sandbox/calls" ]]

# A config pin alone must never select an unrelated remote on a missing tree.
printf 'v1\n' >"$sandbox/managed-machine-config/local-bin.ref"
if HOME="$sandbox/home" XDG_DATA_HOME="$sandbox/data" CONFIG_REPO_ROOT="$sandbox/managed-machine-config" \
    PATH="/usr/bin:/bin" bash "$root/legacy/setup-bin" >"$sandbox/missing-source" 2>&1; then exit 1; fi
grep -q 'Set LOCAL_BIN_REPO' "$sandbox/missing-source"
[[ ! -e "$sandbox/data" ]]
echo 'public fleet opt-in tests passed'
