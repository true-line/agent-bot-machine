#!/bin/bash
# Exercise the public binaries using the nonroot Homebrew owner on a fresh hosted VM.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${GITHUB_REPOSITORY:-}" == true-line/agent-bot-machine &&
   "$(uname -s)" == Darwin && "$(uname -m)" == arm64 && "$(sw_vers -productVersion)" == 27.* ]] || {
  echo 'Requires the disposable hosted macOS 27 arm64 runner.' >&2; exit 1;
}

# Brew, Git and platform tools can print host paths or certificate details. Emit
# only fixed phase results. No subprocess output is uploaded, even on failure.
exec 3>&1 >/dev/null 2>&1
phase='runner preflight'
services_started=false
finish() {
  status=$?
  if [[ "$services_started" == true ]]; then "$machine" daemon stop || true; fi
  if ((status != 0)); then echo "FAIL: $phase" >&3; fi
}
trap finish EXIT
brew=/opt/homebrew/bin/brew
prefix="$("$brew" --prefix)"
cellar="$("$brew" --cellar)"
uid="$(id -u)"
[[ "$prefix" == /opt/homebrew && "$cellar" == "$prefix/Cellar" &&
   "$uid" != 0 && "$(stat -f %u "$prefix")" == "$uid" ]]
tap=mm-gate/public-upgrade
formula="$tap/managed-machine"
tapdir="$("$brew" --repository "$tap")"
for path in "$tapdir" "$cellar/managed-machine" "$prefix/opt/managed-machine" "$prefix/bin/managed-machine" "$prefix/bin/agent-bot-keyd"; do
  [[ ! -e "$path" && ! -L "$path" ]]
done

machine="$prefix/opt/managed-machine/bin/managed-machine"
channel="$prefix/var/agent-machine"
labels=(dev.qwts.agent-machine dev.qwts.agent-bot.keyd)
for path in "$channel" "$HOME/.config/agent-machine" "$HOME/.local/state/agent-bot/keyd"; do
  [[ ! -e "$path" && ! -L "$path" ]]
done
for label in "${labels[@]}"; do
  path="$HOME/Library/LaunchAgents/$label.plist"
  [[ ! -e "$path" && ! -L "$path" ]]
  for domain in gui user; do
    if /bin/launchctl print "$domain/$uid/$label"; then exit 1; fi
  done
done

work="$(mktemp -d /private/tmp/mm-brew-upgrade.XXXXXXXX)"
export HOMEBREW_CACHE="$work/cache" HOMEBREW_LOGS="$work/logs" HOMEBREW_TEMP="$work/tmp"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 HOMEBREW_NO_AUTOREMOVE=1
unset GH_TOKEN GITHUB_TOKEN HOMEBREW_GITHUB_API_TOKEN
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0=
mkdir -p "$HOMEBREW_CACHE" "$HOMEBREW_LOGS" "$HOMEBREW_TEMP"

phase='public release pin history'
recipe=Formula/managed-machine.rb
version_of() { sed -nE 's/^  version "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' "$1"; }
git show "HEAD:$recipe" > "$work/current.rb"
current="$(version_of "$work/current.rb")"
[[ -n "$current" ]]
prior=''
while read -r revision; do
  git show "$revision:$recipe" > "$work/prior.rb"
  prior="$(version_of "$work/prior.rb")"
  if [[ -n "$prior" && "$prior" != "$current" ]]; then break; fi
done < <(git log --first-parent --format=%H HEAD -- "$recipe")
[[ -n "$prior" && "$prior" != "$current" ]]

phase='disposable tap creation'
"$brew" tap-new --no-git "$tap"
if "$brew" commands --quiet | grep -x trust >/dev/null; then "$brew" trust --tap "$tap"; fi
mkdir -p "$tapdir/Formula"

check_release() {
  local version="$1" filename url digest executable helper_pin
  filename="managed-machine_${version}_darwin_arm64.tar.gz"
  url="https://github.com/true-line/agent-bot-machine/releases/download/v$version"
  grep -Fq "tag:   \"v$version\"" "$tapdir/$recipe"
  grep -Fq "url \"$url/$filename\"" "$tapdir/$recipe"
  curl -qfsSL --proto '=https' --proto-redir '=https' --retry 3 "$url/$filename" -o "$work/$filename"
  curl -qfsSL --proto '=https' --proto-redir '=https' --retry 3 "$url/SHA256SUMS" -o "$work/SHA256SUMS"
  digest="$(shasum -a 256 "$work/$filename" | cut -d' ' -f1)"
  grep -Fxq "$digest  $filename" "$work/SHA256SUMS"
  grep -Fq "sha256 \"$digest\"" "$tapdir/$recipe"

  helper_pin="$(git show "v$version:keyd/Cargo.toml" | sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p')"
  [[ -n "$helper_pin" ]]
  for executable in managed-machine agent-bot-keyd; do
    local keg="$cellar/managed-machine/$version/bin/$executable"
    [[ -f "$keg" && "$prefix/bin/$executable" -ef "$keg" && "$prefix/opt/managed-machine/bin/$executable" -ef "$keg" ]]
    tar -xzOf "$work/$filename" "$executable" | cmp -s - "$keg"
  done
  [[ "$(stat -f '%u:%Lp' "$cellar/managed-machine/$version/bin/agent-bot-keyd")" == "$uid:700" ]]
  [[ "$("$prefix/bin/managed-machine" --version)" == "$version" ]]
  [[ "$("$prefix/opt/managed-machine/bin/managed-machine" --version)" == "$version" ]]
  [[ "$("$prefix/bin/agent-bot-keyd" --version)" == "agent-bot-keyd $helper_pin" ]]
}

phase='install previous release'
cp "$work/prior.rb" "$tapdir/$recipe"
"$brew" install --formula "$formula"
check_release "$prior"
echo 'PASS: previous public release installed' >&3

check_services() {
  local version="$1" helper_pin
  helper_pin="$("$prefix/bin/agent-bot-keyd" --version)"
  python3 -I tests/fixtures/public-brew-services-macos.py "$prefix" \
    "$cellar/managed-machine/$version" "${helper_pin#agent-bot-keyd }"
}

phase='install and check previous Machine and keyd LaunchAgents'
services_started=true
"$machine" daemon install
check_services "$prior" > "$work/previous-pids"
[[ -f "$channel/daemon.pub" && ! -L "$channel/daemon.pub" &&
   "$(stat -f '%u:%z' "$channel/daemon.pub")" == "$uid:32" ]]
cp "$channel/daemon.pub" "$work/previous.pub"
echo 'PASS: both previous release LaunchAgents served under the prefix owner' >&3

phase='upgrade installed release'
cp "$work/current.rb" "$tapdir/$recipe"
"$brew" upgrade --formula "$formula"
[[ -d "$cellar/managed-machine/$prior" && -d "$cellar/managed-machine/$current" ]]
phase='clean previous keg and verify current links and bytes'
"$brew" cleanup "$formula"
[[ ! -e "$cellar/managed-machine/$prior" ]]
check_release "$current"
echo 'PASS: upgrade and old-keg cleanup preserved the public release and stable links' >&3

phase='restart installed services after old-keg cleanup'
# Both old processes were left running across the transaction.
while read -r pid; do kill -0 "$pid"; done < "$work/previous-pids"
"$machine" daemon stop
# bootout can return before process exit. A surviving old job is a failure.
for attempt in {1..50}; do
  old_running=false
  while read -r pid; do
    if kill -0 "$pid"; then old_running=true; fi
  done < "$work/previous-pids"
  if [[ "$old_running" == false ]]; then break; fi
  sleep 0.2
done
[[ "$old_running" == false ]]
"$machine" daemon start
phase='verify both current LaunchAgents and preserved Machine identity'
check_services "$current" > /dev/null
[[ -f "$channel/daemon.pub" && ! -L "$channel/daemon.pub" &&
   "$(stat -f '%u:%z' "$channel/daemon.pub")" == "$uid:32" ]]
cmp -s "$work/previous.pub" "$channel/daemon.pub"
echo 'PASS: restarted Machine and keyd used the current keg and preserved the Machine public key' >&3

phase='stop disposable user LaunchAgents'
"$machine" daemon stop
services_started=false
