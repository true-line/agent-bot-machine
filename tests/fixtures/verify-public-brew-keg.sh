# Check the installed executables from the two normal paths against one release.
verify_public_brew_keg() (
  set -o pipefail
  local prefix="$1" cellar="$2" version="$3" helper_pin="$4" archive="$5" uid="$6"
  local executable keg actual
  [[ -n "$helper_pin" ]] || return 1
  for executable in managed-machine agent-bot-keyd; do
    keg="$cellar/managed-machine/$version/bin/$executable"
    [[ -f "$keg" && "$prefix/bin/$executable" -ef "$keg" &&
       "$prefix/opt/managed-machine/bin/$executable" -ef "$keg" ]] || return 1
    tar -xzOf "$archive" "$executable" | cmp -s - "$keg" || return 1
  done
  [[ "$(stat -f '%u:%Lp' "$cellar/managed-machine/$version/bin/agent-bot-keyd")" == "$uid:700" ]] || return 1
  for executable in "$prefix/bin/managed-machine" "$prefix/opt/managed-machine/bin/managed-machine"; do
    actual="$("$executable" --version)" || return 1
    [[ "$actual" == "$version" ]] || return 1
  done
  actual="$("$prefix/bin/agent-bot-keyd" --version)" || return 1
  [[ "$actual" == "agent-bot-keyd $helper_pin" ]] || return 1
)
