#!/usr/bin/env bash
# Run a single acceptance command with a new file Keychain as the checked
# prefix owner's default. For disposable GitHub-hosted macOS runners only.
set -euo pipefail
[[ "$#" -gt 0 && "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "${GITHUB_ACTIONS:-}" == true &&
   "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -sm)" == 'Darwin arm64' &&
   "$(id -u)" != 0 && "$(id -u)" == "$(stat -f %u /opt/homebrew)" ]] || exit 1
umask 077
stage="$(mktemp -d /private/tmp/mm-native-keychain.XXXXXXXX)"
db="$stage/fixture.keychain-db"
trap 'rmdir "$stage"' EXIT
previous="$(/usr/bin/security default-keychain -d user)"
previous="${previous#*\"}"
previous="${previous%\"*}"
[[ "$previous" == /* && "$previous" != "$db" && -f "$previous" ]] || exit 1
cleanup() {
  local status=$? restored
  trap - EXIT
  if /usr/bin/security default-keychain -d user -s "$previous" >/dev/null 2>&1 &&
     restored="$(/usr/bin/security default-keychain -d user)" &&
     [[ "${restored#*\"}" == "$previous\"" ]]; then
    if { [[ ! -f "$db" ]] || /usr/bin/security delete-keychain "$db" >/dev/null 2>&1; } &&
       rm -rf "$stage"; then
      exit "$status"
    fi
    echo 'Temporary Keychain cleanup failed after restoring the original default' >&2
  else
    echo 'Original default Keychain restoration could not be verified; retaining the temporary Keychain' >&2
  fi
  if [[ "$status" == 0 ]]; then status=1; fi
  exit "$status"
}
trap cleanup EXIT
/usr/bin/security create-keychain -p '' "$db" >/dev/null 2>&1
/usr/bin/security unlock-keychain -p '' "$db" >/dev/null 2>&1
/usr/bin/security default-keychain -d user -s "$db" >/dev/null 2>&1
current="$(/usr/bin/security default-keychain -d user)"
[[ "${current#*\"}" == "$db\"" ]] || exit 1
"$@"
