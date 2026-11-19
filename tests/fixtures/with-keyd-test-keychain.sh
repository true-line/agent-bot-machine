#!/usr/bin/env bash
# Run a single acceptance command with a new file Keychain as the checked
# prefix owner's default. For disposable GitHub-hosted macOS runners only.
set -euo pipefail
[[ "$#" -gt 0 && "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "${GITHUB_ACTIONS:-}" == true &&
   "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -sm)" == 'Darwin arm64' &&
   "$(id -u)" != 0 && "$(id -u)" == "$(stat -f %u /opt/homebrew)" ]]
umask 077
stage="$(mktemp -d /private/tmp/mm-native-keychain.XXXXXXXX)"
db="$stage/fixture.keychain-db"
previous="$(/usr/bin/security default-keychain -d user)"
previous="${previous#*\"}"
previous="${previous%\"*}"
[[ "$previous" == /* && "$previous" != "$db" && -f "$previous" ]]
cleanup() {
  /usr/bin/security default-keychain -d user -s "$previous" >/dev/null 2>&1
  if [[ -f "$db" ]]; then /usr/bin/security delete-keychain "$db" >/dev/null 2>&1; fi
  rm -rf "$stage"
}
trap cleanup EXIT
/usr/bin/security create-keychain -p '' "$db" >/dev/null 2>&1
/usr/bin/security unlock-keychain -p '' "$db" >/dev/null 2>&1
/usr/bin/security default-keychain -d user -s "$db" >/dev/null 2>&1
current="$(/usr/bin/security default-keychain -d user)"
[[ "${current#*\"}" == "$db\"" ]]
"$@"
