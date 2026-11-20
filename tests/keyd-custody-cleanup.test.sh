#!/usr/bin/env bash
# Exercise only scratch directories and a recording stub for administrative operations.
set -euo pipefail
source "$(dirname "$0")/fixtures/cleanup-darwin-custody.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

for case in failed-test failed-cleanup partial; do
    base="$scratch/$case"
    mkdir -p "$base/home" "$base/channel" "$base/stage"
    role=fixture; role_home="$base/home"; channel="$base/channel"; temp="$base/stage"
    made_role=true; made_group=true; made_home=true
    if [[ "$case" == partial ]]; then made_role=false; made_home=false; fi
    sudo() {
        case "$*" in
            "-n dscl . -delete /Users/fixture") echo user >>"$base/actions"; return 1 ;;
            "-n dscl . -delete /Groups/fixture") echo group >>"$base/actions" ;;
            "-n rm -rf $role_home") echo home >>"$base/actions"; rmdir "$role_home" ;;
            *) return 1 ;;
        esac
    }
    set +e
    (set -e; trap cleanup_role EXIT; if [[ "$case" == failed-test ]]; then exit 23; fi; exit 0)
    status=$?
    set -e
    [[ ! -e "$channel" && ! -e "$temp" ]] || exit 1
    case "$case" in
        failed-test) [[ "$status" == 23 ]] || exit 1 ;;
        failed-cleanup) [[ "$status" == 1 ]] || exit 1 ;;
        partial) [[ "$status" == 0 && -d "$role_home" && "$(cat "$base/actions")" == group ]] || exit 1; continue ;;
    esac
    [[ ! -e "$role_home" && "$(cat "$base/actions")" == "$(printf 'user\ngroup\nhome\n')" ]] || exit 1
done

# Run the actual entry guards with synthetic account facts. Stop before the
# first filesystem or Keychain operation, including if a guard regresses.
root="$(cd "$(dirname "$0")" && pwd)"
for script in "$root/keyd-custody-macos.test.sh" "$root/fixtures/with-keyd-test-keychain.sh"; do
    awk '/^root=|^umask / {found=1; exit} {print} END {if (!found) exit 1}' "$script" >"$scratch/guard"
    echo 'exit 77' >>"$scratch/guard"
    for scenario in disabled self-hosted root foreign hosted; do
        rc=0
        (
            export MM_KEYD_CUSTODY_TEST=1 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted
            uid=501
            case "$scenario" in
                disabled) GITHUB_ACTIONS=false ;;
                self-hosted) RUNNER_ENVIRONMENT=self-hosted ;;
                root) uid=0 ;;
                foreign) uid=502 ;;
            esac
            uname() { echo 'Darwin arm64'; }
            id() { echo "$uid"; }
            stat() { echo 501; }
            set -- fixture
            source "$scratch/guard"
        ) || rc=$?
        expected=1
        if [[ "$scenario" == hosted ]]; then expected=77; fi
        [[ "$rc" == "$expected" ]] || exit 1
    done
done
