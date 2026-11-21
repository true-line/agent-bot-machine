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

# Exercise restoration without system Keychain calls. The tested copy has no
# path to the real security executable; all state is plain scratch files.
script="$root/fixtures/with-keyd-test-keychain.sh"
sed 's|/usr/bin/security|mock_security|g' "$script" > "$scratch/wrapper"
! grep -q '/usr/bin/security' "$scratch/wrapper" || exit 1
for scenario in success restore-error restore-no-change delete-error failed-test-and-restore; do
    base="$scratch/restore-$scenario"
    mkdir -p "$base"
    touch "$base/prior"
    echo "$base/prior" > "$base/current"
    rc=0
    # Execute as an independent script so errexit has its normal meaning.
    cat > "$base/run" <<'STUB'
set -euo pipefail
export MM_KEYD_CUSTODY_TEST=1 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted
uname() { echo 'Darwin arm64'; }
id() { echo 501; }
stat() { echo 501; }
mktemp() { mkdir "$base/stage" && echo "$base/stage"; }
mock_security() {
    case "$1" in
        default-keychain)
            if [[ "$#" == 3 ]]; then printf '    "%s"\n' "$(cat "$base/current")"; return; fi
            if [[ "$5" == "$base/prior" ]]; then
                case "$scenario" in
                    restore-error|failed-test-and-restore) return 1 ;;
                    restore-no-change) return 0 ;;
                esac
            fi
            echo "$5" > "$base/current" ;;
        create-keychain) touch "$base/stage/fixture.keychain-db" ;;
        unlock-keychain) return 0 ;;
        delete-keychain) touch "$base/deletion"; [[ "$scenario" != delete-error ]] || return 1; rm "$2" ;;
        *) return 1 ;;
    esac
}
run_test() { if [[ "$scenario" == failed-test-and-restore ]]; then return 23; fi; }
set -- run_test
source "$wrapper"
STUB
    base="$base" scenario="$scenario" wrapper="$scratch/wrapper" /bin/bash "$base/run" >/dev/null 2>&1 || rc=$?
    case "$scenario" in
        success) [[ "$rc" == 0 && "$(cat "$base/current")" == "$base/prior" && ! -e "$base/stage" ]] || exit 1 ;;
        delete-error) [[ "$rc" == 1 && "$(cat "$base/current")" == "$base/prior" && -f "$base/stage/fixture.keychain-db" ]] || exit 1 ;;
        *) expected=1
           if [[ "$scenario" == failed-test-and-restore ]]; then expected=23; fi
           [[ "$rc" == "$expected" && ! -e "$base/deletion" && -f "$base/stage/fixture.keychain-db" ]] || exit 1 ;;
    esac
done
