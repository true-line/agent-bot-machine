# Shared by the signed-release staging and public Homebrew fixtures.
source "$(dirname "${BASH_SOURCE[0]}")/install-homebrew-darwin-hq-device.sh"

verify_device_release_signature() {
    local file="$1" identifier="$2" requirement
    requirement="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"Z5DM34QS5U\" and identifier \"$identifier\""
    /usr/bin/codesign --verify --strict "-R=$requirement" "$file"
}

verify_homebrew_device_install() {
    local prefix="$1" version="$2" unpack="$3" source_commit="${4:-}" name mode identifier
    if [[ -n "$source_commit" ]]; then
        local receipt="$prefix/Cellar/managed-machine/$version/libexec/RELEASE_COMMIT"
        [[ "$source_commit" =~ ^[0-9a-f]{40}$ && -f "$receipt" && ! -L "$receipt" ]] &&
            cmp -s "$receipt" <(printf '%s\n' "$source_commit") || return 1
    fi
    for name in managed-machine agent-bot-keyd; do
        if [[ "$name" == managed-machine ]]; then mode=0555; identifier=ai.true-line.agent-bot-machine
        else mode=0700; identifier=ai.true-line.agent-bot-keyd; fi
        verify_homebrew_device_binary "$prefix" "$version" "$name" "$mode" "$unpack/$name" || return 1
        verify_device_release_signature "$prefix/Cellar/managed-machine/$version/bin/$name" "$identifier" || return 1
    done
    local installed_version
    installed_version="$("$prefix/bin/managed-machine" --version)" || return 1
    [[ "$installed_version" == "$version" ]] || return 1
}

# Exercise both formula installations before any service uses the keg.
qualify_homebrew_device_release() (
    set -euo pipefail
    local brew="$1" prefix="$2" version="$3" digest="$4" unpack="$5" source_commit="${6:-}"
    local formula=true-line/agent-bot-machine/managed-machine
    umask 022
    install_homebrew_device_release "$brew" "$version" "$digest"
    verify_homebrew_device_install "$prefix" "$version" "$unpack" "$source_commit" >/dev/null 2>&1 || {
        echo 'FAIL: installed Homebrew release verification' >&2; exit 1;
    }
    "$brew" test "$formula" >/dev/null 2>&1 || { echo 'FAIL: installed Homebrew formula test' >&2; exit 1; }
    "$brew" reinstall --formula "$formula" >/dev/null 2>&1 || { echo 'FAIL: Homebrew formula reinstall' >&2; exit 1; }
    verify_homebrew_device_install "$prefix" "$version" "$unpack" "$source_commit" >/dev/null 2>&1 || {
        echo 'FAIL: reinstalled Homebrew release verification' >&2; exit 1;
    }
    "$brew" test "$formula" >/dev/null 2>&1 || { echo 'FAIL: reinstalled Homebrew formula test' >&2; exit 1; }
    echo 'PASS: formula tests and signed release checks passed after install and reinstall'
)

# Only the historical checksum-qualified archive predates the uninstall command.
qualify_published_device_lifecycle() (
    set -euo pipefail
    local recipe="$1" version="$2" unpack="$3" source_commit="$4" fixtures mode
    fixtures="$(dirname "${BASH_SOURCE[0]}")"
    mode="$(python3 "$fixtures/homebrew-device-pin.py" --published-mode "$recipe")"
    case "$mode" in
        package) echo 'Historical archive passed package verification'; return ;;
        custody) ;;
        *) return 1 ;;
    esac
    [[ "$source_commit" =~ ^[0-9a-f]{40}$ && "$(git rev-parse HEAD)" == "$source_commit" ]] || return 1
    [[ -f "$fixtures/homebrew-uninstall-cycle.sh" && -f "$fixtures/homebrew-launch-agents.py" ]] || {
        echo 'Required Machine uninstall qualification missing from this release' >&2; return 1;
    }
    # The formula writes its checkout commit into the keg. Supply the independently
    # verified publish commit as the expected receipt for both installations.
    printf '%s\n' "$source_commit" > "$unpack/RELEASE_COMMIT"
    MM_KEYD_CUSTODY_TEST=1 bash "$fixtures/with-keyd-test-keychain.sh" \
        bash "$fixtures/homebrew-uninstall-cycle.sh" "$version" "$unpack"
)

# Called by the dedicated-role fixture before enrollment or key creation.
stage_signed_device_release() {
    [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
       "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "$DAEMON_ACCOUNT" == "$(id -un)" &&
       "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
    unpack="$WORK/signed-device-release"
    unpack_signed_device_release "$MM_HQ_DEVICE_ARCHIVE" "$MM_HQ_DEVICE_SHA256" "$unpack" || fail 'invalid signed device release'
    if [[ "${MM_HQ_DEVICE_HOMEBREW:-false}" == true ]]; then
        tap_homebrew_device_release /opt/homebrew/bin/brew /opt/homebrew
        qualify_homebrew_device_release /opt/homebrew/bin/brew /opt/homebrew "$MM_HQ_DEVICE_VERSION" "$MM_HQ_DEVICE_SHA256" "$unpack"
        custody_dir=/opt/homebrew/bin
        ok 'the active Homebrew Machine and private keyd match the reviewed signed release'
    else
        custody_dir="$stage/device-custody"
        sudo install -d -o root -g wheel -m 0755 "$custody_dir"
        sudo install -o "$DAEMON_ACCOUNT" -g "$(id -gn)" -m 0755 "$unpack/managed-machine" "$custody_dir/managed-machine"
        sudo install -o "$DAEMON_ACCOUNT" -g "$(id -gn)" -m 0700 "$unpack/agent-bot-keyd" "$custody_dir/agent-bot-keyd"
        verify_device_release_signature "$custody_dir/managed-machine" ai.true-line.agent-bot-machine
        verify_device_release_signature "$custody_dir/agent-bot-keyd" ai.true-line.agent-bot-keyd
    fi
    MM="$custody_dir/managed-machine"
}
