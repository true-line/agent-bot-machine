# Shared by the signed-release staging and public Homebrew fixtures.
source "$(dirname "${BASH_SOURCE[0]}")/install-homebrew-darwin-hq-device.sh"

verify_device_release_signature() {
    local file="$1" identifier="$2" requirement
    requirement="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"Z5DM34QS5U\" and identifier \"$identifier\""
    /usr/bin/codesign --verify --strict "-R=$requirement" "$file"
}

verify_homebrew_device_install() {
    local prefix="$1" version="$2" unpack="$3" name mode identifier
    for name in managed-machine agent-bot-keyd; do
        if [[ "$name" == managed-machine ]]; then mode=0555; identifier=ai.true-line.agent-bot-machine
        else mode=0700; identifier=ai.true-line.agent-bot-keyd; fi
        verify_homebrew_device_binary "$prefix" "$version" "$name" "$mode" "$unpack/$name" || return 1
        verify_device_release_signature "$prefix/Cellar/managed-machine/$version/bin/$name" "$identifier" || return 1
    done
    [[ "$("$prefix/bin/managed-machine" --version)" == "$version" ]]
}

# Called by the dedicated-role fixture before enrollment or key creation.
stage_signed_device_release() {
    [[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
       "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "$DAEMON_ACCOUNT" == "$(id -un)" &&
       "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
    unpack="$WORK/signed-device-release"
    unpack_signed_device_release "$MM_HQ_DEVICE_ARCHIVE" "$MM_HQ_DEVICE_SHA256" "$unpack" || fail 'invalid signed device release'
    if [[ "${MM_HQ_DEVICE_HOMEBREW:-false}" == true ]]; then
        tap_homebrew_device_release /opt/homebrew/bin/brew /opt/homebrew
        install_homebrew_device_release /opt/homebrew/bin/brew "$MM_HQ_DEVICE_VERSION" "$MM_HQ_DEVICE_SHA256"
        verify_homebrew_device_install /opt/homebrew "$MM_HQ_DEVICE_VERSION" "$unpack" || fail 'invalid installed Homebrew release'
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
