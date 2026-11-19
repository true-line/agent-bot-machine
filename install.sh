#!/usr/bin/env bash
# Install the public Machine Homebrew formula on Apple Silicon.
#
#   (
#     installer="$(mktemp "${TMPDIR:-/tmp}/managed-machine-install.XXXXXX")" || exit 1
#     trap 'rm -f "$installer"' EXIT
#     curl --proto '=https' --proto-redir '=https' -fsSL https://raw.githubusercontent.com/true-line/agent-bot-machine/main/install.sh -o "$installer" &&
#       /bin/bash "$installer"
#   )
set -euo pipefail
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 GIT_TERMINAL_PROMPT=0

TAP="true-line/agent-bot-machine"
REPO_URL="https://github.com/true-line/agent-bot-machine.git"
FORMULA="$TAP/managed-machine"

die() { echo "Error: $*" >&2; exit 1; }

in_admin_group() {
    local groups
    groups="$(id -nG "$1")" || return 1
    [[ " $groups " == *" admin "* ]]
}

# Refresh only Machine's tap. Leave a locally modified, divergent or
# differently sourced checkout for its administrator to reconcile.
refresh_machine_tap() {
    local dir="$1" repo_url="$2" owner_uid="$3" head branch origin dirty
    [[ -d "$dir/.git" && ! -L "$dir/.git" ]] || die "Expected a Git checkout at $dir."
    [[ "$(/usr/bin/stat -f '%u' "$dir")" == "$owner_uid" && "$(/usr/bin/stat -f '%u' "$dir/.git")" == "$owner_uid" ]] ||
        die "The Homebrew administrator must own the Machine tap and its Git directory."
    local git_cmd=(/usr/bin/git -c core.hooksPath=/dev/null -c credential.helper= -C "$dir")
    [[ "$("${git_cmd[@]}" rev-parse --show-toplevel)" == "$dir" ]] || die "Invalid Machine tap directory."
    origin="$("${git_cmd[@]}" remote get-url origin)"
    [[ "${origin%.git}" == "${repo_url%.git}" ]] || die "Machine's tap must use the public remote $repo_url."
    branch="$("${git_cmd[@]}" symbolic-ref --quiet --short HEAD)" || die "Machine's tap is on a detached commit."
    [[ "$branch" == main ]] || die "Machine's tap must be on main to update."
    dirty="$("${git_cmd[@]}" status --porcelain=v1 --untracked-files=all)"
    [[ -z "$dirty" ]] || die "Machine's tap contains local changes. Resolve them before updating."
    "${git_cmd[@]}" fetch --no-tags --no-recurse-submodules "$repo_url" refs/heads/main
    head="$("${git_cmd[@]}" rev-parse --verify FETCH_HEAD^{commit})"
    "${git_cmd[@]}" merge-base --is-ancestor HEAD "$head" || die "Machine's tap contains commits outside public main."
    "${git_cmd[@]}" merge --ff-only "$head"
}

install_formula() {
    local brew="$1" tap="$2" repo_url="$3" formula="$4" owner_uid="$5"
    local repo dir commands formulae
    repo="$("$brew" --repository)"
    [[ -n "$repo" ]] || die "Could not locate the Homebrew repository."
    repo="$(cd "$repo" && pwd -P)"
    dir="$repo/Library/Taps/true-line/homebrew-agent-bot-machine"
    local parent
    for parent in "$repo/Library" "$repo/Library/Taps" "$repo/Library/Taps/true-line"; do
        [[ ! -L "$parent" ]] || die "Unexpected symbolic link at $parent."
    done
    if [[ -e "$dir" || -L "$dir" ]]; then
        [[ "$(cd "$dir" && pwd -P)" == "$dir" ]] || die "Machine's tap must be under $repo/Library/Taps."
        refresh_machine_tap "$dir" "$repo_url" "$owner_uid"
    fi
    commands="$("$brew" commands --quiet)"
    if grep -qx trust <<<"$commands"; then
        "$brew" trust "$repo_url"
    fi
    if [[ ! -d "$dir" ]]; then
        "$brew" tap "$tap" "$repo_url"
    fi
    formulae="$("$brew" list -1 --formula --full-name)"
    if grep -Fxq "$formula" <<<"$formulae"; then
        # Homebrew treats a current formula as a successful upgrade. A pin
        # can also skip an upgrade, so confirm that no update is outstanding.
        "$brew" upgrade "$formula"
        "$brew" outdated --formula --quiet "$formula" || die "Homebrew could not confirm Machine is current."
    else
        "$brew" install "$formula"
    fi
}

# Keep the tap and package transaction in the existing prefix owner's
# account. Pass the same installer functions by value so the authorization
# dialog never runs a caller-writable temporary script by pathname.
run_install() {
    if [[ "$owner_uid" == "$caller_uid" ]]; then
        install_formula "$brew" "$TAP" "$REPO_URL" "$FORMULA" "$owner_uid"
        return
    fi
    local brew_shell='set -euo pipefail
        cd /
        if [[ ! -d "$HOME" || ! -w "$HOME" ]]; then
            HOME=/opt/homebrew/var/mm-home
            (umask 077 && /bin/mkdir -p "$HOME")
        fi
        export HOME PATH=/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin TMPDIR=/tmp
        export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 GIT_TERMINAL_PROMPT=0'
    brew_shell+=$'\n'"$(declare -f die refresh_machine_tap install_formula)"$'\n''install_formula /opt/homebrew/bin/brew "$@"'
    /usr/bin/osascript \
        -e 'on run argv' \
        -e 'set cmd to "cd / && /usr/bin/sudo -H -u " & quoted form of (item 1 of argv) & " -- /bin/bash -c " & quoted form of (item 2 of argv) & " machine-brew "' \
        -e 'repeat with i from 3 to count of argv' \
        -e 'set cmd to cmd & quoted form of (item i of argv as text) & " "' \
        -e 'end repeat' \
        -e 'do shell script cmd with prompt "Install or update Machine with Homebrew in the Homebrew administrator account." with administrator privileges' \
        -e 'end run' "#$owner_uid" "$brew_shell" "$TAP" "$REPO_URL" "$FORMULA" "$owner_uid"
}

main() {
    [[ $# == 0 || ( $# == 1 && "${1:-}" == --update ) ]] || die "Usage: install.sh [--update]"
    [[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || die "Machine's macOS installer requires an Apple Silicon Mac."
    local major
    major="$(sw_vers -productVersion)"
    [[ "${major%%.*}" =~ ^[0-9]+$ && "${major%%.*}" -ge 15 ]] || die "Machine requires macOS 15 or later."

    local caller_uid owner_uid owner brew prefix installer
    caller_uid="$(id -u)"
    [[ "$caller_uid" != 0 ]] || die "Open Terminal as the Homebrew administrator and run the installer without sudo."
    if [[ -x /opt/homebrew/bin/brew ]]; then
        brew=/opt/homebrew/bin/brew
    elif command -v brew >/dev/null 2>&1; then
        brew="$(command -v brew)"
    else
        in_admin_group "$(id -un)" || die "To install Homebrew, run this installer from the administrator account that will own it."
        if [[ -d /opt/homebrew && "$(/usr/bin/stat -f '%u' /opt/homebrew)" != "$caller_uid" ]]; then
            die "Run this installer from the administrator account that owns /opt/homebrew."
        fi
        installer="$(mktemp "${TMPDIR:-/tmp}/homebrew-install.XXXXXX")"
        (trap 'rm -f "$installer"' EXIT
         curl --proto '=https' --proto-redir '=https' -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o "$installer"
         /bin/bash "$installer")
        brew=/opt/homebrew/bin/brew
    fi
    prefix="$("$brew" --prefix)"
    owner_uid="$(/usr/bin/stat -f '%u' "$prefix")"
    [[ "$owner_uid" =~ ^[0-9]+$ && "$owner_uid" != 0 ]] || die "Homebrew's prefix must be owned by a non-root administrator."
    owner="$(id -nu "$owner_uid")"
    in_admin_group "$owner" || die "Homebrew's prefix ($prefix) must be owned by an administrator."
    if [[ "$owner_uid" != "$caller_uid" && ( "$prefix" != /opt/homebrew || "$brew" != /opt/homebrew/bin/brew ) ]]; then
        die "Run this installer as $owner to use Homebrew at $prefix."
    fi

    local result=0
    check_standalone_signing || result=$?
    if [[ "$result" != 0 ]]; then
        [[ "$result" == 42 ]] || exit "$result"
        retire_standalone_signing
        check_standalone_signing || die "The administrator must finish retiring standalone HQ signing before Machine can install."
    fi
    run_install
    local installed="$prefix/opt/managed-machine/bin/managed-machine"
    local version
    version="$("$installed" --version)"
    echo "Machine $version installed. To check it again, run $installed --version."
}

# Homebrew's formula repeats this check after publishing its standard keg.
check_standalone_signing() {
    /usr/bin/ruby --disable-gems -e '
      dir = "/Library/Application Support/ai.true-line.agent-bot-hq/standalone"
      ["declaration-pending-v1", "declaration-v1"].each do |name|
        begin
          File.lstat(File.join(dir, name))
        rescue Errno::ENOENT
          next
        end
        exit 42
      end
    '
}

retire_standalone_signing() {
    # Only this fixed root-owned utility receives elevated rights. The Ruby
    # verifier and the AppleScript command are passed by value to the prompt.
    local verify='require "open3"
      root = "/Library/Application Support/ai.true-line.agent-bot-hq/standalone/installer"
      tool = File.join(root, "standalone-hq-signing")
      path = "/"
      (tool.split("/").reject(&:empty?) + [nil]).each do |part|
        s = File.lstat(path)
        acl, ok = Open3.capture2("/bin/ls", "-lde", path)
        valid = path == tool ? (s.file? && s.nlink == 1) : s.directory?
        abort "Cannot verify the installed administrator retirement utility" unless valid && s.uid.zero? &&
          (s.mode & 022).zero? && ok.success? && acl.lines.drop(1).none? { |l| l.include?(" allow ") }
        path = File.join(path, part) if part
      end
      exec("/usr/bin/ruby", "--disable-gems", tool, "retire")'
    /usr/bin/osascript \
      -e 'on run argv' \
      -e 'set cmd to "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/ruby --disable-gems -e " & quoted form of (item 1 of argv)' \
      -e 'do shell script cmd with prompt "Permanently retire standalone HQ signing before installing Machine." with administrator privileges' \
      -e 'end run' "$verify"
}

main "$@"
