#!/bin/bash
# Pre-release qualification of the checked-out code through Homebrew and launchd.
set -euo pipefail
[[ "$#" == 0 && "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "$(uname -sm)" == 'Darwin arm64' && "$(id -u)" != 0 && "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
case "$(/usr/bin/sw_vers -productVersion)" in 15.*|27.*) ;; *) exit 1;; esac
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
brew=/opt/homebrew/bin/brew
tap=true-line/agent-bot-machine
prefix="$("$brew" --prefix)"
[[ "$prefix" == /opt/homebrew ]] || exit 1
for path in "$("$brew" --repository "$tap")" "$prefix/Cellar/managed-machine" "$prefix/opt/managed-machine" "$prefix/bin/managed-machine" "$prefix/bin/agent-bot-keyd" "$prefix/bin/agent-machine"; do
    [[ ! -e "$path" && ! -L "$path" ]] || { echo 'Source qualification needs a fresh Homebrew runner' >&2; exit 1; }
done
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
version="$(cat VERSION)"
revision="$(git rev-parse HEAD)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$revision" =~ ^[0-9a-f]{40}$ && "$revision" == "$GITHUB_SHA" ]] || exit 1
mkdir -p "$work/source" "$work/tap/Formula"
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$version" -o "$work/source/managed-machine" ./cmd/managed-machine
"$root/scripts/build-darwin-keyd" "$work/source/agent-bot-keyd"
printf '%s\n' "$revision" > "$work/source/RELEASE_COMMIT"
archive="$work/managed-machine-$version.tar.gz"
tar -czf "$archive" -C "$work" source
digest="$(shasum -a 256 "$archive" | awk '{print $1}')"
cat > "$work/tap/Formula/managed-machine.rb" <<FORMULA
class ManagedMachine < Formula
  desc "Disposable source qualification of Machine removal"
  homepage "https://github.com/true-line/agent-bot-machine"
  url "file://$archive"
  version "$version"
  sha256 "$digest"

  def install
    bin.install "managed-machine", "agent-bot-keyd"
    bin.install_symlink "managed-machine" => "agent-machine"
    libexec.install "RELEASE_COMMIT"
  end

  def post_install
    chmod 0700, bin/"agent-bot-keyd"
  end
end
FORMULA
git -C "$work/tap" init --quiet
git -C "$work/tap" add Formula
git -C "$work/tap" -c user.name='Machine CI' -c user.email=fixture@invalid -c commit.gpgsign=false commit --quiet -m 'Install this disposable source build'
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1
"$brew" tap "$tap" "file://$work/tap"
"$brew" install --formula "$tap/managed-machine"
# An installation stopped before the first HQ apply has no root receipt store.
receipts=/private/var/db/managed-machine/members/receipts
sudo -n /bin/test ! -e "$receipts"
sudo -n "$prefix/bin/managed-machine" members uninstall-hq --list |
    jq -e '.matching_plan_ids == [] and (has("resume_plan_id") | not)' >/dev/null
sudo -n /bin/test ! -e "$receipts"
echo 'PASS: fresh HQ uninstall discovery returned no plans and created no receipt directory'
MM_KEYD_CUSTODY_TEST=1 bash tests/fixtures/with-keyd-test-keychain.sh \
    bash tests/fixtures/homebrew-uninstall-cycle.sh "$version" "$work/source"
