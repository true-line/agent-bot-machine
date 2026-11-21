#!/bin/bash
# Test the actual hosted step bodies with inert commands on stock macOS Bash.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"
mkdir -p tests/fixtures bin
cat > tests/fixtures/install-homebrew-darwin-hq-device.sh <<'FIXTURE'
fetch_public_device_archive() { touch fetched; }
FIXTURE
workflow="$root/.github/workflows/darwin-hq-install.yml"
step_body() {
    ruby -ryaml -e 'steps = YAML.load_file(ARGV[0]).fetch("jobs").fetch(ARGV[1]).fetch("steps")
      matches = steps.select { |s| s["name"] == ARGV[2] }
      abort "expected exactly one workflow step" unless matches.size == 1
      puts matches.first.fetch("run")' "$workflow" "$1" "$2"
}
step_body install 'Fetch the reviewed signed Machine release for optional hardware qualification' > fetch.sh
step_body rollback-macos-15 'Check socket preservation when guarded removal is unavailable' > rollback.sh
export RUNNER_TEMP="$work" GITHUB_ENV="$work/env" MM_DEVICE_SHA
MM_DEVICE_SHA="$(printf '%064d' 0)"
if MM_DEVICE_VERSION='wrong' /bin/bash -eu -o pipefail fetch.sh; then exit 1; fi
[[ ! -e fetched && ! -e env ]] || exit 1
MM_DEVICE_VERSION=1.2.3 /bin/bash -eu -o pipefail fetch.sh
[[ -f fetched && -s env ]] || exit 1

printf '#!/bin/sh\necho "$FIXTURE_VERSION"\n' > bin/sw_vers
printf '#!/bin/sh\ntouch rollback\n' > bin/go
chmod +x bin/{go,sw_vers}
export PATH="$work/bin:$PATH"
if FIXTURE_VERSION=27.0 /bin/bash -eu -o pipefail rollback.sh >/dev/null; then exit 1; fi
[[ ! -e rollback ]] || exit 1
FIXTURE_VERSION=15.0 /bin/bash -eu -o pipefail rollback.sh >/dev/null
[[ -e rollback ]] || exit 1

source "$root/tests/fixtures/stage-darwin-hq-device.sh"
verify_homebrew_device_binary() { :; }
verify_device_release_signature() { :; }
printf '#!/bin/sh\necho 1.2.3\nexit 1\n' > bin/managed-machine
chmod +x bin/managed-machine
if verify_homebrew_device_install "$work" 1.2.3 unused; then exit 1; fi
printf '#!/bin/sh\necho 1.2.3\n' > bin/managed-machine
verify_homebrew_device_install "$work" 1.2.3 unused || exit 1

# Reject an invalid or unverified tap revision before invoking an installer.
fake_brew() {
    case "$1" in
        --prefix) echo "$work/prefix" ;;
        --cellar) echo "$work/prefix/Cellar" ;;
        --repository) echo "$work/tap" ;;
        tap) touch tapped ;;
        *) return 1 ;;
    esac
}
git() {
    case "$3" in
        checkout|fetch) return 0 ;;
        rev-parse) echo "$FIXTURE_HEAD" ;;
        *) return 1 ;;
    esac
}
export HOMEBREW_NO_AUTO_UPDATE=1
if MM_HQ_TAP_REVISION=wrong tap_homebrew_device_release fake_brew "$work/prefix"; then exit 1; fi
[[ ! -e tapped ]] || exit 1
export MM_HQ_TAP_REVISION; MM_HQ_TAP_REVISION="$(printf '%040d' 0)"
if FIXTURE_HEAD=other tap_homebrew_device_release fake_brew "$work/prefix"; then exit 1; fi
FIXTURE_HEAD="$MM_HQ_TAP_REVISION" tap_homebrew_device_release fake_brew "$work/prefix" || exit 1

# The hosted repair and upgrade jobs may publish only recognized classifications.
filter="$root/tests/fixtures/darwin-hq-apply-diagnostic.jq"
record='{"diagnostic":"MM_MEMBERS_APPLY_FAILED","message":"private-fixture: query launched HQ as approved owner: sudo exit status 3\nmode 0755, expected 0666, private-fixture"}'
[[ "$(jq -Rsr -f "$filter" <<< "$record")" == 'Machine diagnostic MM_MEMBERS_APPLY_FAILED: query launched HQ as approved owner: sudo exit status 3 / mode 0755, expected 0666' ]]
record='{"diagnostic":"private-fixture","message":"query launched HQ as approved owner: sudo exit status 41"}'
[[ "$(jq -Rsr -f "$filter" <<< "$record")" == 'Machine diagnostic other: unclassified' ]]
