#!/usr/bin/env bash
# Prepare public, pinned test inputs as an ordinary user. This script neither
# installs the service nor touches an existing checkout or account.
set -euo pipefail
[[ $# -ge 1 && $# -le 3 && -d "$1" ]] || { echo 'expected a disposable output directory' >&2; exit 2; }
fixture="$(cd "$1" && pwd -P)"
hq_sha=d52f01f517773565b673ec9735f670922e58dc91
hq_tar_sha=43e99d8d83d2c8623f0b4eb2adbb9bdce1e833e16256b135549de0670e270e14
release="${2:-original}"
if [[ $# == 1 && -n "${MM_HQ_DEVICE_ARCHIVE:-}" ]]; then release=--paired-device; fi
case "$release" in
    original) ;;
    harness) hq_sha=989eb225aefe9b7b8846a66614ab492eb91f7605
        hq_tar_sha=a9c1110d621ed6ae0c0eb6b7bfae1a8c968f5b1b13a8424d4c8cb5f2229e69cb ;;
    --paired-device) hq_sha=a71bcebe62bc107dce91b33ba057cc133de2d5e3
        hq_tar_sha=b80a7b9bc00f65fd169602a57282202f510092f7a7abcc2b5c2c83fc2e687744 ;;
    paired) hq_sha=1e6484ec11e5b2591cf79c40f80e4a1004f99e46
        hq_tar_sha=64f63c48b09b2678ae8dc72585ad030ab458d8f0c1b6a19108282af92f6ad526 ;;
    upgrade) hq_sha=3887da3725222335ed1d4e77c6113a42d9a0ee50
        hq_tar_sha=9b228d8b9dbe57471b2e4007e8aef08026f3c21ef54c1d863585d6b9ac620a29 ;;
    *) echo 'unknown HQ test release' >&2; exit 2 ;;
esac
if [[ $# == 3 ]]; then
    [[ "$release" == upgrade && "$3" == /* && -f "$3" && ! -L "$3" ]] || {
        echo 'only the upgrade fixture accepts an existing regular Node executable' >&2; exit 2
    }
fi
node_dist=node-v24.19.0-darwin-arm64
node_tar_sha=8294b7aa9b03997481c06babf1e8b270c859358f27da57a11509afe537ac381d
node_sha=27db838bb204ef7c21df2931f5656e4c8fb32e6e947f363a402b49714d32b5b1
cd "$fixture"
mkdir bin
if [[ $# == 3 ]]; then
    cp "$3" bin/node
else
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        "https://nodejs.org/dist/v24.19.0/$node_dist.tar.gz" -o node.tar.gz
    printf '%s  node.tar.gz\n' "$node_tar_sha" | shasum -a 256 --check
    tar -xzOf node.tar.gz "$node_dist/bin/node" > bin/node
fi
printf '%s  bin/node\n' "$node_sha" | shasum -a 256 --check
chmod 0755 bin/node
export PATH="$fixture/bin:$PATH"
[[ "$(node --version)" == v24.19.0 && "$(node -p 'process.arch')" == arm64 ]] || exit 1

# Both HQ and its own pinned soul-contracts dependency are public.
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0
git -c init.defaultBranch=main init -q source
git -C source -c credential.helper= fetch -q --depth=1 --no-tags https://github.com/true-line/agent-bot-hq.git "$hq_sha"
git -C source checkout -q --detach FETCH_HEAD
[[ "$(git -C source rev-parse HEAD)" == "$hq_sha" ]] || exit 1
(cd source && bash scripts/ci-build-darwin-artifact.sh "$hq_sha" "$fixture/approved.tar")
printf '%s  approved.tar\n' "$hq_tar_sha" | shasum -a 256 --check
printf '%s  node\n%s  approved.tar\n' "$node_sha" "$hq_tar_sha" > installed.sha256
