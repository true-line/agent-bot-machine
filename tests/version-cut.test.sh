#!/usr/bin/env bash
# Exercise the release transition and create-only tag operation entirely on disk.
set -euo pipefail
script="$(cd "$(dirname "$0")/.." && pwd)/scripts/version-cut.py"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export HOME="$tmp/home" GIT_CONFIG_NOSYSTEM=1 GIT_ALLOW_PROTOCOL=file
export GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid
export GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid
mkdir "$HOME"
git init -q --bare --initial-branch=main "$tmp/origin"
git init -q --initial-branch=main "$tmp/work"
cd "$tmp/work"
git remote add origin "$tmp/origin"
mkdir -p Formula .github
echo 0.11.5 >VERSION
echo 0.12.0 >.github/machine-release-version
echo old >Formula/managed-machine.rb
git add . && git commit -qm 'Request 0.12.0'
base="$(git rev-parse HEAD)"
git switch -qc release/v0.12.0
echo 0.12.0 > VERSION
echo verified-pin >Formula/managed-machine.rb
git add . && git commit -qm 'Release v0.12.0'
pr="$(git rev-parse HEAD)"
git switch -q main
git merge --no-ff --quiet --no-edit "$pr"
cut="$(git rev-parse HEAD)"
git push -q origin main

run() { python3 "$script" "$@"; }
refuses() { if "$@" >/dev/null 2>&1; then echo "unexpected acceptance: $*" >&2; exit 1; fi; }
tag=v0.12.0
[[ "$(run candidate "$cut")" == "$tag" ]]
run lineage "$cut" "$tag" "$base" "$pr"
refuses run lineage "$cut" "$tag" "$pr" "$pr"
refuses run lineage "$cut" "$tag" main "$pr"
refuses run lineage "$cut" "$tag" "$base" "$cut"
refuses run candidate "$pr"
[[ "$(run existing "$cut" "$tag")" == missing ]]

repo=owner/machine
ci='{"id":12,"run_number":4,"run_attempt":1,"conclusion":"success","status":"completed","head_branch":"main","event":"push","path":".github/workflows/go-core.yml","head_sha":"'$cut'","head_repository":{"full_name":"owner/machine"}}'
select_ci() { run ci "$repo" "$cut" go-core.yml; }
[[ "$(printf '{"workflow_runs":[%s]}' "$ci" | select_ci)" == 12 ]]
for bad in "${ci/main/pr}" "${ci/push/pull_request}" "${ci/owner\/machine/fork\/machine}" "${ci/$cut/$pr}" "${ci/go-core.yml/ci.yml}" "${ci/completed/in_progress}"; do
    [[ -z "$(printf '{"workflow_runs":[%s]}' "$bad" | select_ci)" ]]
done
refuses select_ci <<<"{\"workflow_runs\":[${ci/success/failure}]}"
rerun="${ci/\"run_attempt\":1/\"run_attempt\":2}"
[[ -z "$(printf '{"workflow_runs":[%s,%s]}' "$ci" "${rerun/completed/in_progress}" | select_ci)" ]]

pull='[{"number":21,"merged_at":"2026-10-01","merge_commit_sha":"'$cut'","base":{"ref":"main","repo":{"full_name":"owner/machine"}},"head":{"ref":"release/v0.12.0","repo":{"full_name":"owner/machine"},"sha":"'$pr'"},"user":{"type":"Bot","login":"trueline-chores-dumb[bot]"}}]'
select_pr() { run pr "$repo" "$cut" "$tag"; }
[[ "$(select_pr <<<"$pull")" == "21 $pr" ]]
for bad in "${pull/chores-dumb/nonrelease}" "${pull/$cut/$pr}" "${pull/release\/v/topic\/v}" "${pull/main/feature}"; do
    refuses select_pr <<<"$bad"
done

# Another main commit with unchanged release intent cannot redirect the tag.
echo docs >notes
git add notes && git commit -qm docs
later="$(git rev-parse HEAD)"
[[ -z "$(run candidate "$later")" ]]
git push -q origin main
git checkout --detach -q "$cut"
run tag "$cut" "$tag"
[[ "$(git cat-file -t "$tag")" == tag && "$(git rev-parse "$tag^{}")" == "$cut" ]]
run tag "$cut" "$tag"
[[ "$(run existing "$cut" "$tag")" == same ]]
refuses run existing "$later" "$tag"

# A lightweight, conflicting, or superseded remote tag is never replaced.
git --git-dir="$tmp/origin" update-ref -d "refs/tags/$tag"
git --git-dir="$tmp/origin" update-ref "refs/tags/$tag" "$cut"
refuses run existing "$cut" "$tag"
git --git-dir="$tmp/origin" update-ref -d "refs/tags/$tag"
git --git-dir="$tmp/origin" update-ref refs/tags/v0.13.0 "$later"
refuses run existing "$cut" "$tag"
git --git-dir="$tmp/origin" update-ref -d refs/tags/v0.13.0
git tag -d "$tag" >/dev/null
git switch -q main
echo 0.13.0 >.github/machine-release-version
git add .github && git commit -qm 'Superseding release request'
git push -q origin main
git checkout --detach -q "$cut"
refuses run tag "$cut" "$tag"

# An intervening source edit between signing and review invalidates the cut.
git switch -qc drift "$base"
echo changed >code
git add code && git commit -qm drift
git cherry-pick "$pr" >/dev/null
wrong="$(git rev-parse HEAD)"
refuses run lineage "$wrong" "$tag" "$base" "$wrong"
echo 0.13.0 >VERSION
git add VERSION && git commit -qm 'Wrong release request'
refuses run candidate "$(git rev-parse HEAD)"
echo 'version-cut tests passed'
