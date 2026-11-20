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
mkdir -p Formula .github skills/managed-machine
echo 0.11.5 >VERSION
echo 0.12.0 >.github/machine-release-version
echo old >Formula/managed-machine.rb
git add . && git commit -qm 'Request 0.12.0'
base="$(git rev-parse HEAD)"
git switch -qc release/v0.12.0
echo 0.12.0 > VERSION
echo validated >skills/managed-machine/SKILL.md
git add . && git commit -qm 'Release v0.12.0'
pr="$(git rev-parse HEAD)"
git switch -q main
git merge --no-ff --quiet --no-edit "$pr"
cut="$(git rev-parse HEAD)"
git push -q origin main

run() { python3 "$script" "$@"; }
refuses() { if "$@" >/dev/null 2>&1; then echo "unexpected acceptance: $*" >&2; exit 1; fi; }
tag=v0.12.0
export GITHUB_SHA="$cut"
[[ "$(run candidate "$cut")" == "$tag" ]]
run lineage "$cut" "$tag" "$base" "$pr"
refuses run lineage "$cut" "$tag" "$pr" "$pr"
refuses run lineage "$cut" "$tag" main "$pr"
refuses run lineage "$cut" "$tag" "$base" "$base"
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

# Exercise the actual Sign request before the macOS signing job. Only gh is a
# fixture: the exact PR ref, checkout history and release-only diff are real.
(
    git clone -q --no-local "$tmp/work" "$tmp/sign-work"
    cd "$tmp/sign-work"
    workflow="$(dirname "$script")/../.github/workflows/sign.yml"
    ruby -ryaml -e 'steps = YAML.load_file(ARGV.fetch(0)).fetch("jobs").fetch("request").fetch("steps")
      print steps.find { |step| step["name"] == "Verify the reviewed Machine request" }.fetch("run")' \
        "$workflow" > "$tmp/sign-request.sh"
    mkdir scripts
    cp "$script" scripts/version-cut.py
    export GITHUB_REPOSITORY="$repo" GITHUB_REF_PROTECTED=true
    export SIGN_PULL="$pull"
    approved_reviews() { jq -cn --arg head "$1" '[[{id:1,user:{id:1},state:"APPROVED",commit_id:$head}]]'; }
    export SIGN_REVIEWS
    SIGN_REVIEWS="$(approved_reviews "$pr")"
    gh() {
        : > "$SIGN_API_CALLED"
        case "${*: -1}" in
            */pulls\?*) jq -cn --argjson pull "$SIGN_PULL" '[$pull]' ;;
            */reviews\?*) printf '%s\n' "$SIGN_REVIEWS" ;;
            *) return 1 ;;
        esac
    }
    export SIGN_API_CALLED="$tmp/sign-api-called"
    export -f gh
    git push -q origin "$pr:refs/pull/21/head"
    bash "$tmp/sign-request.sh"

    refuses_request() {
        if bash "$tmp/sign-request.sh" > "$tmp/refusal" 2>&1; then
            echo "Sign accepted an ineligible release request" >&2; exit 1
        fi
        grep -Fq "$1" "$tmp/refusal" || exit 1
    }
    GITHUB_REF_PROTECTED=false refuses_request 'requires a protected main branch'
    for rejected_pull in '[]' "${pull/$cut/$base}" "${pull/main/other}" "${pull/release\/v0.12.0/release\/v0.11.5}"; do
        SIGN_PULL="$rejected_pull" refuses_request 'expected the merged Machine release PR at the exact cut SHA'
    done
    SIGN_REVIEWS="$(approved_reviews "$base")" refuses bash "$tmp/sign-request.sh"
    SIGN_REVIEWS="$(jq -c '.[0] += [(.[0][0] | .id=2 | .state="CHANGES_REQUESTED")]' <<<"$SIGN_REVIEWS")" \
        refuses bash "$tmp/sign-request.sh"

    git switch -q --detach "$pr"
    echo 'A separate source change' >product-source
    git add product-source && git commit -qm 'Release with unrelated changes'
    SIGN_HEAD="$(git rev-parse HEAD)"
    SIGN_REVIEWS="$(approved_reviews "$SIGN_HEAD")"
    git push -q origin "$SIGN_HEAD:refs/pull/21/head"
    git switch -q --detach "$base"
    git merge -q --no-ff --no-edit "$SIGN_HEAD"
    GITHUB_SHA="$(git rev-parse HEAD)"
    SIGN_PULL="$(jq -c --arg cut "$GITHUB_SHA" --arg head "$SIGN_HEAD" \
        '.[0].merge_commit_sha=$cut | .[0].head.sha=$head' <<<"$pull")"
    refuses_request 'a version PR may only bump VERSION and its skill metadata'

    # A merge with no version change must stop before looking up a release PR.
    git commit -q --allow-empty -m 'Unrelated change'
    GITHUB_SHA="$(git rev-parse HEAD)"
    rm "$SIGN_API_CALLED"
    refuses bash "$tmp/sign-request.sh"
    test ! -e "$SIGN_API_CALLED" || exit 1
)

# Another main commit with unchanged release intent cannot redirect the tag.
echo docs >notes
git add notes && git commit -qm docs
later="$(git rev-parse HEAD)"
refuses run trusted "$cut" # The worktree moved; it is not the supplied workflow SHA.
export GITHUB_SHA="$later"
run trusted "$cut"
[[ "$(run candidate "$cut")" == "$tag" ]]
[[ -z "$(run candidate "$later")" ]]
git push -q origin main
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
echo 0.13.0 >VERSION
git add VERSION && git commit -qm 'Superseding release request'
git push -q origin main
export GITHUB_SHA="$(git rev-parse HEAD)"
refuses run tag "$cut" "$tag"

# An intervening source edit between signing and review invalidates the cut.
git switch -qc drift "$base"
echo changed >code
git add code && git commit -qm drift
git cherry-pick "$pr" >/dev/null
wrong="$(git rev-parse HEAD)"
git checkout -q main
refuses run trusted "$wrong" # Local object, but outside the trusted main history.
git checkout -q drift
export GITHUB_SHA="$wrong"
refuses run lineage "$wrong" "$tag" "$base" "$pr"
echo 0.11.1 >VERSION
git add VERSION && git commit -qm 'Version went backwards'
export GITHUB_SHA="$(git rev-parse HEAD)"
refuses run candidate "$GITHUB_SHA"
# The renderer may read an older signing tree, but its Go verifier runs in
# the trusted workflow checkout even when that signing tree has its own module.
root="$(dirname "$(dirname "$script")")"
mkdir -p "$tmp/bin" skills/managed-machine
printf '  qwts-versions: ">=0.11.0 <1.0.0"\n' >skills/managed-machine/SKILL.md
echo 'module historical-fixture' >go.mod
git add go.mod skills && git commit -qm 'Historical module fixture'
cat >"$tmp/bin/go" <<'STUB'
#!/bin/sh
pwd > "$CHECK_VERIFIER_CWD"
exit 1
STUB
chmod +x "$tmp/bin/go"
export CHECK_VERIFIER_CWD="$tmp/verifier-cwd"
refuses env PATH="$tmp/bin:$PATH" "$root/scripts/release" render v0.12.0 "$tmp/unsigned" "$tmp/signed"
[[ -f "$CHECK_VERIFIER_CWD" && "$(cat "$CHECK_VERIFIER_CWD")" == "$root" ]] || {
    echo 'Renderer did not run the verifier in the trusted checkout' >&2
    exit 1
}
echo 'version-cut tests passed'
