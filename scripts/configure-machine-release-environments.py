#!/usr/bin/env python3
"""Preview or apply the environment changes for true-line/agent-bot-machine PR 517.

Run with Python 3.9+ and an already authorized gh command. The default is a
read-only preview. Pass --apply to configure the three environments in order.
"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass

REPO = "true-line/agent-bot-machine"
PREFIX = "repos/" + REPO
MAIN = ("branch", "main")
OLD_TAGS = ("tag", "v*")
SCOPE = {"protected_branches": False, "custom_branch_policies": True}
# Guard behavior and privileged job bindings reviewed together in PR 517.
WORKFLOWS = {
    "sign.yml": "1da612199f09fcd1c905008c9b89faf13e0a7863ca096e1a634b273bb2411b15",
    "version-cut.yml": "ca42b4f7274a9b5bfffd178e15fce20969f7c74672d8a42fda1be1836d125020",
    "prepare-release.yml": "d98c169dd9a96bd12a1107d75eeff3b706cd7bc574dacfcd61918fa9d7515773",
}


class Stop(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Stop(message)


def api(path, method="GET", data=None, missing=False):
    args = ["gh", "api", "--hostname", "github.com", "--method", method, PREFIX + path]
    if data is not None:
        args.extend(["--input", "-"])
    try:
        result = subprocess.run(args, input=json.dumps(data) if data is not None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                timeout=45, check=False)
    except FileNotFoundError:
        raise Stop("The authorized gh command must be on PATH.") from None
    except subprocess.TimeoutExpired:
        raise Stop(f"{method} {path} timed out. Rerun the preview to inspect current state.") from None
    if result.returncode:
        status = re.search(r"\bHTTP\s+(\d{3})\b", result.stderr)
        if status and status[1] == "404" and missing and method == "GET":
            return None
        detail = "HTTP " + status[1] if status else "exit " + str(result.returncode)
        raise Stop(f"{method} {path} failed ({detail}). Use an identity authorized for this repository.")
    return json.loads(result.stdout) if result.stdout.strip() else None


def guard_workflows():
    pr = api("/pulls/517")
    require(pr["merged"] is True and pr["base"]["repo"]["full_name"] == REPO and pr["base"]["ref"] == "main",
            "PR 517 must be merged into this repository's main branch.")
    main_sha = api("/commits/main")["sha"]
    merged_sha = pr["merge_commit_sha"]
    require(all(re.fullmatch(r"[a-f0-9]{40}", sha) for sha in (main_sha, merged_sha)),
            "Invalid commit in server response.")
    if main_sha != merged_sha:
        comparison = api(f"/compare/{merged_sha}...{main_sha}")
        require(comparison["status"] in ("ahead", "identical"), "Main does not contain the PR 517 merge.")
    for name, digest in WORKFLOWS.items():
        item = api(f"/contents/.github/workflows/{name}?ref={main_sha}")
        require(item["encoding"] == "base64" and item["type"] == "file", f"Unexpected file metadata for {name}.")
        body = base64.b64decode("".join(item["content"].split()), validate=True)
        require(hashlib.sha256(body).hexdigest() == digest,
                f"{name} differs from the reviewed guard. Review the changed workflow before using this helper.")


@dataclass(frozen=True)
class State:
    scoped: bool
    reviewers: tuple
    prevent_self_review: bool
    can_admins_bypass: bool
    policies: tuple  # ((type, name), id), sorted. Preserve IDs for conditional deletion.


def inspect(name):
    path = "/environments/" + name
    env = api(path, missing=True)
    if env is None:
        return None
    require(env["name"] == name, "Unexpected environment identity.")
    types = [r["type"] for r in env["protection_rules"]]
    require(len(set(types)) == len(types) and set(types) <= {"required_reviewers", "branch_policy"},
            f"{name} has an unexpected deployment protection rule.")
    apps = api(path + "/deployment_protection_rules?per_page=100")
    require(apps["total_count"] == 0 and apps["custom_deployment_protection_rules"] == [],
            f"{name} has custom deployment protection rules.")
    scope = env["deployment_branch_policy"]
    require(scope is None or scope == SCOPE, f"{name} has an unexpected deployment scope.")
    require(("branch_policy" in types) == (scope is not None), f"{name} reports inconsistent branch protection.")
    require(isinstance(env["can_admins_bypass"], bool), f"{name} lacks an explicit bypass setting.")
    reviewers = []
    prevent = False
    for rule in env["protection_rules"]:
        if rule["type"] == "required_reviewers":
            prevent = rule["prevent_self_review"]
            require(isinstance(prevent, bool) and bool(rule["reviewers"]), f"{name} has a malformed reviewer rule.")
            for reviewer in rule["reviewers"]:
                key = (reviewer["type"], reviewer["reviewer"]["id"])
                require(key[0] in ("User", "Team") and type(key[1]) is int and key[1] > 0
                        and key not in reviewers, f"{name} has a malformed reviewer.")
                reviewers.append(key)
    policies = []
    if scope:
        page = api(path + "/deployment-branch-policies?per_page=100")
        for p in page["branch_policies"]:
            key = (p["type"], p["name"])
            require(key not in dict(policies) and type(p["id"]) is int and p["id"] > 0,
                    f"{name} has a malformed or duplicate branch policy.")
            policies.append((key, p["id"]))
        require(page["total_count"] == len(policies), f"{name} has additional branch policies.")
    return State(scope == SCOPE, tuple(sorted(reviewers)), prevent, env["can_admins_bypass"], tuple(sorted(policies)))


def check_release(release, manual):
    require(release is not None and release.scoped, "Expected the existing protected release environment.")
    keys = set(dict(release.policies))
    require(MAIN in keys and keys <= {MAIN, OLD_TAGS}, "Unexpected release branch or tag policy.")
    if not release.reviewers:
        require(keys == {MAIN} and manual is not None and bool(manual.reviewers)
                and manual.scoped and set(dict(manual.policies)) == {MAIN},
                "Release has no reviewers and a completed manual approval environment could not be verified.")


def stage_plan(name, state, reviewers, prevent, bypass):
    if state:
        require(not state.reviewers or (state.reviewers == reviewers and state.prevent_self_review == prevent),
                f"{name} already has a different reviewer configuration.")
        require(not reviewers or bypass or not state.can_admins_bypass,
                f"{name} permits an administrator bypass disallowed by release.")
        require(set(dict(state.policies)) <= {MAIN}, f"{name} has an unexpected branch or tag policy.")
    configure = not state or not state.scoped or state.reviewers != reviewers
    add_main = not state or MAIN not in dict(state.policies)
    return configure, add_main


def reviewers_json(reviewers):
    return [{"type": kind, "id": ident} for kind, ident in reviewers]


def verify_stage(name, reviewers, prevent, bypass):
    state = inspect(name)
    require(state and state.scoped and state.reviewers == reviewers
            and state.prevent_self_review == prevent and state.can_admins_bypass == bypass
            and set(dict(state.policies)) == {MAIN}, f"{name} read-back differs from the intended settings.")


def stage(name, before, reviewers, prevent, bypass, apply):
    configure, add_main = stage_plan(name, before, reviewers, prevent, bypass)
    target_bypass = before.can_admins_bypass if before else bypass
    actions = []
    if configure:
        actions.append("configure deployment scope and reviewers")
    if add_main:
        actions.append("allow branch main")
    description = ", ".join(actions) if actions else "already configured"
    print(f"{name}: {description} ({len(reviewers)} designated reviewers).", flush=True)
    if not apply:
        return
    require(inspect(name) == before, f"{name} changed during preflight. Run the preview again.")
    path = "/environments/" + name
    if configure:
        api(path, "PUT", {"deployment_branch_policy": SCOPE, "can_admins_bypass": target_bypass,
                          "reviewers": reviewers_json(reviewers), "prevent_self_review": prevent})
    if add_main:
        api(path + "/deployment-branch-policies", "POST", {"type": "branch", "name": "main"})
    verify_stage(name, reviewers, prevent, target_bypass)


def run(apply):
    guard_workflows()
    release, manual, cut = (inspect(name) for name in ("release", "release-manual", "version-cut"))
    check_release(release, manual)
    source = release if release.reviewers else manual
    people, prevent = source.reviewers, source.prevent_self_review
    manual_bypass = manual.can_admins_bypass if manual else release.can_admins_bypass
    cut_bypass = cut.can_admins_bypass if cut else release.can_admins_bypass
    # Validate EVERY environment before making the first change.
    stage_plan("release-manual", manual, people, prevent, release.can_admins_bypass)
    stage_plan("version-cut", cut, (), False, cut_bypass)
    stage("release-manual", manual, people, prevent, release.can_admins_bypass, apply)
    stage("version-cut", cut, (), False, cut_bypass, apply)

    old_tag_id = dict(release.policies).get(OLD_TAGS)
    if old_tag_id:
        print("release: remove the v* tag allowance.", flush=True)
    if release.reviewers:
        print("release: remove the duplicate deployment review after verifying manual approval.", flush=True)
    if not apply:
        print("Preview complete. To apply these changes, rerun with --apply.")
        return
    guard_workflows()
    verify_stage("release-manual", people, prevent, manual_bypass)
    verify_stage("version-cut", (), False, cut_bypass)
    require(inspect("release") == release, "Release changed during setup. Run the preview again.")
    if old_tag_id:
        api(f"/environments/release/deployment-branch-policies/{old_tag_id}", "DELETE")
    current = inspect("release")
    expected = State(True, release.reviewers, release.prevent_self_review, release.can_admins_bypass,
                     tuple(p for p in release.policies if p[0] != OLD_TAGS))
    require(current == expected, "Release branch restriction was not confirmed.")
    if release.reviewers:
        # Check the alternate approval path immediately before the last change.
        verify_stage("release-manual", people, prevent, manual_bypass)
        api("/environments/release", "PUT", {"deployment_branch_policy": SCOPE, "reviewers": [],
                                            "prevent_self_review": False, "can_admins_bypass": release.can_admins_bypass})
    verify_stage("release", (), False, release.can_admins_bypass)
    verify_stage("release-manual", people, prevent, manual_bypass)
    verify_stage("version-cut", (), False, cut_bypass)
    print("Verified all three environments. Manual signing retains its designated reviewers.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply and verify changes (default is read-only)")
    args = parser.parse_args()
    try:
        run(args.apply)
    except (Stop, KeyError, ValueError, TypeError) as exc:
        print(f"Stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
