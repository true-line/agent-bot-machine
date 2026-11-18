"""Validate an exact Machine release cut. Invoked by version-cut.yml."""
import json
import os
import re
import subprocess
import sys


def require(ok, message):
    if not ok:
        raise ValueError(message)


def git(*args, env=None):
    return subprocess.check_output(["git", *args], text=True, env=env).strip()


def oid(value):
    require(re.fullmatch(r"[0-9a-f]{40}", value), "expected an immutable commit SHA")
    return value


def version(value):
    require(re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value, re.ASCII),
            f"invalid Machine version {value!r}")
    return tuple(map(int, value.split(".")))


def candidate(cut):
    require(git("rev-parse", "HEAD") == oid(cut), "checkout differs from triggering CI SHA")
    current = git("show", f"{cut}:VERSION")
    previous = git("show", f"{cut}^1:VERSION")
    if current == previous:
        return ""
    require(version(current) > version(previous), "release version must advance")
    for rev in [cut + "^1", cut]:
        require(git("show", f"{rev}:.github/machine-release-version") == current,
                "VERSION differs from the previously reviewed release request")
    return "v" + current


def select_ci(runs, repo, cut, workflow):
    matching = [r for r in runs if r["path"] == ".github/workflows/" + workflow
                and r["head_sha"] == oid(cut) and r["event"] == "push"
                and r["head_branch"] == "main" and r["head_repository"]["full_name"] == repo]
    if not matching:
        return ""
    latest = max(matching, key=lambda r: (r["run_number"], r["run_attempt"]))
    if latest["status"] != "completed":
        return ""
    require(latest["conclusion"] == "success", f"{workflow} concluded {latest['conclusion']}")
    return str(int(latest["id"]))


def select_pr(prs, repo, cut, tag):
    matches = [p for p in prs if p["merged_at"] and p["merge_commit_sha"] == oid(cut)
               and p["base"]["ref"] == "main" and p["base"]["repo"]["full_name"] == repo
               and p["head"]["ref"] == "release/" + tag and p["head"]["repo"]
               and p["head"]["repo"]["full_name"] == repo
               and p["user"]["type"] == "Bot" and p["user"]["login"] == "trueline-chores-dumb[bot]"]
    require(len(matches) == 1, "expected the merged Machine release PR at the exact cut SHA")
    return f"{int(matches[0]['number'])} {oid(matches[0]['head']['sha'])}"


def lineage(cut, tag, signed_base, pr_head):
    require(candidate(cut) == tag, "cut version changed")
    require(git("show", "-s", "--format=%P", oid(pr_head)) == oid(signed_base),
            "release PR must have one commit on the immutable signing SHA")
    require(git("show", "-s", "--format=%s", pr_head) == "Release " + tag,
            "unexpected release commit subject")
    require(git("rev-parse", cut + "^{tree}") == git("rev-parse", pr_head + "^{tree}"),
            "merged tree differs from the reviewed release PR")
    require(git("merge-base", signed_base, cut) == signed_base, "signing SHA is not a cut ancestor")
    paths = "Formula/managed-machine.rb\nVERSION"
    for base in [signed_base, cut + "^1"]:
        require(git("diff", "--name-only", base, cut) == paths, "unexpected release delta")
    require(git("show", f"{signed_base}:.github/machine-release-version") == tag[1:],
            "draft was signed for a different release request")


def remote_tag_state(cut, tag):
    target = version(tag.removeprefix("v"))
    require(tag.startswith("v"), "Machine tag must start with v")
    refs = {}
    for line in git("ls-remote", "--tags", "origin", "refs/tags/v*").splitlines():
        sha, ref = line.split("\t")
        refs[ref.removeprefix("refs/tags/")] = sha
    if tag in refs:
        require(refs.get(tag + "^{}") == oid(cut), f"{tag} exists at another commit or is lightweight")
        return "same"
    for existing in refs:
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", existing):
            require(version(existing[1:]) < target, f"newer Machine tag {existing} already exists")
    return "missing"


def tag_cut(cut, tag):
    require(candidate(cut) == tag, "requested tag differs from cut version")
    if remote_tag_state(cut, tag) == "same":
        return
    git("fetch", "--quiet", "--no-tags", "origin", "+refs/heads/main:refs/remotes/origin/main")
    main = "refs/remotes/origin/main"
    require(git("merge-base", cut, main) == cut, "cut is no longer on main")
    for path in ["VERSION", ".github/machine-release-version"]:
        require(git("show", f"{main}:{path}") == tag[1:], "release request was superseded on main")
    env = dict(os.environ, GIT_COMMITTER_NAME="trueline-chores-dumb[bot]",
               GIT_COMMITTER_EMAIL="trueline-chores-dumb[bot]@users.noreply.github.com")
    git("-c", "tag.gpgSign=false", "tag", "-a", tag, oid(cut), "-m", "Release " + tag, env=env)
    # Git rejects an existing different ref. A concurrent identical cut is
    # successful even if its annotated tag object has a different timestamp.
    pushed = subprocess.run(["git", "push", "origin", f"refs/tags/{tag}:refs/tags/{tag}"])
    require(remote_tag_state(cut, tag) == "same", f"annotated tag push failed ({pushed.returncode})")


if __name__ == "__main__":
    try:
        mode, *args = sys.argv[1:]
        if mode == "candidate":
            print(candidate(*args))
        elif mode == "ci":
            print(select_ci(json.load(sys.stdin)["workflow_runs"], *args))
        elif mode == "pr":
            print(select_pr(json.load(sys.stdin), *args))
        elif mode == "lineage":
            lineage(*args)
        elif mode == "existing":
            print(remote_tag_state(*args))
        elif mode == "tag":
            tag_cut(*args)
        else:
            raise ValueError("unknown version-cut command")
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(f"version cut: {error}")
