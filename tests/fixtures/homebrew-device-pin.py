"""Read the generated Homebrew release pin without loading the formula as Ruby."""
import os
import re
import subprocess
import sys
from pathlib import Path

FORMULA = "Formula/managed-machine.rb"
LEGACY = ("0.12.4", "e98ea0d764b13e9b30c714bb9b299fff80ec1f07cbcd30e4037f3bdb795a2b6e")


def single(pattern, text):
    matches = re.findall(pattern, text, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("expected a single Homebrew release pin")
    return matches[0]


def pin(text):
    header = text.split('  resource "', 1)[0]
    source = single(r'^  url "([^"]+)",$', header)
    if source != "https://github.com/true-line/agent-bot-machine.git":
        raise ValueError("unexpected Homebrew source repository")
    version = single(r'^  version "((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})"$', header)
    core = single(r'^  resource "core" do\n((?:    [^\n]*\n)+)  end$', text)
    tag = single(r'^      tag:   "([^"]+)"$', header)
    url = single(r'^    url "([^"]+)"$', core)
    asset = f"managed-machine_{version}_darwin_arm64.tar.gz"
    if tag != "v" + version or url != f"https://github.com/true-line/agent-bot-machine/releases/download/{tag}/{asset}":
        raise ValueError("Homebrew release version, source tag and Darwin URL disagree")
    return version, single(r'^    sha256 "([0-9a-f]{64})"$', core)


def at(revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("expected an immutable push commit")
    return pin(subprocess.check_output(["git", "show", f"{revision}:{FORMULA}"], text=True))


def qualification(previous, current):
    if previous == current:
        return "unchanged"
    if previous[0] == current[0] or (current[0] == LEGACY[0] and current != LEGACY):
        raise ValueError("a published Homebrew version changed its archive checksum")
    if current == LEGACY:
        return "package"
    return "custody"


def push_selection(env, read=at):
    if env["GITHUB_EVENT_NAME"] == "pull_request":
        return {}
    if (env["GITHUB_EVENT_NAME"] != "push" or env["GITHUB_REPOSITORY"] != "true-line/agent-bot-machine"
            or env["GITHUB_REF"] != "refs/heads/main" or env["PROTECTED"] != "true"
            or env["AFTER"] != env["GITHUB_SHA"]):
        raise ValueError("expected an immutable protected-main push")
    previous, current = read(env["BEFORE"]), read(env["AFTER"])
    return {"mode": qualification(previous, current), "version": current[0], "digest": current[1]}


if __name__ == "__main__":
    if sys.argv[1:] == ["--event"]:
        for key, value in push_selection(os.environ).items():
            print(f"{key}={value}")
    elif len(sys.argv) == 2:
        print(*pin(Path(sys.argv[1]).read_text(encoding="utf-8")))
    else:
        sys.exit("expected a formula path or --event")
