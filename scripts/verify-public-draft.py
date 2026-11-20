"""Match the assets being published to the signed dist and release-gate files."""
import hashlib
import json
from pathlib import Path
import re
import sys


def require(condition):
    if not condition:
        raise ValueError


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def check(phase, version, snapshot, rows):
    require(phase in ("downloaded", "publish"))
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version))
    targets = ("darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64", "windows_arm64")
    dist = {"SHA256SUMS": Path("signed/SHA256SUMS")}
    metadata = {"support-matrix.md": Path("support-matrix.md"), "managed-machine.rb": Path("Formula/managed-machine.rb")}
    for target in targets:
        suffix = "zip" if target.startswith("windows_") else "tar.gz"
        archive = f"managed-machine_{version}_{target}.{suffix}"
        dist[archive] = Path("signed", archive)
        gate = "release-gate-" + target.replace("_", "-") + ".json"
        metadata[gate] = Path(gate)

    require(isinstance(rows, list))
    assets = {row["name"]: row for row in rows}
    require(len(assets) == len(rows) and len({row["id"] for row in rows}) == len(rows))
    require(dist.keys() <= assets.keys() <= dist.keys() | metadata.keys())
    observed = {}
    for name, path in (dist if phase == "downloaded" else dist | metadata).items():
        row = assets[name]
        require(row["state"] == "uploaded" and type(row["id"]) is int and row["id"] > 0)
        require(row["digest"] == digest(path))
        if name in dist:
            observed[name] = row["id"]
    if phase == "downloaded":
        snapshot.write_text(json.dumps(observed))
    else:
        require(observed == json.loads(snapshot.read_text()))
        repo = "https://github.com/true-line/agent-bot-machine"
        tag = f"v{version}"
        downloads = f"{repo}/releases/download/{tag}"
        print(f"[Changes through {tag}]({repo}/commits/{tag}).")
        print()
        print(f"See the [support matrix]({downloads}/support-matrix.md) for tested targets. "
              f"Verify downloads with the [SHA-256 checksums]({downloads}/SHA256SUMS). "
              f"The [Homebrew formula]({downloads}/managed-machine.rb) pins the macOS archive.")


if __name__ == "__main__":
    try:
        check(sys.argv[1], sys.argv[2], Path(sys.argv[3]), json.load(sys.stdin))
    except (IndexError, KeyError, OSError, TypeError, ValueError):
        sys.exit("Public release draft inventory or digest mismatch")
