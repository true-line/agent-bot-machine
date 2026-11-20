"""Select the latest producing attempt for each gate and native target in this run."""

import json
import re
import shutil
import sys
from pathlib import Path

ARTIFACT = re.compile(
    r"(?P<stem>(?:walkthrough|(?:install|provider|config|fleet|release)-gate)-"
    r"(?P<os>linux|darwin|windows)-(?P<arch>arm64|amd64))-attempt-(?P<attempt>[1-9][0-9]*)"
)


def select(source, destination):
    latest = {}
    for artifact in source.iterdir():
        name = ARTIFACT.fullmatch(artifact.name)
        if name is None or not artifact.is_dir() or artifact.is_symlink():
            raise ValueError(f"unexpected gate artifact: {artifact.name}")
        stem = name["stem"]
        attempt = int(name["attempt"])
        if stem not in latest or attempt > latest[stem][0]:
            latest[stem] = (attempt, artifact, f'{name["os"]}/{name["arch"]}')

    if not latest:
        raise ValueError("no gate receipts were downloaded")
    destination.mkdir()
    for stem, (attempt, artifact, target) in sorted(latest.items()):
        receipt = artifact / (stem + ".json")
        if list(artifact.iterdir()) != [receipt] or receipt.is_symlink() or not receipt.is_file():
            raise ValueError(f"expected exactly {receipt.name} in {artifact.name}")
        with receipt.open(encoding="utf-8") as stream:
            if json.load(stream)["target"] != target:
                raise ValueError(f"{artifact.name} contains evidence for a different target")
        # Existing Go gates still validate the contents, including failures and revision.
        shutil.copyfile(receipt, destination / receipt.name)
        print(f"{stem}: producer attempt {attempt}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: select-gate-evidence.py ARTIFACT_DIRECTORIES NEW_DESTINATION")
    try:
        select(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, KeyError, TypeError, ValueError) as exc:
        sys.exit(f"gate evidence selection failed: {exc}")
