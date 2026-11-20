import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify-public-draft.py"


class DraftTest(unittest.TestCase):
    def test_all_published_bytes_and_original_ids(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            dist = ["SHA256SUMS"]
            metadata = ["support-matrix.md", "Formula/managed-machine.rb"]
            for target in ("darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64", "windows_arm64"):
                suffix = "zip" if target.startswith("windows") else "tar.gz"
                dist.append(f"managed-machine_1.2.3_{target}.{suffix}")
                metadata.append("release-gate-" + target.replace("_", "-") + ".json")

            rows = []
            for i, path in enumerate([*("signed/" + f for f in dist), *metadata], 1):
                f = root / path
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(f.name.encode())
                rows.append(dict(id=i, name=f.name, state="uploaded", digest="sha256:" + hashlib.sha256(f.read_bytes()).hexdigest()))

            def run(phase, assets, ok):
                cmd = [sys.executable, str(SCRIPT), phase, "1.2.3", str(root / "snapshot")]
                r = subprocess.run(cmd, input=json.dumps(assets), text=True, capture_output=True, cwd=root)
                self.assertEqual(r.returncode == 0, ok)
                self.assertEqual(r.stdout, "")
                if not ok:
                    self.assertEqual(r.stderr.strip(), "Public release draft inventory or digest mismatch")

            run("downloaded", rows[:len(dist)], True)
            run("publish", rows, True)
            run("downloaded", rows, True)  # retry with generated metadata already attached
            run("publish", [*rows, dict(rows[0], id=123, name="unexpected-attachment")], False)
            run("publish", [dict(rows[0], id=123), *rows[1:]], False)
            run("publish", [dict(rows[0], digest=rows[1]["digest"]), *rows[1:]], False)
            run("publish", [dict(rows[0], state="new"), *rows[1:]], False)
            run("publish", rows[:-1], False)
            run("publish", [*rows, rows[0]], False)
            (root / metadata[0]).write_bytes(b"changed after upload")
            run("publish", rows, False)


if __name__ == "__main__":
    unittest.main()
