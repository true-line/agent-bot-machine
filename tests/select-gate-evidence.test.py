"""Partial reruns keep untouched targets and select retries by numeric attempt."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/select-gate-evidence.py"


class GateEvidence(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.attempts = self.root / "attempts"
        self.attempts.mkdir()

    def put(self, target, attempt, result):
        stem = "provider-gate-" + target.replace("/", "-")
        directory = self.attempts / f"{stem}-attempt-{attempt}"
        directory.mkdir()
        file = directory / (stem + ".json")
        file.write_text(json.dumps({"target": target, "result": result}), encoding="utf-8")
        return file

    def select(self):
        return subprocess.run([sys.executable, SCRIPT, self.attempts, self.root / "selected"],
                              capture_output=True, text=True)

    def test_partial_retry_uses_latest_for_each_producer(self):
        mac = self.put("darwin/arm64", 1, "pass")
        self.put("linux/amd64", 1, "fail")
        newest = self.put("linux/amd64", 10, "pass")
        self.put("linux/amd64", 2, "fail")
        result = self.select()
        self.assertEqual(result.returncode, 0, result.stderr)
        for file in (mac, newest):
            self.assertEqual((self.root / "selected" / file.name).read_bytes(), file.read_bytes())

    def test_newer_failed_receipt_goes_to_existing_gate(self):
        self.put("linux/amd64", 1, "pass")
        failed = self.put("linux/amd64", 2, "fail")
        self.assertEqual(self.select().returncode, 0)
        self.assertEqual((self.root / "selected" / failed.name).read_bytes(), failed.read_bytes())

    def test_incomplete_latest_does_not_fall_back(self):
        self.put("linux/amd64", 1, "pass")
        self.put("linux/amd64", 2, "pass").unlink()
        self.assertNotEqual(self.select().returncode, 0)

    def test_target_label_matches_receipt(self):
        file = self.put("linux/amd64", 1, "pass")
        file.write_text('{"target":"darwin/arm64"}', encoding="utf-8")
        self.assertNotEqual(self.select().returncode, 0)


if __name__ == "__main__":
    unittest.main()
