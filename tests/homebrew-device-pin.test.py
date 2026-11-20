import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

PATH = Path(__file__).parent / "fixtures" / "homebrew-device-pin.py"
spec = importlib.util.spec_from_file_location("homebrew_device_pin", PATH)
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)


class HomebrewDevicePinTest(unittest.TestCase):
    def test_formula_and_protected_push(self):
        before, after = "1" * 40, "2" * 40
        event = dict(GITHUB_EVENT_NAME="push", GITHUB_REPOSITORY="true-line/agent-bot-machine",
                     GITHUB_REF="refs/heads/main", PROTECTED="true", BEFORE=before, AFTER=after, GITHUB_SHA=after)
        formula = (Path(__file__).resolve().parents[1] / pins.FORMULA).read_text()
        version, sha = pins.pin(formula)
        edited = formula.replace('desc "', 'desc "Edited ')
        self.assertEqual(pins.pin(edited), (version, sha))
        self.assertRaises(ValueError, pins.pin, formula.replace(f'tag:   "v{version}"', 'tag:   "v0.0.0"'))
        self.assertRaises(ValueError, pins.pin, formula.replace('    sha256 "', '    sha256 "extra'))
        cases = [
            (pins.pin(formula), pins.pin(edited), "unchanged"),
            (("0.12.1", "a" * 64), pins.LEGACY, "package"),
            (pins.LEGACY, ("0.12.5", "b" * 64), "custody"),
            (("0.12.5", "a" * 64), ("0.12.6", "c" * 64), "custody"),
        ]
        for previous, current, expected in cases:
            self.assertEqual(pins.push_selection(event, {before: previous, after: current}.__getitem__),
                             {"mode": expected, "version": current[0], "digest": current[1]})
        self.assertRaises(ValueError, pins.qualification, ("0.12.1", "a" * 64), ("0.12.4", "b" * 64))
        self.assertRaises(ValueError, pins.qualification, ("0.12.6", "a" * 64), ("0.12.6", "b" * 64))
        for field, value in [("PROTECTED", "false"), ("GITHUB_REF", "refs/heads/test"), ("AFTER", before)]:
            self.assertRaises(ValueError, pins.push_selection, {**event, field: value}, self.fail)

    def test_release_attached_formula_checks_installed_source_each_time(self):
        stage = PATH.with_name("stage-darwin-hq-device.sh")
        script = r"""
            set -eu
            source "$1"
            receipt="$PWD/Cellar/managed-machine/1.2.3/libexec/RELEASE_COMMIT"
            mkdir -p "$(dirname "$receipt")" bin
            printf '#!/bin/sh\necho 1.2.3\n' > bin/managed-machine
            chmod 0755 bin/managed-machine
            install_homebrew_device_release() { printf '%s\n' "$first" > "$receipt"; }
            verify_homebrew_device_binary() { :; }
            verify_device_release_signature() { :; }
            brew_fixture() {
                echo "$1" >> operations
                if [[ "$1" == reinstall ]]; then printf '%s\n' "$second" > "$receipt"; fi
            }
            first="$2" second="$3"
            qualify_homebrew_device_release brew_fixture "$PWD" 1.2.3 unused unused "$4"
        """
        cut, older = "a" * 40, "b" * 40
        cases = [(cut, cut, cut, True, ["test", "reinstall", "test"]),
                 (older, cut, cut, False, []),
                 (cut, older, cut, False, ["test", "reinstall"]),
                 (older, older, "", True, ["test", "reinstall", "test"])]
        for first, second, expected, ok, operations in cases:
            with self.subTest(first=first, second=second, expected=expected), tempfile.TemporaryDirectory() as work:
                result = subprocess.run(["bash", "-c", script, "test", stage, first, second, expected],
                                        cwd=work, capture_output=True)
                self.assertEqual(result.returncode == 0, ok)
                log = Path(work, "operations")
                self.assertEqual(log.read_text().splitlines() if log.exists() else [], operations)

    def test_published_recipe_requires_the_verified_bytes(self):
        fixture = PATH.with_name("install-homebrew-darwin-hq-device.sh")
        script = """
            source "$1"
            download_device_release_asset() {
                [[ "$1" == '1.2.3' && "$2" == managed-machine.rb ]] && cp input "$3"
            }
            use_published_device_formula 1.2.3 "$2" downloaded.rb tapped.rb
        """
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            published = b"release-attached formula"
            (scratch / "input").write_bytes(published)
            digest = hashlib.sha256(published).hexdigest()
            tapped = scratch / "tapped.rb"
            for expected, accepted in [(digest, True), ("0" * 64, False), ("", False)]:
                with self.subTest(expected=expected):
                    tapped.write_bytes(b"previous tap pin")
                    result = subprocess.run(["bash", "-c", script, "test", fixture, expected],
                                            cwd=scratch, capture_output=True)
                    self.assertEqual(result.returncode == 0, accepted)
                    self.assertEqual(tapped.read_bytes(), published if accepted else b"previous tap pin")

    def test_pr_never_reads_a_release_pin(self):
        self.assertEqual(pins.push_selection({"GITHUB_EVENT_NAME": "pull_request"}, self.fail), {})


if __name__ == "__main__":
    unittest.main()
