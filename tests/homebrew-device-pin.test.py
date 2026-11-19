import importlib.util
from pathlib import Path
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

    def test_pr_never_reads_a_release_pin(self):
        self.assertEqual(pins.push_selection({"GITHUB_EVENT_NAME": "pull_request"}, self.fail), {})


if __name__ == "__main__":
    unittest.main()
