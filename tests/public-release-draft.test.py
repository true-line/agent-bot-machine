import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify-public-draft.py"


class DraftTest(unittest.TestCase):
    def test_workflow_reads_all_asset_pages(self):
        pages = [[{"name": name, "label": None, "uploader": {"id": 41898282, "type": "Bot"}}]
                 for name in ("first", "second")]

        class Assets(BaseHTTPRequestHandler):
            def do_GET(self):
                second = parse_qs(urlsplit(self.path).query).get("page") == ["2"]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if not second:
                    self.send_header("Link", f'<http://127.0.0.1:{self.server.server_port}/assets?page=2>; rel="next"')
                self.end_headers()
                self.wfile.write(json.dumps(pages[int(second)]).encode())

            def log_message(self, *args):
                pass

        with HTTPServer(("127.0.0.1", 0), Assets) as server, tempfile.TemporaryDirectory() as home:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                endpoint = "repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID/assets?per_page=100"
                workflow = (SCRIPT.parents[1] / ".github/workflows/release.yml").read_text().replace("\\\n", "")
                reads = [line.strip() for line in workflow.splitlines() if endpoint in line]
                self.assertEqual(len(reads), 2)
                for line in reads:
                    args = shlex.split(line)
                    self.assertEqual(args[:2], ["gh", "api"])
                    self.assertEqual(args.pop(), "|")
                    # Substitute only the API endpoint. Exercise the workflow's real gh flags and page handling.
                    args[args.index(endpoint)] = f"http://127.0.0.1:{server.server_port}/assets?per_page=100"
                    args[0] = shutil.which("gh")
                    self.assertIsNotNone(args[0], "the release workflow requires GitHub CLI")
                    got = subprocess.run(args, check=True, capture_output=True, text=True, timeout=10,
                                         env={"HOME": home, "GH_CONFIG_DIR": home, "GH_TOKEN": "fixture",
                                              "GH_NO_UPDATE_NOTIFIER": "1"})
                    self.assertEqual(json.loads(got.stdout), pages[0] + pages[1])
            finally:
                server.shutdown()
                thread.join()

    def test_all_published_bytes_and_original_ids(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            dist = ["SHA256SUMS"]
            metadata = ["support-matrix.md", "Formula/managed-machine.rb"]
            for target in ("darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64", "windows_arm64"):
                suffix = "zip" if target.startswith("windows") else "tar.gz"
                dist.append(f"managed-machine_1.2.3_{target}.{suffix}")
                metadata.append("release-gate-" + target.replace("_", "-") + ".json")

            bot = {"id": 41898282, "type": "Bot"}
            rows = []
            for i, path in enumerate([*("signed/" + f for f in dist), *metadata], 1):
                f = root / path
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(f.name.encode())
                rows.append(dict(id=i, name=f.name, state="uploaded", label=None, uploader=bot,
                                 digest="sha256:" + hashlib.sha256(f.read_bytes()).hexdigest()))

            def run(phase, assets, ok, version="1.2.3"):
                cmd = [sys.executable, str(SCRIPT), phase, version, str(root / "snapshot")]
                r = subprocess.run(cmd, input=json.dumps(assets), text=True, capture_output=True, cwd=root)
                self.assertEqual(r.returncode == 0, ok)
                if not ok or phase == "downloaded":
                    self.assertEqual(r.stdout, "")
                if not ok:
                    self.assertEqual(r.stderr.strip(), "Public release draft inventory, attribution or digest mismatch")
                return r.stdout

            run("downloaded", rows[:len(dist)], True)
            body = run("publish", rows, True)
            repo = "https://github.com/true-line/agent-bot-machine"
            for url in (repo + "/commits/v1.2.3", *(repo + "/releases/download/v1.2.3/" + name
                        for name in ("SHA256SUMS", "support-matrix.md", "managed-machine.rb"))):
                self.assertIn("(" + url + ")", body)
            attribution = "Unreviewed change by @fixture-contributor"
            (root / "notes.md").write_text(attribution)
            self.assertEqual(run("publish", [dict(row, label="") for row in rows], True), body)
            for change in ({"label": attribution}, {"uploader": {"id": 41898282, "type": "User"}},
                           {"uploader": {"id": 1000, "type": "Bot"}}, {"uploader": None}, {"uploader": {}}):
                # An initial download or a retry with metadata already present must
                # refuse before the workflow uploads any replacement assets.
                for i in (0, len(dist)):
                    candidate = rows.copy()
                    candidate[i] = dict(candidate[i], **change)
                    run("downloaded", candidate, False)
                    run("publish", candidate, False)
            for missing in ("label", "uploader"):
                row = rows[0].copy()
                del row[missing]
                run("publish", [row, *rows[1:]], False)
            self.assertNotIn("fixture-contributor", body)
            run("publish", rows, False, version="1.2.3\n" + attribution)
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
