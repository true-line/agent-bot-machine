#!/usr/bin/env bash
# No signing identity, Keychain, or Apple connection is needed for these cases.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$root/packaging/darwin/owner-profile.py" <<'PY'
import copy
import datetime
import hashlib
from pathlib import Path
import plistlib
import runpy
import shutil
import subprocess
import sys
import tempfile

signer = runpy.run_path(sys.argv[1])
team, app, resolve = signer["TEAM"], signer["APP"], signer["resolve"]
prefix = "A123456789"
group = prefix + "." + app
rights = {
    "com.apple.developer.team-identifier": team,
    "com.apple.application-identifier": group,
    "keychain-access-groups": [prefix + ".*"],
}
template = {
    "com.apple.developer.team-identifier": "$(DEVELOPMENT_TEAM)",
    "com.apple.application-identifier": "$(AppIdentifierPrefix)" + app,
    "keychain-access-groups": ["$(AppIdentifierPrefix)" + app],
}
profile = {
    "ApplicationIdentifierPrefix": [prefix], "TeamIdentifier": [team],
    "Platform": ["OSX"], "ProvisionsAllDevices": True,
    "ExpirationDate": datetime.datetime(2099, 1, 1),
    "DeveloperCertificates": [b"test certificate"], "Entitlements": rights,
}
cert = b"test certificate"
fingerprint = hashlib.sha1(cert).hexdigest().upper()
for groups in ([group], [prefix + ".*"]):
    profile["Entitlements"]["keychain-access-groups"] = groups
    entitlements, leaf = resolve(profile, template, fingerprint)
    assert entitlements["keychain-access-groups"] == [group] and leaf == cert

def refuse(candidate, label, requested=template, identity=fingerprint):
    try:
        resolve(candidate, requested, identity)
    except ValueError as error:
        assert str(error) == label
        return
    raise AssertionError(f"unexpectedly accepted {label}")

marker = "synthetic-private-value"
for field, value in [
    ("ApplicationIdentifierPrefix", [marker]), ("ApplicationIdentifierPrefix", [123]),
    ("TeamIdentifier", [marker]), ("ProvisionsAllDevices", False),
    ("ExpirationDate", datetime.datetime(2000, 1, 1)), ("ExpirationDate", marker),
    ("ProvisionedDevices", []), ("Platform", ["iOS"]), ("Platform", "OSX"),
    ("DeveloperCertificates", [marker.encode()]), ("DeveloperCertificates", cert),
    ("Entitlements", [marker]),
]:
    refuse(dict(profile, **{field: value}), field)
for field, value in [
    ("com.apple.developer.team-identifier", marker),
    ("com.apple.application-identifier", prefix + ".ai.true-line.agent-bot-machine"),
    ("com.apple.application-identifier", prefix + ".*"),
    ("keychain-access-groups", ["*"]), ("keychain-access-groups", {group: marker}),
    ("com.apple.security.get-task-allow", True),
]:
    other = copy.deepcopy(profile)
    other["Entitlements"][field] = value
    refuse(other, "Entitlements." + field)
for field in profile:
    missing = dict(profile)
    del missing[field]
    refuse(missing, field)
refuse(profile, "DeveloperCertificates", identity=hashlib.sha1(marker.encode()).hexdigest().upper())
refuse(profile, "Identity entitlements template", requested=dict(template, **{marker: marker}))

# Run the production signer up to the first packaging step. The replacement
# tools neither inspect a real Keychain nor invoke codesign or Apple services.
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory) / marker
    repo = Path(sys.argv[1]).resolve().parents[2]
    work = root / "owner"
    work.mkdir(parents=True)
    tools = root / "bin"
    tools.mkdir()
    (root / "packaging").symlink_to(repo / "packaging", target_is_directory=True)
    template_path = root / "owner-source/owner-presence-macos/OwnerPresence.entitlements"
    template_path.parent.mkdir(parents=True)
    template_path.write_bytes(plistlib.dumps(template))
    for name in ("awk", "python3"):
        (tools / name).symlink_to(shutil.which(name))
    security = tools / "security"
    security.write_text("""#!/bin/sh
[ "$*" = 'find-identity -v -p codesigning fixture' ] || exit 72
printf '  1) %s "Developer ID Application: Fixture (Z5DM34QS5U)"\\n' "$FIXTURE_FINGERPRINT"
""")
    security.chmod(0o755)
    install = tools / "install"
    install.write_text("#!/bin/sh\nexit 73\n")
    install.chmod(0o755)
    env = dict(PATH=str(tools), RUNNER_TEMP=str(root), SIGN_KEYCHAIN="fixture", NOTARY_KEY_PATH="fixture",
               NOTARY_KEY_ID="fixture", NOTARY_ISSUER_ID="fixture", FIXTURE_FINGERPRINT=fingerprint)

    def preflight(profile_bytes, label=None):
        (work / "profile.plist").write_bytes(profile_bytes)
        leaf = work / "identity.der"
        if leaf.exists():
            leaf.unlink()
        proc = subprocess.run(["/bin/bash", repo / "scripts/sign-owner-app", "0.12.4"],
                              cwd=root, env=env, capture_output=True, check=False)
        assert proc.stdout == b""
        if label is None:
            assert proc.returncode == 73 and proc.stderr == b""
            assert leaf.read_bytes() == cert
            assert plistlib.loads((work / "entitlements.plist").read_bytes()) == entitlements
        else:
            assert proc.returncode == 1 and not leaf.exists()
            assert proc.stderr.decode() == f"Invalid owner approval profile or entitlements: {label}\n"
            assert (work / "entitlements.plist").stat().st_size == 0

    preflight(plistlib.dumps(dict(profile, DeveloperCertificates=[marker.encode(), cert])))
    preflight(plistlib.dumps(dict(profile, DeveloperCertificates=[marker.encode()])), "DeveloperCertificates")
    malformed = f"<plist><integer>{marker}</integer></plist>".encode()
    preflight(malformed, "profile")
    template_path.write_bytes(malformed)
    preflight(plistlib.dumps(profile), "Identity entitlements template")

print("Owner signing preflight selected the exact leaf and reported only failed check names.")
PY
