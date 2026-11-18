#!/usr/bin/env bash
# No signing identity, Keychain, or Apple connection is needed for these cases.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$root/packaging/darwin/owner-profile.py" <<'PY'
import copy
import datetime
import runpy
import sys

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
for groups in ([group], [prefix + ".*"]):
    profile["Entitlements"]["keychain-access-groups"] = groups
    assert resolve(profile, template, cert)["keychain-access-groups"] == [group]

def refuse(candidate, requested=template, identity=cert):
    try:
        resolve(candidate, requested, identity)
    except ValueError:
        return
    raise AssertionError("unexpectedly accepted profile or entitlement")

for field, value in [
    ("TeamIdentifier", ["A000000000"]), ("ProvisionsAllDevices", False),
    ("ExpirationDate", datetime.datetime(2000, 1, 1)), ("ProvisionedDevices", []),
    ("Platform", ["iOS"]),
]:
    refuse(dict(profile, **{field: value}))
for field, value in [
    ("com.apple.application-identifier", prefix + ".ai.true-line.agent-bot-machine"),
    ("com.apple.application-identifier", prefix + ".*"),
    ("keychain-access-groups", ["*"]), ("com.apple.security.get-task-allow", True),
]:
    other = copy.deepcopy(profile)
    other["Entitlements"][field] = value
    refuse(other)
refuse(profile, identity=b"other certificate")
refuse(profile, requested=dict(template, **{"keychain-access-groups": ["*"]}))
print("Owner profile accepted two permitted group forms and refused eleven incompatible inputs.")
PY
