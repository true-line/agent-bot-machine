"""Resolve the owner app's entitlements against a decoded Developer ID profile."""
import datetime
import hashlib
import plistlib
import re
import sys

TEAM = "Z5DM34QS5U"
APP = "ai.true-line.agent-bot-owner-presence"


def resolve(profile, template, certificate):
    rights = profile["Entitlements"]
    prefix, = profile["ApplicationIdentifierPrefix"]
    group = f"{prefix}.{APP}"
    if not (
        re.fullmatch(r"[A-Z0-9]{10}", prefix)
        and profile["TeamIdentifier"] == [TEAM]
        and "OSX" in profile["Platform"]
        and profile.get("ProvisionsAllDevices") is True
        and "ProvisionedDevices" not in profile
        and profile["ExpirationDate"] > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        and any(hashlib.sha1(der).hexdigest().upper() == certificate for der in profile["DeveloperCertificates"])
        and rights.get("com.apple.developer.team-identifier") == TEAM
        and rights.get("com.apple.application-identifier") == group
        and not rights.get("com.apple.security.get-task-allow")
        and any(g in (group, prefix + ".*") for g in rights.get("keychain-access-groups", []))
    ):
        raise ValueError("profile does not authorize the owner app and this Developer ID certificate")
    expected = {
        "com.apple.developer.team-identifier": "$(DEVELOPMENT_TEAM)",
        "com.apple.application-identifier": "$(AppIdentifierPrefix)" + APP,
        "keychain-access-groups": ["$(AppIdentifierPrefix)" + APP],
    }
    if template != expected:
        raise ValueError("review the updated Identity entitlements before signing")
    return {
        "com.apple.developer.team-identifier": TEAM,
        "com.apple.application-identifier": group,
        "keychain-access-groups": [group],
    }


if __name__ == "__main__":
    try:
        with open(sys.argv[1], "rb") as profile, open(sys.argv[2], "rb") as template:
            result = resolve(plistlib.load(profile), plistlib.load(template), sys.argv[3])
        plistlib.dump(result, sys.stdout.buffer)
    except (KeyError, TypeError, ValueError) as error:
        sys.exit(f"Invalid owner approval profile or entitlements: {error}")
