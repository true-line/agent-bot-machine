"""Resolve the owner app's entitlements against a decoded Developer ID profile."""
import datetime
import hashlib
import plistlib
import re
import sys

TEAM = "Z5DM34QS5U"
APP = "ai.true-line.agent-bot-owner-presence"


class InvalidField(ValueError):
    """Identifies a failed check using a fixed label safe for the signing log."""


def require(condition, field):
    if not condition:
        raise InvalidField(field)


def array_of(value, item_type):
    return isinstance(value, list) and all(isinstance(item, item_type) for item in value)


def resolve(profile, template, fingerprint):
    require(isinstance(profile, dict), "profile")
    prefixes = profile.get("ApplicationIdentifierPrefix")
    require(
        array_of(prefixes, str) and len(prefixes) == 1 and re.fullmatch(r"[A-Z0-9]{10}", prefixes[0]),
        "ApplicationIdentifierPrefix",
    )
    group = f"{prefixes[0]}.{APP}"
    require(profile.get("TeamIdentifier") == [TEAM], "TeamIdentifier")
    platforms = profile.get("Platform")
    require(array_of(platforms, str) and "OSX" in platforms, "Platform")
    require(profile.get("ProvisionsAllDevices") is True, "ProvisionsAllDevices")
    require("ProvisionedDevices" not in profile, "ProvisionedDevices")
    expiry = profile.get("ExpirationDate")
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    require(isinstance(expiry, datetime.datetime) and expiry.tzinfo is None and expiry > now, "ExpirationDate")
    certificates = profile.get("DeveloperCertificates")
    require(array_of(certificates, bytes), "DeveloperCertificates")
    # codesign selects by SHA-1 fingerprint. Its full leaf DER is compared
    # again after signing, so the certificate name and list order are irrelevant.
    matches = {der for der in certificates if der and hashlib.sha1(der).hexdigest().upper() == fingerprint}
    require(len(matches) == 1, "DeveloperCertificates")

    rights = profile.get("Entitlements")
    require(isinstance(rights, dict), "Entitlements")
    require(rights.get("com.apple.developer.team-identifier") == TEAM,
            "Entitlements.com.apple.developer.team-identifier")
    require(rights.get("com.apple.application-identifier") == group,
            "Entitlements.com.apple.application-identifier")
    require(rights.get("com.apple.security.get-task-allow", False) is False,
            "Entitlements.com.apple.security.get-task-allow")
    groups = rights.get("keychain-access-groups")
    require(array_of(groups, str) and (group in groups or prefixes[0] + ".*" in groups),
            "Entitlements.keychain-access-groups")
    expected = {
        "com.apple.developer.team-identifier": "$(DEVELOPMENT_TEAM)",
        "com.apple.application-identifier": "$(AppIdentifierPrefix)" + APP,
        "keychain-access-groups": ["$(AppIdentifierPrefix)" + APP],
    }
    require(template == expected, "Identity entitlements template")
    entitlements = {
        "com.apple.developer.team-identifier": TEAM,
        "com.apple.application-identifier": group,
        "keychain-access-groups": [group],
    }
    return entitlements, matches.pop()


def load_plist(path, label):
    try:
        with open(path, "rb") as source:
            return plistlib.load(source)
    except Exception:
        # plistlib and its XML parser can include input values in errors.
        raise InvalidField(label) from None


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: owner-profile.py PROFILE TEMPLATE SIGNING_FINGERPRINT LEAF_DER_OUTPUT")
    try:
        profile = load_plist(sys.argv[1], "profile")
        template = load_plist(sys.argv[2], "Identity entitlements template")
        entitlements, leaf = resolve(profile, template, sys.argv[3])
        with open(sys.argv[4], "wb") as output:
            output.write(leaf)
        plistlib.dump(entitlements, sys.stdout.buffer)
    except InvalidField as error:
        sys.exit(f"Invalid owner approval profile or entitlements: {error}")
    except OSError:
        sys.exit("Could not write signing preflight output")
