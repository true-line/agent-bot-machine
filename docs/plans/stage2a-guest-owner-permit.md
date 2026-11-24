# Disposable Tart guest owner permit

## Intent

This one-use qualification path lets the already paired macOS Machine
administrator sign a permit for a specific guest Machine owner challenge.
It does not install, approve, or apply a members plan. The ordinary owner
helper's same-host Machine pin remains mandatory outside a distinct
guest-only review command in the identity repository.

## Target

The administrator runs
`managed-machine daemon guest-owner-permit CHALLENGE_FILE VM_NAME VM_MAC
GUEST_BUILD TARTCTL_SHA256 TART_APP_SHA256 --human`. The private challenge
file lives in the administrator's mode 0700 `~/Library/TartQualification`
directory and is mode 0600. The command requires the current paired Machine
identity and owner pin, rejects an agent session, checks the guest-signed
response and the exact plan digest, then observes the running VM through the
locally pinned Tart wrapper. It compares the VM's host-reported MAC, the
guest's interface MAC and OS build, and the guest's published Machine key.
The administrator supplies the independently reviewed wrapper and app digests;
Machine checks those bytes and signs both digests into the permit. The
identity reviewer must display both to the owner. No SSH host key or
guest-supplied claim substitutes for direct observation.

The output is JSON version 1. Its host signature is Ed25519 over UTF-8
`agent-bot-machine-owner/guest-permit/v1` followed by a newline and these
newline-separated fields in order: version, host Machine key, guest Machine
key, VM name, VM MAC, guest build, Tart wrapper SHA-256, Tart app SHA-256,
action, HQ key, owner key, plan ID, plan
digest, SHA-256 of the exact signed guest response frame without its trailing
newline, challenge nonce, issued-at Unix seconds, expires-at Unix seconds,
permit nonce, then a final newline. `signature` is standard base64 and is
excluded from the signed bytes. The permit expires with the guest challenge,
at most 120 seconds after issue. The guest-only identity reviewer must
verify this signature under the installed physical host Machine pin, verify
the guest signature and every exact field, recheck expiry after local owner
presence, and rely on the guest Machine's durable challenge consumption to
refuse replay. It must show the physical host and guest fingerprints and
plan details to the owner. An earlier permit or approval for a different
guest, key, plan, or challenge authorizes nothing.

## Acceptance

The paired administrator can issue a permit only for the exact live Tart
guest key, signed challenge, approved owner key, plan, and 120-second window.
Changed executable bytes, a stopped or replaced VM, wrong account, changed
plan, missing owner pairing, or expired challenge must refuse. The identity
reviewer must refuse a changed permit and guest replay. Owner presence and
plan application are separate actions.

## Replay

Run the daemon and guestowner package tests, including the independent
observer pin and changed-challenge cases. On a disposable VM, compare Tart's
directly observed guest key and MAC with the signed challenge, issue the
permit from the paired host administrator, and test that the guest consumes
one owner proof once. Keep the private owner and Machine keys on their
respective hosts.

This path changes no Machine/keyd private key storage or administrative
custody. The physical Stage 2a gates remain unclaimed until the complete
installed end-to-end run produces their evidence.
