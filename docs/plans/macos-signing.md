---
status: active
overview: >-
  Ship the darwin core as a Developer ID signed and notarized managed-machine
  CLI binary, with no .app bundle, no keychain-access-groups entitlement, and
  no Secure Enclave wrap; store the daemon key in a dedicated file keychain
  (`daemon.keychain-db`) with a self-only ACL. Merging a reviewed version PR starts signing. The release publishes the signed
  Homebrew digest with the five platform archives.
related_prs: [440, 441, 451]
related_issues: [442, 446]
---

# macOS signing

## Intent

Owner direction (2026-11-01, #446): ship the darwin/arm64 `managed-machine` CLI
binary signed with the owner's Developer ID Application certificate and
notarized by Apple as a plain CLI binary — no `.app` bundle, no embedded
provisioning profile, no `keychain-access-groups` entitlement, and no Secure
Enclave key wrap.

On macOS the daemon's 32-byte Ed25519 seed is stored in a dedicated file
keychain at `~/.config/agent-machine/daemon.keychain-db` through
`Security.framework` in-process (`SecKeychainCreate` / `SecKeychainOpen` /
`SecKeychainUnlock`, then `SecItemAdd`, `SecItemCopyMatching`,
`SecItemUpdate`, `SecItemDelete`) under service `ai.true-line.agent-bot-machine`
and account `daemon.key`, targeted with `kSecUseKeychain` so `SecItemAdd` never
falls through to `login.keychain-db` or `System.keychain`. The item has a
`SecAccessRef` ACL (`SecTrustedApplicationCreateFromPath(NULL, ...)` +
`SecAccessCreate`) trusting only the signed daemon binary. `kSecAttrAccessible`
is omitted: that Data Protection attribute on a file keychain makes
`SecItemAdd` call Authorization Services and fail with OSStatus `-60008` when
the prefix-owner account has no GUI session that can prompt. The dedicated
keychain is created with an empty password (never typed, never displayed).
Open unlocks it in-process with that empty password, disables keychain
prompts, restores the previous default keychain so this file does not become
the account default, and turns off lock-on-sleep. Only a missing
keychain file or `errSecItemNotFound` (`-25300`) is treated as absent; every
other status (including unlock failure or an item whose ACL does not trust
only the daemon binary) fails closed, except an unsigned rebuild at the same
executable path: that is a stale `SecTrustedApplication` hash, and `Load`
rebinds the ACL to the current binary (or rotates the item if Darwin refuses
the read). A trusted-app path that is not this executable still fails closed.
On `Save`, `errSecDuplicateItem` checks
the existing item's ACL first: if it already passes `verifyItemSelfOnlyACL`,
`Save` updates its data in place via `SecItemUpdate` so a failure or crash can
never delete a valid daemon key; only if the existing item fails
`verifyItemSelfOnlyACL` (an untrusted pre-planted item) does `Save` delete and
re-add with a fresh self-only ACL. Existing pre-keychain installs migrate once
from an on-disk `daemon.key` into the dedicated keychain item and then delete
`daemon.key`.

The prefix-owner account (`admin`) does not have a usable login keychain: it
is not a GUI login session, and a password reset leaves `login.keychain-db`
locked or absent. Pairing therefore must not depend on that store. Owner
direction (#446) still applies: no `.app` bundle, no Secure Enclave, no
`keychain-access-groups`. The dedicated file keychain uses the same self-only
ACL as the login-keychain design; it is created and unlocked in-process so
the daemon can pair without a GUI keychain prompt.

### Owner approval for a new HQ pairing

The owner approval client runs in the signed-in user session and uses a separate
Secure Enclave key. Machine verifies its proof in the Homebrew prefix owner's
admin account. The Machine daemon continues to use its dedicated keychain for
its own Ed25519 identity. [D4 and the cross-account channel](cross-account-channel.md#s5--agent-bot-is-the-control-plane-other-repos-p7p8)

For a fresh enrollment obtain the owner's P-256 public key directly from the
independently verified, provisioned owner client. The prefix owner runs
`managed-machine daemon pair --pin-owner BASE64`. Obtain HQ's Ed25519 public
key and SHA-256 fingerprint from the provisioned HQ service. In the prefix
owner's account run:

```sh
managed-machine daemon pair --client agent-daemon --enroll "$hq_key" --fingerprint "$hq_fingerprint" --owner-challenge
```

Pass the JSON challenge to the owner client. The owner checks the intended Machine
and HQ identities and approves the pairing. Submit the resulting public proof
as the prefix owner:

```sh
managed-machine daemon pair --client agent-daemon --enroll "$hq_key" --fingerprint "$hq_fingerprint" --owner-proof "$proof"
```

A challenge is valid for two minutes; requesting a replacement invalidates
its predecessor. Machine checks the signature under its existing owner pin and
binds the accepted HQ key to the local `_agent-bot-hq` UID. An existing HQ
enrollment needs a separate authorized transition. Replacing the owner key
also requires a separate rotation procedure. On hosts with an owner pin, only
signed `status` and `receipts` from that HQ account are currently authorized.
Additional verbs require their own action-specific presence checks before
they can be enabled. A signature verifies possession of the pinned key;
provisioning and physical qualification establish its hardware provenance.

**Dedicated-keychain ACL threat model.** The self-only `SecAccessRef` ACL
prevents silent reads or ACL changes by other processes running as the
prefix owner. The keychain file is `0600` in a `0700` directory. Another local
process running as that user can still trigger a macOS Keychain Access
confirmation dialog and read the item if the logged-in user approves the
prompt. Owner direction (#446) accepts this trade-off in order to ship a
plain CLI binary with no `.app` bundle.

Signing runs on the version PR merge commit. The Homebrew pin comes from the verified signed Darwin archive.

## Target

**Apple setup (owner, done 2026-11-01).** Team `Z5DM34QS5U`; signing identifier
`ai.true-line.agent-bot-machine`; Developer ID Application certificate expiring
2031-07-14; an App Store Connect team key with the Developer role for
notarization. The five signing secrets (`MACOS_DEVID_P12`,
`MACOS_DEVID_P12_PASSWORD`, `NOTARY_KEY_P8`, `NOTARY_KEY_ID`,
`NOTARY_ISSUER_ID`) live only in the GitHub environment `release`, which
requires the owner's approval and admits the `main` branch and `v*` tags.

**Archive.** `mm-release build` writes the darwin archive as `LICENSE` (`0644`)
and `managed-machine` (`0755`), identical in layout to the Linux and Windows
archives.

**Signing.** Merge the bot’s reviewed version PR to start Sign on protected main. The request job checks the merged PR and its approval. The main-only `release` environment supplies the signing identity. A manual dispatch remains available for recovery and the separate owner app.

The macOS signing job builds the
deterministic dist, imports the Developer ID identity into a temporary keychain
via `security -i` on stdin (so neither the keychain password nor the `.p12`
password appears in `argv`, and `-T /usr/bin/codesign` restricts key use to
`codesign`), prepends that keychain to the user keychain search list (restoring
the original search list in `if: always()`), and runs `scripts/sign-darwin`:
sign `managed-machine` with the hardened runtime and a secure timestamp, check
authority, Team ID, identifier and runtime flag, notarize with `notarytool`
(removing the temporary `.p8` file immediately afterward), require Gatekeeper's
`Notarized Developer ID` assessment
(`spctl -a -t open --context context:primary-signature -vv`), repack with
`mm-release repack`, and check with `mm-release verify-signed`. The signed dist
is uploaded to the draft release `vX.Y.Z`. It is the only workflow that may
read secrets.

**Verification.** `mm-release verify-signed -unsigned D -signed S -team T`
needs no macOS: the four other archives are byte-identical; in the darwin
archive `LICENSE` is byte-identical and `managed-machine` matches the
deterministic build outside the code signature (only the `LC_CODE_SIGNATURE`
datasize and `__LINKEDIT` vmsize/filesize may differ, the signature must end
the file, and it must name the Team ID), with no extra files. With
`-require-pin` the formula must pin the signed darwin digest.

### Release automation

Changes merged to `main` open or refresh a version PR. Merging the reviewed version PR starts the five-target Machine build and macOS signing. After CI and signing pass on that merge commit, automation tags it and publishes the verified archives. The published release includes the Homebrew formula with the signed macOS checksum. A separate formula-only PR updates the tap.

The release workflows use three GitHub environments.

- `release` holds the Apple signing and notarization credentials. Restrict deployments to the branch `main`. Normal Machine releases use the reviewed version change as authorization.
- `release-manual` requires the designated owner reviewer for manual signing, including owner-presence builds and recovery. Restrict it to the branch `main`. This environment needs no secrets.
- `version-cut` restricts release PR and tag automation to the branch `main`. The automation uses the repository installation of the release App and the `CHORES_DUMB_CLIENT_ID` and `CHORES_DUMB_PRIVATE_KEY` credentials. It creates signed release commits and pushes the tag with an installation token so the tag triggers the Release workflow.

During migration, configure the manual gate and verify its required reviewer before removing the separate reviewer from `release`. The signing workflow must already be deployed on `main` before that change.

## Acceptance

- `go test ./internal/daemon` covers dedicated-keychain round-trip (`Load`,
  `Save`, in-place `SecItemUpdate` rotation, `Delete`) including a HOME with
  no login keychain, fail-closed behavior on malformed keychain or disk items,
  one-time migration from legacy `daemon.key` into `daemon.keychain-db`, and
  the child-process seam proving key bytes never appear in any child process's
  `argv` or `env`.
- `go test ./cmd/mm-release` covers repack and verify-signed refusals (changed
  code, wrong Team ID, data after the signature, extra or changed files, a
  changed other archive), and on darwin/arm64 proves a real `codesign` re-sign
  passes.
- `TestSignWorkflowContract` pins the release-request path and manual dispatch on `main`, the
  `release` environment, `contents: write` on the job alone, only the five
  CLI signing secrets plus the profile on owner-app dispatches through `env`, and no password-bearing `security` flags or
  `-A` on the command line.
- `tests/release.test.sh` and `tests/formula-core.test.sh` run `prepare` and
  `tag` against `tests/fixtures/fake-gh`: a failed signing run aborts prepare
  cleanly, a resume reuses the draft, `tag` refuses a missing or unsigned
  draft, the formula pins the signed digest, and the generated formula installs
  both executables side by side and passes its `test do` in the Ruby harness.
- The macOS PR job runs `foreign_presence_item_survives_refused_owner_request`
  in a disposable Keychain. A second executable owns the synthetic presence
  item. After the bundled helper refuses an owner request, the original writer
  must still find the same value. [Machine #507](https://github.com/true-line/agent-bot-machine/issues/507)
  tracks the owner-approved migration and subsequent public-key continuity check.
  The same job checks that the CLI classifies a readable item with an untrusted
  access list as exit 3 and preserves its original contents.

## Replay

1. Merge a change to main and inspect the generated version PR.
2. Merge the reviewed version PR. Confirm Sign and both CI workflows ran on its merge SHA.
3. Confirm the tag points to that SHA and the public release has the five archives, checksums, five platform reports and the verified Homebrew formula.

### Signing the owner approval app (HQ #56)

Machine's main-only **Sign** dispatch accepts `owner-presence` as an optional
artifact. It builds the pinned Identity source on Apple Silicon, using the same
reviewed release environment, Developer ID identity and notarization service
as the CLI. The default dispatch still builds the five Machine archives.
The app is the signed-in owner's approval client. The custody helper continues
to run under the prefix owner's account.

The existing release environment input `MACOS_PROVISION_PROFILE` from #441
contains the base64 of the embeddable Developer ID distribution profile for
`ai.true-line.agent-bot-owner-presence`. Only a distribution profile suitable
for embedding in the delivered app belongs here. The signer checks the
team, expiry, application identifier and authorized Keychain group. It selects
the profile certificate by the SHA-256 digest that the release keychain reports
for the selected signing identity, then compares its full DER to the signed
app's leaf certificate. A rejected profile reports the
first failed field by name. The signer grants only the app's exact group. The profile for the retired
`AgentBotMachine.app` has a different application identifier.

After notarization, Machine staples the ticket, archives the app and checks
the extracted copy with codesign, stapler and Gatekeeper. The dispatch creates
a separate `owner-presence-vX.Y.Z` draft containing the zip and its SHA-256.
Physical owner presence and the subsequent signed HQ response are pilot checks.
