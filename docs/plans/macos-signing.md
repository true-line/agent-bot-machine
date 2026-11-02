---
status: active
overview: >-
  Ship the darwin core as a Developer ID signed and notarized managed-machine
  CLI binary, with no .app bundle, no keychain-access-groups entitlement, and
  no Secure Enclave wrap; store the daemon key in the login keychain with a
  self-only ACL. Signing happens during `scripts/release prepare`, before the
  formula pin, in an approval-gated GitHub environment.
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

On macOS the daemon's 32-byte Ed25519 seed is stored in the login keychain
through `Security.framework` in-process (`SecItemAdd`, `SecItemCopyMatching`,
`SecItemUpdate`, `SecItemDelete`) under service `ai.true-line.agent-bot-machine`
and account `daemon.key`, with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
and a `SecAccessRef` ACL (`SecTrustedApplicationCreateFromPath(NULL, ...)` +
`SecAccessCreate`) trusting only the signed daemon binary. There is no
empty-password `daemon.keychain-db` fallback and no dual-format payload path;
only `errSecItemNotFound` (`-25300`) is treated as absent, and every other
status (including `-34018` `errSecMissingEntitlement` or an item whose ACL does
not trust only the daemon binary) fails closed. On `Save`, `errSecDuplicateItem`
checks the existing item's ACL first: if it already passes
`verifyItemSelfOnlyACL`, `Save` updates its data in place via `SecItemUpdate`
so a failure or crash can never delete a valid daemon key; only if the existing
item fails `verifyItemSelfOnlyACL` (an untrusted pre-planted item) does `Save`
delete and re-add with a fresh self-only ACL. Existing pre-keychain installs
migrate once from an on-disk `daemon.key` into the login keychain item and then
delete `daemon.key`; `daemon.keychain-db` files are never opened or imported.

**Login-keychain ACL threat model.** The self-only `SecAccessRef` ACL prevents
silent reads or ACL changes by other processes running in the user session.
Because the item lives in the login keychain (rather than the `.app`-only Data
Protection Keychain / Secure Enclave), another local process can still trigger a
macOS Keychain Access confirmation dialog and read the item if the logged-in
user approves the prompt. Owner direction (#446) accepts this trade-off in
order to ship a plain CLI binary with no `.app` bundle.

Signing runs during the release PR so the formula still pins the darwin archive
before the tag exists, and the pin names the signed archive.

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

**Signing.** `.github/workflows/sign.yml` is dispatched on `main` with a
version. In the `release` environment on a macOS runner it builds the
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

**Release flow.** `scripts/release prepare` builds the dist, reuses a draft
that verifies or dispatches `sign.yml` at origin/main and waits for the run
(the owner approves the deployment), verifies the draft, writes the formula
with the signed digest, and commits `Release vX.Y.Z`. `scripts/release tag`
rebuilds, downloads the draft and runs `verify-signed -require-pin` before
pushing the tag. On the tag, `release.yml` verifies the same way and publishes
the draft instead of creating a release.

## Acceptance

- `go test ./internal/daemon` covers login-keychain round-trip (`Load`, `Save`,
  in-place `SecItemUpdate` rotation, `Delete`), fail-closed behavior on
  malformed keychain or disk items, one-time migration from legacy
  `daemon.keychain-db` and `daemon.key` with deletion of the old copy after
  `Save`, and the child-process seam proving key bytes never appear in any
  child process's `argv` or `env`.
- `go test ./cmd/mm-release` covers repack and verify-signed refusals (changed
  code, wrong Team ID, data after the signature, extra or changed files, a
  changed other archive), and on darwin/arm64 proves a real `codesign` re-sign
  passes.
- `TestSignWorkflowContract` pins `sign.yml`: dispatch only, `main` only, the
  `release` environment, `contents: write` on the job alone, only the five
  signing secrets through `env`, and no password-bearing `security` flags or
  `-A` on the command line.
- `tests/release.test.sh` and `tests/formula-core.test.sh` run `prepare` and
  `tag` against `tests/fixtures/fake-gh`: a failed signing run aborts prepare
  cleanly, a resume reuses the draft, `tag` refuses a missing or unsigned
  draft, the formula pins the signed digest, and the formula installs and
  passes its `test do` in the Ruby harness.

## Replay

1. On clean main, `scripts/release prepare vX.Y.Z`; approve the `release`
   deployment when the script prints the run URL.
2. Open and merge the printed release PR.
3. With the owner's confirmation, `scripts/release tag vX.Y.Z`.
