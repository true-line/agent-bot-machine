# Stage 2a H source producer

## Intent

Install the owner-reviewed HQ and Node release bytes into the A-owned H-code
snapshot. The H installer must prove that its selected files and reviewed
omissions come from the same authenticated release before the existing v3
seal and H descriptor signer can publish a protected HQ launch.

## Target

The H producer receives a canonical H inventory, a canonical HQ source
manifest, explicit excluded source paths, and independently authenticated
HQ, Node, and Contracts release pins from the owner-plan installer. The
owner plan names the Contracts tag and commit, full vendored file count and
digest, and H-selected runtime file count and digest. The source manifest
contains every HQ release path considered for H: each path is either in the
installed H inventory or in the exact omission list. Omissions are limited to
reviewed synthetic Contracts fixtures. The Node component has exactly one
installed `bin/node` row. A pinned full HQ archive may contain other source
files; its whole-archive hash authenticates them, but they are never copied
into the H snapshot.

Root reads the pinned raw artifacts from private, checked source locations,
verifies the HQ archive and Node bytes, and stages only the selected rows.
It also checks the archive's `governance/soul-contracts.json` and
`governance/interim-release.json` against those owner-plan pins. The raw
source proof runs immediately before staging on the root install path.
The existing A-owned v3 seal remeasures the staged tree. The separate H
descriptor signer binds the sealed inventory, owner plan, runtime argv, and
fixed preloader paths. A receives no network access or new runtime helper.
Source selection and artifact hashes alone grant no authority to seal or
start; the caller must first authenticate the owner Saved plan, paired
approval, release attestations, and root install receipt.

## Acceptance

- The exact source manifest and inventory are canonical, bounded, and
  digest-pinned. Every selected HQ row and every omitted source row appears
  exactly once, with no case aliases or path traversal.
- The full HQ archive hash and Node binary hash match the independently
  authenticated owner-plan pins. The archive contains only regular files and
  directories and no hidden second archive, links, or unreviewed metadata.
- Every selected and excluded HQ source path matches the byte hash in the
  source manifest. Full vendored Contracts bytes match the pinned full
  Contracts digest before runtime fixture omissions are applied; the
  selected runtime subset matches the HQ release metadata and the reviewed
  owner-plan pin.
- The H inventory remains within the approved file, per-file, total-byte,
  and directory limits. A seals the exact staged rows and the H descriptor
  is published only from a verified install-plan proof and observed A seal.
  Machine requires the three cooperative modules imported by the merged HQ
  entrypoint and the reviewed B bridge verifier module in the selected H
  inventory.
- Missing authority, mismatched artifacts, extra selected paths, stale or
  inconsistent source metadata, failed A seal, or descriptor mismatch fail
  closed. No qualification T result is claimed from an installer test.

## Replay

Run the H source closure unit and mutation tests on the reviewed PR head,
then the repository's Go test and vet gates. Build the exact Darwin HQ
artifact from a clean merged HQ commit and immutable Contracts tag, verify
the full raw archive and source manifest, and rehearse the selected H map
privately. Finally, exercise the root-to-A installer in a disposable macOS
guest with the exact owner-reviewed plan and record the seal, descriptor,
refusals, and guest cleanup. Physical T01/T02/T03/T21 is a separate run.
