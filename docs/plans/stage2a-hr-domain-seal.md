# Stage 2a H/R domain seal component

## Intent

Supply the Machine-owned H-code and per-Soul R-runtime inventory seal needed by
the owner-reviewed Stage 2a install. This component does not grant a protected
start or physical qualification. Machine/keyd protected operations and keys
remain in the secure A account under PDR-0091. The A-owned snapshot rule is
the owner decision in Platform discussion #123.

## Target

The reviewed installer prepares fresh private A:reader nodes: an A-owned
`0700` wrapper containing only an A-owned `0700` snapshot tree and an A-owned
`0600` canonical inventory sidecar. A fixed network-denied helper runs with
A's UID/GID and no supplementary groups. A independently measures the exact
reviewed H or R file and directory closure, checks the dedicated reader group,
exclusively publishes the snapshot and sibling sidecar in their distinct
installation namespaces, seals the root `0555` and sidecar `0440`, syncs and
remeasures both. Root independently reobserves the returned reference.
The shared root-owned `0711` parent is traverse-only; A walks it with held
no-follow search descriptors and opens the final A-owned namespace for read.
Every protected use must recheck the installed nodes and compare the owner
plan, selected release manifests, A key and signed H/R binding. The new v3
component does not change the v1/v2 parser limits or lift
`stage2aProtectedStartContractReady=false`.

For later cooperative starts, A reads the fixed root-owned applied H upgrade
receipt and checks its retained exact install approval, canonical saved plan,
H descriptor witness, installed signed descriptor, and current live pair. The
approval's ten-minute TTL authorizes the installation ceremony; expiry or
pruning of that transient approval file does not invalidate a correctly
installed H. A fresh one-use reservation is still required for each start.
Missing, changed, retired, or unpaired installed authority fails closed.

The owner approved v3 structural ceilings of 512 files, 1,024 child directories,
384 MiB per file, 1 GiB per domain, and a 2 MiB sidecar on 2026-11-22.
This did not approve any selected source, installation plan or protected
launch. The exact installed policy must choose limits within those ceilings.
H and R snapshots use distinct
domain-separated names under A:reader `0750` namespaces. The static H
descriptor and HQ preloader metadata are separate from these inventory trees.

The R producer is an additive v3 path in the paired Soul install. Its exact
owner plan pins canonical inventory bytes and digest, limits, sorted component
source repository/commit/tag, artifact format (`tar`, `raw` or exact-member
`zip`), artifact and
manifest paths and hashes, and one
distinct root-owned materialized source root per component. Each manifest is
exact JCS with all and only its inventory `release_path`/SHA-256 rows. Root
remeasures artifact bytes, checks every tar/ZIP member or exact raw binary against
its manifest, checks each complete source-root closure, copies
only approved files into fresh private A:R nodes, and invokes the fixed A
seal. The applied root receipt and A-owned policy carry the same typed R
reference; the loader checks that match and reopens the sealed nodes before
any future positive start. This R-only install requires the per-Soul sudo
rule to be absent and does not publish one; a later reviewed activation must
bind the actual runner executable and entry to this sealed R tree. Legacy v2
start remains closed. Retirement removes the per-Soul authority and any rule
after the idle-role check, retaining
the root receipt, snapshot and audit claim for review.

## Acceptance

- Canonical JCS and directory closure reject duplicate, aliased, missing,
  extra, writable, linked, ACL-bearing and changed nodes.
- The parser accepts its declared 512-file/1,024-directory maximum without
  widening the legacy JSON budget.
- A's fixed helper proves offline A UID/GID custody and seals a 480-file H
  fixture and an R fixture containing a file larger than the v2 256 MiB cap
  in a disposable macOS VM. These are component checks, not T gates.
- The paired HQ installer, authenticated release mapping, static H descriptor,
  protected preloader/guard and v3 one-use reservation must be reviewed
  together before the protected-start gate can open. T01/T02/T03/T21 require
  separate physical evidence on the designated host.
- An expired install approval in a matching applied root receipt remains
  install evidence, while a started receipt, mismatched plan or A key, absent
  H witness, or failed live pair cannot authorize a later reservation.
- The paired v3 R install accepts only exact source and manifest pins, rejects
  added/missing source rows and changed bytes, and records one A-sealed R ref
  in both installed policy and applied root receipt. A failed or partial
  install leaves no successful receipt or usable protected start.

## Replay

Run `GOTOOLCHAIN=go1.27.3 go test -p 1 ./... -count=1`, `go vet ./...`,
and `git diff --check` from this repository. Cross-compile members for
Windows to confirm target POSIX name derivation remains portable. In a fresh
disposable Tart clone with three dedicated local A/H/R accounts, build the
`stage2a_guest` test binary and exact `SoulLauncher`, install the latter at
its fixed path, then run `TestStage2aV3GuestSealHAndR` with the test's explicit
account and launcher-hash environment. Record exact source and binary hashes,
guest exit, H/R results and clone cleanup. Do not count that fixture as T03.
For the R producer successor, run `TestStage2aV3GuestInstallRuntime` in a
fresh disposable clone with the same exact installed launcher and dedicated
A/R accounts. It must reject an added source file, then copy the one-file
reviewed R tree into fresh A-private staging, publish through the fixed A
helper, and reopen the installed root and sidecar. Record its signed source
head, binary hashes, guest output and clone cleanup. This test proves only
the producer seam; it does not exercise an owner proof or a Soul start.
When the private stock adapter source-stage map is present, set
`STAGE2A_V3_STOCK_ZIP_MAPPING` to its absolute path and run
`TestStage2aRuntimeV3StockZipCompatibility`. It hashes the exact ZIP and
checks the two expanded members against the proposed R rows; it supplies no
release, owner-plan, A-seal, or T03 authority.
