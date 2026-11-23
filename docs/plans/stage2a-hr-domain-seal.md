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
Every protected use must recheck the installed nodes and compare the owner
plan, selected release manifests, A key and signed H/R binding. The new v3
component does not change the v1/v2 parser limits or lift
`stage2aProtectedStartContractReady=false`.

The proposed v3 structural ceilings are 512 files, 1,024 child directories,
384 MiB per file, 1 GiB per domain, and a 2 MiB sidecar. They are draft
parsing limits; an owner-approved installed policy must choose exact allowed
limits before any positive protected path. H and R snapshots use distinct
domain-separated names under A:reader `0750` namespaces. The static H
descriptor and HQ preloader metadata are separate from these inventory trees.

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

## Replay

Run `GOTOOLCHAIN=go1.27.3 go test -p 1 ./... -count=1`, `go vet ./...`,
and `git diff --check` from this repository. Cross-compile members for
Windows to confirm target POSIX name derivation remains portable. In a fresh
disposable Tart clone with three dedicated local A/H/R accounts, build the
`stage2a_guest` test binary and exact `SoulLauncher`, install the latter at
its fixed path, then run `TestStage2aV3GuestSealHAndR` with the test's explicit
account and launcher-hash environment. Record exact source and binary hashes,
guest exit, H/R results and clone cleanup. Do not count that fixture as T03.
