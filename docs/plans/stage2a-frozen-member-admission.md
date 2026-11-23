# Stage 2a frozen member admission

## Intent

Bind the protected Hello member claim to the exact measured Soul definition
before Machine signs a start. This closes a role and adapter substitution in
the existing one-use reservation path. It does not add a second protected
adapter process or confer T01, T03 or T21 credit.

## Target

- Machine reads `Contents/SoulInfo.json` from the descriptor-checked frozen
  definition snapshot during HelloStart. Its size, mode, inode and SHA-256
  must still match the installed approved definition records.
- The Hello requested roles must be the same complete member set as that
  file, keyed by unique member ID. Role, adapter ID and exact adapter version
  must match for every member; exactly one role is `lead`.
- A missing, extra, duplicated or changed member refuses before Machine
  signs the Hello start. The existing signed Hello payload digest then binds
  the exact canonical claim bytes.
- The current single child and endpoint reservation remains single child.
  A separate reviewed contract and implementation must bind each stock
  process and broker runtime before two members can qualify together.

## Acceptance

- A two-member frozen definition accepts the same complete Hello roles in
  either order and refuses missing, duplicated, changed-role, changed-adapter
  and changed-version claims.
- A changed Soul ID or duplicate JSON key in the frozen file refuses.
- The existing canonical Hello and post-Hello finalization tests still pass.

## Replay

Run `GOTOOLCHAIN=go1.27.3 go test -p 1 ./internal/members` and
`GOTOOLCHAIN=go1.27.3 go vet ./...` from this worktree. Record the exact
source head and CI result. A fixture or simulator pass does not prove the
physical protected host boundary; the owner-reviewed release and same-run
test evidence remain required.
