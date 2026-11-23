# Stage 2a post-Ready member lease

## Intent

Keep one previously admitted, stock ACP child and its fixed R wrapper alive
only while Machine's secure administrator A can recheck the exact installed
authority and every retained protected role. Aggregate Ready admits the first
lease; a subsequent lease depends on the preceding signed runtime lease.
This record alone does not authorize B provider ingress or establish physical
T01, T03 or T21 evidence.

## Target

- The paired H forwards a wrapper challenge over the existing authenticated
  local admission path. H supplies the kernel-observed wrapper UID and PID;
  A reobserves that exact process and its ACP child, the other child, R, B,
  qualification Q and the owner driver before every signature.
- A reloads the exact A-owned installed authority, checks its digest against
  the active reservation, and rechecks the installed snapshots, owner approval
  cutoff and durable stop claims. Machine/keyd signing remains in A.
- A signs a purpose-separated member runtime envelope that binds the exact
  aggregate Ready, assignment, child observation, B authority, member grant,
  B arm receipt, installed authority digest, process identities and a fresh
  32-byte challenge. It signs the previous envelope digest for renewal and
  retains the last sequence, nonce, expiry and digest per member.
- The first lease must issue before Ready expires. Every renewal must arrive
  before the preceding lease expires. Every expiry is at most five seconds
  after issuance and no later than the installed owner approval cutoff.
  Stop, expiry, changed process, changed authority or replay refuses.
- The fixed wrapper must verify and consume these leases before continuing
  the child. A separate B runtime lease and verified H/R/B consumer path are
  required before a protected end-to-end launch is enabled.
- The member runtime lease requires the digest of H's separately committed,
  Ready-bound two-member finalization. H fsyncs and reopens its canonical
  record before sending the exact bytes and digest through a distinct paired
  Machine intake. A checks its own signed assignment, child observation,
  aggregate Ready, B authority, both arm rows and live kernel roles, then
  caches the exact H bytes and signs a purpose-separated acknowledgement.
  H reopens the durable record on each renewal and sends its exact bytes;
  A compares them with the cached record before signing a member lease.
  This handoff does not attest B's private relay socket birthtime.

## Acceptance

- The parser refuses a wrong wrapper peer, malformed challenge, absent or
  unexpected previous envelope digest, invalid digest and oversized sequence.
- The lease window refuses a late first request, late renewal, wrong prior
  expiry, sequence replay and owner approval cutoff.
- The daemon routes the new verb only through paired Stage 2a authority and
  refuses it when that authority is unavailable.
- The synthetic replay from soul-contracts #89 proves the exact canonical H
  intake, A acknowledgement signature and reopened-byte renewal wire shape;
  altered H bytes under the committed digest refuse.
- A real two-member protected run must demonstrate both wrappers and B
  renewing under the same owner-approved installation, followed by prompt
  cutoff on stop and safe retirement. Fixture checks cannot satisfy that gate.

## Replay

Run `GOTOOLCHAIN=go1.27.3 go test -p 1 ./internal/members ./internal/daemon`
and `GOTOOLCHAIN=go1.27.3 go vet ./internal/members ./internal/daemon` in the
isolated Machine worktree. The checked-in synthetic replay is copied from
soul-contracts #89 head `c8696d21aa704ebc73445693a91c5552b0044d91`.
Record the Machine exact signed head and hosted CI. The
protected boundary is unverified until an installed release and same-run
physical evidence cover both harness accounts and direct, sibling and stopped
access refusal.
