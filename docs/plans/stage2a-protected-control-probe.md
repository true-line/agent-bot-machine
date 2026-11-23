# Stage 2a protected control probe

## Intent

Collect bounded, A-joined negative-control observations for the one-use
protected Soul start. The control process is distinct from the stock ACP
child, so its result cannot alone establish a physical T01 or T03 pass.

## Target

- A derives the exact direct test-provider port from the signed HQ epoch,
  installation and start: `49152 + (SHA256("agent-bot-stage2a-local-provider-v1\0"
  + hq_epoch + "\0" + installation_id + "\0" + start_id)[0:2] BE mod 16384)`.
  Its signed ChildReady payload binds the installed provider config digest,
  model and request digest. The owner-reviewed Q install pins the distinct
  `control_peer_installation_id`; A finds one live B2 reservation, rechecks
  its kernel UID and A-published private proof node, then signs the derived
  sibling socket and proof paths. HQ and R cannot choose targets.
- After checking the signed ChildReady payload and first live lease, the R-UID
  child wrapper starts the measured Machine binary under the exact installed
  child Seatbelt profile. The helper runs before ACP traffic, has a two-second
  upper bound, and cannot grant A/root network access.
- The helper attempts exact `POST /stage2a/local-provider/v1` requests with
  JSON `{model,request_sha256}` over direct IPv4 and IPv6 loopback to that
  port, a connection to the assigned B relay, a
  connection to the sibling relay, and a read of the actual A-owned, B2-group
  proof file at the path derived from the live B2 assignment. No proof bytes
  enter R. Direct and sibling attempts require `EPERM` or
  `EACCES`; the assigned relay must connect. A `connected`, `ENOENT`, timeout,
  or ambiguous result in a denial position refuses the control.
- The R wrapper records the stock child and probe as distinct kernel
  PID/parent/UID/GID/start identities, plus the exact reservation, ChildReady,
  profile, plan and provider selectors. Its raw result is capped at 8,192
  bytes. A must retain the raw bytes, independently recheck the live R/B/child
  and installed selector join, and compare provider listener logs showing
  zero direct hits before signing any physical result.
- A stop/HQ-restart cutoff is a separate post-stop observation. A pre-ACP
  negative control cannot stand in for that cutoff or the stock child’s own
  network behavior. HQ currently binds the candidate provider on IPv4 only;
  the IPv6 attempt proves sandbox denial but has no separate provider-listener
  zero-hit log.
- T01 also needs a B2-issued challenge-bound broker handle copied under A
  custody and refused when R1 presents it through its own broker path before
  any protected operation, including after HQ restart. Sibling socket and
  proof-file denial are separate controls.

## Acceptance

- A missing or changed signed selector, provider digest, sibling identity,
  profile or measured Machine binary refuses before the probe runs.
- A different probe PID, swapped stock child, lost live lease, direct provider
  hit, unexpected socket or file outcome, or missing raw A record refuses.
- The disposable native fixture exercises the profile’s direct IPv4/IPv6
  denial, assigned-relay allowance and sibling socket denial. Its token file
  uses mode `0000` under the current test UID; the physical run must instead
  show the real A-owned, B2-group `0440` proof and `02710` parent, and deny
  R1's read without exposing the bytes.
- T01/T03 remain open until the exact owner-approved physical Mac run joins
  stock ACP observations, provider logs, A-signed evidence and cutoff.

## Replay

Run `go test -p 1 ./internal/members ./cmd/managed-machine` and `go vet ./...`
from this worktree. Record the source tree, installed Machine binary/profile
digests, signed selector, process observations, raw probe result, provider
listener logs and guest disposal. Repeat the protected case on the designated
physical host before assigning T credit.
