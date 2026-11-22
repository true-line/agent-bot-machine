# Stage 2a authenticated qualification evidence source

Status: source for review only. It does not authorize a protected launch, mark a
profile qualified, or establish a physical T01/T02/T03/T21 result.

## Trust and custody

Machine A runs under the secure administrative account. Only A may ask keyd to
sign the fixed `agent-bot/qualification-host-report/v3` purpose with the
designated host's Secure Enclave P-256 key. The owner-signed v3 policy envelope,
the independently reviewed owner Ed25519 root and key ID, the designated host
identity, and a revocation snapshot no older than **3,600 seconds** are inputs
to verification. The Machine Ed25519 public key used for A's one-use records
must be independently reviewed and enrolled; a key embedded in an evidence
envelope is not a trust anchor. Verification uses supplied local bytes and does
not require network access.

The v3 host report is canonical ASCII JSON under the contract's bounded JCS
subset. A's pre-sign execution completion record commits to the candidate
report before keyd signs it. A's post-sign report commitment seals the exact
host envelope and pre-sign record. The release verifier checks both distinct
completed-run chains, owner policy, signed Souls build, Sigstore release
attestation, qualification subject, and report references. It does not measure
the installed host files or grant launch permission.

## Independent Q process

The independent qualification observer Q is distinct from the per-Soul runtime
R, HQ, B, and A. The source pin reviewed for this interface is
`true-line/soul-conformance` commit
`c72e48c352147ff8f7771b7e50eca468ffd41848`, with executable
`suites/stage2a/qualification-runner.mjs` SHA-256
`cd8675de434d482a7631cfaca0a1b507f0627f9d0954d5b721ee5b6f71b55cd3`.
An owner-reviewed install plan must pin the exact installed Node executable,
this Q source, `/bin/ps`, dedicated numeric Q UID and primary GID, canonical
path roots, and the test-plan digest. A must remeasure those bytes and identities
on the designated host. A local source pin alone cannot satisfy that plan.

Root must install the one-use socket parent owned by A with Q's group and mode
`02710`, with no allow ACL. A verifies that directory by a no-follow descriptor
walk, creates one random Unix socket at mode `0660` with the inherited Q group,
and accepts exactly one connection. A authenticates the Darwin kernel peer PID
and UID, Q's live primary GID, exact executable and arguments, and process start
identity before disclosing a fresh 32-byte challenge. It rechecks the peer around
each observation. Q receives no HQ owner connection or FD4.

The A/Q channel uses one 4-byte big-endian length followed by 1–65,536 bytes of
canonical ASCII JSON. A sends `begin`, Q sends `ready`, A sends bounded `observe`
requests, and Q sends raw `observation` frames. A validates each Q frame against
the exact request bytes, session, sequence, challenge hash, profile, and reviewed
path roots. Q's `finished` frame must commit to the count and SHA-256 of the
exact length-prefixed observation frames, then close the stream. A retains the
exact length-prefixed begin, ready, request, response, finish-request, and
finished bytes in a private finalized session result. A also records when it
observed a clean EOF with no trailing bytes; the framed-byte verifier rejects
a missing EOF or one timestamped before `finished`.
Unknown path access (`EACCES` or `EPERM`) remains unknown and cannot prove
absence. No raw Q frame carries a pass/fail verdict.

## A-owned bundle and release checks

The draft A-only sink verifies the signed reservation, B finalization, and stop
envelopes against the enrolled Machine key and A-owned durable files. It binds
the finalized Q session to the exact reservation digest, installation, Soul,
start, host, profile, cohort, path roots, Q source and identity, and test plan.
It rechecks paired request/response frames and requires a stop record saying
both dedicated runtime UIDs are idle before atomically storing the bundle.
A synthetic test invokes the complete sink with a verified owner policy, host
ES256 envelope, signed A pre/post records and a private A-owned store, then
refuses a changed Q observation with stale transcript digests. A coherent
replacement transcript is not yet bound by the host signature. That test
grants no physical gate.

The separate `mm-qualification-verify-release --host-v3` command parses the
supplied owner root, policy, trusted Sigstore roots, exact release and Souls
bundles, two host envelopes, two A pre-sign completion records, two A post-sign
commitments, and independently enrolled Machine public key entirely offline.
Its v3 acceptance result remains **unqualified** even for valid synthetic
chains until it also authenticates the physical gate manifests, segment
attestations, raw Q/ACP/OS evidence and installed inputs. The signed-chain
check is only a diagnostic component. Machine's live acceptance path must
also prevent policy rollback and remeasure installed adapter, runner, Soul,
host, and Q inputs before launch.

## Open acceptance work

There is no production Q account installation or A spawn/call site in this
source slice. The composite A bundle is written after the host report and
post-sign commitment, so it cannot be a pre-sign gate-manifest reference.
The exact Q session bytes, clean-EOF fact, and A identity assertions still need
a separate A-authenticated, durably sealed pre-sign index and a distinct
finished-plus-clean-EOF receipt before the host report is signed. The index
must bind the exact begin, ready, request, response, finish-request, and
finished bytes, paired transcript digests, observed Q PID and
kernel start identity, sequence and count, and A-observed EOF without trailing
bytes. A must independently corroborate Q's raw
observations with kernel, filesystem, receipt, and ACP capture facts. The exact per-gate
A-corroborated artifact format must bind T01, T02, T03, and the distinct
cooperative T21 run to the signed report `gates` references and be checked by
the offline verifier. The current offline diagnostic checks signed gate claims
and digest references but does not resolve the underlying Q, ACP, or OS bytes.
The low-level local object reader accepts only content-addressed
`qualification://stage2a/{gate-manifest,blob}/<lowercase-sha256-hex>` URIs whose
suffix equals the signed `sha256:` digest, opens each archive component without
following links, refuses linked or nonregular objects, bounds the read and
rehashes the exact bytes. The source caps are 1 MiB for gate manifests and
64 MiB for raw objects; callers may impose tighter limits. This reader does
not authenticate the archive writer, parse a gate manifest, or turn a signed
pass claim into a physical result.
The v3 signed-report shape now requires each gate evidence reference to use the
gate-manifest URI class, match its digest suffix, and differ from the other
gates' manifest digests. Synthetic v3 vectors use distinct references for the
three protected gates and the cooperative gate; they are not physical objects.
An offline component helper verifies the designated-host report signature and
resolves those exact manifest bytes from the local root. It checks the fixed
canonical v1 gate-manifest field set, profile/host/suite selectors, ordered
segments, shared cohort/owner plan/host observation, unique segment and attempt
identities/references, and exactly one report anchor across the set.
It returns the bytes for the future physical verifier; it does not verify
segment signatures, raw issuer receipts, Q or ACP streams, installed inputs,
or physical outcomes, and it cannot credit a gate.
Restart, outage, race, and recovery checks need distinct
spent starts and Q sessions in a reviewed multi-segment aggregation rule;
the report's top-level run chain covers only its primary segment. An
authenticated local capture of both owner ACP directions is also missing.
A signed report or local transport test alone cannot
satisfy those gates. The owner-reviewed M2 install tuple, released adapter and
Souls bytes, HQ-started physical runs, and independent signed results remain
required before protected launch or Stage 2a acceptance can proceed.
