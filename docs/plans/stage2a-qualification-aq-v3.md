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

The source-only pre-sign issuer verifies the paired framed Q session, distinct
Q and A-signed reservation launch challenges, recorded kernel Q PID/UID/GID,
process start, executable/argv, and the exact one-use socket path and listener
device/inode/birthtime that A checked before accepting and unlinking it. It
signs an index with the independently enrolled A Ed25519 key over the raw wire
object's digest, the
ordered interleaving of both directions, per-direction hashes and count,
source/test-plan pins, and run selectors. A separate signature binds the
finished frame, index envelope, and A-observed clean EOF with no trailing
bytes. The A-owned sink checks the signed reservation already in its private
claim store and publishes wire, index, then EOF receipt as three immutable
files; the EOF receipt is the final marker. A replay of the same Q session is
refused. Synthetic tests verify the exact stored bytes and both signatures.
This source helper has no production caller, report reference, or physical
verdict; the future A caller must finish this publication before asking keyd
to sign the host report.

The portable `VerifyQPreSignV3` offline component accepts exact local wire,
index, EOF receipt, and reservation envelope bytes plus an independently
enrolled A Ed25519 key. It verifies both distinct signature purposes, canonical
bounded payloads, the reservation's launch challenge, the A-signed one-use Q
socket and kernel identity fields, all length-prefixed frames and ordered transcript hashes,
request/observation pairing, and a signed clean EOF. It returns selectors and
digests for later joins, without a gate verdict. Its reservation join requires
the secure-admin `machine/v2` contract and schema version 2 used by v3 reports;
the legacy root-owned `machine/v1` record is refused. The caller must still bind
these digests to an A-signed physical segment and the host report, then verify
installed inputs, raw ACP/OS evidence, and physical results before acceptance.

## Physical segment wire under review

The first segment form represents one **completed protected reserved start**
for T01, T02, or T03. It does not describe the cooperative T21 run: the
current `Stage2aFinalizationPurpose` is B-specific, and T21 must not borrow
protected B authority. A canonical
`stage2a-physical-segment` object has exactly these top-level fields:
`schema_version` (1), `kind`, `gate`, `profile`, `host_id`, `cohort_id`,
`suite_revision`, `owner_plan_sha256`, `segment_id`, `purpose`,
`report_anchor`, `terminal_state` (`stopped`), `installation_id`, `soul_id`,
`start_id`, `launch_id`, `measurement_binding_sha256`, `q_session_status`
(`completed`), `q_session_id`, `q_challenge_sha256`, and `artifacts`.
`artifacts` is an object with exactly these content-addressed blob references:
`reservation`, `b_finalization`, `stop`, `q_wire`, `q_index`, `q_eof`,
`owner_acp_to_hq`, `hq_acp_to_owner`, `os_observation`, and
`installed_inputs`. Each reference uses the existing gate-object tuple
`{role,uri,sha256,size_bytes,issuer}` and an exact role equal to its field
name. The containing gate manifest's segment ID, purpose, report-anchor bit,
gate, profile, host, cohort, and measurement binding must agree. Its
`segment_manifest` reference addresses these exact bytes. Both containing
references use issuer `machine-a`: role `segment_manifest` for the manifest
and role `segment_attestation` for the A envelope. All ten inner references
also use issuer `machine-a` until a separately specified source is reviewed.

The distinct A-signed `segment_attestation` envelope uses the existing
six-field Machine Ed25519 record under purpose
`agent-bot/stage2a-physical-segment/v1`. Its canonical payload has exactly
`schema_version` (1), `kind` (`stage2a-physical-segment-attestation`),
`gate`, `profile`, `host_id`, `cohort_id`, `suite_revision`,
`owner_plan_sha256`, `segment_id`, `purpose`, `report_anchor`,
`terminal_state`, `installation_id`, `soul_id`, `start_id`, `launch_id`,
`measurement_binding_sha256`, `q_session_status`, `q_session_id`,
`q_challenge_sha256`, `segment_manifest_sha256`,
`reservation_sha256`, `b_finalization_sha256`, `stop_sha256`,
`q_wire_sha256`, `q_index_sha256`, `q_eof_sha256`,
`owner_acp_to_hq_sha256`, `hq_acp_to_owner_sha256`,
`os_observation_sha256`, `installed_inputs_sha256`, and `signed_at`.
It excludes the manifest's `artifacts` object; the manifest digest binds it.
Each digest equals the exact referenced object's digest. The attestation
contains no report, gate-manifest, keyd-signature, or post-sign commitment
reference: A must issue it before requesting the host report signature.
Its `signed_at` must follow A's observed Q EOF and idle stop and precede the
host report's pre-sign completion. The reservation, B finalization, and stop
objects keep their distinct A signature purposes and must join the same
start, launch, and installed measurement.
The one `report_anchor=true` segment must join the report's top-level
reservation, finalization, challenge, and measurement binding.

This segment form forbids an absent Q session, missing finalization, or a
non-idle stop. Refusals before reservation or Q completion are separate
`attempts` in the gate manifest, with distinct A-authenticated refusal and
terminal records; they never pretend to be completed segments or fabricate
Q frames. A future positive verifier must also resolve the actual ACP and OS
capture bytes, confirm their A-observed peer custody, remeasure installed
inputs, and check the gate-specific stimulus inventory. Field shape or an
A signature by itself grants no gate credit. The producer, capture formats,
T21 segment form, and gate-specific inventory remain open; public v3
acceptance stays closed.

### Compact installed-input object under review

The proposed `installed_inputs` blob is a canonical RFC 8785 JSON object,
at most 1 MiB, with exact top-level fields `schema_version` (1), `kind`
(`stage2a-installed-inputs`), `installation_id`, `soul_id`, `start_id`,
`launch_id`, `host_id`, `profile`, `plan_id`, `installed_plan_digest`,
`measurement_binding_sha256`, `definition_records`,
`launch_input_records`, `host_adapters_json`, `host_installation_json`,
`definition_snapshot`, `launch_inputs_snapshot`, `opened_files`, and
`observed_at`. The four nested references use the segment's exact
`{role,uri,sha256,size_bytes,issuer}` tuple, issuer `machine-a`, and
content-addressed `qualification://stage2a/blob/<lowercase-sha256>` URIs.
Their roles match their field names. They address the exact canonical
definition record array (up to 4 MiB), launch-input object (up to 1 MiB),
and the two separately opened host JSON files (up to 64 KiB each). The
measurement binding digest is the ordinary SHA-256 of its exact canonical
bytes; the definition and launch record hashes retain their separate
owner-approved purpose plus NUL preimages.

`opened_files` lists every regular file in the two approved snapshots,
sorted by `scope/path`, where `scope` is `definition` or `launch`. Each row
has exactly `scope`, `path`, `size_bytes`, `mode`, `sha256`, `owner_uid`,
`owner_gid`, `device`, `inode`, `generation`, `birthtime_ns`, `link_count`,
`acl_allow_count`, and `observed_at`. A must produce each row from a
no-follow descriptor read under its pinned namespace, comparing metadata
before and after hashing and rejecting allow ACLs, changed bytes, extra
entries, and changed snapshot identity. The offline consumer joins every
row to the exact record bytes, both snapshot identities, the selected
command under either approved snapshot, all eight named component and
sandbox-policy digest references to launch files, the effective profile,
and the separately hashed host projection files. It does not archive large
executable bytes.
The offline resolver also requires the authenticated A stop time and A
segment-signing time: every opened-file timestamp and the wrapper timestamp
must fall from the signed idle stop through the segment signature, inclusive.
The caller must verify the stop and segment signatures and the segment's exact
`installed_inputs_sha256` before crediting that join. Passing arbitrary times
to the component is not A authentication.
The companion `ResolveSignedInstalledInputInventoryV3` component verifies
both envelopes against an independently enrolled A Ed25519 key, joins the
signed idle stop and attestation to the same installation, start, launch,
host, profile, plan and measurement binding, checks the exact stop and
inventory digests, then applies the bounded offline inventory check. It does
not authenticate the reservation/Q chain, attest a release, or prove a gate.

The current wrapper covers the frozen definition and R-readable launch-input
snapshot. It does not attest a separate H-readable HQ/Comms/contracts code
domain or join that domain to a signed release. The two-domain binding,
access and measurement limits still need a reviewed contract. H and R must
not gain a shared writable or readable group through this draft.
The current `Stage2aLaunchInputRecords` v1 source contract and this offline
consumer require eight component digests backed by R-snapshot files, including
`harness` and `test_provider`. The owner has clarified that the base
HQ/Machine/Souls install is harness-free and does not request Stage 2a
protected-launch qualification. A protected pilot is a separate, owner-reviewed
selection; ACP/Claude and any other selected test inputs must be measured
exactly. The current eight-component v1 protected schema is not silently
reinterpreted for the base install. A reviewed successor must specify optional
component mapping and the separate H code measurement before this draft can
credit an installed protected pilot.
The signed v3 qualification's `adapter.package_sha256` and
`launch.executable`/`launch.code_inputs` claims need an exact reviewed mapping
to opened R inventory paths and the adapter release attestation. The
`measurement_binding.package_sha256` names the Machine package and is a
different subject; this draft never equates those two package digests.

The source-only A archive helper publishes the unsigned wrapper and four
nested blobs in the pinned A-private qualification store under
`objects/sha256/<prefix>/<digest>`. It verifies the wrapper's exact canonical
bytes and nested references, creates no-follow A-owned mode-0700 directories,
uses exclusive mode-0600 full-sync object commits, and only reuses an existing
name after rechecking its exact bytes and private metadata. A disposable native
test passes a producer-to-archive-to-offline read, identical replay, changed
same-name object refusal, wrong-A-account refusal and symlinked archive-parent
refusal. This helper has no production caller or A-signed segment issuer yet.
The physical segment attestation must bind the exact wrapper digest
before an offline verifier can credit the observation. Raw ACP/OS custody,
case inventory, native results, and T21's distinct form remain separate
requirements. No public acceptance gate uses this component yet.

The portable `ResolveSignedProtectedSegmentsV3` component follows the signed
protected report's T01/T02/T03 gate references, verifies each completed and
stopped segment manifest and A attestation, resolves all ten exact local blob
references, checks the distinct A reservation/B finalization/idle-stop chain,
and joins the signed Q wire/index/EOF through `VerifyQPreSignV3`. It refuses
changed, missing or wrongly signed bytes. Every supplemental protected segment
must also match the report anchor's installed installation, Soul, plan,
package, frozen definition and launch inputs, and both snapshot identities;
a fresh start, launch ID and HQ epoch may differ after restart.
This prevents one signed cohort from substituting another installed Soul for
only a negative or recovery case. It returns no physical gate verdict:
the ACP/OS blobs and installed-input inventory still need fixed capture
schemas and independent measured-byte checks, and gate attempts and required
negative cases still need authenticated enumeration. T21 needs its separate
cooperative R-only form. The public v3 gate remains unqualified.

The portable `VerifyMeasurementRecordDigestsV3` component accepts the exact
canonical RFC 8785 JCS definition-record array and launch-input object. It
independently computes the approved purpose-NUL-SHA-256 measurements and joins
them to a `machine/v2` measurement binding. A cross-package synthetic vector
matches Machine's definition and launch-input producers; changed, noncanonical
and duplicate-key bytes refuse. This is a digest component only. The caller
must authenticate the binding through the designated-host report and A
reservation, validate every record against the owner plan, and prove A's
descriptor-read installed-file, snapshot and process custody. The raw ACP/OS
captures, source issuer, T21 form and physical case inventory also remain
necessary before public v3 acceptance.

The portable `parseHRMeasurementBindingV3` component accepts only the
ordinary `machine/v3` H/R binding from soul-contracts v0.9.0 (introduced in
v0.8.0). It checks inherited nonroot A snapshot constraints, the exact derived
R snapshot and sidecar names, the owner plan and inventory digest joins,
selected H descriptor digest, ordered R source/artifact/manifest claims, the
distinct adapter qualification attestation, and broker executable fields. The
synthetic Contracts vector and changed H/R, release, plan and source-tag
refusals are parser tests. This component is not a signed reservation verifier
and does not open public v3 acceptance. A first-qualification candidate
requires a separate purpose and binding; it cannot satisfy this ordinary parser by
omitting the adapter qualification attestation.

The separate first-qualification component consumes the distinct signed
candidate reservation from Contracts v0.9.0. It derives only the fixed
`machine/v2` summary carried by the v3 host report, verifies the A signature
under the independently enrolled Machine key, and joins the full reservation
envelope digest, admission challenge, host and Soul identity, selected adapter
ZIP, executable and ordered code-input paths to the report. When the full
protected report supplies its bridge principals, the A UID and sealed R reader
UID/GID must match the reported Machine and runner account. Its tests use the
exact Contracts candidate vector and the Machine H producer's paired report
summary. This check does not verify approval spending, the sealed R files,
Q/ACP/OS captures or any physical T result. The ordinary release attestation
still follows qualification and the public acceptance gate remains closed.

The earlier managed-cooperative T21 diagnostic consumes the distinct A-signed
`agent-bot/soul-cooperative-reservation/v3` envelope from Contracts #75
(merged reviewed head `2076eb64022921624a75dd271d024bc02e2ef55a`).
That direct-transport vector was superseded for the protected B route by
Contracts v0.10.1 and v0.10.2; this earlier diagnostic grants no brokered-B
qualification.
It verifies the enrolled A key and exact canonical bytes, derives the fixed
`machine/v2` host-report projection, and joins the report to the H descriptor,
sealed R inventory, frozen definition and launch roots, runner UID/GID,
H-owned per-start admission and runner-scoped broker endpoints, H-hosted broker
module identity, released adapter claim, challenge and
reservation digest. Its paired synthetic vector and substitution tests are
source-level evidence only. The complete H descriptor, R sidecar and
cooperative launch-input records must still be resolved and remeasured from
A-custodied bytes. A separate offline R sidecar parser checks canonical
inventory bytes, the purpose-separated R digest, sidecar size/hash, the exact
file and directory closure, numeric ceilings, release-path uniqueness and the
signed R reference counts. It does not authenticate file contents or custody.
The offline `CheckCooperativeHostReportRInventoryV3` diagnostic composes the
designated-host report signature, A-signed cooperative reservation and exact
R sidecar, then requires the reported adapter executable and every code-input
digest to equal a row for that adapter component in the sidecar. It also
requires an executable inventory mode and refuses another component's file,
an unlisted path, or a coherent sidecar replacement with changed code bytes.
The cooperative parser checks the derived per-installation start socket name.
It accepts an optional qualification-provider config only when its exact
canonical bytes match the signed digest; ordinary cooperative starts can omit
that test-only config. The matching launch-input harness/provider pins still
need independent measurement.
It remains a claim-to-inventory join: the actual sealed files, component
release manifest, Q runner and physical T21 result are not established by it.
One-use spending, release attestation, T21 segment artifacts and physical
results remain separate gates; this diagnostic cannot return a positive Stage
2a acceptance result.

The protected B successor in Contracts v0.10.2 binds two distinct A-signed
canonical envelopes. The R-visible primary reservation selects exactly
`adapter_transport: "brokered-b"` and carries the digest of the static B
launch object plus explicit member and relay endpoints. The H/B-only
`agent-bot/soul-cooperative-bridge-assignment/v3` envelope binds the SHA-256 of
the complete primary envelope and carries the full B launch object and broker
endpoint. `VerifyCooperativeBridgeAssignmentV3` checks both signatures under
the independently enrolled Machine public key, exact canonical bytes and
field sets, host/installation/start/launch/plan/HQ epoch/time equality,
measurement binding, exact digest joins, Machine-derived R/B accounts and
UID/GID ranges, endpoint paths/modes/peer and parent identity claims, and the
ordered `sandbox-exec` argv. Tests use the released synthetic B vector and
coherently re-signed substitutions. This helper is source-only: it neither
measures installed B/R files or live socket parents nor verifies one-use
spending, release attestation, raw Q/ACP/OS captures, physical T21, or a v3
report/completion successor. The public acceptance result remains unqualified.

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

The v3 producer `mm-qualification-preflight --host-v3` path also refuses after
its signed-chain diagnostic check and emits no success receipt. A successful
chain and Souls build alone cannot authorize the release workflow to sign a
qualification. The producer needs the same authenticated physical traversal
and installed-byte binding before a v3 preflight result can be enabled.

## Open acceptance work

There is no production Q account installation or A spawn/call site in this
source slice. The composite A bundle is written after the host report and
post-sign commitment, so it cannot be a pre-sign gate-manifest reference.
The pre-sign index and EOF receipt now have source issuers and a private sink,
but their exact digests are not yet bound into a segment attestation or signed
host report, and no production order enforces their publication before keyd.
A must independently corroborate Q's raw
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
