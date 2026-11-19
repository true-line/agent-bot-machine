---
name: member-accounts
status: active
overview: On Linux, provision the harness credential accounts from HQ's configuration, their broker endpoint directories, outbound-IP isolation, and HQ's launch rule. Nothing runs as root until the owner has approved the exact plan in the local web UI.
related_prs: [471, 472, 473, 474, 476, 478]
---

# Harness accounts, endpoint directories, egress isolation and the launch rule

Issues: [#470](https://github.com/true-line/agent-bot-machine/issues/470) and
[#496](https://github.com/true-line/agent-bot-machine/issues/496).
Source: rows 16a, 16b and the machine-owned boundary in row 16c of the
[agent-bot-hq migration plan](https://github.com/true-line/agent-bot-hq/blob/main/docs/daemon-plugin-split.md),
and the owner's decisions of 2026-11-10 recorded there.

## Intent

[PDR-0053](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0053-soul-life-and-agent-replace-member.md)
sets the unit to one OS account per harness credential, shared by the agents
of every Soul using that credential. HQ is not root and creates none of this.
HQ verifies the layout at start (`hq/harness-accounts.mjs`) and refuses anything
else. Account provisioning and this egress boundary do not by themselves
establish the protected profile; PDR-0053 leaves the protected eligibility of
shared harness accounts unspecified. HQ admission verification and workspace
views remain separate row 16c work.

The `members` command, `--members` flag, saved plan fields and installed paths
retain their compatibility names. They do not define a per-Soul account unit.

The owner decided:

- agent-bot-machine creates the accounts, the directories and the rule, once,
  at provisioning. HQ uses the rule at runtime. Launches do not go through
  agent-machine, because it holds the keys (D4).
- Before any command runs as root, the owner sees the request and accepts it
  in the local web UI. For this slice that is the Approvals tab of the local
  web UI in agent-bot-identity. The hosted website does not approve or run it.

The same plan creates the HQ account when it does not exist. That is S6 in
[cross-account-channel.md](cross-account-channel.md), issue
[#475](https://github.com/true-line/agent-bot-machine/issues/475).

## Target

On macOS, `members plan` without an account list retains the HQ-only plan.
Pass `--hq-config` to plan one role for each distinct credential account in
`harnesses.accounts`, or `--members` to supply the account names directly.
The owner's digest approval and root apply create each harness role with
a unique UID, a same-name private group, a locked password, shell
`/usr/bin/false`, and a 0700 home at `/var/agent-bot-harness-<account>`.
Existing harness accounts must match the managed role. Shared HQ and owner
accounts are refused for a harness plan. Darwin only provisions the accounts
in this plan. The Linux endpoint, launch and egress steps below are separate
parts of the protected-harness qualification on macOS.
The disposable macOS acceptance test is `tests/members-apply-macos.test.sh`.

### What is created

For an HQ account `H` and each listed harness credential account `M`:

| Thing                                       | Owner, group, mode                      | Notes                                                                                                                                                                                             |
| ------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Account `H`, when it does not exist         | its own private group, no other members | A service account: no password, shell `nologin`, in no other group. Home `/var/lib/H` at 0700, which is HQ's state                                                                                |
| Account `M`                                 | its own private group, no other members | No password, no login shell beyond what a harness needs, not in `sudo`, `admin` or `H`'s group. Home at 0700                                                                                       |
| `/run/agent-bot-hq/members/`                | `H` or root, 0755                       | Not writable by group or others                                                                                                                                                                   |
| `/run/agent-bot-hq/members/M/`              | `H`, group of `M`, 2750                 | HQ creates `broker.sock` inside, 0660                                                                                                                                                             |
| `/etc/tmpfiles.d/agent-bot-hq-members.conf` | root, 0644                              | Recreates the two directories at boot, because `/run` is cleared                                                                                                                                  |
| `/usr/local/sbin/agent-bot-hq-members-egress` | root, 0755                            | Owns and replaces `ABHQ_MEMBER_EGRESS` in both `iptables` and `ip6tables`; rejects outbound IP from each listed `M`, without affecting Unix-domain sockets                                        |
| `/etc/systemd/system/agent-bot-hq-members-egress.service` | root, 0644              | Enables the exact approved policy at boot and activates it before the launch rule is installed                                                                                                   |
| `/etc/sudoers.d/agent-bot-hq-members`       | root, 0440                              | `H` may run commands as the listed `M` accounts and as nothing else. No root, no group target, no `SETENV`. A fixed environment allowlist. Checked with `visudo -c` before it is moved into place |

Refused, never adopted: an `M` that already exists with a shared group, a
password, extra group memberships or uid 0; an `M` equal to `H`, to the prefix
owner or to the invoking owner; two distinct account names with one uid.
The names `root` and `admin` are reserved even if a lookup finds no account.

### Three steps, three actors

1. **Plan (no privilege).** `managed-machine members plan` reads the list and
   the host, and writes a saved plan: every account, directory and file it
   would create or repair, with the exact contents of every managed file. It
   changes nothing. It prints the plan ID and `plan_digest`, the SHA-256 of
   the plan's canonical JSON. An agent may run it.
2. **Approve (the owner, in the local web UI).** The plan appears as a
   proposal in the Approvals tab, showing the same content the digest covers.
   When the owner approves, the daemon behind that UI sends agent-machine a
   signed `approve-members` request carrying the plan ID and digest.
   agent-machine checks the signature as it does for every verb, then records
   the approval in its own state directory: plan ID, digest, time, expiry.
   An approval is good for 10 minutes and for one apply.
3. **Apply (root).** `managed-machine members apply <plan-id>` runs as root.
   It rebuilds the plan from the host as it is now, and continues only if
   - an unexpired, unused approval for that plan ID exists,
   - the approval file is owned by the prefix owner and not writable by
     anyone else, and
   - the rebuilt plan's digest equals the approved digest.

   A host that changed after approval gives a different digest and nothing
   runs. It then applies the plan, marks the approval used, and writes a
   receipt with no secrets.

`apply` takes a plan ID and nothing else, like the daemon's `apply`
(ADR-0012). There is no flag that skips the approval.

### Paired HQ service recovery on macOS

When the dedicated HQ account already exists and its service is down, the
prefix administrator saves a fresh HQ service plan in the default members
store. The enrolled HQ CLI fetches the plan over the signed Machine channel.
The operator carries its one-operation signed challenge to the daily owner's
local Approvals interface, and returns the public proof to the same HQ CLI.
The [paired workflow](https://github.com/true-line/agent-bot-machine/issues/539)
keeps the existing enrollment and owner pin. A failed earlier root apply has
already claimed its own plan ID.

The channel verb is `hq-service-recovery`. All requests carry the exact
`plan_id` and `plan_digest`. Its signed `option` selects an operation.

| Option | Additional request fields | Signed success state and body |
| --- | --- | --- |
| `challenge` | None | `challenged` with the exact fields below |
| `approve` | `challenge_nonce`, `owner_signature` | `approved` with the existing members approval record |
| `cancel` | `challenge_nonce` | `cancelled` with `plan_id` and `plan_digest` |

The usual HQ Ed25519 request signature includes the existing
`plan_digest` suffix. Following it, append the LF-separated field name and
value for `challenge_nonce` when present, then `owner_signature` when
present. The transport signature has no trailing LF. The Machine reply
uses the existing signed response frame and binds the transport request nonce.

The challenge body contains exactly `action`, `machine_key`, `hq_key`,
`owner_key`, `plan_id`, `plan_digest`, `nonce`, `expires_at` and
`plan_canonical`. Preserve the original signed response bytes for handoff.
The receiver verifies the Machine key against its independently trusted
SHA-256 fingerprint and recomputes the plan digest over the canonical UTF-8
string, including its final LF. The owner's signer verifies that its hardware
key equals the pinned `owner_key` and shows the exact service and owner before
requesting presence.

The owner's ECDSA P-256/SHA-256 signature covers the following UTF-8 lines,
including the final LF. Machine and HQ keys and the 32-byte challenge nonce
are lowercase hex. The owner key is canonical standard base64 of the
uncompressed 65-byte public point. Expiry is decimal Unix time, at most
120 seconds from issuance. The returned signature is standard base64 of
the ASN.1 DER signature.

```text
agent-bot-machine-owner/v1
hq-service-recovery
<MACHINE_KEY>
<HQ_KEY>
<OWNER_KEY>
<PLAN_ID>
<PLAN_DIGEST>
<CHALLENGE_NONCE>
<EXPIRES_AT>
```

Machine checks the current protected peer and kernel UID, current Machine and
owner keys, and a locally rebuilt exact plan at issue and before approval.
The sole allowed steps are the unchanged dedicated HQ account and its
verified LaunchDaemon create/write. The member list must be empty. The
retained archive, Node executable, extracted files, owner and service
definition must match. An active HQ process or conflicting job is refused.
Issuing a challenge replaces the old one. Cancellation matches the challenge
nonce and cannot revoke its replacement. A successful proof is consumed in
durable state before recording the usual ten-minute approval. Only the
existing human-run `sudo managed-machine members apply PLAN_ID` acts on the
host and verifies the running service. The protected route leaves generic
member approvals, first installation, and enrollment on their existing terms.

### Updating a running paired HQ release on macOS

The prefix administrator stages an independently verified new HQ release and
runs `managed-machine members plan --hq-service NEW_SERVICE_JSON --upgrade-from PREVIOUS_PLAN_ID`.
Machine requires the retained previous saved plan, its completed root apply
receipt, the matching installed plist and a running dedicated HQ job.
The previous receipt commits to the original canonical plan through its
digest. Machine verifies both releases, their extracted files, the same
pinned Node executable and the protected version 2 owner-control directory.
The role, owner UID and state location are part of the reviewed plan.

The paired HQ CLI exports `hq-service-upgrade` through the signed Machine
channel. The challenge, transport signature and owner transcript use the
service recovery field order above with `hq-service-upgrade` as the purpose.
The service step has action `upgrade`. Its content includes
`previous_plan_id`, `previous_plan_digest`, `previous` and `next`.
The last two values are the full service records, including their plists.
The owner reviews this exact change and returns a fresh proof signed by
the existing owner key. A compatible protected owner proof provider is
required. The administrator runs `sudo managed-machine members apply PLAN_ID`
in their own terminal.

The service update supports an already Machine-backed HQ on Apple Silicon
running Darwin kernel 25 or later. Both releases must report the same public
hardware signer identity and generation. An older software signer requires
a separate custody migration before this operation. Machine checks this
before stopping the running HQ. It also checks the current HQ pairing and
its enrollment epoch, validates the existing job's UID, then records the
reviewed inputs before unloading it. The two verified plists exchange
atomically. Launchd restarts HQ using the new release. Machine verifies the
owner endpoint and the signed HQ-to-Machine status through the dedicated role.

After interruption, repeat the same `members apply PLAN_ID` command. The
root transaction record identifies the exact reviewed files, original pairing
and last phase. Machine can confirm a running new release or restore the
verified previous one. It leaves an unidentified job, changed plist or
unverified endpoint intact for administrator reconciliation. A completed
receipt permits a read-only verification when the previous terminal result
was lost. Retain the old release, its saved plan and the shared Node binary
through completion.

### How root is obtained

The owner runs `sudo managed-machine members apply <plan-id>` in their own
terminal. sudo's password prompt is the privilege grant; the approval is the
consent to this exact plan. Agent accounts, agent sessions and harness
markers are refused before anything is read, as `ssh enroll` and `--update`
do. The machine daemon still never runs as root and gains no execution verb:
`approve-members` only records a digest.

### What the approval does and does not prove

Until HQ has its own account (S6), the daemon behind the local web UI runs in
the owner's account, and so does its client key. A process in that account
could sign `approve-members` itself. It still could not run the apply: that
needs the owner's password. So the approval binds what is applied to what
the owner was shown, and sudo keeps an agent from applying it. After S6 the
signing key is out of the owner's account and the approval stands alone.

### Removal

`members plan` with an account absent from the unique account set plans the
removal of its sudoers entry, egress rules and endpoint directory. Removing one
adapter does not remove an account still used by another adapter. The account
and its home are kept and reported, never deleted by this tool: the home may
hold work.

## Open questions for the owner

| Question                                    | Recommendation                                                                                                            |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Account names                               | `abm-<name>`, at most 32 characters, matching `^[a-z_][a-z0-9_-]{0,31}$`, which is what HQ accepts                        |
| One list for both sides                     | HQ's `harnesses.accounts` maps adapter IDs to accounts. `members plan` reads that file and provisions each distinct account once |
| A graphical prompt instead of terminal sudo | Not now. `pkexec` can be added later without changing the plan, the approval or the digest                                |

## As built

**Step 1, the plan** (`internal/members`):

```sh
managed-machine members plan [--hq-account <account>] (--hq-config <path> | --members <a,b,...>) [--dir <path>]
```

- `--hq-config` reads `harnesses.accounts` (adapter ID to account) and optional
  `harnesses.dir` from HQ's `config.json`. Multiple adapters may share an
  account; the provisioner sorts and deduplicates the account set before
  building the plan. Omitted `dir` uses `/run/agent-bot-hq/members`.
- The `harnesses` section accepts only `accounts` and `dir`. Adapter IDs follow
  HQ's `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`; account names follow
  `^[a-z_][a-z0-9_-]{0,31}$`. The existing provisioning path restrictions
  still apply, including a clean absolute directory safe for tmpfiles/sudoers.
- Missing, null or malformed account maps are refused before saving a plan.
  An explicit `accounts: {}` requests the existing removal plan, never deletion
  of accounts or homes. A legacy `members` section, even alongside `harnesses`,
  is refused with migration advice; there is no fallback to the retired mapping.
- `--members` still names accounts directly. Equivalent account sets retain
  the same version-3 plan and digest, approval protocol and apply behavior.
  Adapter-to-account binding remains HQ's responsibility; the plan covers
  the accounts and host changes it provisions.
- The first record carries `plan_id`, `plan_digest`, `changes` and
  `applied: false`. One record follows per step, with the exact content of
  each file.
- Step actions are `create`, `repair`, `remove`, `none` and `write`.
- **The sudoers step is always `write`.** `/etc/sudoers.d` is closed to
  everyone but root, so a plan made without privilege cannot see what is
  there. A step that depended on it would give root's rebuild a different
  digest and no apply could ever match. Apply checks the existing file
  itself, as root.
- An account that already exists is verified, never changed. Its password
  can only be read as root, so that check is at apply.
- New accounts get home `/home/<account>` and shell `/usr/sbin/nologin`.
  `sudo -u` runs a command directly, so a harness needs no login shell.
- Diagnostics: `MM_MEMBERS_UNSUPPORTED`, `MM_MEMBERS_LIST_INVALID`,
  `MM_MEMBERS_ACCOUNT_REFUSED`, `MM_MEMBERS_PATH_REFUSED`,
  `MM_MEMBERS_PLAN_FAILED`.

**The HQ account** (`internal/members`, S6):

- The first step of every plan has kind `hq-account`.
- **Missing:** the step is `create`. Apply runs
  `useradd --system --create-home --home-dir /var/lib/<account> --user-group --shell /usr/sbin/nologin`,
  sets the home to 0700, and fails unless the new account is locked. It comes
  before the harness accounts, so the directories, the tmpfiles entry and the
  launch rule never name an account that does not exist.
- **Exists and is dedicated** (a private group of its own name, nobody else
  in it, no other group): it is verified like a harness account. Its home
  must be its own directory and is repaired to 0700; a password, an empty
  one or no shadow entry is `MM_MEMBERS_ACCOUNT_REFUSED` at apply.
- **Exists and is shared** (the owner's own account, where HQ runs until it
  moves): it is accepted and left exactly as it is. The step says
  `not a dedicated account` and why, so that is what the owner approves.
  HQ's state is then only as private as that account, and HQ reports
  `managed-cooperative`.
- **The owner is steered to the dedicated account.** `--hq-account` defaults
  to `agent-bot-hq`, so a plan that names no account creates and uses the
  dedicated one. A plan or apply on a shared account reports
  `hq_account_dedicated: false` and an `advice` line saying what every
  process in that account can then do and to plan again without
  `--hq-account`. The same recommendation is in the step the owner approves.
- uid 0 is refused. A harness account that shares the HQ account's uid is refused.
- The plan version is 3. A plan saved by an older build has another digest
  and cannot be approved.

**Step 2, the approval record** (`internal/daemon`, `internal/members`):

- `approve-members` is a verb of agent-machine. The request carries
  `plan_id` and `plan_digest`; any other field is `MM_DAEMON_UNDECLARED`,
  and so is `plan_digest` on any other verb, even empty or null. The digest
  is in the signed payload, as the two lines `plan_digest` and its value
  after the nonce. A request without it signs exactly as before.
- `plan_id` must be a plan ID and `plan_digest` 64 lowercase hex characters.
  The plan ID becomes a file name, so nothing else reaches the disk.
- The daemon writes `members/approvals/<plan-id>.json` in its state
  directory (directory `0700`, file `0600`): `plan_id`, `plan_digest`,
  `approved_at`, `expires_at`. The response has state `approved` and the
  same four fields as its body. A second approval of one plan replaces the
  first. Expired and unreadable approval files are removed on each write.
- **The daemon does not read the plan.** The plan file is private to the
  account that made it, which is usually not the daemon's account. So the
  daemon cannot refuse an unknown plan ID. An approval for a plan that does
  not exist is inert: apply finds no plan and runs nothing. The acceptance
  line below is corrected to match.
- Only the paired agent-daemon key can send it. The terminal key is refused
  with `MM_DAEMON_UNKNOWN_KEY`, as for every verb but `update`, `status` and
  `receipts`.
- Another OS refuses with `MM_MEMBERS_UNSUPPORTED` and writes nothing.
- It writes no receipt. A receipt belongs to the apply.

**Step 3, the apply** (`internal/members`):

```sh
sudo managed-machine members apply <plan-id>
```

It takes a plan ID and nothing else. The checks run in this order, and each
refusal comes before any change:

1. **The caller.** Linux, effective uid 0 and a `SUDO_UID` that is not 0,
   or `MM_MEMBERS_ROOT_REQUIRED`: a root login has no owner behind it. The
   account that ran sudo is the owner. An agent account, an agent marker in
   the environment, or an agent marker in the environment of any process
   above sudo (read from `/proc`) is `MM_MEMBERS_CALLER_REFUSED`. sudo
   resets the environment of the command, so the ancestors are where a
   session started from an agent still shows.
2. **The plan.** Read from the owner's state directory,
   `~owner/.local/share/managed-machine/members/plans/`. Only its request
   (HQ account, directory, members) is used; the plan is built again from
   the host. A plan saved under a custom `XDG_DATA_HOME` is not found:
   sudo does not carry that variable, and apply does not trust it.
3. **The approval.** Read from agent-machine's state directory: the home of
   the Homebrew prefix owner, or the owner's own home where there is no
   prefix. The approvals directory and the file must be owned by that
   account, writable by nobody else, and the file a regular file. It must
   name this plan ID, be unexpired, and carry the digest of the plan just
   rebuilt. Anything else is `MM_MEMBERS_NOT_APPROVED`.
4. **What only root can read.** An existing harness account must be locked:
   a shadow field starting with `!` or `*`. A password, an empty field or
   no entry is `MM_MEMBERS_ACCOUNT_REFUSED`. A launch rule already at
   `/etc/sudoers.d/agent-bot-hq-members` that this tool did not write is
   `MM_MEMBERS_PATH_REFUSED`. Occupied egress script or unit paths without the
   managed header are also refused. Before the approval is claimed,
   `/bin/sh -n` parses the exact helper and both `iptables-restore --test` variants
   parse its owner-match rule; all programs are absolute paths. A missing or
   unsupported prerequisite changes nothing and does not consume the approval.
5. **One apply per approval.** The receipt is created, exclusively, at
   `/var/lib/managed-machine/members/receipts/<plan-id>.json` before the
   first change. If it exists, the approval was used. The receipt is in a
   root-owned directory so no other account can remove it and reuse the
   approval. This replaces "marks the approval used": apply writes nothing
   into a directory another account controls.

**The launch rule says `NOSETENV`.** sudo implies `SETENV` for a rule whose
command is `ALL`, whatever `Defaults !setenv` says. The first run on real
accounts showed the HQ account passing a variable on the command line. The
rule is now `H ALL = (ABHQ_MEMBERS) NOPASSWD: NOSETENV: ALL`, and the CI job
checks that a variable outside the allowlist is refused both ways.

Then the steps run in plan order: accounts, directories, the tmpfiles entry,
the egress helper and unit, egress activation, and the launch rule last.

- Accounts: `/usr/sbin/useradd --create-home --home-dir /home/<m>
  --user-group --shell /usr/sbin/nologin <m>`, then the home is set to 0700
  and the account is checked to be locked. Programs are named by absolute
  path and run with a fixed environment.
- Directories: created, then owner and group, then mode, because changing
  the owner clears the setgid bit.
- Files: written to a dot-named temporary file beside the target, which
  sudo skips, then renamed. The launch rule is checked with
  `/usr/sbin/visudo -c -f` on the temporary file first; a rule that fails
  is removed and never installed.
- Egress: systemd is reloaded, the unit is enabled for boot, restarted and
  required to be active. Its tool-owned IPv4 and IPv6 chains reject output by
  uid for exactly the approved member list. Unix-domain broker sockets do not
  cross these chains. If activation fails during an upgrade, an existing
  managed launch rule is removed before apply fails, so a member cannot keep
  launching without the boundary.
- After the last step the plan is built once more. Any remaining change is
  `MM_MEMBERS_APPLY_FAILED`. A failed apply leaves earlier steps in place,
  says which step stopped it, and records `failed` in the receipt.

The CI job `member accounts (real accounts)` runs
`tests/members-apply.test.sh` on a GitHub-hosted Linux runner with real
accounts, sudo, visudo, systemd and both firewall families. It covers the
acceptance list below except three lines: HQ's own layout check (that code is
in agent-bot-hq; the script
asserts the same owners, groups and modes), a deliberately broken rule
(covered by a Go test with an injected failure, because the tool cannot be
made to generate one), and `approve-members` itself (Go tests in
`internal/daemon`; the script writes the approval file in the same form).

On split accounts Machine serves saved IDs and canonical plan bytes to the
enrolled HQ service account through the signed [`members-plans` read
operation](machine-daemon.md#closed-verb-set). Fetching a plan leaves its
approval and apply state untouched. The protected approval step for an
already paired HQ is tracked in [Machine #539](https://github.com/true-line/agent-bot-machine/issues/539).

**Local owner approval is built.** agent-bot-identity's
[proposal route](https://github.com/true-line/agent-bot-identity/blob/774e177a0c79ef4ab404de4df3cfb35949e4db6a/agent-web.mjs)
reads the saved plan, verifies its canonical digest, and presents its steps
in the local Approvals tab. Only the approved callback sends `approve-members`
with the plan ID and digest. Its `machine-members.mjs`,
`tests/machine-members.test.mjs`, `tests/web-client.test.mjs` and
`tests/machine-route.test.mjs` cover digest matching, owner-only approval and
the signed request. These component tests and machine's injected approval
fixture do not claim a complete live-host UI-to-root provisioning rehearsal.

## Acceptance

On real accounts in CI (Linux), as in agent-bot-hq's member accounts step:

- `plan` changes nothing and its digest is stable across two runs.
- Current HQ harness configuration produces the same plan as the equivalent
  direct account list. Shared accounts are provisioned once, mapping order
  does not change the digest, and malformed or legacy configuration leaves
  existing saved plans untouched. An explicit empty map plans removal.
- `apply` without an approval, with an expired or used approval, with an
  approval file a non-owner can write, or after the host changed, runs
  nothing and says which.
- A plan on a host with no HQ account creates it first. After the apply it
  is a locked service account in no other group; its home is 0700 and
  neither the owner nor a harness account can enter it. The owner's own account named
  as the HQ account is left alone and the plan says it is shared.
- After an approved apply: HQ's layout check passes; the HQ account can start
  a process as a harness account and cannot start one as root or as an
  unlisted account; a harness account cannot use the rule or enter another
  harness account's endpoint directory or home. Processes sharing one account
  are not isolated from each other by these filesystem permissions.
- The persistent egress service is enabled and active. A listed member cannot
  connect to local IPv4 or IPv6 listeners, while the owner can; the member can
  still connect to a Unix-domain listener. Removing a member removes only its
  egress rules, and restarting the service restores the approved policy.
- A second approved apply on the same host is a no-op.
- `visudo -c` passes, and a deliberately broken rule is never installed.
- An agent account or session is refused before anything is read.
- `approve-members` with a bad signature, a malformed plan ID or digest, or
  extra fields is refused like any other verb. `apply` with an approval for
  a plan ID it has no plan for runs nothing.

## Replay

1. Read this plan, [machine-daemon.md](machine-daemon.md),
   [cross-account-channel.md](cross-account-channel.md) and `AGENTS.md`.
2. Work in a soul worktree, not the owner's primary checkout.
3. Build order: the plan and its digest (`internal/members`, pure, tested
   with injected host readers); the `approve-members` verb in
   `internal/daemon`; the root apply; the CI job on real accounts. The
   proposal type in agent-bot-identity's `agent-web.mjs` is built; retain its
   plan/digest compatibility when changing the input mapping.
4. Gate: `gofmt -l . && go vet ./... && go test ./...`.
5. Update the closed verb set in [machine-daemon.md](machine-daemon.md) in
   the change that adds `approve-members`.

### Opt-in Linux HQ service

For a new dedicated installation, add `--hq-service RECORD.json` to the normal
`members plan`. The owner reviews and approves it and runs `members apply`
through the existing local flow. Machine uses a previously verified, extracted
[HQ interim artifact](https://github.com/true-line/agent-bot-hq/blob/main/docs/interim-release-runbook.md)
supporting `check-owner-control` and `--owner-control`. The deployment operator
selects a versioned install location and verifies both the archive and the Node
runtime before use. This example illustrates the record shape; replace both
paths and SHA-256 values with the installed, approved target.

```json
{
  "release_dir": "/opt/example-releases/VERSION/hq",
  "artifact_sha256": "<lowercase SHA-256 of the approved interim tar>",
  "node": "/opt/example-runtime/VERSION/bin/node",
  "node_sha256": "<lowercase SHA-256 of the installed Node executable>"
}
```

The `hq` extraction, every entry below it, Node, and their parent directories
must be root-owned, free of symlinks, and closed to group/other writes.
Planning and apply compare the extracted tree to the approved digest using
the builder's GNU tar options and compare Node's bytes to its digest. The
unit paths, account, UID and deployment record are in the approved steps.
The Linux host supplies systemd, GNU tar, runuser, and `/usr/bin/python3`
for HQ's peer-credential check.

Systemd opens `/run/agent-bot-hq/control.sock` mode 0600 for the approved
owner. Its socket-activated service runs as `agent-bot-hq`, with private state
in `/var/lib/agent-bot-hq/.agent-bot-hq`. Apply verifies capability as HQ, then
requests status over the new socket as the owner. An activation error records
a failed receipt; inspect the service and socket before making a fresh plan.
A conflicting installed unit requires an explicit cutover with rollback.
The existing owner-account instance, its admission clients, pairing, enrollment
and credentials require their own migration. This opt-in installs a distinct
service and does not transfer that state or qualify a protected host.

### macOS HQ LaunchDaemon

A macOS owner can run `managed-machine members plan --hq-service <record.json>`
and approve/apply its digest through the existing members workflow. The service
record uses the Linux `release_dir`, `artifact_sha256`, `node` and `node_sha256`
fields and adds `archive`, the absolute path to the retained approved Darwin
ustar artifact. Stage the archive, its complete extraction (ending in `/hq`)
and a standalone Node executable under root-owned, read-only-to-others paths.
The installer checks each extracted entry, the Node digest, and Mach-O loader
dependencies. Node must use Apple system libraries. Owner-writable Homebrew
runtimes are unsuitable. No build tools or downloads run during installation.

Machine creates the system LaunchDaemon `ai.true-line.agent-bot-hq` for
`_agent-bot-hq`. The verified Darwin archive selects the owner-control
endpoint. Existing unmarked archives use `darwin-owner-control/v1` and
`/private/var/agent-bot-hq-control.sock`. An archive advertising
`owner_control_capability: darwin-owner-control/v2` in
`governance/interim-release.json` uses
`/Library/Application Support/ai.true-line.agent-bot-hq/owner-control.sock`.
The v2 service step shows whether Machine will create or verify the
`root:wheel` mode `0755` directory. Machine verifies the root-owned ancestors and refuses ACL entries that grant access
or an installed plist that differs from the approved job. It preserves a pre-existing
directory on failure and can remove its newly created directory only when
the job is confirmed absent and the same directory is empty.

Kernel peer credentials and the approved owner's UID authorize each request.
Machine checks the matching versioned capability as the dedicated HQ account
and queries the running endpoint as the approved owner. Both layouts use a
root-owned socket at mode `0666`. The existing signed plan and pairing
continue to refer to their original subject. Changing an installed service's
layout or release requires an explicit cutover. A second approved apply
verifies the same loaded job. The experimental v2 layout requires installation
evidence on a Mac with fully enabled SIP. In the macOS 27 HQ installation
workflow, the manually selected `require_sip` input enforces this condition.

Hosted upgrade tests run a real system LaunchDaemon under its dedicated
account. One job verifies that a software predecessor keeps its PID and plist
when a service-only upgrade is refused. A second uses the public paired HQ
releases, a disposable owner key and a test executable that delegates to the
native admin keyd in a temporary Keychain. It checks rollback after a candidate
status failure, a successful replacement and a read-only retry. The hosted
test executable is built separately from the distributed Machine binary.
Testing the distribution signature requirement for the upgrade requires a
public signed Machine and keyd release supporting both hardware custody and
the upgrade operation. Physical SIP-enabled evidence remains a separate gate.

For a newly started job that advertises `darwin-hq-launch-exits/v2`, exit
88 reports a native socket check-in return of 159. Machine includes the
sandbox classification when this Mac's launchctl confirms it.

First-install failure rolls back the new registration. Role-account state stays
in its private home. This service operation does not qualify the protected
profile. The [HQ service issue](https://github.com/true-line/agent-bot-hq/issues/88)
tracks the scope and remaining acceptance evidence.
