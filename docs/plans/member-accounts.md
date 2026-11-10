---
name: member-accounts
status: active
overview: On Linux, create one OS account per Soul member, the broker endpoint directories HQ verifies, and the rule that lets the HQ account start members. Nothing runs as root until the owner has approved the exact plan in the local web UI.
related_prs: []
---

# Member accounts, endpoint directories and the launch rule

Issue: [#470](https://github.com/true-line/agent-bot-machine/issues/470).
Source: rows 16a and 16b of the
[agent-bot-hq migration plan](https://github.com/true-line/agent-bot-hq/blob/main/docs/daemon-plugin-split.md),
and the owner's decisions of 2026-11-10 recorded there.

## Intent

The Linux protected profile needs each Soul member in its own OS account, so
one member cannot read another member's state or speak for it. HQ is not root
and creates none of this. HQ already verifies the layout at start
(`hq/members.mjs` in agent-bot-hq) and refuses anything else.

The owner decided:

- agent-bot-machine creates the accounts, the directories and the rule, once,
  at provisioning. HQ uses the rule at runtime. Launches do not go through
  agent-machine, because it holds the keys (D4).
- Before any command runs as root, the owner sees the request and accepts it
  in the local web UI. For this slice that is the Approvals tab of the local
  web UI in agent-bot-identity. The hosted website does not approve or run it.

This depends on S6 in [cross-account-channel.md](cross-account-channel.md)
(the HQ account). Until S6 lands, the tests name a throwaway HQ account.

## Target

Linux only. macOS waits for HQ plan row 29; every command here refuses on
another OS before it reads anything.

### What is created

For an HQ account `H` and each listed member account `M`:

| Thing                                       | Owner, group, mode                      | Notes                                                                                                                                                                                             |
| ------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Account `M`                                 | its own private group, no other members | No password, no login shell beyond what a member needs, not in `sudo`, `admin` or `H`'s group. Home at 0700                                                                                       |
| `/run/agent-bot-hq/members/`                | `H` or root, 0755                       | Not writable by group or others                                                                                                                                                                   |
| `/run/agent-bot-hq/members/M/`              | `H`, group of `M`, 2750                 | HQ creates `broker.sock` inside, 0660                                                                                                                                                             |
| `/etc/tmpfiles.d/agent-bot-hq-members.conf` | root, 0644                              | Recreates the two directories at boot, because `/run` is cleared                                                                                                                                  |
| `/etc/sudoers.d/agent-bot-hq-members`       | root, 0440                              | `H` may run commands as the listed `M` accounts and as nothing else. No root, no group target, no `SETENV`. A fixed environment allowlist. Checked with `visudo -c` before it is moved into place |

Refused, never adopted: an `M` that already exists with a shared group, a
password, extra group memberships or uid 0; an `M` equal to `H`, to the prefix
owner or to the invoking owner; two members with one uid.

### Three steps, three actors

1. **Plan (no privilege).** `managed-machine members plan` reads the list and
   the host, and writes a saved plan: every account, directory and file it
   would create or repair, with the exact contents of the two files. It
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

`members plan` with a member taken off the list plans the removal of its
sudoers entry and endpoint directory. The account and its home are kept and
reported, never deleted by this tool: a member's home may hold work.

## Open questions for the owner

| Question                                    | Recommendation                                                                                                            |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Account names                               | `abm-<name>`, at most 32 characters, matching `^[a-z_][a-z0-9_-]{0,31}$`, which is what HQ accepts                        |
| One list for both sides                     | HQ's `members.accounts` config names the accounts. `members plan` reads that file, so the provisioner and HQ cannot drift |
| A graphical prompt instead of terminal sudo | Not now. `pkexec` can be added later without changing the plan, the approval or the digest                                |

## Acceptance

On real accounts in CI (Linux), as in agent-bot-hq's member accounts step:

- `plan` changes nothing and its digest is stable across two runs.
- `apply` without an approval, with an expired or used approval, with an
  approval file a non-owner can write, or after the host changed, runs
  nothing and says which.
- After an approved apply: HQ's layout check passes; the HQ account can start
  a process as a member account and cannot start one as root or as an
  unlisted account; a member account cannot use the rule; a member cannot
  enter another member's endpoint directory or home.
- A second approved apply on the same host is a no-op.
- `visudo -c` passes, and a deliberately broken rule is never installed.
- An agent account or session is refused before anything is read.
- `approve-members` with a bad signature, an unknown plan ID or extra fields
  is refused like any other verb.

## Replay

1. Read this plan, [machine-daemon.md](machine-daemon.md),
   [cross-account-channel.md](cross-account-channel.md) and `AGENTS.md`.
2. Work in a soul worktree, not the owner's primary checkout.
3. Build order: the plan and its digest (`internal/members`, pure, tested
   with injected host readers); the `approve-members` verb in
   `internal/daemon`; the root apply; the CI job on real accounts. The
   proposal type in agent-bot-identity's `agent-web.mjs` follows, and the
   matching screen in the design source.
4. Gate: `gofmt -l . && go vet ./... && go test ./...`.
5. Update the closed verb set in [machine-daemon.md](machine-daemon.md) in
   the change that adds `approve-members`.
