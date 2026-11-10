---
name: member-accounts
status: active
overview: On Linux, create one OS account per Soul member, the broker endpoint directories HQ verifies, and the rule that lets the HQ account start members. Nothing runs as root until the owner has approved the exact plan in the local web UI.
related_prs: [471, 472, 473, 474, 476, 478]
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

The same plan creates the HQ account when it does not exist. That is S6 in
[cross-account-channel.md](cross-account-channel.md), issue
[#475](https://github.com/true-line/agent-bot-machine/issues/475).

## Target

Linux only. macOS waits for HQ plan row 29; every command here refuses on
another OS before it reads anything.

### What is created

For an HQ account `H` and each listed member account `M`:

| Thing                                       | Owner, group, mode                      | Notes                                                                                                                                                                                             |
| ------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Account `H`, when it does not exist         | its own private group, no other members | A service account: no password, shell `nologin`, in no other group. Home `/var/lib/H` at 0700, which is HQ's state                                                                                |
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

## As built

**Step 1, the plan** (`internal/members`):

```sh
managed-machine members plan [--hq-account <account>] (--hq-config <path> | --members <a,b,...>) [--dir <path>]
```

- `--hq-config` reads `members.accounts` and `members.dir` from HQ's
  `config.json`. `--members` names the accounts directly.
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
  `sudo -u` runs a command directly, so a member needs no login shell.
- Diagnostics: `MM_MEMBERS_UNSUPPORTED`, `MM_MEMBERS_LIST_INVALID`,
  `MM_MEMBERS_ACCOUNT_REFUSED`, `MM_MEMBERS_PATH_REFUSED`,
  `MM_MEMBERS_PLAN_FAILED`.

**The HQ account** (`internal/members`, S6):

- The first step of every plan has kind `hq-account`.
- **Missing:** the step is `create`. Apply runs
  `useradd --system --create-home --home-dir /var/lib/<account> --user-group --shell /usr/sbin/nologin`,
  sets the home to 0700, and fails unless the new account is locked. It comes
  before the member accounts, so the directories, the tmpfiles entry and the
  launch rule never name an account that does not exist.
- **Exists and is dedicated** (a private group of its own name, nobody else
  in it, no other group): it is verified like a member account. Its home
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
- uid 0 is refused. A member that shares the HQ account's uid is refused.
- The plan version is 2. A plan saved by an older build has another digest
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
4. **What only root can read.** An existing member account must be locked:
   a shadow field starting with `!` or `*`. A password, an empty field or
   no entry is `MM_MEMBERS_ACCOUNT_REFUSED`. A launch rule already at
   `/etc/sudoers.d/agent-bot-hq-members` that this tool did not write is
   `MM_MEMBERS_PATH_REFUSED`.
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
and the launch rule last.

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
- After the last step the plan is built once more. Any remaining change is
  `MM_MEMBERS_APPLY_FAILED`. A failed apply leaves earlier steps in place,
  says which step stopped it, and records `failed` in the receipt.

The CI job `member accounts (real accounts)` runs
`tests/members-apply.test.sh` on a GitHub-hosted Linux runner with real
accounts, sudo and visudo. It covers the acceptance list below except three
lines: HQ's own layout check (that code is in agent-bot-hq; the script
asserts the same owners, groups and modes), a deliberately broken rule
(covered by a Go test with an injected failure, because the tool cannot be
made to generate one), and `approve-members` itself (Go tests in
`internal/daemon`; the script writes the approval file in the same form).

The proposal in the local web UI is not built. Nothing sends
`approve-members` yet.

## Acceptance

On real accounts in CI (Linux), as in agent-bot-hq's member accounts step:

- `plan` changes nothing and its digest is stable across two runs.
- `apply` without an approval, with an expired or used approval, with an
  approval file a non-owner can write, or after the host changed, runs
  nothing and says which.
- A plan on a host with no HQ account creates it first. After the apply it
  is a locked service account in no other group; its home is 0700 and
  neither the owner nor a member can enter it. The owner's own account named
  as the HQ account is left alone and the plan says it is shared.
- After an approved apply: HQ's layout check passes; the HQ account can start
  a process as a member account and cannot start one as root or as an
  unlisted account; a member account cannot use the rule; a member cannot
  enter another member's endpoint directory or home.
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
   proposal type in agent-bot-identity's `agent-web.mjs` follows, and the
   matching screen in the design source.
4. Gate: `gofmt -l . && go vet ./... && go test ./...`.
5. Update the closed verb set in [machine-daemon.md](machine-daemon.md) in
   the change that adds `approve-members`.
