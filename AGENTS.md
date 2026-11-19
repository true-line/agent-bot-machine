# managed-machine

Machine setup and orchestration, distributed as a self-tapped Homebrew formula. Idempotent; safe to re-run.

## Agent migration protocol

If asked to migrate a machine with this repo:

1. Do not explore this repo.
2. Do not clone this repo.
3. Copy `skills/managed-machine/SKILL.md` to your agent's skill directory:
   - Devin: `~/.config/devin/skills/managed-machine/SKILL.md`
4. Invoke the `managed-machine` skill and follow it.
5. If the curl install fails because the Homebrew formula has no released tag/sha, stop and tell the user the repo needs a release before migration can proceed.

## Agent contribution mode

- If contributing changes to this repo: read the constraints below, then explore as needed.

## Constraints

- no secrets in repo; auth/keys generated per machine or from macOS Keychain
- this repository is public: content from the private managed-machine-config repo, machine records and key records never enter it, including as test fixtures, goldens or examples; fixtures stay synthetic (#262)
- legacy/setup-* scripts source legacy/lib/install.sh; keep helpers reusable
- desktop apps install from homebrew/cask only into `/Applications`; legacy/lib/cask-app.sh verifies tap, sha256, vendor hosts, and Developer ID Team ID before trusting the bundle
- bundle integrity passes on `codesign --verify --deep --strict` or, failing that, on a Gatekeeper assessment that proves notarization and names the same Team ID; identity checks are never skipped
- a catalog row with `allow_rolling_url` accepts `sha256 :no_check` for vendors serving one rolling URL, and nothing else — malformed digests and off-allowlist hosts are still refused; such a row must pass the Gatekeeper notarization check, since no checksum stands behind it
- desktop apps with no cask use vendor-dmg rows (pinned vendor URL + DMG sha256 + Team ID, staged bundle verified before anything under /Applications moves); a sparkle row resolves its appcast enclosure at download time and still requires that host on url_hosts; a bare url_hosts entry also matches a www. prefix, a leading-dot entry is matched as written, and a redirect is kept only when the final host is allowlisted; the sha256 rule is enforced before an already-installed sparkle app short-circuits; on-disk occupiers converge in place, adopt stays cask-only
- CLI formulae install from homebrew/core only via brew-formula catalog rows; legacy/lib/apps.sh verifies the tap before `brew install`
- an opted-in fleet chooses its apps in its checkout’s apps.json. Optional config/<name> scripts apply settings after installation
- Homebrew prefix stays with an admin-group owner (typically `admin`); never chown it to a non-admin invoking user
- the machine daemon runs as that prefix owner, never as root, and does not execute shell scripts. `managed-machine daemon install` writes a per-user service unit, loads it with launchctl or systemctl --user, and refuses agent accounts, root, and a foreign home. It does not register a Windows service. A cask whose published install needs elevation is refused and left as a human action. Agent accounts install pinned catalog entries through the daemon. Publishing a catalog entry is the approval. `managed-machine --update` is a thin client of that daemon and falls back to the legacy update script when the daemon is not installed
- The public package contains Machine and its orchestration files. A fleet administrator may supply a separate config checkout for dotfiles, policy, tools, and apps. Personal repositories must never be fetched by a default install, bootstrap, update, or release.
- state manifests live in ~/.config/managed-machine/*.manifest; never commit *.manifest
- bootstrap outcomes live in ~/.config/managed-machine/bootstrap.manifest; never record command output or secrets there
- local machine identity lives in ~/.config/managed-machine/machine.toml; never commit machine.toml to this repo
- SSH enrollment is explicit and human-only: bootstrap/--update/setup-gh/account setup never create, upload, or register SSH keys, never request key-upload scopes, never switch git_protocol to SSH, and never enable SSH signing; `managed-machine ssh enroll --authentication|--signing|--fleet` is the only path, behind an OS authorization dialog that names the local account, GitHub login, and purposes; agent accounts/sessions, root, and foreign-HOME invocations are refused before any mutation, and there is no --yes or env opt-out
- SSH passphrase policy lives in ~/.config/managed-machine/ssh-key-policy.toml; never commit ssh-key-policy.toml
- Versioned fleet records and public SSH keys belong to the configured fleet repository. Publishing fleet state is reserved for explicit enrollment and fleet commands.
- An opted-in fleet may select its own tools source and pin it in local-bin.ref.
- legacy/git-hooks/ runs gitleaks protect --staged; legacy/setup-git-hooks wires hooks only when run from the checkout toplevel (setting core.hooksPath=legacy/git-hooks and repairing an existing git-hooks value), and chains an existing core.hooksPath instead of replacing it
- bin/managed-machine is the portable Go core CLI entry point; on macOS it delegates surviving legacy routes to legacy/bin/managed-machine (resolved via MANAGED_MACHINE_LEGACY_ROOT, ../libexec/legacy in Homebrew installs, or ../legacy in a checkout)
- the portable Go core lives at the repository root (`go.mod` module `github.com/qwts/managed-machine`, `cmd/managed-machine`, `internal/`, documented in `docs/go-core.md` and vetted by `.github/workflows/go-core.yml`): run `gofmt -l . && go vet ./... && go test ./...` from the repository root
- legacy/scripts/update upgrades the tree it runs from, so it sources no library on both sides of `brew upgrade`: it re-execs itself afterward, and everything past the upgrade belongs to one version. Adding a `source` before the re-exec guard reintroduces the mixed-version run that broke Chrome installs on the upgrading run only
- Formula/managed-machine.rb pins the public Machine source version and signed core digest. A reviewed change to .github/machine-release-version starts signing. Release preparation builds and verifies the five archives using only Machine, then pins the verified signed digest in a release PR. The approved release PR merge authorizes automation to tag that exact commit after its CI passes. The tag starts verification and publication.
- the darwin core ships as a Developer ID signed, notarized `managed-machine` binary (`Z5DM34QS5U`, identifier `ai.true-line.agent-bot-machine`, docs/plans/macos-signing.md); only sign.yml uses the five CLI signing secrets and the owner-app distribution profile in the main-only `release` environment. The normal reviewed version request signs Machine and the pinned owner app in separate jobs at the same version and commit. The profile is restricted to the owner-app job. Manual signing requires the `release-manual` reviewer. Release PR and tag jobs use a repository-scoped App token; never pin, publish or install a darwin archive that `mm-release verify-signed` has not accepted
- Fleet bootstrap uses the configured setup scripts and catalog. Fresh public installations have no personal package list. Agent-bot installation, upgrades, account wiring, credential seeding and interposition remain outside Machine.
- tests are plain bash, no runner: `bash tests/<name>.test.sh`. Run the full suite from a neutral working directory so Git credential fixtures do not inherit a checkout's local bot helper: `root="$(pwd)"; (cd /tmp && for t in "$root"/tests/*.test.sh; do bash "$t" || exit "$?"; done)`
- `--update` refuses from agent sessions/harness markers (exits skipped before any dialog); run it from a human Terminal in the owner's account
- docs/plans/ are durable specs (Intent, Target, Acceptance, Replay): update the matching plan in the same change, never delete; the commit-identity rule below always applies
- install.sh is curlable; checks brew ownership before proceeding
- confirm before destructive/repo-wide actions
- never `git config` user.name/user.email. The macOS account decides whose work a commit is (ENG-0339, which supersedes ENG-0045): in a `qwts-<harness>-agent` account every checkout is bot work, attributed to that harness's `qwts-<harness>-agent[bot]` App by agent-bot's hooks (they add the `Agent-Identity` trailer; never hand-write it). In the owner's account the harness is the owner's delegate by default: plain human commits as `qwts`, with no trailer or other agent marker, unless it is told to act as the bot through `GH_AGENT_APP`, `--app`, or a worktree pin (`agentbot.app`), which keep bot attribution wherever that worktree lives. Worktree directories (`.claude/worktrees/` and the like) are a layout choice, not an identity boundary. As the delegate, if git would otherwise use a macOS full name or a `*.local`/`*.lan` hostname email, set `GIT_AUTHOR_NAME`/`GIT_COMMITTER_NAME` to `qwts` and `GIT_AUTHOR_EMAIL`/`GIT_COMMITTER_EMAIL` to `91036491+qwts@users.noreply.github.com` for the commit rather than committing with them. Never put a macOS full name or a `*.local`/`*.lan` hostname email in a `Co-authored-by` trailer either
- setup-agent-bot is retired; managed-machine does not manage agent-bot installation or wiring

<!-- governed:shared-agent-discovery:start -->

## Shared agent conventions and skills

PR-first workflow, validation-before-push, commit and PR hygiene, and the
untrusted-input threat model are defined once, for every repo, in the
[org-wide agent conventions](https://github.com/qwts/agent-sop/blob/main/docs/reference/agent-conventions.md).
Before creating or copying a repo-local skill, consult the reviewed
[shared agent skills](https://github.com/qwts/agent-sop/blob/74e775ef23d8e7d8f8e693ccc2329f430978c096/skills/README.md)
index. Reuse only the pinned version supplied by the governed harness; a skill
genuinely specific to this repository belongs in its local context.
This repository is governed by
[agent-sop](https://github.com/qwts/agent-sop) — its
[shared SOPs](https://github.com/qwts/agent-sop/blob/main/docs/sop/README.md)
and [engineering decisions](https://github.com/qwts/agent-sop/blob/main/docs/decisions/README.md)
apply here by default
([ENG-0008](https://github.com/qwts/agent-sop/blob/main/docs/decisions/ENG-0008-shared-sop-inheritance.md):
inherit by default, vary by explicit delta).
<!-- governed:shared-agent-discovery:end -->
