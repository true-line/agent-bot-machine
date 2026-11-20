# managed-machine

Machine installs and manages software, configuration and agent accounts. The public macOS package includes the Machine CLI and its Homebrew integration. Organizations can supply their own configuration and software catalog.

## Install on a fresh Mac

On an Apple Silicon Mac running macOS 15 or later, open Terminal and run the public installer. On a Mac without Homebrew, use the administrator account that will own Homebrew.

```bash
(
  installer="$(mktemp "${TMPDIR:-/tmp}/managed-machine-install.XXXXXX")" || exit 1
  trap 'rm -f "$installer"' EXIT
  curl --proto '=https' --proto-redir '=https' -fsSL https://raw.githubusercontent.com/true-line/agent-bot-machine/main/install.sh -o "$installer" &&
    /bin/bash "$installer"
)
```

The installer downloads the public package from [true-line/agent-bot-machine](https://github.com/true-line/agent-bot-machine). If Homebrew already belongs to another administrator, macOS asks permission to run Homebrew in that account. A successful install prints a confirmation. The confirmation includes the installed version. Run `managed-machine --update` to update Machine from its public tap.

To pair a new HQ with Machine on macOS, the signed-in owner must approve its
exact Machine challenge. Fresh approvals await a compatible unbundled
owner-presence provider. Existing pairings continue to use their saved pins.
See [owner approval for a new HQ pairing](docs/plans/macos-signing.md#owner-approval-for-a-new-hq-pairing).

### Delivery channels

| Platform | Install method |
|---|---|
| macOS 15+ on Apple Silicon (`darwin/arm64`) | [Public installer](install.sh) with the [Homebrew formula](Formula/managed-machine.rb). |
| Linux (`linux/amd64`, `linux/arm64`) | [install-core.sh](install-core.sh) verifies the release archive against `SHA256SUMS` and installs to `$HOME/.local/bin` by default. |
| Windows (`windows/amd64`, `windows/arm64`) | [install-core.ps1](install-core.ps1) verifies the release ZIP against `SHA256SUMS` and installs to `%LOCALAPPDATA%\Programs\managed-machine` by default. |

All platforms use the [public Machine releases](https://github.com/true-line/agent-bot-machine/releases). To use an existing policy checkout with the portable core, point `MANAGED_MACHINE_POLICY_DIR` at its directory.

## Usage

Portable core commands (all five targets):

```bash
managed-machine software [name] [--available|--install|--refresh] [--category <name>] [--provider <name>|--recipe <id>] [--user|--global|--custom <path>] [--json|--human]
managed-machine config [name] [--available|--status|--check|--plan|--apply] [--from-plan <id>] [--category <name>] [--global|--user|--custom <path>] [--json|--human]
managed-machine status [--section software|config|flavor|fleet [name]] [--global|--user|--custom <path>] [--json|--human]
managed-machine fleet [owner] [--keys|--access|--refresh|--plan|--apply|--check|--publish|--unpublish <fp>] [--owner <id>] [--key <path>] [--label <text>] [--from-plan <id|path>] [--user] [--json|--human]
managed-machine members plan [--hq-account <account>] (--hq-config <path> | --members <a,b,...>) [--dir <path>] [--json|--human]
sudo managed-machine members apply <plan-id> [--json|--human]
managed-machine skill [name] [--kind <kind>] [--bundle <bundle>] [--search <term>] [--version <v>] [--next <h>] [--json|--human] | skill path [--json|--human]
managed-machine platform [--json|--human]
managed-machine version [--json|--human]
managed-machine --version    # print the release version
managed-machine --help       # show usage (also -h, help, or no command)
```

Legacy commands (macOS only; Homebrew install — delegated to `libexec/legacy/bin/managed-machine`; see the [compatibility rule](docs/plans/f01-caller-characterization.md)):

- `[legacy] setup <name> [args] | setup --list [--json]` (`managed-machine setup bin`, `managed-machine setup setup-bin`, `managed-machine setup zsh-functions`; converted catalog names execute natively in the Go core)
- `[legacy] catalog list|resolve [--json] [--no-refresh]`
- `[legacy] adopt [<name>]` (`managed-machine adopt`, `managed-machine adopt vscode`)
- `[legacy] add-agent <slug>|--all [--full-name <persona>] [--with-harness]` (`managed-machine add-agent qwts-goose-agent`, `managed-machine add-agent qwts-claude-agent --with-harness`, `managed-machine add-agent --all --with-harness`)
- `[legacy] account setup|doctor <account> [--json]` (`managed-machine account setup qwts-claude-agent [--json]`, `managed-machine account doctor qwts-claude-agent [--json]`)
- `[legacy] ssh enroll|status [--authentication|--signing|--fleet|--json]`
- `[legacy] --bootstrap [--interactive|--non-interactive]` (`managed-machine --bootstrap`, `managed-machine --bootstrap --interactive`, `managed-machine --bootstrap --non-interactive`)
- `[legacy] --update` (`managed-machine --update`)
- `[legacy] fleet remove <machine-id> [--yes] [--revoke-github] [--dry-run] [--json]`
- `[legacy] status --section bootstrap|update [--json]`

Bare `managed-machine status [--json|--human]` is served by the portable Go core (exit 0; reporting `software`, `config`, and `flavor`, with `--section fleet` available under `--user`), and `managed-machine skill path [--json|--human]` is a core command on all five targets (reporting `MM_SKILL_BUNDLE_MISSING`, exit 1, on archive installs where the skill bundle is not present). On macOS, `[legacy] status --section bootstrap|update [--json]` remains a read-only legacy route printing the last recorded `bootstrap.manifest` and `update.manifest` outcomes. The 17 legacy `status` sections removed in `v0.11.0` and `fleet list` fail on all five targets with `MM_LEGACY_ROUTE_REMOVED` (exit 2) naming each route's replacement or `no replacement`: `status --section managed-machine` -> `managed-machine version`; `status --section ssh` -> `managed-machine ssh status`; `status --section agent-accounts` -> `managed-machine account doctor`; `status --section catalog` -> `managed-machine setup --list and managed-machine software --available`; `fleet list` -> `managed-machine fleet --keys`; and `status --section machine|local-bin|zsh-functions|pins|toolchain|homebrew|gh|nvm|node|hostname|rustup|rustc|cargo` -> `no replacement`.

---

## Setup scripts

All setup scripts are safe to re-run.

`managed-machine setup` with no name — or an invalid name — prints every setup name with a ✓ beside the ones already installed: a Homebrew receipt plus the app bundle for signed casks, a Team ID-verified bundle for vendor DMGs, a formula receipt, the CLI command on `PATH` for CLI rows, or the marker each infrastructure script checks (`~/.nvm/nvm.sh`, the local-bin manifest, and so on). The mark only appears for states the installer itself would call done — a receiptless app occupier or an unverified bundle shows no ✓. Fleet catalog entries come from the configured checkout.

Fleet owners declare their own desktop apps and CLIs in the optional config checkout’s `apps.json`. managed-machine ships the install engines (signed cask, direct vendor DMG, official CLI, `brew-formula` for `homebrew/core`, and so on). After an app is present, fleet bootstrap runs `config/<name>` from that checkout when that script exists — configuration only, never install. Catalog rows install on bootstrap and `--update` unless they set `"auto": false`; those are `managed-machine setup <name>` only. Adding ChatGPT is a catalog row (and an optional config script); it does not require a managed-machine release. A new *kind* of installer does.

### Agent utility tools

A fleet catalog can include CLI tools. For example, with `taplo` installed, agents read machine TOML (`~/.config/agent-sop/config.toml`, `~/.config/managed-machine/machine.toml`) with `taplo get -f <file>` — `taplo get -f ~/.config/agent-sop/config.toml -o json` dumps JSON, `taplo get -f <file> 'repos.org'` extracts one value.

`ripgrep` (`rg`), `fd`, and `ast-grep` (`sg`) cover repository search without whole-file reads: `rg -n <pattern>`, `fd <name>`, `sg -p '<pattern>'`.

### Signed-cask verification

A `signed-cask` row is trusted only after the cask resolves to the exact `homebrew/cask` token, the download and homepage hosts match the row's allowlists, and the installed bundle proves its identity: a `Developer ID Application` authority whose Team ID equals the row's `team_id`. Identity is never waived.

Bundle integrity is satisfied by either check:

1. `codesign --verify --deep --strict`, or
2. the Gatekeeper assessment (`spctl -a -t exec`), which must report `source=Notarized Developer ID` and name the same Team ID.

The second path exists because `--deep --strict` rejects a bundle whose nested helpers carry `com.apple.FinderInfo`/quarantine attributes — *"resource fork, Finder information, or similar detritus not allowed"*. Homebrew Cask stamps those attributes during extraction, so Chromium-based apps such as Brave fail a check their signature and notarization both pass. Gatekeeper additionally proves notarization, which `codesign` never checks, so the fallback is stricter than the primary path in that respect.

### Rolling vendor URLs

Casks normally must publish a real `sha256`; `:no_check` is refused. Some vendors (Google Chrome, for one) serve a single rolling "latest" URL, so `homebrew/cask` has no per-build checksum to publish. Such a row opts in explicitly:

```json
{ "name": "chrome", "kind": "signed-cask", "token": "google-chrome",
  "team_id": "EQHXZ8M8AV", "allow_rolling_url": true }
```

The flag accepts `:no_check` and nothing else — a malformed digest, an off-allowlist host, an unnotarized bundle, or a Team ID mismatch is still refused. It trades the install-time checksum for notarized Developer ID verification, so a row carrying it **must** pass the Gatekeeper assessment: the `codesign --deep --strict` shortcut above does not apply, because passing it alone would install a build with neither a checksum nor a notarization behind it.

Note that every auto-updating app in the catalog already relies on that same guarantee for each update after the first, since the install-time checksum covers only the initial download.

### Direct vendor DMGs

A `vendor-dmg` row installs a desktop app with no `homebrew/cask` token by
fetching the vendor's DMG directly — no Homebrew involved at any step:

```json
{ "name": "qwen-desktop", "kind": "vendor-dmg",
  "app_name": "Qwen Code Desktop.app", "team_id": "NF4574S59H",
  "url_arm64": "https://github.com/.../Qwen-Code-Desktop-arm64.dmg",
  "url_x86_64": "https://github.com/.../Qwen-Code-Desktop-x64.dmg",
  "url_hosts": ["github.com"], "sha256": "no_check",
  "allow_rolling_url": true }
```

The URL must be `https` on a `url_hosts` allowlist entry, and the download's
`sha256` must match — or be `"no_check"` behind `allow_rolling_url`, with the
same mandatory-notarization trade as above. A bare allowlist entry matches
that host and its `www.` form. An entry that starts with `.` matches that
host and its subdomains as written (`.www.example.com` does not widen to
`example.com`), for CDNs whose hostname changes per request. Redirects are
followed only when the host that actually responded is allowlisted too.
Per-architecture builds use `url_arm64`/`url_x86_64` (plus
`sha256_arm64`/`sha256_x86_64` when the digests differ); a single `url`
serves every architecture. The staged bundle is signature-verified before
anything under `/Applications` moves, and a bundle already on disk must
first prove its Team ID — an impostor is reported, never replaced. A pinned
`version` converges drift (reinstalls on mismatch); without one, presence
plus a valid signature is installed. A row with `"sparkle": true` puts a
Sparkle appcast in `url`; the enclosure is resolved at download time and
its host must be on `url_hosts`. The digest rule is checked before that
short-circuit, so a bad catalog fails even when the app is already present.
`managed-machine adopt` stays cask-only: vendor-DMG occupiers converge in
place, so there is nothing to adopt.

A row that takes over an app a Homebrew cask installed names that cask in
`retire_cask` (Muse.app, after Homebrew disabled `homebrew/cask/muse`). While
Homebrew still records the cask, the next run downloads and verifies the
vendor DMG first, and only then removes the Homebrew record with
`brew uninstall --cask --force`. The app bundle is moved aside for that
uninstall and put back in the same authorization phase, so the installed app
stays as it is and keeps updating itself. Nothing is zapped, so user data is
kept. A running app is skipped, and a DMG that fails verification leaves the
record and the app untouched. A record whose app is gone is retired before the
verified DMG installs.

### Interactive and noninteractive bootstrap

Bootstrap uses interactive mode when it can open the current terminal, including a controlling terminal behind a curl pipe. Otherwise it uses noninteractive mode. `--interactive` requires a terminal. `--non-interactive` never presents a dialog.

In interactive mode, bootstrap builds and displays an upfront execution plan showing every step, whether it requires administrator privileges (`[admin]` vs `[user]`), and what packages, paths, and apps it affects. It prompts once for confirmation and requests a single macOS administrator authorization dialog (`osascript` / Authorization Services) covering all privileged actions for the entire run. Mutating Homebrew commands drop to the prefix owner (`admin` when that account exists). If authorization is declined, privileged catalog apps are recorded in `~/.config/managed-machine/declined-apps.manifest` and skipped on subsequent `--update` runs until explicitly installed via `managed-machine setup <name>`.

A step that cannot finish in the current run is skipped and is not part of that install. Bootstrap does not fail that step and does not print a `managed-machine setup <name>` follow-up. Failed is reserved for unexpected errors. Vendor-installed desktop apps already in `/Applications` are skipped. Bootstrap, `--update`, and `setup-gh` never create, upload, or register SSH keys; enrolling SSH identity is the explicit human-only `managed-machine ssh enroll` action.

The latest machine-readable result is atomically written with mode-600 permissions to `~/.config/managed-machine/bootstrap.manifest` (and `update.manifest`). It records the `plan_id`, planned steps, statuses, short reasons, and timestamps—never command output or secrets.

`setup-devin` installs the CLI in every mode. Browser authentication is skipped when no interactive terminal is available; an already-authenticated install is left alone.

| Script | Purpose |
|---|---|
| `setup-brew` | Install Homebrew if missing (wires `brew shellenv` into your shell). Writes a dedup `# BEGIN brew` `PATH` block into `.zshenv` so every shell reaches the prefix. |
| `setup-hostname` | Prompt (macOS dialog) for a hostname and set `LocalHostName`, `ComputerName`, and `HostName` (`name.lan`) via `scutil`. Re-run `managed-machine setup hostname` to correct a bad name. |
| `setup-zsh` | Install starter `~/.zshenv`, `~/.zprofile`, `~/.zshrc`. Unguarded or vendor PATH fragments are moved to `<name>.<epoch>.bak` and rewritten with duplicate-entry guards; already-guarded files are left in place. |
| `setup-nvm` | Install upstream NVM, add a managed zsh initialization block, install the current Node.js LTS release, and make it the default. |
| `setup-git-hooks` | Install gitleaks via brew. On a managed-machine git clone, wire pre-commit scanning without replacing an existing `core.hooksPath`. From a Homebrew install this step skips hook wiring — libexec is not the git toplevel. |
| `setup-gh` | Install GitHub CLI via brew; authenticate gh over HTTPS; wire gh as the git credential helper; configure the Git identity (login + private noreply); refresh the persistent private config checkout (pull-only). Never touches SSH keys, signing, or the fleet registry — see `managed-machine ssh enroll`. |
| `setup-agent-bot` and `setup-agent-bot-gh` | Retired. `managed-machine setup agent-bot` and `managed-machine setup agent-bot-gh` report that installation, identity wiring, credential seeding, and gh interposition are no longer managed here. Existing installations, credentials, and interposer files are left intact. |
| `setup-bin` | Keep local-bin at the pin read from the persistent `managed-machine-config/local-bin.ref`, then run its `install` (links tools into `~/.local/bin`, prunes renames, ensures `~/.local/bin` on `PATH`). |
| `setup-zsh-functions` | Keep zsh-functions at the pin read from the persistent `managed-machine-config/zsh-functions.ref`, then run its `install` (links functions, `zsh-profile`, and the managed `.zshenv` loader block). |
| `setup-proton-pass` | Install the [Proton Pass CLI](https://proton.me/pass/cli) when missing (lands in `~/.local/bin`). |
| `setup-muse` | Install [Meta Muse Code](https://dev.meta.ai/) (`muse` CLI) when missing via the official installer. Lands in `~/.local/bin`; skips the installer's PATH edit because that directory is already managed. |
| `setup-claude` | Install [Claude Code](https://code.claude.com/docs/en/quickstart) (`claude`) when missing via the official installer. |
| `setup-codex-cli` | Install the [OpenAI Codex CLI](https://github.com/openai/codex) (`codex`) when missing. Distinct from `setup-codex`, which only merges managed codex config. |
| `setup-antigravity` | Install the [Antigravity CLI](https://antigravity.google/docs/cli/install) (`agy`) when missing via the official installer. Lands in `~/.local/bin`. |
| `setup-grok-build` | Install [Grok Build](https://x.ai/build) (`grok`) when missing via the official installer. Lands in `~/.local/bin`; the installer runs with no login shell to edit, so its PATH block never lands in `~/.zshrc` (every official installer runs that way, and one that edits `~/.zshrc` anyway is reported). |
| `setup-aider` | Install [Aider](https://aider.chat/) (`aider`) when missing via the official installer, which is the uv bootstrapper (runs with `UV_NO_MODIFY_PATH=1`; lands in `~/.local/bin`). Then installs a managed `~/.aider.conf.yml` when you have none — it sets `git-commit-verify: true`, because aider otherwise commits with `--no-verify` and skips the gitleaks pre-commit hook. An existing config is never touched. |
| `setup-droid` | Install [Droid CLI](https://docs.factory.ai/droid-cli/quickstart) (`droid`) when missing via the official installer. Lands a checksum-verified binary in `~/.local/bin`; the installer takes no prompts and edits no shell rc file. |
| `setup-goose` | Install [Goose CLI](https://goose-docs.ai/docs/getting-started/installation) (`goose`) when missing via the official installer (runs with `CONFIGURE=false`, so the interactive provider wizard never runs; lands in `~/.local/bin`). |
| `setup-opencode` | Install [OpenCode](https://opencode.ai/download) v2 (`opencode`, pinned to 2.0.18) with the official v2 installer. Links `~/.opencode/bin` into `~/.local/bin` and skips the installer's PATH edit. A managed v1 is replaced in place at the same path; an `opencode` that managed-machine did not install is left alone, and when it is not v2 the step is skipped with how to remove it. |
| `setup-opencode-app` | Install the [OpenCode](https://opencode.ai/download) desktop app from `homebrew/cask/opencode-desktop` with the same signed-cask checks (Anomaly Team ID `5NZ4Q7NXJ4`). |
| `setup-codex` | Merge the managed Codex configuration into `~/.codex/config.toml` (no secrets, auth stays in Keychain): `dotfiles/codex/defaults.toml` is the synced default setup, and `dotfiles/codex/profiles/<name>.toml` files are opt-in variants — `managed-machine setup codex --profile <name>` installs one as `~/.codex/<name>.config.toml`, the layered profile file Codex loads for `codex --profile <name>` (e.g. `muse` for Meta Muse Spark); `--disable-profile <name>` removes it. The managed block merges idempotently; conflicting user-set keys and user-owned profile files are never clobbered — setup reports the exact manual merge and defers instead. |
| `setup-devin` | Install the [Devin CLI](https://docs.devin.ai/cli) into `~/.local/bin`; preserve authenticated sessions, run setup interactively when needed, or report authentication as deferred. |
| `setup-lmstudio` | Install [LM Studio](https://lmstudio.ai/) via Homebrew Cask when missing. Installs to `/Applications` (override with `MANAGED_MACHINE_LMSTUDIO_APPDIR`). |
| `setup-vscode` | Install [Visual Studio Code](https://code.visualstudio.com/) from `homebrew/cask/visual-studio-code` only after verifying tap, sha256, vendor download host, and Microsoft Team ID `UBF8T346G9`. |
| `setup-cursor` | Install [Cursor](https://www.cursor.com/) from `homebrew/cask/cursor` with the same signed-cask checks (Anysphere Team ID `VDXQ22DGB9`). |
| `setup-claude-app` | Install the [Claude](https://claude.com/download) desktop app from `homebrew/cask/claude` (Anthropic Team ID `Q6L2SF6YDW`). |
| `setup-muse-app` | Install the [Muse](https://muse.ai/) desktop app from Meta's Sparkle feed (Team ID `V9WTTPBFK9`). The Homebrew cask URL returns HTTP 403 `not_eligible` for an anonymous download, so this row follows the public appcast instead. |
| `setup-antigravity-app` | Install the [Antigravity](https://antigravity.google/) hub from `homebrew/cask/antigravity` (Google Team ID `EQHXZ8M8AV`). |
| `setup-antigravity-ide` | Install [Antigravity IDE](https://antigravity.google/product/antigravity-ide) from `homebrew/cask/antigravity-ide` (same Google Team ID). |
| `setup-kiro` | Install [Kiro](https://kiro.dev/) from `homebrew/cask/kiro` with the same signed-cask checks (Team ID `94KV3E626L`). |
| `setup-kiro-cli` | Install the [Kiro CLI](https://kiro.dev/) from `homebrew/cask/kiro-cli` (same Team ID). |
| `setup-rust` | Install [rustup](https://rustup.rs/) when missing (default profile: stable + rustfmt/clippy); ensure `${CARGO_HOME:-~/.cargo}/bin` on `PATH`. |

Harnesses without a dedicated script install straight from the catalog — `managed-machine setup <name>` accepts catalog names and aliases. The roster's catalog-only harnesses are `amp`, `cline`, `copilot`, `deepseek`, `grok` (alias of `grok-build`), `hermes`, `pi`, `qwen`, `warp`, and `zcode`.

Existing vendor-installed desktop apps are not mutated by `setup-*`. Use `managed-machine adopt` to take them over with Homebrew:

```bash
managed-machine adopt              # every allowlisted app that is safe to adopt
managed-machine adopt <name>       # one app (cask token or alias)
```

Canonical names are cask tokens; setup-name aliases are accepted. `--help` and unknown names print this list:

- `antigravity` (alias: `antigravity-app`) — hub, not `agy` CLI
- `antigravity-ide`
- `brave-browser` (alias: `brave`)
- `chatgpt` (alias: `chatgpt-app`)
- `claude` (alias: `claude-app`) — desktop app, not Claude Code CLI
- `cursor`
- `devin-desktop` (alias: `devin-app`)
- `discord`
- `docker-desktop` (alias: `docker`)
- `google-chrome` (alias: `chrome`)
- `grok-bot` (alias: `grokbot`)
- `kiro`
- `kiro-cli`
- `lm-studio` (alias: `lmstudio`)
- `opencode-desktop` (alias: `opencode-app`) — desktop app, not OpenCode CLI
- `slack`
- `telegram`
- `visual-studio-code` (alias: `vscode`)
- `warp`
- `zcode`

Adopt skips (does not fail the whole run) when the app already has a Homebrew receipt, is running, is missing, or fails Developer ID / Team ID verification. A running Cursor helper that still has `/Applications/Cursor.app` mapped is treated as running: quit the app and re-run. Apps stay in `/Applications`; brew runs as the prefix owner when this user cannot write the prefix. `setup-*` / catalog config is re-run afterward so signature checks pass. Adopt covers signed-cask rows only; `vendor-dmg` rows converge a vendor-installed bundle in place during install, so there is nothing to adopt.

---

## SSH enrollment

SSH identity is **never** provisioned by default setup: `install.sh`, `--bootstrap`, `--update`, `setup-gh`, and `account setup` do not generate keys, upload them, load `ssh-agent`/Keychain, request key-upload scopes, switch `git_protocol` to SSH, configure SSH signing, or register fleet identity. Existing keys, GitHub registrations, `~/.ssh/config`, and signing settings are always preserved — nothing is removed, revoked, or rotated automatically. Agent accounts cannot enroll at all; `account setup` never gives them SSH keys.

Enrollment is a separate, explicit, human-authorized action:

```bash
managed-machine ssh enroll --authentication
managed-machine ssh enroll --signing
managed-machine ssh enroll --fleet
managed-machine ssh enroll --authentication --signing --fleet   # any combination
managed-machine ssh status                                       # read-only report
```

At least one purpose flag is required; purposes are never silently enabled together:

- `--authentication` creates (or reuses) `~/.ssh/id_rsa_github`, adds the `Host github.com` block to `~/.ssh/config` when absent, loads the key into `ssh-agent`/Keychain, uploads the public key as a GitHub *authentication* key, and sets `gh`'s `git_protocol` to `ssh`.
- `--signing` uploads the same public key as a GitHub *signing* key, enables global SSH commit/tag signing (`gpg.format`, `user.signingkey`, `commit.gpgsign`, `tag.gpgSign`, `gpg.ssh.allowedSignersFile`), refreshes the managed `allowed_signers` block from the fleet registry, and adds the local key outside that block so this machine's own commits verify even without fleet enrollment.
- `--fleet` writes local identity state to `~/.config/managed-machine/machine.toml`, registers the machine under `fleet/machines/` in the selected fleet checkout, publishes managed fleet state, and syncs local `authorized_keys`.

Before any change the command prints the plan — local account, home, GitHub login, key fingerprint or creation intent, and the selected purposes — then asks through the macOS authorization dialog, which names the same account, login, and purposes. Cancellation, a headless/noninteractive session, or an identity mismatch leaves all state unchanged and reports that no enrollment occurred. There is no `--yes` and no environment opt-out; an agent session, an account in the OS-level `agents` group, or an account named in the agent roster is refused before any dialog.

The authorization gate uses `osascript`'s administrator dialog (`Authorization Services`). Per the owner's decision on #120, the ~5-minute grant cache and Touch ID are accepted: the dialog is an OS-native human confirmation, not a guaranteed fresh-password challenge. Every mutation still runs unprivileged as the invoking account, so an administrator approving for a standard human user cannot land keys under the admin home.

`ssh enroll` is retry-safe: whether a key is already registered is read from the account's public key listings (which need no scope), the match is an exact key-body match, and a listing failure stops the run rather than uploading a duplicate. Upload scopes (`admin:public_key`, `admin:ssh_signing_key`, each reported with the operation that needs it) are requested only here and only when a key actually has to be uploaded — never during default setup. Partial failures report which purposes completed; re-running finishes the rest.

### SSH key policy

Enrolled GitHub SSH keys are created unencrypted (`ssh-keygen -N ''`) so the flow cannot hang on a passphrase prompt. The choice is recorded locally in mode-600 `~/.config/managed-machine/ssh-key-policy.toml` and is never committed. Existing complete key pairs are reused unchanged.

Machine IDs are stable, filesystem-safe forms of the SSH public-key SHA-256 fingerprint. Initial registration timestamps and bootstrap refs are preserved on reruns.

Commit signatures verify locally as well as on GitHub: `--signing` sets `gpg.ssh.allowedSignersFile` to `~/.ssh/allowed_signers` and rewrites a `# BEGIN managed-machine` block in that file from the fleet registry, one entry per machine key under the configured git email principal. Lines outside the block are never touched, and re-running `ssh enroll --signing` (or `fleet remove`) refreshes the block after fleet changes, so `git log --show-signature` verifies commits from every registered machine.

On the first fleet enrollment, existing keys in `managed-machine-config/ssh/authorized_keys` are imported as legacy machine records before that file is regenerated. Registration and removal stage only fleet machine records and the generated allowlist, create a commit using the configured Git identity, and push automatically. Concurrent joins rebase unique machine records and regenerate `authorized_keys`; unrelated changes or non-generated conflicts stop without being staged. Once a fleet is selected, setup only *refreshes* its checkout (fetch + rebase when clean); publishing managed fleet state always goes through `ssh enroll --fleet` or `managed-machine fleet`.

The default writable checkout is `$XDG_DATA_HOME/managed-machine/managed-machine-config` when `XDG_DATA_HOME` is set, or `~/.local/share/managed-machine/managed-machine-config` otherwise. Set `CONFIG_REPO_ROOT` to use an explicit existing checkout, or `MANAGED_MACHINE_CONFIG_REPO_URL` to select the fleet repository. Embedded credentials in HTTP remote URLs are rejected.

```bash
managed-machine fleet --keys
managed-machine fleet remove sha256-...             # prompts for confirmation
managed-machine fleet remove sha256-... --yes       # explicit noninteractive removal
managed-machine fleet remove sha256-... --revoke-github
```

Removal deletes and publishes the exact registry entry, regenerates fleet/local `authorized_keys`, and removes local `machine.toml` when decommissioning the current machine. GitHub authentication and signing keys are retained unless `--revoke-github` is supplied. Revocation runs only after the fleet removal is pushed; if GitHub revocation fails, the public key is retained under `~/.config/managed-machine/pending-github-key-revocations/` so rerunning the same command can finish safely.

An administrator-selected Git repository is the supported fleet backend. Gist, synced-folder, and database backends are intentionally deferred.

---

## Agent accounts

[ENG-0339](https://github.com/qwts/playbook-engineering/blob/main/docs/decisions/ENG-0339-os-account-determines-persona.md) moves the agent/human persona boundary to the macOS account: one **standard** account per harness, short name = the harness-level roster slug, full name = the persona. The account name is the whole mapping — no registry file exists beyond the roster plus that convention.

```bash
managed-machine add-agent qwts-goose-agent
managed-machine add-agent qwts-devin-agent --full-name Devin
managed-machine add-agent qwts-claude-agent --with-harness
managed-machine add-agent --all --with-harness   # every active roster identity, in roster order
```

`--all` runs the same single-slug flow once per active roster identity (retired identities are skipped), so a fleet Mac never needs a hand-written per-account loop: each account keeps its own administrator prompt, per-account failures are collected, and the run exits nonzero naming every slug that failed.

The slug is validated against the organization roster (an existing agent-bot config, a profile at `~/.config/managed-machine/organization-profile.json`, or `MANAGED_MACHINE_ORG_PROFILE`); unknown and retired slugs fail closed. Creation adds the standard macOS account to the `agents` group and may set its public GitHub avatar. Managed-machine does not fetch, copy, or seed App credentials, install an identity runtime, or run identity bootstrap. Existing identity installations and files remain untouched. The compliance report covers the account, group, picture, name, home, optional harness, and shared coordination space. It does not report identity readiness. When Little Snitch is installed the report reminds you to pre-seed allow rules for the harness before running headless.

Use `managed-machine account doctor <account> [--json]` for a live, read-only per-account and harness check (`managed-machine status --section agent-accounts` was removed in `v0.11.0`).

### Account setup and live readiness

ENG-0339 also gives every agent account its **own harness** and account-local environment. For an already existing, active roster account, run:

```bash
managed-machine account setup qwts-claude-agent
managed-machine account doctor qwts-claude-agent --json
```

The public forms are `managed-machine account setup <active-existing-roster-account> [--json]` and `managed-machine account doctor <account> [--json]`. These commands require the target account's UID and HOME, or explicit administrator authorization through the existing cross-account mechanism. Merely changing HOME does not authorize another account, and there is no passwordless `su` path.

`account setup` prepares only the selected account's shell/local-bin configuration and roster-selected harness, using explicitly provisioned fleet sources. A harness with a separate CLI setup uses that CLI target (`codex-cli` or `kiro-cli` rather than its dotfile or IDE setup). Shared Homebrew, formulae, and casks remain **admin-owned prerequisites**: the account flow does not mutate Homebrew as the agent or change its ownership. Desktop casks remain machine-wide in `/Applications`. Missing bundles or unsupported catalog installers report pending work or failure rather than silently succeeding. The account flow does not run human `setup-gh`, SSH setup, fleet registration, full bootstrap, or `--update`, and it does not install unrelated harnesses. Generic `config/<name>` post-install scripts are not run in account mode: the harness uses its native defaults rather than inheriting potentially human-specific setup actions. Identity runtime installation, App credential seeding, and identity wiring are outside managed-machine account setup.

`account doctor` is a **live, read-only** per-account check of the shell environment and selected harness; it does not install or repair anything. It does not inspect or claim identity readiness. Both commands use the same readiness report, with optional machine-readable JSON. Exit status is `0` for `ready`, `75` for `pending_user_action`, and `1` for `not_ready` (failed required checks). In a headless session, readiness requiring a GUI login remains `pending_user_action`, not an installation failure or a false ready result. Vendor sign-in and identity runtime readiness are outside this report. Complete automated readiness currently covers supported account-local CLI harnesses; shared-formula and desktop-only rows require admin/attended verification and are not certified ready here.

On later runs, the default persistent account config can fast-forward from a newer explicitly provisioned clean seed using local-only Git transport. Dirty or divergent target changes are preserved and reported for reconciliation; an explicit target-owned `CONFIG_REPO_ROOT` is an override, not silently refreshed. If no seed is available, an existing valid checkout is retained with an explicit no-refresh notice.

When fleet policy selects local-bin, doctor checks its recorded commit and canonical checkout path, verifies the checkout is still at that commit with clean Git state, and checks managed command links against its tracked executable files. Older ref-only manifests need account setup to establish this evidence. Readiness covers only checks owned by managed-machine; it makes no identity or credential readiness claim.

Setup reruns its preparation and live checks even if an older harness success marker exists: cached success is not proof of current readiness. `add-agent <slug> --with-harness` delegates to this account setup phase through its existing administrator authorization. Without `--with-harness`, provisioning retains its opt-in behavior and does not run account setup. Use `managed-machine account doctor <account>` to check live per-account readiness. IDE-bound harnesses stay attended-only (ENG-0339 §8); log into the account to finish GUI-dependent readiness.

Identity, not directory, decides whose work a checkout is: inside a `qwts-*-agent` account every checkout is bot work; in the owner's account a harness is the owner's delegate unless told to act as the bot (`GH_AGENT_APP`, `--app`, or a worktree pin). Worktree directories are layout only. The runtime-side retirement of the old directory guards is tracked in qwts/agent-bot-identity#187.

Decommissioning an account (`remove-agent`) is deliberately deferred: stop sessions, revoke key material, archive audit metadata, remove the account, and retire the roster row in governance — tracked in qwts/managed-machine#80.

---

## Optional fleet tools

To add a fleet tool collection, set `LOCAL_BIN_REPO` to its clone URL and put its version in `local-bin.ref` in the fleet config checkout. Use `ZSH_FUNCTIONS_REPO` and `zsh-functions.ref` for shell functions. Existing tool checkouts can reuse their origin. New tool checkouts live in the invoking user’s Machine data directory. The pin must be an **immutable ref** — a git tag (e.g. `v0.1.0`) or a commit SHA — so re-running setup with the same pin is reproducible. A moving branch fails with a clear error; the explicit escape hatch for a one-off run is:

```bash
MANAGED_MACHINE_ALLOW_BRANCH_PIN=1 managed-machine setup bin
```

`setup-bin` checks out the pinned ref (skipping `git fetch` entirely when the immutable pin is already checked out) and runs local-bin's `install`. For an older install that still has a prefix-owned `libexec/legacy/local-bin` checkout, advancing an unsatisfied pin requests administrator authorization to run mutating git operations as the prefix owner, securely forwarding the invoking user's GitHub credentials through a temporary credential helper (never exposing tokens in argv) so private repository checkouts authenticate successfully. Downstream `install` symlinks into `~/.local/bin` as the invoking user. Every run records the pin and the exact commit it resolved to in mode-600 `~/.config/managed-machine/local-bin.manifest`, which is never committed.

GeniusBar's "Install command-line tools" writes `~/.local/bin/agent-bot` and `agent-comms` as small sh wrappers marked `# geniusbar-cli-tool`, and adds a PATH line under the same marker to `~/.zprofile`. Those belong to GeniusBar. managed-machine installs no agent-bot or agent-comms of its own. `setup-bin` refuses, before linking anything, when a local-bin tool would replace a GeniusBar wrapper, and `setup-zsh` neither counts GeniusBar's marked PATH line as stale nor drops it when it rewrites `~/.zprofile` for another reason.

`setup-zsh-functions` mirrors `setup-bin` for the configured shell functions repository: it checks out the pinned ref from `managed-machine-config/zsh-functions.ref` (same immutable-ref rule and branch-pin rejection) and runs that repo's `install`, recording mode-600 `~/.config/managed-machine/zsh-functions.manifest`. Prefix-owned checkouts escalate through the same authorization path.

Override the pin for a single run:

```bash
HOME_BIN_REF=v0.2.0 managed-machine setup bin
```

Bump the pin by editing `managed-machine-config/local-bin.ref` and committing it in `managed-machine-config`. Publish new local-bin versions as git tags; managed-machine tracks them by ref.

---

## Update an existing machine

```bash
managed-machine --update
```

Run updates from a human Terminal. The Homebrew prefix stays under its administrator owner. A machine with fleet configuration can also refresh the selected configuration and tools. Existing fleet data stays outside the Homebrew package.

Managed-machine no longer owns agent-bot installation, upgrades, pinning, machine wiring, account credential seeding, or GitHub CLI interposition. The retired setup commands explain this boundary and leave existing runtime state untouched.

### Codex desktop GitHub identity

Stock Homebrew `gh` remains the human CLI by default. Managed-machine no longer supports agent-bot GitHub CLI interposition. Existing interposer files and installations are left intact; no setup or update step repairs them.

---

For npm packages with native dependencies, the catalog can declare
`install_scripts`, an array of reviewed exact dependency versions (for example,
`["node-pty@1.2.0-beta.15"]`). Setup first installs with scripts disabled, then
rebuilds only those versions. This works with npm’s advisory and blocking script
policies and leaves persistent npm settings alone. Bare names, ranges and URLs
are refused. The field requires a managed-machine release with reviewed-script
support; update the engine before publishing a catalog that uses it.

DeepSeek setup requires the reviewed list and validates its global executable,
native FFI addon and PTY spawn helper without a model call or credentials. A
healthy existing installation is a no-op; one with broken native helpers is
repaired, and setup fails if the check still cannot pass.

## Releasing a new version

1. Merge the changes to `main`. Machine opens or refreshes a version PR. The default bump is a patch. Set a higher target in `.github/machine-release-version` when a different version is needed.
2. Review and merge the version PR. Machine builds the five archives and signs and notarizes the macOS CLI and custody helper at that merge commit.
3. When CI and signing pass, Machine tags the tested commit and publishes the archives, checksums, platform reports and pinned Homebrew formula. A formula-only PR then updates the tap to the published release.

Manual Machine signing dispatches require a deployment review. Operators can use `scripts/release prepare` and `scripts/release tag` for recovery. [Signing and release configuration](docs/plans/macos-signing.md)

---

## Layout

```
managed-machine/
├── Formula/
│   └── managed-machine.rb    # self-tapped Homebrew formula (tag/sha pinned; installs Go core as bin/managed-machine)
├── cmd/
│   ├── managed-machine/      # portable Go core CLI entry point (docs/go-core.md)
│   ├── mm-catalog-report/    # legacy app catalog classifier (F05)
│   ├── mm-fleet-import/      # legacy fleet machine record importer (S5 L05)
│   ├── mm-release/           # deterministic five-target release archive builder and verifier (S6 R02)
│   └── mm-walkthrough/       # multi-target walkthrough and slice gates (F08, S2-S8)
├── internal/                 # portable Go core packages (target, cli, legacy, software, config, fleet, status, skill, ...)
├── docs/
│   ├── go-core.md            # Go core module architecture, packages and gates
│   └── plans/                # durable engineering plans
├── go.mod                    # module github.com/qwts/managed-machine (Go 1.27.3)
├── go.sum
├── scripts/
│   └── release               # prepare release branch/PR and push release tag (prepare|tag)
├── install.sh                # macOS (darwin/arm64) one-shot Homebrew bootstrap installer
├── install-core.sh           # Linux (linux/amd64, linux/arm64) verifying Go core installer
├── install-core.ps1          # Windows (windows/amd64, windows/arm64) verifying Go core installer
├── legacy/                   # surviving macOS-only Bash routes (staged to libexec/legacy by Formula/managed-machine.rb)
│   ├── bin/
│   │   └── managed-machine   # legacy Bash entry point (invoked by the Go core on darwin)
│   ├── scripts/
│   │   ├── account           # agent account setup and live readiness doctor
│   │   ├── add-agent         # provision macOS agent accounts from the organization roster
│   │   ├── adopt             # take over vendor-installed signed-cask apps
│   │   ├── bootstrap         # run all setup-* in order
│   │   ├── catalog           # list and resolve legacy catalog entries
│   │   ├── fleet             # decommission fleet machines (fleet remove)
│   │   ├── ssh               # human-only SSH enrollment and status
│   │   ├── status            # read-only bootstrap and update manifest outcomes
│   │   └── update            # brew update/upgrade + safe setup re-runs
│   ├── setup-brew
│   ├── setup-zsh             # sources dotfiles from the persistent private checkout
│   ├── setup-nvm             # installs NVM and the current Node.js LTS release
│   ├── setup-gh              # synchronizes private fleet records and authorized_keys
│   ├── setup-bin             # local-bin orchestrator; pin from managed-machine-config
│   ├── setup-zsh-functions   # zsh-functions orchestrator; pin from managed-machine-config
│   ├── setup-proton-pass
│   ├── setup-muse
│   ├── setup-claude
│   ├── setup-codex-cli       # OpenAI Codex CLI binary
│   ├── setup-antigravity
│   ├── setup-grok-build
│   ├── setup-aider
│   ├── setup-droid
│   ├── setup-goose
│   ├── setup-opencode
│   ├── setup-opencode-app
│   ├── setup-devin
│   ├── setup-codex           # sources dotfiles from ../managed-machine-config/dotfiles/codex
│   ├── setup-lmstudio
│   ├── setup-vscode
│   ├── setup-cursor
│   ├── setup-claude-app
│   ├── setup-muse-app
│   ├── setup-antigravity-app
│   ├── setup-antigravity-ide
│   ├── setup-kiro
│   ├── setup-kiro-cli
│   ├── setup-rust
│   ├── setup-git-hooks
│   ├── lib/
│   │   ├── install.sh        # shared bootstrap helpers
│   │   ├── cask-app.sh       # signed Homebrew cask app installs and adopt
│   │   ├── vendor-dmg.sh     # direct vendor DMG downloads and installs
│   │   ├── config-repo.sh    # persistent private checkout + safe git synchronization
│   │   └── fleet.sh          # machine identity and private fleet registry
│   └── git-hooks/            # gitleaks pre-commit; setup-git-hooks chains an existing hooksPath
└── skills/
    ├── managed-machine/SKILL.md    # agent skill for bootstrap and update
    └── onboard-harness/SKILL.md    # agent skill for onboarding new harnesses
```

The portable Go core (`module github.com/qwts/managed-machine` in `go.mod`, with entry point `cmd/managed-machine` and packages under `internal/`) lives at the repository root and is documented in [`docs/go-core.md`](docs/go-core.md). Run `go test ./...` (`go test ./internal/...`) and `go run ./cmd/managed-machine platform` from the repository root.

Local identity and manifests live under `~/.config/managed-machine/`; an opted-in fleet’s default config checkout lives under `$XDG_DATA_HOME/managed-machine/` when set, or `~/.local/share/managed-machine/` otherwise. The `~/.local/bin` PATH block in `~/.zshrc` uses the `# BEGIN local-bin` markers (shared with local-bin's `install`) so existing machines need no PATH migration. The NVM initialization block uses `# BEGIN nvm` markers and manages `NVM_DIR` (default `~/.nvm`). The cargo PATH block uses `# BEGIN rustup` markers and honors `CARGO_HOME` (default `~/.cargo`). All three blocks are guarded so nested shells that inherit PATH never prepend a duplicate entry (the nvm block loads `nvm.sh --no-use` when `node` already resolves under `NVM_DIR`, and activates normally otherwise so the configured version wins over a system node). The `~/.ssh/authorized_keys` block uses `# BEGIN managed-machine` markers; `ssh enroll --fleet` rewrites the legacy `# BEGIN local-bin new-machine` block in place on first sync.
