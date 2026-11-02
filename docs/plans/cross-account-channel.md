---
status: active
overview: >-
  Make the prefix-owner executor usable from the user account over a signed
  local channel: dedicated Darwin keychain, shared socket, any-local-UID
  pairing gate, and a thin-client enroll path that does not need the user's
  0700 ~/.config. Later slices finish install verbs, the LaunchAgent, the
  agent-bot client, and the hosted relay.
related_prs: []
related_issues:
  - true-line/agent-bot-machine#442
  - true-line/agent-bot-machine#446
---

# Cross-account signed channel

Companion to [machine-daemon.md](machine-daemon.md) (P3–P8) and
[macos-signing.md](macos-signing.md). This file is the product path: admin
runs the executor; user and agent-bot are the clients. Pairing admin to
itself is not the product.

Owner direction (2026-11-02):

1. agent-machine talks to agent-bot over a signed protected channel. The
   intended path is every request through agent-bot.
2. A thin client still has to work from the user account when only
   agent-machine is installed, under the same signed-channel rules.

## Intent

The prefix-owner account (`admin`, uid 501) owns Homebrew and runs the
daemon. The daily account (`user`, uid 502) and agent-bot must call it.
Three things made that impossible on this machine and are the S1 fix:

| Failure | Cause | Fix in S1 |
|---|---|---|
| `daemon pair` as admin: OSStatus `-60008` / “A keychain cannot be found” | Login keychain is absent or locked for a non-GUI prefix-owner account. `kSecAttrAccessible` on a file keychain also prompts Authorization Services. | Dedicated `daemon.keychain-db` created and unlocked in-process with an empty password (never typed). No Data Protection attribute. Self-only ACL. Default keychain is restored after open. |
| Rebuild then `daemon run`: OSStatus `-2147415734` | Unsigned rebuild changes the binary hash; Darwin refuses `SecTrustedApplicationValidateWithPath`. | `Load` rebinds the ACL to the same path, or rotates the item if Darwin refuses the read. A different trusted-app path still fails closed. |
| User cannot reach a paired admin daemon | Socket was `0600` in a `0700` home; Gate required the daemon UID; `~/.config` is `0700` so admin cannot read `client.pub`. | Channel in prefix `var/agent-machine` (`0755`/`0666`), `daemon.pub` `0644`, `enroll/` `1733`. Gate accepts any local UID whose signature is a live pairing key. `PairClient` writes `$HOME/agent-machine.client.pub` and `enroll/terminal.pub`. |

S1 does not install software, does not start a LaunchAgent, and does not
talk to agent-bot. Those are S2–S5.

## Target

```mermaid
flowchart LR
  userTerm["user: thin client"] -->|"signed RPC"| ch
  agentBot["user: agent-bot / P7"] -->|"signed RPC"| ch
  subgraph prefixOwner [admin / prefix owner]
    ch["var/agent-machine socket + daemon.pub + enroll/"]
    exec["agent-machine daemon"]
    keys["~/.config/agent-machine 0700"]
  end
  ch --> exec
  exec --> keys
```

### Split of state

| Path | Owner | Mode | Contents |
|---|---|---|---|
| `~admin/.config/agent-machine` | prefix owner | `0700` | `daemon.keychain-db`, `peers/*`, private seed after migrate |
| `$HOMEBREW_PREFIX/var/agent-machine` | prefix owner | `0755` | `daemon.sock` `0666`, `daemon.pub` `0644` |
| `$HOMEBREW_PREFIX/var/agent-machine/enroll` | prefix owner | `1733` (Go `0o733\|os.ModeSticky`; `os.Chmod(0o1733)` does not set sticky) | `terminal.pub` / `agent-daemon.pub` drops |
| `~user/.config/agent-machine` | user | `0700` | `client.key` |
| `~user/agent-machine.client.pub` | user | `0644` | readable drop when `~/.config` is `0700` |

Windows keeps the named pipe. Linux uses the same prefix `var/` layout.

### Pairing

Two clients only: `terminal` and `agent-daemon`.

1. User: `daemon pair` mints `client.key`, writes the home-root pub, and
   tries `enroll/terminal.pub`.
2. Admin: `daemon pair --enroll PATH` (`--client terminal|agent-daemon`)
   stages `peers/<client>.*`. `PATH` may be the home-root pub, the enroll
   drop, or any readable 32-byte pub. On `EACCES` the command falls back
   to those drops (`loadPublicForEnroll`).
3. User: `daemon status` and `--update` dial `ChannelSocket()`, sign with
   `client.key`, and accept a response only when `daemon.pub` verifies it.

`Caller.Refuse()` still blocks `install` / `run` / `unpair` / `enroll` for
a non-owner. `RefuseClient()` allows user `pair` and signed `status`.
Catalog remains agent-daemon-only.

### Darwin key store

See [macos-signing.md](macos-signing.md). Constraints from #446 stay: no
`.app` bundle, no Secure Enclave, no `keychain-access-groups`. The login
keychain is not used. Empty-password `SecKeychainCreate` must pass a
non-NULL empty buffer (`-50` if the pointer is NULL).
`SetUserInteractionAllowed(false)` is only around `Unlock`; leaving it
off for `SecItemAdd` yields `-25293`.

## Acceptance

### S1 — this change (proved 2026-11-02 on this machine)

- `go test ./internal/daemon` covers dedicated-keychain round-trip with no
  login keychain, stale-ACL rebind, default-keychain restore, channel
  modes `0755`/`0666`/`1733`, any-local-UID signed accept, negative
  peer UID refuse, purge that keeps the channel dir, and
  `TestThinClientStatusFromOtherUID`.
- Admin `daemon pair` writes the dedicated keychain item and
  `daemon.pub` next to the socket. A second unsigned rebuild of the same
  path still loads.
- User `daemon pair` returns a readable drop
  (`$HOME/agent-machine.client.pub` or `enroll/terminal.pub`).
- Admin `daemon pair --enroll` of that drop stages `peers/terminal.*`.
- User `daemon status` against a running admin daemon reports
  `channel=signed` and a daemon state. That is the product proof for S1.

### S2 — enroll UX (same repo, next PR)

`pair --enroll` with no path reads `EnrollDropDir()/terminal.pub`.
`pair` as the user prints the exact admin enroll command. No
`/Users/Shared` and no `chmod 777` in the documented path.

### S3 — keep the executor up (same repo)

`daemon install` as the prefix owner writes and loads the LaunchAgent
(or systemd user unit) so `daemon run` is not a foreground Terminal
session. Agent accounts, root, and a foreign HOME stay refused. A cask
whose published install needs elevation stays a human action.

### S4 — thin-client verbs that do work (same repo; machine-daemon P5/P6)

From the user account, the paired thin client runs `status`, `receipts`,
and `update` over the signed channel. `plan` / `apply` stay closed
except through agent-daemon once P7 exists. `--update` falls back to
the legacy script only when no daemon is installed.

### S5 — agent-bot is the control plane (other repos; P7/P8)

P7: agent-daemon client in agent-bot-identity, pairing through
agent-bot-keyd, same channel rules. P8: MCP `machine_request` /
`machine_result` / `machine_status` relay through agents.true-line.ai
(true-line/agent-bot#66, #71). The thin client remains the fallback
when agent-bot is not installed.

## Replay

1. Read this plan, [machine-daemon.md](machine-daemon.md),
   [macos-signing.md](macos-signing.md), and `AGENTS.md`.
2. Work in a soul worktree. Do not use the owner primary checkout.
3. S1 files: `internal/daemon/keychain_darwin.go`, `channel.go`,
   `listen_unix.go`, `pairing_file.go`, `protocol.go`, `run.go`,
   `caller.go`, `command.go`, `update_client.go`,
   `cmd/managed-machine/main.go`.
4. Gate: `gofmt -l . && go vet ./... && go test ./internal/daemon`.
   Full `go test ./...` is the CI gate; `cmd/mm-walkthrough` is
   long-running and is not required to land S1 locally.
5. Machine proof, as prefix owner then as user:

   ```sh
   # admin
   managed-machine daemon pair
   managed-machine daemon run
   # other tty, admin
   managed-machine daemon pair --enroll /Users/<user>/agent-machine.client.pub
   # user
   managed-machine daemon pair
   managed-machine daemon status
   ```

   Expected user status: `channel=signed`.
6. After S1 merges, open S2 from this file. Do not reopen the login
   keychain design. #442 Linux/Windows `daemon.key` and the parent-dir
   owner check stay on #442.
