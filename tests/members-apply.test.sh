#!/usr/bin/env bash
# Member accounts on real Linux accounts (docs/plans/member-accounts.md,
# #470): plan, approval, root apply, and what the result allows.
#
# This test creates OS accounts and writes /etc/sudoers.d. It runs only on a
# throwaway GitHub-hosted Linux runner, and only when asked:
#   MM_MEMBERS_REAL_ACCOUNTS=1 bash tests/members-apply.test.sh
#
# The approval file is written here in the form agent-machine's
# approve-members verb writes it. The verb itself is covered by the Go tests
# in internal/daemon.
set -euo pipefail

if [ "${MM_MEMBERS_REAL_ACCOUNTS:-}" != "1" ] || [ "${GITHUB_ACTIONS:-}" != "true" ] || [ "$(uname -s)" != "Linux" ]; then
    echo "members-apply: skipped (needs MM_MEMBERS_REAL_ACCOUNTS=1 on a GitHub-hosted Linux runner)"
    exit 0
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
MM="$WORK/managed-machine"
(cd "$ROOT" && go build -o "$MM" ./cmd/managed-machine)

HQ=abhq-ci
A=abm-ci-a
B=abm-ci-b
DIR=/run/agent-bot-hq/members
RULE=/etc/sudoers.d/agent-bot-hq-members
ME="$(id -un)"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

# The account agent-machine runs in: the Homebrew prefix owner, or this one.
DAEMON_ACCOUNT="$ME"
if [ -e /home/linuxbrew/.linuxbrew ]; then
    DAEMON_ACCOUNT="$(stat -c %U /home/linuxbrew/.linuxbrew)"
fi
DAEMON_HOME="$(getent passwd "$DAEMON_ACCOUNT" | cut -d: -f6)"
APPROVALS="$DAEMON_HOME/.config/agent-machine/members/approvals"
echo "owner $ME, agent-machine account $DAEMON_ACCOUNT"

as_daemon() { if [ "$DAEMON_ACCOUNT" = "$ME" ]; then "$@"; else sudo -u "$DAEMON_ACCOUNT" "$@"; fi; }

# approve <plan-id> <digest> [minutes-from-now]
approve() {
    local id="$1" digest="$2" minutes="${3:-10}" tmp
    tmp="$(mktemp)"
    printf '{"plan_id":"%s","plan_digest":"%s","approved_at":"%s","expires_at":"%s"}\n' \
        "$id" "$digest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u -d "$minutes minutes" +%Y-%m-%dT%H:%M:%SZ)" >"$tmp"
    chmod 644 "$tmp"
    as_daemon mkdir -p "$APPROVALS"
    as_daemon chmod 700 "$DAEMON_HOME/.config/agent-machine" "$DAEMON_HOME/.config/agent-machine/members" "$APPROVALS"
    as_daemon cp "$tmp" "$APPROVALS/$id.json"
    as_daemon chmod 600 "$APPROVALS/$id.json"
    rm -f "$tmp"
}

# plan <members> sets PLAN_ID, PLAN_DIGEST and PLAN_CHANGES.
plan() {
    local out
    out="$("$MM" members plan --hq-account "$HQ" --members "$1")"
    out="${out%%$'\n'*}"
    PLAN_ID="$(jq -r .plan_id <<<"$out")"
    PLAN_DIGEST="$(jq -r .plan_digest <<<"$out")"
    PLAN_CHANGES="$(jq -r .changes <<<"$out")"
    [ -n "$PLAN_ID" ] && [ "${#PLAN_DIGEST}" = 64 ] || fail "plan printed no id or digest: $out"
}

# refused <diagnostic> <command...>: the command fails with that diagnostic.
refused() {
    local want="$1" out
    shift
    if out="$("$@" 2>&1)"; then fail "expected $want, but it ran: $*"; fi
    grep -q "$want" <<<"$out" || fail "expected $want from: $* -- got: $out"
}

untouched() {
    ! getent passwd "$A" >/dev/null || fail "$A exists after a refused apply"
    ! getent passwd "$HQ" >/dev/null || fail "$HQ exists after a refused apply"
    sudo test ! -e "$RULE" || fail "$RULE exists after a refused apply"
    sudo test ! -e "$DIR" || fail "$DIR exists after a refused apply"
}

# The installed rule parses as part of the whole sudoers configuration.
# `visudo -c` exits non-zero on GitHub's runner before anything is changed
# (/etc/sudoers.d/runner has mode 0640 there), so the check is that visudo
# reports this rule as parsed, not its exit status.
sudoers_ok() {
    local out
    out="$(sudo visudo -c 2>&1 || true)"
    if grep -qx "$RULE: parsed OK" <<<"$out"; then return 0; fi
    echo "$out" >&2
    sudo cat "$RULE" >&2 || true
    return 1
}

# The HQ account does not exist yet: the plan creates it (S6).
! getent passwd "$HQ" >/dev/null || fail "$HQ exists before the test"

# --- an account that is not dedicated is accepted and named as such ----------
shared="$("$MM" members plan --hq-account "$ME" --members "$A" | sed -n 2p)"
[ "$(jq -r .kind <<<"$shared")" = "hq-account" ] || fail "the first step is not the HQ account: $shared"
[ "$(jq -r .action <<<"$shared")" = "none" ] || fail "a shared HQ account is not left alone: $shared"
grep -q "not a dedicated account" <<<"$shared" || fail "a shared HQ account is not named as shared: $shared"
grep -q "Recommended: plan without --hq-account" <<<"$shared" || fail "a shared HQ account carries no recommendation: $shared"
head="$("$MM" members plan --hq-account "$ME" --members "$A" | sed -n 1p)"
[ "$(jq -r .hq_account_dedicated <<<"$head")" = "false" ] || fail "a shared HQ account is reported as dedicated: $head"
jq -e '.advice | test("agent-bot-hq")' <<<"$head" >/dev/null || fail "the plan gives no advice for a shared HQ account: $head"
ok "the owner's own account as HQ is left alone and the plan says it is shared"

# --- plan changes nothing and its digest is stable ---------------------------
plan "$A,$B"
first="$PLAN_DIGEST"
plan "$A,$B"
[ "$first" = "$PLAN_DIGEST" ] || fail "two plans of one host have different digests"
untouched
ok "plan changes nothing and its digest is stable"

# --- refusals, each before any change ---------------------------------------
refused MM_MEMBERS_ROOT_REQUIRED "$MM" members apply "$PLAN_ID"
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
untouched
ok "apply without root or without an approval runs nothing"

approve "$PLAN_ID" "$PLAN_DIGEST" -1
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
ok "an expired approval runs nothing"

approve "$PLAN_ID" "$PLAN_DIGEST"
as_daemon chmod 666 "$APPROVALS/$PLAN_ID.json"
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
ok "an approval others can write runs nothing"

approve "$PLAN_ID" "$(printf '%064d' 0)"
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
ok "an approval for another digest runs nothing"

approve "$PLAN_ID" "$PLAN_DIGEST"
sudo mkdir -p /run/agent-bot-hq
sudo mkdir -m 777 "$DIR"
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
sudo rmdir "$DIR" /run/agent-bot-hq
ok "a host that changed after the approval runs nothing"

approve "$PLAN_ID" "$PLAN_DIGEST"
refused MM_MEMBERS_CALLER_REFUSED env CLAUDECODE=1 bash -c "sudo '$MM' members apply '$PLAN_ID'; exit \$?"
untouched
sudo test ! -e "/var/lib/managed-machine/members/receipts/$PLAN_ID.json" || fail "a refused apply used the approval"
ok "an agent session above sudo is refused and uses no approval"

# --- an approved apply ------------------------------------------------------
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >"$WORK/apply.jsonl"
[ "$(head -n 1 "$WORK/apply.jsonl" | jq -r .applied)" = "true" ] || fail "apply did not report applied"
[ "$(head -n 1 "$WORK/apply.jsonl" | jq -r .hq_account_dedicated)" = "true" ] || fail "a created HQ account is not reported as dedicated"
ok "an approved apply ran"

# The HQ account: a locked service account whose home nobody else can enter.
HQ_HOME="/var/lib/$HQ"
[ "$(getent passwd "$HQ" | cut -d: -f6,7)" = "$HQ_HOME:/usr/sbin/nologin" ] || fail "$HQ is $(getent passwd "$HQ")"
[ "$(sudo stat -c '%U %G %a' "$HQ_HOME")" = "$HQ $HQ 700" ] || fail "$HQ_HOME is $(sudo stat -c '%U %G %a' "$HQ_HOME")"
[ "$(id -Gn "$HQ")" = "$HQ" ] || fail "$HQ is in groups: $(id -Gn "$HQ")"
[ "$(id -u "$HQ")" -lt 1000 ] || fail "$HQ has uid $(id -u "$HQ"), not a service account's"
sudo grep -q "^$HQ:[!*]" /etc/shadow || fail "$HQ is not locked"
! ls "$HQ_HOME" 2>/dev/null || fail "the owner can enter the HQ account's home"
sudo -u "$HQ" test -w "$HQ_HOME" || fail "the HQ account cannot write its own home"
ok "the HQ account was created as a locked service account with a private home"

[ "$(stat -c '%U %G %a' "$DIR")" = "root root 755" ] || fail "$DIR is $(stat -c '%U %G %a' "$DIR")"
for m in "$A" "$B"; do
    [ "$(sudo stat -c '%U %G %a' "$DIR/$m")" = "$HQ $m 2750" ] || fail "$DIR/$m is $(sudo stat -c '%U %G %a' "$DIR/$m")"
    [ "$(sudo stat -c '%U %G %a' "/home/$m")" = "$m $m 700" ] || fail "/home/$m is $(sudo stat -c '%U %G %a' "/home/$m")"
    [ "$(id -Gn "$m")" = "$m" ] || fail "$m is in groups: $(id -Gn "$m")"
    sudo grep -q "^$m:[!*]" /etc/shadow || fail "$m is not locked"
done
[ "$(sudo stat -c '%U %G %a' "$RULE")" = "root root 440" ] || fail "$RULE is $(sudo stat -c '%U %G %a' "$RULE")"
[ "$(stat -c '%U %G %a' /etc/tmpfiles.d/agent-bot-hq-members.conf)" = "root root 644" ] || fail "the tmpfiles entry has the wrong owner or mode"
sudoers_ok || fail "visudo -c fails after the apply"
sudo systemd-tmpfiles --create /etc/tmpfiles.d/agent-bot-hq-members.conf || fail "the tmpfiles entry is not accepted"
[ "$(sudo stat -c '%U %G %a' "$DIR/$A")" = "$HQ $A 2750" ] || fail "tmpfiles changed $DIR/$A"
[ "$(sudo jq -r .result "/var/lib/managed-machine/members/receipts/$PLAN_ID.json")" = "applied" ] || fail "no applied receipt"
ok "accounts, directories, rule, tmpfiles entry and receipt are as planned"

# --- what the rule allows ---------------------------------------------------
as_hq() { sudo -u "$HQ" "$@"; }
[ "$(as_hq sudo -n -u "$A" /usr/bin/id -un)" = "$A" ] || fail "the HQ account cannot start a process as $A"
[ "$(as_hq sudo -n -u "$B" /usr/bin/id -un)" = "$B" ] || fail "the HQ account cannot start a process as $B"
! as_hq sudo -n -u root /usr/bin/true 2>/dev/null || fail "the HQ account can run as root"
! as_hq sudo -n /usr/bin/true 2>/dev/null || fail "the HQ account can run as root by default"
! as_hq sudo -n -u "$ME" /usr/bin/true 2>/dev/null || fail "the HQ account can run as an unlisted account"
! as_hq sudo -n -u "$A" -g root /usr/bin/true 2>/dev/null || fail "the HQ account can pick a group"
! sudo -u "$A" sudo -n -u "$B" /usr/bin/true 2>/dev/null || fail "a member can use the rule"
! sudo -u "$A" ls "$DIR/$B" 2>/dev/null || fail "a member can enter another member's endpoint directory"
! sudo -u "$A" ls "/home/$B" 2>/dev/null || fail "a member can enter another member's home"
! sudo -u "$A" ls "$HQ_HOME" 2>/dev/null || fail "a member can enter the HQ account's home"
sudo -u "$A" ls "$DIR/$A" >/dev/null || fail "a member cannot enter its own endpoint directory"
envout="$(as_hq env AGENT_BOT_SOULS_ROLE=lead LEAKED=1 sudo -n -u "$A" /usr/bin/env)"
grep -q '^AGENT_BOT_SOULS_ROLE=lead$' <<<"$envout" || fail "an allowed variable did not reach the member"
! grep -q '^LEAKED=' <<<"$envout" || fail "a variable outside the allowlist reached the member"
! as_hq sudo -n -u "$A" LEAKED=1 /usr/bin/env 2>/dev/null | grep -q '^LEAKED=' || fail "the HQ account can set a variable on the command line"
! as_hq env LEAKED=1 sudo -n -E -u "$A" /usr/bin/env 2>/dev/null | grep -q '^LEAKED=' || fail "the HQ account can keep its whole environment with -E"
ok "the HQ account starts members and nothing else; members are separated"

# --- one apply per approval; a second plan is a no-op ------------------------
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
ok "a used approval does not allow a second apply"

sleep 1
plan "$A,$B"
[ "$PLAN_CHANGES" = "0" ] || fail "a provisioned host still plans $PLAN_CHANGES changes"
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
[ "$(as_hq sudo -n -u "$A" /usr/bin/id -un)" = "$A" ] || fail "the rule broke on a second apply"
ok "a second approved apply changes nothing"

# --- removal keeps the account and its home ---------------------------------
sleep 1
plan "$A"
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
sudo test ! -e "$DIR/$B" || fail "$DIR/$B is still there"
getent passwd "$B" >/dev/null || fail "the removed member's account was deleted"
sudo test -d "/home/$B" || fail "the removed member's home was deleted"
! as_hq sudo -n -u "$B" /usr/bin/true 2>/dev/null || fail "the HQ account can still run as the removed member"
[ "$(as_hq sudo -n -u "$A" /usr/bin/id -un)" = "$A" ] || fail "the remaining member was lost"
sudoers_ok || fail "visudo -c fails after the removal"
ok "a removed member loses its rule and directory; its account and home stay"

echo "members-apply: all checks passed"
