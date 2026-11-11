#!/usr/bin/env bash
# The HQ account on a real macOS host (docs/plans/cross-account-channel.md,
# S6): plan, approval, root apply, and what the account is afterwards. On
# macOS a plan holds the HQ account alone.
#
# This test creates an OS account. It runs only on a throwaway GitHub-hosted
# macOS runner, and only when asked:
#   MM_MEMBERS_REAL_ACCOUNTS=1 bash tests/members-apply-macos.test.sh
#
# The approval file is written here in the form agent-machine's
# approve-members verb writes it. The verb itself is covered by the Go tests
# in internal/daemon.
set -euo pipefail

if [ "${MM_MEMBERS_REAL_ACCOUNTS:-}" != "1" ] || [ "${GITHUB_ACTIONS:-}" != "true" ] || [ "$(uname -s)" != "Darwin" ]; then
    echo "members-apply-macos: skipped (needs MM_MEMBERS_REAL_ACCOUNTS=1 on a GitHub-hosted macOS runner)"
    exit 0
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
chmod 755 "$WORK"
MM="$WORK/managed-machine"
(cd "$ROOT" && go build -o "$MM" ./cmd/managed-machine)

HQ=_abhq-ci
HQ_HOME=/var/abhq-ci
RECEIPTS=/var/db/managed-machine/members/receipts
ME="$(id -un)"

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
# dscl prints an attribute outside its standard set as dsAttrTypeNative:<name>.
attr() { dscl . -read "/Users/$1" "$2" 2>/dev/null | sed -En "s/^(dsAttrTypeNative:)?$2: //p"; }
exists() { dscl . -read "/Users/$1" UniqueID >/dev/null 2>&1; }

# The account agent-machine runs in: the Homebrew prefix owner, or this one.
DAEMON_ACCOUNT="$ME"
for prefix in /opt/homebrew /usr/local/Homebrew; do
    if [ -e "$prefix" ]; then
        DAEMON_ACCOUNT="$(stat -f %Su "$prefix")"
        break
    fi
done
DAEMON_HOME="$(attr "$DAEMON_ACCOUNT" NFSHomeDirectory)"
APPROVALS="$DAEMON_HOME/.config/agent-machine/members/approvals"
echo "owner $ME, agent-machine account $DAEMON_ACCOUNT"

as_daemon() { if [ "$DAEMON_ACCOUNT" = "$ME" ]; then "$@"; else sudo -u "$DAEMON_ACCOUNT" "$@"; fi; }

# approve <plan-id> <digest> [minutes-from-now, signed]
approve() {
    local id="$1" digest="$2" minutes="${3:-+10}" tmp
    tmp="$(mktemp)"
    printf '{"plan_id":"%s","plan_digest":"%s","approved_at":"%s","expires_at":"%s"}\n' \
        "$id" "$digest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u -v"${minutes}M" +%Y-%m-%dT%H:%M:%SZ)" >"$tmp"
    chmod 644 "$tmp"
    as_daemon mkdir -p "$APPROVALS"
    as_daemon chmod 700 "$DAEMON_HOME/.config/agent-machine" "$DAEMON_HOME/.config/agent-machine/members" "$APPROVALS"
    as_daemon cp "$tmp" "$APPROVALS/$id.json"
    as_daemon chmod 600 "$APPROVALS/$id.json"
    rm -f "$tmp"
}

# plan sets PLAN_ID, PLAN_DIGEST, PLAN_CHANGES and PLAN_STEP.
plan() {
    local out
    out="$("$MM" members plan --hq-account "$HQ")"
    PLAN_STEP="$(sed -n 2p <<<"$out")"
    out="${out%%$'\n'*}"
    PLAN_ID="$(jq -r .plan_id <<<"$out")"
    PLAN_DIGEST="$(jq -r .plan_digest <<<"$out")"
    PLAN_CHANGES="$(jq -r .changes <<<"$out")"
    PLAN_DEDICATED="$(jq -r .hq_account_dedicated <<<"$out")"
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
    ! exists "$HQ" || fail "$HQ exists after a refused apply"
    sudo test ! -e "$HQ_HOME" || fail "$HQ_HOME exists after a refused apply"
}

! exists "$HQ" || fail "$HQ exists before the test"

# --- member accounts are not planned on macOS --------------------------------
refused MM_MEMBERS_UNSUPPORTED "$MM" members plan --hq-account "$HQ" --members abm-ci-a
ok "a plan with member accounts is refused"

# --- an account that is not dedicated is accepted and named as such ----------
shared="$("$MM" members plan --hq-account "$ME" | sed -n 2p)"
[ "$(jq -r .action <<<"$shared")" = "none" ] || fail "a shared HQ account is not left alone: $shared"
grep -q "not a dedicated account" <<<"$shared" || fail "a shared HQ account is not named as shared: $shared"
head="$("$MM" members plan --hq-account "$ME" | sed -n 1p)"
[ "$(jq -r .hq_account_dedicated <<<"$head")" = "false" ] || fail "a shared HQ account is reported as dedicated: $head"
jq -e '.advice | test("_agent-bot-hq")' <<<"$head" >/dev/null || fail "the plan gives no advice for a shared HQ account: $head"
ok "the owner's own account as HQ is left alone and the plan says it is shared"

# --- plan changes nothing and its digest is stable ---------------------------
plan
first="$PLAN_DIGEST"
[ "$(jq -r .action <<<"$PLAN_STEP")" = "create" ] || fail "the plan does not create the HQ account: $PLAN_STEP"
plan
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

approve "$PLAN_ID" "$(printf '%064d' 0)"
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
ok "an approval for another digest runs nothing"

approve "$PLAN_ID" "$PLAN_DIGEST"
refused MM_MEMBERS_CALLER_REFUSED env CLAUDECODE=1 bash -c "sudo '$MM' members apply '$PLAN_ID'; exit \$?"
untouched
sudo test ! -e "$RECEIPTS/$PLAN_ID.json" || fail "a refused apply used the approval"
ok "an agent session above sudo is refused and uses no approval"

# --- an approved apply ------------------------------------------------------
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >"$WORK/apply.jsonl"
[ "$(head -n 1 "$WORK/apply.jsonl" | jq -r .applied)" = "true" ] || fail "apply did not report applied"
ok "an approved apply ran"

# The HQ account: a hidden role account nobody can log in to, whose home
# nobody else can enter.
[ "$(attr "$HQ" NFSHomeDirectory)" = "$HQ_HOME" ] || fail "$HQ has home $(attr "$HQ" NFSHomeDirectory)"
[ "$(attr "$HQ" UserShell)" = "/usr/bin/false" ] || fail "$HQ has shell $(attr "$HQ" UserShell)"
[ "$(attr "$HQ" Password)" = "*" ] || fail "$HQ has a password field other than *"
[ -z "$(attr "$HQ" AuthenticationAuthority)" ] || fail "$HQ has an authentication authority"
[ "$(attr "$HQ" IsHidden)" = "1" ] || fail "$HQ is not hidden"
uid="$(id -u "$HQ")"
[ "$uid" -ge 300 ] && [ "$uid" -le 399 ] || fail "$HQ has uid $uid, not a role account's"
[ "$(id -gn "$HQ")" = "$HQ" ] || fail "$HQ has primary group $(id -gn "$HQ")"
# Groups that even the nobody account is in hold every account.
everyones="$(id -Gn nobody | tr ' ' '\n')"
extra="$(id -Gn "$HQ" | tr ' ' '\n' | grep -v -x -e "$HQ" | grep -v -x --fixed-strings "$everyones" || true)"
[ -z "$extra" ] || fail "$HQ is in other groups: $extra"
[ "$(sudo stat -f '%Su %Sg %Lp' "$HQ_HOME")" = "$HQ $HQ 700" ] || fail "$HQ_HOME is $(sudo stat -f '%Su %Sg %Lp' "$HQ_HOME")"
! ls "$HQ_HOME" 2>/dev/null || fail "the owner can enter the HQ account's home"
sudo -u "$HQ" test -w "$HQ_HOME" || fail "the HQ account cannot write its own home"
[ "$(sudo jq -r .result "$RECEIPTS/$PLAN_ID.json")" = "applied" ] || fail "no applied receipt"
ok "the HQ account was created as a locked, hidden role account with a private home"

# --- one apply per approval; a second plan is a no-op ------------------------
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
ok "a used approval does not allow a second apply"

sleep 1
plan
[ "$PLAN_CHANGES" = "0" ] || fail "a provisioned host still plans $PLAN_CHANGES changes: $PLAN_STEP"
[ "$PLAN_DEDICATED" = "true" ] || fail "the created HQ account is not reported as dedicated: $PLAN_STEP"
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
ok "a second approved apply changes nothing"

# --- a home others can enter is repaired ------------------------------------
sudo chmod 755 "$HQ_HOME"
sleep 1
plan
[ "$(jq -r .action <<<"$PLAN_STEP")" = "repair" ] || fail "an open home is not planned for repair: $PLAN_STEP"
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
[ "$(sudo stat -f '%Lp' "$HQ_HOME")" = "700" ] || fail "the home was not set back to 0700"
ok "an HQ home that others can enter is set back to 0700"

echo "members-apply-macos: all checks passed"
