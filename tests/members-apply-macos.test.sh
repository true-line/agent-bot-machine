#!/usr/bin/env bash
# The HQ and harness credential accounts on a real macOS host: plan,
# approval, root apply, account identity and private home ownership.
#
# This test creates an OS account. It runs only on a throwaway GitHub-hosted
# macOS runner, and only when asked:
#   MM_MEMBERS_REAL_ACCOUNTS=1 bash tests/members-apply-macos.test.sh
#
# Generic account cases seed the existing approval record. The dedicated
# first-HQ case at the end exports and imports a signed owner proof via the
# production CLI, then applies its exact plan using sudo.
set -euo pipefail

if [ "${MM_MEMBERS_REAL_ACCOUNTS:-}" != "1" ]; then
    if [[ "${1:-}" == --real-hq ]]; then echo "real HQ install requires the hosted fixture opt-in" >&2; exit 1; fi
    echo "members-apply-macos: skipped (needs MM_MEMBERS_REAL_ACCOUNTS=1 on a GitHub-hosted macOS runner)"
    exit 0
fi
if [ "${GITHUB_ACTIONS:-}" != "true" ] || [ "${MM_MEMBERS_RUNNER:-}" != "github-hosted" ] || [ "$(uname -s)" != Darwin ]; then
    echo "members-apply-macos: real account test requires a disposable GitHub-hosted macOS runner" >&2
    exit 1
fi

# The real archive case has a separate hosted runner. Keep the macOS 15
# native fixture and the helper's generic account/approval cases independent.
case "${1:-}" in
    "") ;;
    --real-hq)
        sw_vers
        /bin/launchctl version
        sip_status="$(LC_ALL=C /usr/bin/csrutil status)"
        printf '%s\n' "$sip_status"
        if [[ "${MM_HQ_REQUIRE_SIP:-false}" == true && "$sip_status" != 'System Integrity Protection status: enabled.' ]]; then
            echo 'SIP qualification requires a fully enabled runner' >&2; exit 1
        fi
        printf 'Architecture: %s\n' "$(uname -m)"
        [[ "$#" == 1 && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "$(uname -m)" == arm64 && "$(sw_vers -productVersion)" == 27.* ]] || {
            echo 'real HQ install requires a disposable GitHub-hosted Apple Silicon macOS 27 runner' >&2; exit 1;
        } ;;
    *) echo 'unknown macOS fixture' >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The component needs one macOS 27 run, including when the install matrix
# also qualifies a paired predecessor. Run it before creating accounts.
if [[ "${1:-}" == --real-hq && "${MM_HQ_UPGRADE_TEST:-}" != paired ]]; then
    /usr/bin/python3 -I "$ROOT/tests/fixtures/darwin-harness-egress.py"
fi
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
    out="$("$MM" members plan --hq-account "$HQ" "$@")"
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

if [[ "${1:-}" == --real-hq ]]; then
    source "$ROOT/tests/fixtures/hq-launchd-install.sh"
    exit 0
fi

! exists "$HQ" || fail "$HQ exists before the test"

# Darwin wire-up of the endpoint directory is a separate work item.
refused MM_MEMBERS_UNSUPPORTED "$MM" members plan --dir /tmp/unmanaged
ok "a request to install endpoint directories is refused"

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

# Two credentials get two OS principals. Multiple adapters sharing one
# credential get one account, on the same digest-bound approval path.
A=_abm-ci-a
B=_abm-ci-b
for member in "$A" "$B"; do
    ! exists "$member" || fail "$member already exists on this runner"
    sudo test ! -e "/var/agent-bot-harness-$member" || fail "a harness home already exists"
done
jq -n --arg a "$A" --arg b "$B" '{harnesses:{accounts:{first:$a,second:$b,shared:$a},dir:"/var/run/agent-bot-hq/members"}}' >"$WORK/hq.json"
refused MM_MEMBERS_LIST_INVALID "$MM" members plan --hq-account "$HQ" --members "$ME"
refused MM_MEMBERS_ACCOUNT_REFUSED "$MM" members plan --hq-account "$HQ" --members nobody
plan --hq-config "$WORK/hq.json"
[ "$PLAN_CHANGES" = 2 ] || fail "expected two accounts; plan contains $PLAN_CHANGES changes"
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
! exists "$A" && ! exists "$B" || fail "an unapproved plan created a harness account"
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
[ "$(id -u "$A")" != "$(id -u "$B")" ] || fail "credential accounts share a UID"
for member in "$A" "$B"; do
    uid="$(id -u "$member")"
    home="/var/agent-bot-harness-$member"
    [ "$uid" != "$(id -u "$HQ")" ] && [ "$uid" != "$(id -u "$ME")" ] || fail "$member shares a UID"
    [ "$uid" -ge 300 ] && [ "$uid" -le 399 ] && [ "$(id -g "$member")" = "$uid" ] || fail "$member has non-role IDs"
    [ "$(id -gn "$member")" = "$member" ] || fail "$member lacks its private group"
    [ "$(attr "$member" NFSHomeDirectory)" = "$home" ] || fail "$member has the wrong home"
    [ "$(attr "$member" UserShell)" = /usr/bin/false ] && [ "$(attr "$member" Password)" = '*' ] || fail "$member can log in"
    [ -z "$(attr "$member" AuthenticationAuthority)" ] && [ "$(attr "$member" IsHidden)" = 1 ] || fail "$member is not a locked, hidden role"
    [ "$(sudo stat -f '%Su %Sg %Lp' "$home")" = "$member $member 700" ] || fail "$home is not private"
    sudo -u "$member" test -w "$home" || fail "$member cannot write its own home"
done
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
sleep 1
plan --members "$B,$A"
[ "$PLAN_CHANGES" = 0 ] || fail "the explicit account list plans $PLAN_CHANGES changes on a provisioned host"
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
ok "two distinct credential principals and their private homes survive an approved reapply"

source "$ROOT/tests/fixtures/hq-launchd-install.sh"
echo "members-apply-macos: all checks passed"
