# Sourced only inside the existing throwaway enrolled HQ fixture. All local
# review keys belong to this CI job. Use the real foreground Machine daemon.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_MEMBERS_REAL_ACCOUNTS:-}" == 1 && "${MM_HQ_UPGRADE_TEST:-}" == legacy &&
   -z "${MM_HQ_DEVICE_ARCHIVE:-}" && "$role" == _agent-bot-hq ]] || exit 1

hosted_harness_accounts() (
    set -euo pipefail
    local left=_abh-ci-proof-a right=_abh-ci-proof-b
    local account p output row plan_id digest role_uid
    local transfer="$signer/account-proof" client="$stage/account-review-hq" files="$stage/account-review-handoff"
    mkdir -m 0700 "$transfer"
    for account in "$left" "$right"; do
        ! exists "$account" || fail 'fixture account exists before test'
        p="/var/agent-bot-harness-$account"
        [[ ! -e "$p" && ! -L "$p" ]] || fail 'fixture home exists before test'
    done
    # This subshell owns the proof handoff. The outer hosted fixture removes
    # its staging tree. The ephemeral runner owns the tested role accounts.
    trap 'sudo rm -f "$stage/account-review-handoff/challenge" "$stage/account-review-handoff/proof"; rm -f "$signer/account-proof/proof"' EXIT
    local hq_source=cc979cf12ad9b8b932b70f7efb28c74f1b0e47d6
    local identity_source=5cc799016e62dd07c1a05d452e92ed8de22cac47
    checkout_review_source account-hq agent-bot-hq "$hq_source"
    checkout_review_source account-identity agent-bot-identity "$identity_source"
    # Stage only the reviewed client sources. launchd continues running the predecessor.
    sudo install -d -o root -g wheel -m 0755 "$client"
    git -C "$subjects/account-hq" -c tar.umask=0022 archive "$hq_source" -- hq sdk scripts governance package.json |
        sudo tar -xpf - -C "$client"
    sudo install -d -o "$role" -g "$role" -m 0700 "$files"
    local src="$subjects/account-identity/owner-presence-macos"
    xcrun --sdk macosx swiftc -swift-version 5 -parse-as-library \
        "$src/PairingChallenge.swift" "$src/HarnessLaunchPlan.swift" "$src/HarnessAccountPlan.swift" \
        "$src/HarnessLaunchChallenge.swift" "$src/HarnessMachinePin.swift" "$src/HarnessNativeReview.swift" \
        "$ROOT/tests/fixtures/paired-darwin-hq-accounts-owner.swift" -o "$transfer/owner-proof"
    account_cli() {
        (cd / && sudo -n -H -u "$role" -- "$stage/node" "$client/hq/main.mjs" machine harness-account-provision "$@")
    }
    role_uid="$(id -u "$role")"
    output="$("$MM" members plan --harness-account-provision --members "$right,$left")"
    row="${output%%$'\n'*}"
    plan_id="$(jq -er '.plan_id' <<<"$row")"
    digest="$(jq -er '.plan_digest' <<<"$row")"
    jq -e '.purpose=="harness-account-provision" and .changes==2' <<<"$row" >/dev/null
    refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$plan_id"
    account_cli export "$plan_id" --socket "$channel" >"$transfer/challenge"
    jq -e --arg id "$plan_id" --arg digest "$digest" --arg machine "$machine_key" --arg owner "$pin" \
        --arg hq "$hq_key" --arg role "$role" --argjson role_uid "$role_uid" --arg a "$left" --arg b "$right" '
        .body | .action=="harness-account-provision" and .plan_id==$id and .plan_digest==$digest and
        .machine_key==$machine and .hq_key==$hq and .owner_key==$owner and
        (.plan_canonical|fromjson|
          .version==3 and .purpose=="harness-account-provision" and .members==[$a,$b] and .dir=="none" and
          .hq_account==$role and [.steps[].target]==[$role,$a,$b] and
          [.steps[].kind]==["hq-account","account","account"] and [.steps[].action]==["none","create","create"] and
          .steps[0].uid==$role_uid and ([.steps[].uid]|unique|length)==3 and
          all(.steps[]; .uid==.gid and .uid>=300 and .uid<=399 and .group==.target and .mode=="0700") and
          all(.steps[1:][]; .detail==("home /var/agent-bot-harness-"+.target+", shell /usr/bin/false, private group, no password, no other groups")))
        ' "$transfer/challenge" >/dev/null
    [[ "$(jq -j '.body.plan_canonical' "$transfer/challenge" | shasum -a 256 | awk '{print $1}')" == "$digest" ]]
    "$transfer/owner-proof" "$transfer/challenge" "$published" "$signer/owner.raw" > "$transfer/proof"
    sudo install -o "$role" -g "$role" -m 0600 "$transfer/challenge" "$transfer/proof" "$files"
    approve_accounts() {
        account_cli approve --challenge-file "$files/challenge" --proof-file "$files/proof" --socket "$channel"
    }
    approve_accounts | jq -e --arg id "$plan_id" --arg d "$digest" '.state=="approved" and .plan_id==$id and .plan_digest==$d' >/dev/null
    if approve_accounts >"$transfer/replay.out" 2>"$transfer/replay.error"; then fail 'owner proof replay succeeded'; fi
    grep -Fq 'MM_DAEMON_PEER_REFUSED' "$transfer/replay.error"
    (cd "$signer" && sudo "$MM" members apply "$plan_id") | jq -e '.applied and .changes==2' >/dev/null

    local uid home receipt="$RECEIPTS/$plan_id.json"
    for account in "$left" "$right"; do
        home="/var/agent-bot-harness-$account"
        uid="$(jq -er --arg a "$account" '.body.plan_canonical|fromjson|.steps[]|select(.target==$a)|.uid' "$transfer/challenge")"
        [[ "$(id -u "$account"):$(id -g "$account"):$(id -gn "$account")" == "$uid:$uid:$account" ]]
        [[ "$(attr "$account" NFSHomeDirectory)" == "$home" && "$(attr "$account" UserShell)" == /usr/bin/false &&
           "$(attr "$account" Password)" == '*' && -z "$(attr "$account" AuthenticationAuthority)" &&
           "$(attr "$account" IsHidden)" == 1 && ! -L "$home" ]]
        [[ "$(sudo stat -f '%u:%g:%Lp' "$home")" == "$uid:$uid:700" ]]
        [[ "$(dscl . -search /Users PrimaryGroupID "$uid" | awk '{print $1}')" == "$account" ]]
        # Refuse explicit or nested group members. dscl -plist returns an
        # array for each attribute present in the Directory Services record.
        dscl -plist . -read "/Groups/$account" | /usr/bin/python3 -I -c '
import plistlib, sys
record = plistlib.loads(sys.stdin.buffer.read())
attrs = {"GroupMembership", "GroupMembers", "NestedGroups"}
sys.exit(0 if isinstance(record, dict) and record and
         all(not values for key, values in record.items() if key.rsplit(":", 1)[-1] in attrs) else 1)'
        sudo -n -u "$account" test -w "$home"
    done
    if sudo -n -u "$left" test -x "/var/agent-bot-harness-$right" ||
       sudo -n -u "$right" test -x "/var/agent-bot-harness-$left"; then fail 'another role could enter its peer home'; fi
    [[ "$(sudo stat -f '%u' "$receipt")" == 0 && ! -L "$receipt" ]]
    local mode
    mode="$(sudo stat -f '%Lp' "$receipt")"
    (( (8#$mode & 022) == 0 ))
    sudo jq -e --arg id "$plan_id" --arg d "$digest" --arg a "$left" --arg b "$right" '
        .result=="applied" and .plan_id==$id and .plan_digest==$d and .members==[$a,$b] and .changes==2' "$receipt" >/dev/null
    local before
    before="$(sudo shasum -a 256 "$receipt")"
    refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$plan_id"
    [[ "$(sudo shasum -a 256 "$receipt")" == "$before" && "$(id -u "$role")" == "$role_uid" ]]
    paired_status
    ok 'paired Machine created two reviewed harness roles with private homes and retained a one-use receipt'
)
hosted_harness_accounts
