# Sourced only inside the existing throwaway enrolled HQ fixture. All local
# review keys belong to this CI job. Use the real foreground Machine daemon.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_MEMBERS_REAL_ACCOUNTS:-}" == 1 && ( "${MM_HQ_UPGRADE_TEST:-}" == legacy || "${MM_HQ_UPGRADE_TEST:-}" == paired ) &&
   -z "${MM_HQ_DEVICE_ARCHIVE:-}" && "$role" == _agent-bot-hq ]] || exit 1

hosted_harness_accounts() (
    set -euo pipefail
    # The EXIT trap needs these subshell variables even if Bash unwinds function
    # locals after an error. The subshell keeps them private to this fixture.
    left=_abh-ci-proof-a right=_abh-ci-proof-b
    local account p output row plan_id digest role_uid
    transfer="$signer/account-proof" files="$stage/account-review-handoff"
    local client="$stage/account-review-hq"
    broker=none
    local changes=2
    if [[ "$MM_HQ_UPGRADE_TEST" == paired ]]; then
        broker="$runtime_dir/ipc"
        [[ "$runtime_dir" == '/Library/Application Support/ai.true-line.agent-bot-hq' && -d "$runtime_dir" &&
           ! -e "$broker" && ! -L "$broker" ]] || fail 'an empty broker layout is required'
        changes=5
    fi
    mkdir -m 0700 "$transfer"
    for account in "$left" "$right"; do
        ! exists "$account" || fail 'fixture account exists before test'
        p="/var/agent-bot-harness-$account"
        [[ ! -e "$p" && ! -L "$p" ]] || fail 'fixture home exists before test'
    done
    # This subshell owns the proof handoff. The outer hosted fixture removes
    # its staging tree. The ephemeral runner owns the tested role accounts.
    cleanup_account_handoff() {
        sudo rm -f "$files/challenge" "$files/proof"
        rm -f "$transfer/proof"
        if [[ "$broker" != none && -d "$broker" && ! -L "$broker" ]]; then
            # The fixture required this layout to be absent. Only empty test
            # directories may be removed, including after a partial apply.
            sudo rmdir "$broker/$left" "$broker/$right" "$broker" 2>/dev/null || :
        fi
    }
    trap cleanup_account_handoff EXIT
    local hq_source=cc979cf12ad9b8b932b70f7efb28c74f1b0e47d6
    local identity_source=5cc799016e62dd07c1a05d452e92ed8de22cac47
    checkout_review_source account-hq agent-bot-hq "$hq_source"
    checkout_review_source account-identity agent-bot-identity "$identity_source"
    # Run the actual archive without replacing the service used by the upgrade test.
    (cd "$subjects/account-hq" && PATH="$stage:$PATH" bash scripts/ci-build-darwin-artifact.sh "$hq_source" "$transfer/hq.tar")
    printf '%s  %s\n' 890d97304da0a3668503fb56824d5af5158ed9a38d81bef80025c1a76317f218 "$transfer/hq.tar" | shasum -a 256 -c -
    sudo install -d -o root -g wheel -m 0755 "$client"
    sudo tar -xpf "$transfer/hq.tar" --strip-components 1 -C "$client"
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
    # The same adapter/account mapping is used by the packaged broker fixture.
    jq -n --arg a "$left" --arg b "$right" --arg dir "$broker" '
        {harnesses: {accounts: {"adapter-a":$a, "adapter-b":$b}}} |
        if $dir=="none" then . else .harnesses.dir=$dir end' >"$transfer/config.json"
    plan_accounts() { "$MM" members plan --harness-account-provision --hq-config "$transfer/config.json"; }
    output="$(plan_accounts)"
    row="${output%%$'\n'*}"
    plan_id="$(jq -er '.plan_id' <<<"$row")"
    digest="$(jq -er '.plan_digest' <<<"$row")"
    jq -e --argjson changes "$changes" '.purpose=="harness-account-provision" and .changes==$changes' <<<"$row" >/dev/null
    refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$plan_id"
    account_cli export "$plan_id" --socket "$channel" >"$transfer/challenge"
    jq -e --arg id "$plan_id" --arg digest "$digest" --arg machine "$machine_key" --arg owner "$pin" \
        --arg hq "$hq_key" --arg role "$role" --arg dir "$broker" --argjson role_uid "$role_uid" --arg a "$left" --arg b "$right" '
        .body | .action=="harness-account-provision" and .plan_id==$id and .plan_digest==$digest and
        .machine_key==$machine and .hq_key==$hq and .owner_key==$owner and
        (.plan_canonical|fromjson|
          .version==3 and .purpose=="harness-account-provision" and .members==[$a,$b] and .dir==$dir and
          .hq_account==$role and [.steps[:3][].target]==[$role,$a,$b] and
          [.steps[:3][].kind]==["hq-account","account","account"] and [.steps[:3][].action]==["none","create","create"] and
          .steps[0].uid==$role_uid and ([.steps[:3][].uid]|unique|length)==3 and
          all(.steps[:3][]; .uid==.gid and .uid>=300 and .uid<=399 and .group==.target and .mode=="0700") and
          all(.steps[1:3][]; .detail==("home /var/agent-bot-harness-"+.target+", shell /usr/bin/false, private group, no password, no other groups")) and
          (.steps[3:] == (if $dir=="none" then [] else
            [{kind:"directory",target:$dir,action:"create",owner:"root",group:"wheel",mode:"0755"}] +
            ([$a,$b] | map({kind:"directory",target:($dir+"/"+.),action:"create",owner:$role,group:.,mode:"2750"}))
          end)))
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
    (cd "$signer" && sudo "$MM" members apply "$plan_id") | jq -e --argjson changes "$changes" '.applied and .changes==$changes' >/dev/null

    local uid home groups common_groups nobody_gid gid receipt="$RECEIPTS/$plan_id.json"
    nobody_gid="$(id -g nobody)"
    common_groups="$(id -G nobody)"
    [[ -n "$common_groups" ]] || fail 'could not identify system-wide group memberships'
    for account in "$left" "$right"; do
        home="/var/agent-bot-harness-$account"
        uid="$(jq -er --arg a "$account" '.body.plan_canonical|fromjson|.steps[]|select(.target==$a)|.uid' "$transfer/challenge")"
        [[ "$(id -u "$account"):$(id -g "$account"):$(id -gn "$account")" == "$uid:$uid:$account" ]]
        [[ "$(attr "$account" NFSHomeDirectory)" == "$home" && "$(attr "$account" UserShell)" == /usr/bin/false &&
           "$(attr "$account" Password)" == '*' && -z "$(attr "$account" AuthenticationAuthority)" &&
           "$(attr "$account" IsHidden)" == 1 && ! -L "$home" ]]
        # The private primary group must also be the only effective group
        # beyond memberships shared by macOS accounts, including nobody.
        groups="$(id -G "$account")"
        [[ " $groups " == *" $uid "* ]] || fail 'effective group list omits the reviewed private group'
        for gid in $groups; do
            [[ "$gid" == "$uid" || ( "$gid" != "$nobody_gid" && " $common_groups " == *" $gid "* ) ]] || fail 'harness has an unreviewed supplementary group'
        done
        [[ "$(sudo stat -f '%u:%g:%Lp' "$home")" == "$uid:$uid:700" ]]
        (cd / && sudo -n -H -u "$account" /bin/sh -c '
            test "$HOME" = "$1" && cd "$HOME" && test "$(/usr/bin/id -u)" = "$2"
        ' verify-home "$home" "$uid") || fail 'harness cannot enter its private home as the reviewed UID'
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
    sudo test -f "$receipt" && sudo test ! -L "$receipt" || fail 'unexpected receipt type'
    [[ "$(sudo stat -f '%u' "$receipt")" == 0 ]]
    local mode
    mode="$(sudo stat -f '%Lp' "$receipt")"
    (( (8#$mode & 022) == 0 ))
    sudo jq -e --arg dir "$broker" --argjson changes "$changes" --arg id "$plan_id" --arg d "$digest" --arg a "$left" --arg b "$right" '
        .result=="applied" and .plan_id==$id and .plan_digest==$d and .dir==$dir and .members==[$a,$b] and .changes==$changes' "$receipt" >/dev/null
    local before
    before="$(sudo shasum -a 256 "$receipt")"
    refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$plan_id"
    [[ "$(sudo shasum -a 256 "$receipt")" == "$before" && "$(id -u "$role")" == "$role_uid" ]]
    output="$(plan_accounts)"
    jq -e '.purpose=="harness-account-provision" and .changes==0' <<<"${output%%$'\n'*}" >/dev/null
    if [[ "$broker" != none ]]; then
        [[ "$(stat -f '%Su:%Sg:%Lp' "$broker")" == root:wheel:755 ]]
        for account in "$left" "$right"; do
            [[ "$(stat -f '%Su:%Sg:%Lp' "$broker/$account")" == "$role:$account:2750" ]]
        done
        local broker_state="$stage/account-broker-state"
        sudo install -d -o "$role" -g "$role" -m 0700 "$broker_state"
        (cd / && "$stage/node" "$client/tests/packaged-darwin-harness-bind.mjs" "$client" "$broker_state" "$left" "$right")
        # The existing service rollback test requires its runtime directory empty.
        sudo rmdir "$broker/$left" "$broker/$right" "$broker"
    fi
    paired_status
    ok 'paired Machine created two reviewed harness roles with private homes and retained a one-use receipt'
)
hosted_harness_accounts
