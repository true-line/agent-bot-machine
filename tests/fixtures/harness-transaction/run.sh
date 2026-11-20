# Sourced after this job has pinned its one-use owner key and enrolled its new HQ.
[[ "${MM_HARNESS_TRANSACTION:-}" == 1 && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${GITHUB_ACTIONS:-}" == true && "$(sw_vers -productVersion)" == 27.* &&
   "$MM" == "$WORK/fixture-machine" && "$layout_v2" == true ]] || exit 1
root="$ROOT/tests/fixtures/harness-transaction"
checkout_review_source accounts agent-bot-hq 72d160d37e78e016d65c46dc424e0f192f50c3ce
python3 "$root/roles.py" "$subjects/accounts/tests/packaged-darwin-harness-accounts.py"
fixture_dir="$runtime_dir/fixture-qualification"
adapter="$fixture_dir/member-adapter"
digest="$(jq -er .sha256 "$root/fixture-policy.json")"
[[ "$adapter" == "$(jq -er .executable "$root/fixture-policy.json")" ]] || exit 1
sudo mkdir -m 0755 "$fixture_dir"
sudo install -o root -g wheel -m 0755 "$WORK/member-adapter" "$adapter"
adapter_node="$(stat -f '%d:%i:%u:%g:%Lp' "$adapter")"
[[ "$(shasum -a 256 "$adapter" | awk '{print $1}')" == "$digest" ]] || exit 1
sudo install -o root -g wheel -m 0444 "$root/checkin.py" "$stage/checkin.py"
cd /
accounts=(_abm-ci-a _abm-ci-b)
home_ids=()
role_ids=()
for account in "${accounts[@]}"; do
    role_ids+=("$(id -u "$account"):$(id -g "$account")")
    home_ids+=("$(sudo stat -f '%d:%i:%u:%g:%Lp' "/var/agent-bot-harness-$account")")
done
jq '{adapters:[. as $p | .mappings|to_entries[] |
     {adapter_id:.key,account:.value,executable:$p.executable,sha256:$p.sha256,args:[]}]}' \
    "$root/fixture-policy.json" > "$signer/adapters.json"

# All protected installs/retirements use the live enrolled HQ channel. The ephemeral
# owner signs only the exact plan selected here, already authenticated by the HQ CLI.
handoff() {
    local action="$1" plan_arg="$2" first response planjson message transfer
    first="$("$MM" members plan "--harness-launch-$action" "$plan_arg")"
    first="${first%%$'\n'*}"
    tx_id="$(jq -er .plan_id <<<"$first")"
    tx_digest="$(jq -er .plan_digest <<<"$first")"
    response="$signer/$action.json"
    message="$signer/$action.transcript"
    hq_machine "harness-launch-$action" export "$tx_id" --socket "$channel" > "$response"
    jq -e --arg m "$machine_key" --arg h "$hq_key" --arg owner "$pin" --arg id "$tx_id" \
        --arg digest "$tx_digest" --arg action "harness-launch-$action" '
      .ok==true and (.body | .action==$action and .machine_key==$m and .hq_key==$h and
       .owner_key==$owner and .plan_id==$id and .plan_digest==$digest and .expires_at>now)' "$response" >/dev/null
    planjson="$signer/$action.canonical"
    jq -j '.body.plan_canonical' "$response" > "$planjson"
    [[ "$(shasum -a 256 "$planjson" | awk '{print $1}')" == "$tx_digest" ]] || exit 1
    "$signer/check-harness-plan" "$planjson" "$tx_id" "$tx_digest" "$action"
    jq -e --arg action "$action" --arg id "${install_id_for_rule:-}" --arg digest "${install_digest_for_rule:-}" \
      --slurpfile expected "$signer/adapters.json" '
      .members==["_abm-ci-a","_abm-ci-b"] and
      (.steps[0].content|fromjson | .action==$action and
        ([.adapters[]|del(.uid)] == $expected[0].adapters) and
        (if $action=="retire" then .installed_plan_id==$id and .installed_plan_digest==$digest else true end))' "$planjson" >/dev/null
    jq -j '.body|["agent-bot-machine-owner/v1",.action,.machine_key,.hq_key,.owner_key,.plan_id,.plan_digest,.nonce,(.expires_at|tostring),""]|join("\n")' "$response" > "$message"
    fixture_owner_proof "$message" > "$signer/$action.proof"
    transfer="$stage/transfer-$tx_id"
    sudo mkdir -m 0700 "$transfer"
    sudo chown "$role:$role" "$transfer"
    sudo install -o "$role" -g "$role" -m 0600 "$response" "$transfer/frame"
    sudo install -o "$role" -g "$role" -m 0600 "$signer/$action.proof" "$transfer/proof"
    hq_machine "harness-launch-$action" approve --challenge-file "$transfer/frame" \
       --proof-file "$transfer/proof" --socket "$channel" | jq -e --arg id "$tx_id" \
       --arg digest "$tx_digest" '.state=="approved" and .plan_id==$id and .plan_digest==$digest' >/dev/null
    if [[ "$action" == install ]]; then
        local refusal
        if refusal="$(sudo "$WORK/managed-machine" members apply "$tx_id" 2>&1)"; then
            fail 'ordinary Machine accepted an unqualified adapter'
        fi
        [[ "$refusal" == *'no verified Darwin adapter qualification'* ]] || fail 'ordinary Machine refused for another reason'
        sudo test ! -e "$RECEIPTS/$tx_id.json" || fail 'ordinary refusal spent the plan'
    fi
    local receipt="$RECEIPTS/$tx_id.json" before
    sudo "$MM" members apply "$tx_id" | jq -es --arg id "$tx_id" --arg digest "$tx_digest" \
      --arg receipt "$receipt" 'length==1 and (.[0] | .applied==true and .plan_id==$id and
      .plan_digest==$digest and .receipt==$receipt)' >/dev/null
    sudo jq -e --arg id "$tx_id" --arg digest "$tx_digest" --arg purpose "harness-launch-$action" \
      '.result=="applied" and .plan_id==$id and .plan_digest==$digest and .harness_approval.purpose==$purpose' "$receipt" >/dev/null
    before="$(sudo shasum -a 256 "$receipt")"
    sudo "$MM" members apply "$tx_id" | jq -es --arg id "$tx_id" --arg digest "$tx_digest" \
      --arg receipt "$receipt" --arg action "$action" 'length==1 and (.[0] | .plan_id==$id and
      .plan_digest==$digest and .receipt==$receipt and
      (if $action=="install" then .result=="already-applied" and (has("applied")|not)
       else .applied==true and (has("result")|not) end))' >/dev/null
    [[ "$(sudo shasum -a 256 "$receipt")" == "$before" ]] || fail 'reapply rewrote completed receipt'
}
handoff install "$signer/adapters.json"
install_id_for_rule="$tx_id"
install_digest_for_rule="$tx_digest"
"$MM" members plan --harness-launch-install "$signer/adapters.json" | jq -es --arg id "$tx_id" \
   '.[0].changes==0 and .[0].installed_plan_id==$id' >/dev/null
ok 'paired harness install and read-only reapply preserved the completed root receipt'
(cd / && sudo -n -H -u "$role" -- /usr/bin/env "GITHUB_ACTIONS=$GITHUB_ACTIONS" "RUNNER_ENVIRONMENT=$RUNNER_ENVIRONMENT" /usr/bin/python3 -I "$stage/checkin.py" "$tx_digest")
handoff retire "$install_id_for_rule"
# Check from the same privilege domain as removal. Only a missing leaf
# beneath an open, existing directory establishes absence.
sudo -n /usr/bin/python3 -I - <<'PYABSENT'
import os

leaves = {
    "/Library/Application Support/ai.true-line.agent-bot-hq": ("harness-launch", "harness-egress.sb", "harness-launch-policy.json"),
    "/private/etc/sudoers.d": ("agent-bot-hq-harness-launch",),
}
for parent, names in leaves.items():
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in names:
            try:
                os.lstat(name, dir_fd=fd)
            except FileNotFoundError:
                continue
            raise SystemExit("retired grant file remains: " + name)
    finally:
        os.close(fd)
PYABSENT
for i in 0 1; do
    account="${accounts[i]}"
    [[ "$(id -u "$account"):$(id -g "$account")" == "${role_ids[i]}" ]] || fail 'credential account changed'
    [[ "$(sudo stat -f '%d:%i:%u:%g:%Lp' "/var/agent-bot-harness-$account")" == "${home_ids[i]}" ]] || fail 'role or home changed'
    sudo rmdir "$runtime_dir/ipc/$account"
done
sudo rmdir "$runtime_dir/ipc"
[[ ! -L "$adapter" && "$(stat -f '%d:%i:%u:%g:%Lp' "$adapter")" == "$adapter_node" &&
   "$(shasum -a 256 "$adapter" | awk '{print $1}')" == "$digest" ]] || fail 'fixture executable changed'
sudo rm "$adapter"
sudo rmdir "$fixture_dir"
ok 'paired retirement and repeat preserved two homes and the positive audit receipt'
