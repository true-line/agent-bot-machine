# Sourced after the existing positive, owner-approved service repair.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_MEMBERS_REAL_ACCOUNTS:-}" == 1 && "$role" == _agent-bot-hq && "$layout_v2" == true &&
   -z "${MM_HQ_DEVICE_ARCHIVE:-}" && "$ME" == "$DAEMON_ACCOUNT" ]] || exit 1
case "$MM_HQ_UPGRADE_TEST" in legacy|paired) ;; *) exit 1 ;; esac

upgrade_public="$WORK/upgrade-public"
mkdir "$upgrade_public"
bash "$ROOT/tests/fixtures/prepare-real-darwin-hq.sh" "$upgrade_public" upgrade "$stage/node"
next_dir="$stage/upgrade-public"

# The old and new service records share precisely the original, verified Node.
install_upgrade_tree() {
    local tar_input="$1" target="$2" output="$3" sha="$4"
    [[ "$(shasum -a 256 "$tar_input" | awk '{print $1}')" == "$sha" ]] || exit 1
    sudo install -d -o root -g wheel -m 0755 "$target"
    sudo install -o root -g wheel -m 0644 "$tar_input" "$target/approved.tar"
    sudo tar --no-same-owner -xpf "$target/approved.tar" -C "$target"
    jq --arg tar "$target/approved.tar" --arg dir "$target/hq" --arg sum "$sha" \
       '.archive=$tar | .release_dir=$dir | .artifact_sha256=$sum' "$record" > "$output"
}
next_sum="$(awk '$2=="approved.tar" {print $1}' "$upgrade_public/installed.sha256")"
install_upgrade_tree "$upgrade_public/approved.tar" "$next_dir" "$WORK/upgrade-public.json" "$next_sum"
upgrade_command() {
    (cd / && sudo -n -H -u "$role" -- "$stage/node" "$next_dir/hq/hq/main.mjs" machine hq-service-upgrade "$@")
}
approve_upgrade() {
    local prior="$1" prior_digest="$2" next_record="$3" rows row transfer
    rows="$("$MM" members plan --hq-service "$next_record" --upgrade-from "$prior")"
    row="${rows%%$'\n'*}"
    upgrade_id="$(jq -er '.plan_id' <<<"$row")"
    upgrade_digest="$(jq -er '.plan_digest' <<<"$row")"
    upgrade_command export "$upgrade_id" --socket "$channel" > "$signer/upgrade.json"
    jq -e --arg id "$upgrade_id" --arg digest "$upgrade_digest" --arg prior "$prior" --arg prior_digest "$prior_digest" \
        --arg machine "$machine_key" --arg hq "$hq_key" --arg owner "$pin" --slurpfile next "$next_record" '
        .body | .action=="hq-service-upgrade" and .machine_key==$machine and .hq_key==$hq and .owner_key==$owner
        and .plan_id==$id and .plan_digest==$digest and (.plan_canonical|fromjson| .members==[]
        and [.steps[].action]==["none","upgrade"] and (.steps[1].content|fromjson|.previous_plan_id==$prior
        and .previous_plan_digest==$prior_digest and .next.service==$next[0]))' "$signer/upgrade.json" >/dev/null
    # Only in this disposable fixture, use its existing independently pinned
    # software owner key and the exact domain-separated upgrade transcript.
    jq -j '.body|["agent-bot-machine-owner/v1",.action,.machine_key,.hq_key,.owner_key,.plan_id,.plan_digest,.nonce,(.expires_at|tostring),""]|join("\n")' \
        "$signer/upgrade.json" > "$signer/upgrade-message"
    fixture_owner_proof "$signer/upgrade-message" > "$signer/upgrade-proof.json"
    transfer="$stage/transfer-$upgrade_id"
    sudo install -d -o "$role" -g "$role" -m 0700 "$transfer"
    sudo install -o "$role" -g "$role" -m 0600 "$signer/upgrade.json" "$signer/upgrade-proof.json" "$transfer"
    upgrade_command approve --challenge-file "$transfer/upgrade.json" --proof-file "$transfer/upgrade-proof.json" --socket "$channel" |
        jq -e --arg id "$upgrade_id" --arg digest "$upgrade_digest" '.state=="approved" and .plan_id==$id and .plan_digest==$digest' >/dev/null
}
job_pid() {
    sudo launchctl print "system/$label" | awk '$1=="pid" && $2=="=" {print $3}'
}
require_release() {
    local src="$1" expected="$2" job
    [[ "$(id -u "$role")" == "$role_uid" && "$(sudo stat -f '%d:%i:%u:%g:%Lp' "$role_home")" == "$home_id" ]] || exit 1
    job="$(job_pid)"
    [[ "$job" =~ ^[1-9][0-9]*$ && "$(ps -o uid= -p "$job" | tr -d ' ')" == "$role_uid" ]] || exit 1
    grep -Fq "<string>$src/hq/main.mjs</string>" "$plist"
    paired_status
    (cd / && "$stage/node" "$src/hq/main.mjs" status --owner-control --json) |
       jq -e --arg owner "$ME" --argjson uid "$(id -u)" --arg thumb "$expected" '
         .hq.sockets.ownerControl.account==$owner and .hq.sockets.ownerControl.uid==$uid
         and (.hq.signer|.backend=="machine" and .key_storage=="hardware" and .available==true and .thumbprint==$thumb)' >/dev/null
}
# Only the disposable runner's own successful repair receipt is involved.
# Its original inode is returned before the test proceeds to any real switch.
check_private_predecessor_receipt() {
    local previous="$RECEIPTS/$repair_id.json" inode hash before pid_before
    [[ "$(sudo stat -f '%u' "$previous")" == 0 ]] || exit 1
    sudo jq -e --arg id "$repair_id" --arg digest "$repair_digest" --arg owner "$ME" --arg role "$role" '
        .plan_id==$id and .plan_digest==$digest and .owner==$owner and .hq_account==$role and .dir=="none"
        and .members==[] and .result=="applied" and .changes==1 and (.finished_at|type=="string" and length>0)
        and (.failed_at // "")==""' "$previous" >/dev/null
    sudo chmod 0600 "$previous"
    [[ ! -r "$previous" ]] || fail 'ordinary planning can unexpectedly read the private root receipt'
    inode="$(sudo stat -f '%d:%i' "$previous")"
    hash="$(shasum -a 256 "$plist" | awk '{print $1}')"
    before="$(stat -f '%d:%i' "$plist")"
    pid_before="$(job_pid)"

    # Export and authorize the plan normally while only root can read its receipt.
    approve_upgrade "$repair_id" "$repair_digest" "$WORK/upgrade-public.json"
    (
        held="$RECEIPTS/.ci-withheld-$repair_id.json"
        sudo test ! -e "$held" && sudo test ! -L "$held" || fail 'unexpected receipt staging file'
        restore_receipt() {
            if sudo test -e "$held"; then
                [[ "$(sudo stat -f '%d:%i' "$held")" == "$inode" ]] && sudo test ! -e "$previous" &&
                    sudo test ! -L "$previous" && sudo mv "$held" "$previous"
            fi
        }
        trap restore_receipt EXIT
        sudo mv "$previous" "$held"
        if (cd "$signer" && sudo "$MM" members apply "$upgrade_id") >"$signer/missing-prior.log" 2>&1; then
            fail 'upgrade touched a service without its predecessor receipt'
        fi
        grep -Fq "$repair_id.json" "$signer/missing-prior.log" ||
            grep -Eiq '(prior|previous).*(receipt|apply record)' "$signer/missing-prior.log" ||
            fail 'upgrade failed for a reason other than the missing predecessor receipt'
    )
    [[ "$(sudo stat -f '%d:%i' "$previous")" == "$inode" && "$(job_pid)" == "$pid_before" &&
       "$(stat -f '%d:%i' "$plist")" == "$before" && "$(shasum -a 256 "$plist" | awk '{print $1}')" == "$hash" ]] || exit 1
    paired_status
    ok 'ordinary upgrade review accepted a private receipt; root refused its absence before changing the job'
}
# Keep private status documents, owner proofs and raw command lines off CI logs.
# Only emit fixed product classifications from the first diagnostic.
report_upgrade_failure() {
    # Only fixed enum values from this disposable job's root-owned journal.
    sudo jq -r '
      .phase as $phase | (["prepared","stopping-previous","switching","starting-next","stopping-next","restoring-previous","starting-previous"] |
      if index($phase) then $phase else "unknown" end) as $safe
      | "HQ journal phase: " + $safe + "; endpoint: " +
        (if .stopping == null then "not recorded" elif .stopping.socket.inode == 0 then "observed absent" else "recorded" end)
    ' "$RECEIPTS/.hq-service-upgrade.json" >&2 2>/dev/null || :
    jq -Rsr -f "$ROOT/tests/fixtures/darwin-hq-apply-diagnostic.jq" "$1" >&2
}
upgrade_case() (
    local baseline prior_sha prior_inode active before bad_tree bad_archive bad_sum
    local phase="read predecessor service"
    set -E
    trap 'printf "FAIL: hosted service upgrade phase [%s], fixture line %d, exit %d\n" "$phase" "$LINENO" "$?" >&2' ERR
    prior_inode="$(stat -f '%d:%i' "$plist")"
    prior_sha="$(shasum -a 256 "$plist" | awk '{print $1}')"
    before="$(job_pid)"
    if [[ "$MM_HQ_UPGRADE_TEST" == legacy ]]; then
        if "$MM" members plan --hq-service "$WORK/upgrade-public.json" --upgrade-from "$repair_id" > "$signer/legacy-upgrade.log" 2>&1; then
            fail 'legacy software service unexpectedly upgraded'
        fi
        grep -Fq 'requires a separate custody migration' "$signer/legacy-upgrade.log"
        [[ "$(job_pid)" == "$before" && "$(stat -f '%d:%i' "$plist")" == "$prior_inode" ]] || exit 1
        [[ "$(shasum -a 256 "$plist" | awk '{print $1}')" == "$prior_sha" ]] || exit 1
        paired_status
        ok 'service-only upgrade refused the existing software signer before stopping the system job'
        return
    fi
    phase="check private predecessor receipt"
    check_private_predecessor_receipt
    phase="verify predecessor hardware signer and running release"
    baseline="$(cd / && "$stage/node" "$stage/hq/hq/main.mjs" status --owner-control --json | jq -er '.hq.signer|select(.available and .backend=="machine" and .key_storage=="hardware")|.thumbprint')"
    require_release "$stage/hq" "$baseline"
    ok 'predecessor status confirmed the original paired hardware signer'
    phase="prepare fault candidate"
    # Exercise the real release and authenticated socket. Fail the negative
    # candidate only after its owner status request actually succeeded.
    bad_tree="$WORK/upgrade-fault"
    mkdir "$bad_tree"
    tar -xpf "$upgrade_public/approved.tar" -C "$bad_tree"
    "$stage/node" --input-type=module - "$bad_tree/hq/hq/interim-core.mjs" <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
const p=process.argv[2], code=readFileSync(p,'utf8');
const marker = "    if (args.json || args.cmd === 'souls') console.log(JSON.stringify(res.result, null, 2));";
if (code.split(marker).length !== 2) throw Error('pinned HQ status success branch changed');
writeFileSync(p, code.replace(marker, `    if (args.cmd === 'status' && args.ownerControl && args.json) {
      process.exitCode = 42;
      return;
    }
${marker}`));
JS
    bad_archive="$WORK/upgrade-fault.tar"
    (cd "$bad_tree" && gtar --format=ustar -cf "$bad_archive" hq)
    bad_sum="$(shasum -a 256 "$bad_archive" | awk '{print $1}')"
    install_upgrade_tree "$bad_archive" "$stage/upgrade-fault" "$WORK/upgrade-fault.json" "$bad_sum"
    phase="plan and approve fault candidate"
    approve_upgrade "$repair_id" "$repair_digest" "$WORK/upgrade-fault.json"
    ok 'fault candidate received its signed owner approval'
    phase="apply fault candidate and check rollback"
    if (cd "$signer" && sudo "$MM" members apply "$upgrade_id") > "$signer/failed-upgrade.log" 2>&1; then
        fail 'failed status candidate unexpectedly passed'
    fi
    if ! grep -Fq MM_MEMBERS_APPLY_FAILED "$signer/failed-upgrade.log" ||
       ! grep -Fq 'query launched HQ as approved owner: sudo exit status 42' "$signer/failed-upgrade.log"; then
        report_upgrade_failure "$signer/failed-upgrade.log"
        fail 'approved upgrade failed before the injected owner status result'
    fi
    if ! grep -Fq 'previous HQ release, Machine pairing and original hardware signer verified after rollback' "$signer/failed-upgrade.log"; then
        report_upgrade_failure "$signer/failed-upgrade.log"
        fail 'Machine reached the injected owner status failure but did not confirm rollback'
    fi
    phase="verify failed receipt and original release"
    sudo jq -e --arg id "$upgrade_id" --arg digest "$upgrade_digest" '.result=="failed" and .plan_id==$id and .plan_digest==$digest' "$RECEIPTS/$upgrade_id.json" >/dev/null
    [[ "$(stat -f '%d:%i' "$plist")" == "$prior_inode" && "$(shasum -a 256 "$plist" | awk '{print $1}')" == "$prior_sha" ]] || exit 1
    require_release "$stage/hq" "$baseline"
    ok 'fault candidate rolled back to the original plist and signer'
    phase="approve and apply public candidate"
    approve_upgrade "$repair_id" "$repair_digest" "$WORK/upgrade-public.json"
    (cd "$signer" && sudo "$MM" members apply "$upgrade_id")
    sudo jq -e --arg id "$upgrade_id" --arg digest "$upgrade_digest" '.result=="applied" and .plan_id==$id and .plan_digest==$digest' "$RECEIPTS/$upgrade_id.json" >/dev/null
    require_release "$next_dir/hq" "$baseline"
    phase="repeat completed upgrade"
    active="$(job_pid)"
    (cd "$signer" && sudo "$MM" members apply "$upgrade_id") | jq -e '.applied==true' >/dev/null
    [[ "$(job_pid)" == "$active" ]] || exit 1
    ok 'real system service rollback restored its plist and hardware signer; public candidate upgraded once and preserved its paired role'
    phase="discover the installed receipt and preview uninstall"
    sudo "$MM" members uninstall-hq --list | jq -e --arg id "$upgrade_id" --arg old "$repair_id"         '(.matching_plan_ids|index($id))!=null and (.matching_plan_ids|index($old))==null' >/dev/null
    sudo "$MM" members uninstall-hq "$upgrade_id" --dry-run | jq -e '.result=="would-uninstall"' >/dev/null
    [[ "$(job_pid)" == "$active" ]] || fail 'uninstall preview disturbed the running service'
    phase="remove the reviewed system service and verify retained role"
    sudo "$MM" members uninstall-hq "$upgrade_id" | jq -e '.result=="uninstalled"' >/dev/null
    if sudo launchctl print "system/$label" >/dev/null 2>&1; then
        fail 'uninstall left the HQ job registered'
    else
        [[ "$?" == 113 ]] || fail 'launchd did not confirm the HQ job was absent'
    fi
    [[ ! -e "$plist" && ! -L "$plist" && ! -e "$socket" && ! -L "$socket" ]] || fail 'uninstall left the HQ plist or socket'
    [[ -d "$runtime_dir" && -d "$next_dir/hq" && -x "$stage/node" &&
       "$(sudo stat -f '%d:%i:%u:%g:%Lp' "$role_home")" == "$home_id" ]] || fail 'uninstall changed retained service data'
    paired_status
    [[ "$(hq_machine identity | jq -er '.public_key')" == "$hq_key" ]] || fail 'uninstall changed the paired HQ identity'
    sudo "$MM" members uninstall-hq "$upgrade_id" | jq -e '.result=="already-uninstalled"' >/dev/null
    ok 'receipt-bound HQ uninstall removed the running job, plist and endpoint and retained paired identity and release files'

)
upgrade_case
