# Sourced only by the disposable macOS account CI after its plan and apply tests.
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || fail 'expected disposable runner'
role=_agent-bot-hq
label=ai.true-line.agent-bot-hq
plist="/Library/LaunchDaemons/$label.plist"
socket=/private/var/agent-bot-hq-control.sock
! exists "$role" && [[ ! -e "$plist" && ! -L "$plist" && ! -e "$socket" && ! -L "$socket" ]] || fail 'existing HQ installation'
! sudo launchctl print "system/$label" >/dev/null 2>&1 || fail 'existing HQ job'
stage="$(sudo mktemp -d /private/var/hq-install-ci.XXXXXXXX)"
signer="$WORK/first-hq-owner-signer"
cleanup_launch() {
    sudo launchctl bootout "system/$label" >/dev/null 2>&1 || true
    sudo rm -f "$plist" "$socket"
    sudo rm -rf "$stage"
    rm -rf "$signer"
}
trap cleanup_launch EXIT
sudo chmod 0755 "$stage"
fixture="$WORK/launch-fixture"
mkdir -p "$fixture/hq"/{hq,helpers,governance}
touch "$fixture/hq/hq/main.mjs"
printf '%s\n' 'exec(*ARGV.drop(1))' > "$fixture/hq/helpers/darwin-owner.rb"
printf '%s\n' '{"target_platform":"darwin"}' > "$fixture/hq/governance/interim-release.json"
chmod -R u=rwX,go=rX "$fixture/hq"
python3 - "$fixture" <<'PYTAR'
import os, sys, tarfile
os.chdir(sys.argv[1])
with tarfile.open("approved.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
    archive.add("hq")
PYTAR
sudo install -m 0644 -o root -g wheel "$fixture/approved.tar" "$stage/approved.tar"
sudo tar --no-same-owner -xf "$stage/approved.tar" -C "$stage"
clang -Wall -Werror -o "$fixture/runtime" "$ROOT/tests/fixtures/hq-launchd-runtime.c"
sudo install -m 0755 -o root -g wheel "$fixture/runtime" "$stage/node"
record="$WORK/hq-service.json"
jq -n --arg root "$stage" --arg a "$(shasum -a 256 "$stage/approved.tar" | awk '{print $1}')" \
    --arg n "$(shasum -a 256 "$stage/node" | awk '{print $1}')" \
    '{archive:($root+"/approved.tar"),release_dir:($root+"/hq"),artifact_sha256:$a,node:($root+"/node"),node_sha256:$n}' > "$record"
# Exercise the actual first-HQ boundary on this throwaway runner. An
# ephemeral software owner key qualifies transport and signature verification.
# Secure Enclave presence remains a separate physical-Mac acceptance test.
[[ "$DAEMON_ACCOUNT" == "$ME" ]] || fail 'first-HQ test must run as the Homebrew prefix owner'
[[ ! -e "$DAEMON_HOME/.config/agent-machine/owner-pair.json" ]] || fail 'owner already pinned'
mkdir -m 0700 "$signer"
openssl ecparam -name prime256v1 -genkey -noout -out "$signer/key.pem"
pin="$(openssl ec -in "$signer/key.pem" -pubout -outform DER 2>/dev/null | tail -c 65 | openssl base64 -A)"
"$MM" daemon pair >/dev/null
"$MM" daemon pair --pin-owner "$pin" >/dev/null
first_hq_approve() {
    local id="$1" digest="$2" challenge="$signer/challenge.json" message="$signer/message" sig
    "$MM" daemon first-hq export "$id" > "$challenge"
    jq -e --arg id "$id" --arg digest "$digest" '
        .action == "first-hq-provision" and .plan_id == $id and .plan_digest == $digest and
        ((.plan_canonical | fromjson) | .hq_account == "_agent-bot-hq" and .members == [] and
        ([.steps[].kind] == ["hq-account", "service"]) and .steps[0].action == "create")
    ' "$challenge" >/dev/null
    [[ "$(jq -j '.plan_canonical' "$challenge" | shasum -a 256 | awk '{print $1}')" == "$digest" ]] || fail 'canonical bytes differ from saved plan'
    jq -j '["agent-bot-machine-owner/v1", .action, .machine_key, .plan_id, .plan_digest, .nonce, (.expires_at | tostring), ""] | join("\n")' "$challenge" > "$message"
    sig="$(openssl dgst -sha256 -sign "$signer/key.pem" "$message" | openssl base64 -A)"
    jq -n --arg public_key "$pin" --arg signature "$sig" '{public_key:$public_key,signature:$signature}' > "$signer/proof.json"
    refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$id"
    "$MM" daemon first-hq approve "$id" --proof-file "$signer/proof.json" | jq -e '.state == "approved"' >/dev/null
    refused MM_DAEMON_CALLER_REFUSED "$MM" daemon first-hq approve "$id" --proof-file "$signer/proof.json"
    ! exists "$role" || fail 'proof import created an account'
}
for count in 1 2; do
    out="$("$MM" members plan --hq-service "$record")"
    row="${out%%$'\n'*}"
    id="$(jq -r .plan_id <<<"$row")"
    digest="$(jq -r .plan_digest <<<"$row")"
    if [[ "$count" == 1 ]]; then
        first_hq_approve "$id" "$digest"
    else
        [[ "$(jq -r .changes <<<"$row")" == 0 ]] || fail 'unexpected reapply change'
        refused MM_DAEMON_CALLER_REFUSED "$MM" daemon first-hq export "$id"
        # Existing steady-state idempotence fixture after first HQ is complete.
        approve "$id" "$digest"
    fi
    sudo "$MM" members apply "$id" || fail 'approved LaunchDaemon apply failed'
    sudo jq -e --arg id "$id" --arg digest "$digest" '.result == "applied" and .plan_id == $id and .plan_digest == $digest' "$RECEIPTS/$id.json" >/dev/null
    if [[ "$count" == 1 ]]; then
        uid="$(id -u "$role")"
        [[ "$uid" -ge 300 && "$uid" -le 399 && "$(id -g "$role")" == "$uid" ]]
        [[ "$(attr "$role" NFSHomeDirectory)" == /var/agent-bot-hq ]]
        [[ "$(sudo stat -f '%Su %Sg %Lp' /var/agent-bot-hq)" == "$role $role 700" ]]
        refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$id"
        refused MM_DAEMON_CALLER_REFUSED "$MM" daemon first-hq export "$id"
    fi
    "$stage/node" "$stage/hq/hq/main.mjs" status --owner-control --json | jq -e '.hq.sockets.ownerControl.peer_check=="getpeereid"' >/dev/null
    [[ "$(sudo stat -f '%Su %Sg %Lp' "$plist")" == 'root wheel 644' ]]
    [[ "$(sudo stat -f '%Su %Lp' /var/agent-bot-hq/.agent-bot-hq)" == "$role 700" ]]
    newpid="$(sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" {print $3}')"
    [[ "$newpid" =~ ^[0-9]+$ ]]
    if [[ "$count" == 2 ]]; then [[ "$pid" == "$newpid" ]] || fail 'reapply restarted HQ'; fi
    pid="$newpid"
done
sudo sh -c 'printf x >> "$1"' sh "$stage/hq/hq/main.mjs"
refused MM_MEMBERS_PATH_REFUSED "$MM" members plan --hq-service "$record"
ok 'approved Darwin service active as its role, idempotent reapply, changed extraction refused'
