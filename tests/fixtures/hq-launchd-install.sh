# Sourced only by the disposable macOS installation and account CI jobs.
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || fail 'expected disposable runner'
role=_agent-bot-hq
label=ai.true-line.agent-bot-hq
plist="/Library/LaunchDaemons/$label.plist"
socket=/private/var/agent-bot-hq-control.sock
runtime_dir="/Library/Application Support/$label"
layout_v2=false
! exists "$role" && [[ ! -e "$plist" && ! -L "$plist" && ! -e "$socket" && ! -L "$socket" ]] || fail 'existing HQ installation'
! sudo launchctl print "system/$label" >/dev/null 2>&1 || fail 'existing HQ job'
real_hq=false
if [[ "${1:-}" == --real-hq ]]; then real_hq=true; fi
if "$real_hq"; then
    stage="$(sudo mktemp -d /Library/hq-install-ci.XXXXXXXX)"
else
    stage="$(sudo mktemp -d /private/var/hq-install-ci.XXXXXXXX)"
fi
signer="$WORK/first-hq-owner-signer"
cleanup_launch() {
    sudo launchctl bootout "system/$label" >/dev/null 2>&1 || true
    sudo rm -f "$plist" "$socket"
    if "$layout_v2" && [[ -d "$runtime_dir" && ! -L "$runtime_dir" ]]; then
        sudo rmdir "$runtime_dir" || return 1
    fi
    sudo rm -rf "$stage"
    rm -rf "$signer"
}
trap cleanup_launch EXIT
sudo chmod 0755 "$stage"
if [[ -n "${MM_HQ_DEVICE_ARCHIVE:-}" ]]; then
    source "$ROOT/tests/fixtures/stage-darwin-hq-device.sh"
fi
if [[ "${MM_HQ_UPGRADE_TEST:-}" == paired ]]; then
    [[ "$real_hq" == true && "${MM_KEYD_CUSTODY_TEST:-}" == 1 && -z "${MM_HQ_DEVICE_ARCHIVE:-}" ]] || exit 1
    provider_dir="$stage/upgrade-provider"
    sudo install -d -o root -g wheel -m 0755 "$provider_dir"
    # Add two fixture files to the disposable build. No tracked product source
    # is replaced. A single executable both creates and reads its self-only
    # Machine Keychain item from first pairing through the upgrade.
    module="$(cd "$ROOT" && go list -m)"
    jq -jRs --arg module "$module" 'split("MODULE_PATH") | if length == 2 then join($module) else error("expected one module placeholder") end' \
        "$ROOT/tests/fixtures/paired-darwin-hq-upgrade-main.go.txt" > "$WORK/hosted-upgrade-main.go"
    jq -n --arg root "$ROOT" --arg main "$WORK/hosted-upgrade-main.go" '{Replace:{
        ($root+"/cmd/managed-machine/hosted_upgrade_fixture_darwin.go"):$main,
        ($root+"/internal/daemon/hosted_upgrade_fixture_darwin.go"):($root+"/tests/fixtures/paired-darwin-hq-upgrade-daemon.go.txt")
    }}' > "$WORK/upgrade-overlay.json"
    (cd "$ROOT" && go build -overlay "$WORK/upgrade-overlay.json" -o "$WORK/native-upgrade-test" ./cmd/managed-machine)
    "$ROOT/scripts/build-darwin-keyd" "$WORK/native-upgrade-keyd"
    sudo install -o "$ME" -g "$(id -gn)" -m 0700 "$WORK/native-upgrade-keyd" "$provider_dir/agent-bot-keyd"
    sudo install -o "$ME" -g "$(id -gn)" -m 0700 "$WORK/native-upgrade-test" "$provider_dir/managed-machine"
    MM="$provider_dir/managed-machine"
fi
prepare_native_hq_fixture() {
    local fixture="$1"
    shift
    mkdir -p "$fixture/hq"/{hq,helpers,governance}
    touch "$fixture/hq/hq/main.mjs"
    printf '%s\n' 'exec(*ARGV.drop(1))' > "$fixture/hq/helpers/darwin-owner.rb"
    if "$layout_v2"; then
        printf '%s\n' '{"target_platform":"darwin","owner_control_capability":"darwin-owner-control/v2"}' > "$fixture/hq/governance/interim-release.json"
        set -- "$@" -DMM_FIXTURE_OWNER_V2
    else
        printf '%s\n' '{"target_platform":"darwin"}' > "$fixture/hq/governance/interim-release.json"
    fi
    chmod -R u=rwX,go=rX "$fixture/hq"
    python3 - "$fixture" <<'PYTAR'
import os, sys, tarfile
os.chdir(sys.argv[1])
with tarfile.open("approved.tar", "w", format=tarfile.USTAR_FORMAT) as archive:
    archive.add("hq")
PYTAR
    clang -Wall -Werror "$@" -o "$fixture/runtime" "$ROOT/tests/fixtures/hq-launchd-runtime.c"
}

install_hq_fixture() {
    local fixture="$1" runtime="$2" stage="$3" record="$4" checksums="${5:-}"
    sudo install -m 0644 -o root -g wheel "$fixture/approved.tar" "$stage/approved.tar"
    sudo install -m 0755 -o root -g wheel "$runtime" "$stage/node"
    if [[ -n "$checksums" ]]; then
        (cd "$stage" && shasum -a 256 --check "$checksums")
    fi
    sudo tar --no-same-owner -xf "$stage/approved.tar" -C "$stage"
    jq -n --arg root "$stage" --arg a "$(shasum -a 256 "$stage/approved.tar" | awk '{print $1}')" \
        --arg n "$(shasum -a 256 "$stage/node" | awk '{print $1}')" \
        '{archive:($root+"/approved.tar"),release_dir:($root+"/hq"),artifact_sha256:$a,node:($root+"/node"),node_sha256:$n}' > "$record"
}

fixture="$WORK/launch-fixture"
record="$WORK/hq-service.json"
if "$real_hq"; then
    mkdir "$fixture"
    bash "$ROOT/tests/fixtures/prepare-real-darwin-hq.sh" "$fixture" "${MM_HQ_PREDECESSOR:-original}"
    install_hq_fixture "$fixture" "$fixture/bin/node" "$stage" "$record" "$fixture/installed.sha256"
    case "$(jq -er '.owner_control_capability // "v1-unmarked"' "$stage/hq/governance/interim-release.json")" in
        v1-unmarked) ;;
        darwin-owner-control/v2)
            [[ ! -e "$runtime_dir" && ! -L "$runtime_dir" ]] || fail 'preexisting HQ runtime directory'
            socket="$runtime_dir/owner-control.sock"
            layout_v2=true ;;
        *) fail 'unknown pinned HQ transport layout' ;;
    esac
    if [[ "${MM_HQ_REQUIRE_SIP:-false}" == true ]]; then
        "$layout_v2" || fail 'SIP qualification requires the pinned v2 HQ archive'
    fi
else
    prepare_native_hq_fixture "$fixture"
    install_hq_fixture "$fixture" "$fixture/runtime" "$stage" "$record"
fi
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
# Sign only the purpose-specific transcript constructed by a test case.
fixture_owner_proof() {
    local message="$1" sig
    sig="$(openssl dgst -sha256 -sign "$signer/key.pem" "$message" | openssl base64 -A)"
    jq -n --arg public_key "$pin" --arg signature "$sig" '{public_key:$public_key,signature:$signature}'
}
first_hq_approve() {
    local id="$1" digest="$2" challenge="$signer/challenge.json" message="$signer/message"
    "$MM" daemon first-hq export "$id" > "$challenge"
    jq -e --arg id "$id" --arg digest "$digest" '
        .action == "first-hq-provision" and .plan_id == $id and .plan_digest == $digest and
        ((.plan_canonical | fromjson) | .hq_account == "_agent-bot-hq" and .members == [] and
        ([.steps[].kind] == ["hq-account", "service"]) and .steps[0].action == "create")
    ' "$challenge" >/dev/null
    [[ "$(jq -j '.plan_canonical' "$challenge" | shasum -a 256 | awk '{print $1}')" == "$digest" ]] || fail 'canonical bytes differ from saved plan'
    jq -j '["agent-bot-machine-owner/v1", .action, .machine_key, .plan_id, .plan_digest, .nonce, (.expires_at | tostring), ""] | join("\n")' "$challenge" > "$message"
    if "$layout_v2"; then
        jq -e --arg dir "$runtime_dir" --arg socket "$socket" '
            .plan_canonical|fromjson|.steps[1].content|fromjson|
            .runtime_directory == {path:$dir,action:"create",owner:"root",group:"wheel",mode:"0755"} and
            (.plist|contains("<string>"+$socket+"</string>"))
        ' "$challenge" >/dev/null || fail 'first-HQ review omits the root-managed runtime namespace'
    fi
    fixture_owner_proof "$message" > "$signer/proof.json"
    refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$id"
    "$MM" daemon first-hq approve "$id" --proof-file "$signer/proof.json" | jq -e '.state == "approved"' >/dev/null
    refused MM_DAEMON_CALLER_REFUSED "$MM" daemon first-hq approve "$id" --proof-file "$signer/proof.json"
    ! exists "$role" || fail 'proof import created an account'
}
check_real_hq_status() {
    jq -e --arg role "$role" --arg owner "$ME" --arg socket "$socket" --argjson uid "$(id -u)" '
        .profile == "managed-cooperative" and .hq.account == $role and
        (.hq.sockets.ownerControl | .peer_check == "getpeereid" and .account == $owner and .uid == $uid and .path == $socket)
    ' >/dev/null || fail 'real HQ did not confirm cooperative status for the approved owner'
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
        if "$real_hq"; then
            # Owner-pinned Machine has no signer for an already running, no-op
            # service plan. A repeat apply must leave the existing job running.
            refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$id"
            sudo test ! -e "$RECEIPTS/$id.json" || fail 'unapproved reapply produced a receipt'
        else
            # Existing steady-state idempotence fixture after first HQ is complete.
            approve "$id" "$digest"
        fi
    fi
    # The role and owner probes must work from a terminal inside a private
    # directory. The native runtime checks cwd when run through nested sudo.
    if [[ "$count" == 1 ]] || ! "$real_hq"; then
        (cd "$signer" && sudo "$MM" members apply "$id") || fail 'approved LaunchDaemon apply failed'
        sudo jq -e --arg id "$id" --arg digest "$digest" '.result == "applied" and .plan_id == $id and .plan_digest == $digest' "$RECEIPTS/$id.json" >/dev/null
    fi
    if [[ "$count" == 1 ]]; then
        uid="$(id -u "$role")"
        [[ "$uid" -ge 300 && "$uid" -le 399 && "$(id -g "$role")" == "$uid" ]] || exit 1
        [[ "$(attr "$role" NFSHomeDirectory)" == /var/agent-bot-hq ]] || exit 1
        [[ "$(sudo stat -f '%Su %Sg %Lp' /var/agent-bot-hq)" == "$role $role 700" ]] || exit 1
        refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$id"
        refused MM_DAEMON_CALLER_REFUSED "$MM" daemon first-hq export "$id"
    fi
    status="$(cd / && "$stage/node" "$stage/hq/hq/main.mjs" status --owner-control --json)"
    jq -e '.hq.sockets.ownerControl.peer_check=="getpeereid"' <<<"$status" >/dev/null
    if "$real_hq"; then
        check_real_hq_status <<<"$status"
        if "$layout_v2"; then
            [[ ! -L "$runtime_dir" && "$(stat -f '%Su:%Sg:%Lp' "$runtime_dir")" == 'root:wheel:755' &&
               -S "$socket" && ! -L "$socket" && "$(stat -f '%Su:%Lp' "$socket")" == 'root:666' ]] || fail 'incorrect v2 directory or socket'
            if denied="$(cd / && sudo -n -H -u nobody -- "$stage/node" "$stage/hq/hq/main.mjs" status --owner-control --json 2>&1)"; then
                fail 'another account received owner status'
            fi
            jq -e '.ok == false and (.transport_error == "connection closed" or .transport_error == "read ECONNRESET")' <<<"$denied" >/dev/null ||
                fail 'separate account did not reach the peer-checked listener'
        fi
    fi
    [[ "$(sudo stat -f '%Su %Sg %Lp' "$plist")" == 'root wheel 644' ]] || exit 1
    [[ "$(sudo stat -f '%Su %Lp' /var/agent-bot-hq/.agent-bot-hq)" == "$role 700" ]] || exit 1
    newpid="$(sudo launchctl print "system/$label" | awk '$1 == "pid" && $2 == "=" {print $3}')"
    [[ "$newpid" =~ ^[0-9]+$ ]] || exit 1
    if "$real_hq"; then [[ "$(ps -o uid= -p "$newpid" | tr -d ' ')" == "$(id -u "$role")" ]] || fail 'HQ PID has the wrong account'; fi
    if [[ "$count" == 2 ]]; then [[ "$pid" == "$newpid" ]] || fail 'reapply restarted HQ'; fi
    pid="$newpid"
done
if "$real_hq"; then
    ok 'signed first-HQ install served cooperative status; the refused repeat apply preserved its PID'
    # Run in a subshell to own the foreground Machine child independently of launchd cleanup.
    (source "$ROOT/tests/fixtures/paired-darwin-hq-recovery.sh")
else
    sudo sh -c 'printf x >> "$1"' sh "$stage/hq/hq/main.mjs"
    refused MM_MEMBERS_PATH_REFUSED "$MM" members plan --hq-service "$record"
    ok 'approved Darwin service active as its role, idempotent reapply, changed extraction refused'
fi
