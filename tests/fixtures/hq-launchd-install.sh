# Sourced only by the disposable macOS account CI after its plan and apply tests.
[[ "${RUNNER_ENVIRONMENT:-}" == github-hosted ]] || fail 'expected disposable runner'
role=_agent-bot-hq
label=ai.true-line.agent-bot-hq
plist="/Library/LaunchDaemons/$label.plist"
socket=/private/var/agent-bot-hq-control.sock
! exists "$role" && [[ ! -e "$plist" && ! -L "$plist" && ! -e "$socket" && ! -L "$socket" ]] || fail 'existing HQ installation'
! sudo launchctl print "system/$label" >/dev/null 2>&1 || fail 'existing HQ job'
stage="$(sudo mktemp -d /private/var/hq-install-ci.XXXXXXXX)"
cleanup_launch() {
    sudo launchctl bootout "system/$label" >/dev/null 2>&1 || true
    sudo rm -f "$plist" "$socket"
    sudo rm -rf "$stage"
}
trap cleanup_launch EXIT
sudo chmod 0755 "$stage"
fixture="$WORK/launch-fixture"
mkdir -p "$fixture/hq"/{hq,helpers,governance}
touch "$fixture/hq/hq/main.mjs"
printf '%s\n' 'exec(*ARGV.drop(1))' > "$fixture/hq/helpers/darwin-owner.rb"
printf '%s\n' '{"target_platform":"darwin"}' > "$fixture/hq/governance/interim-release.json"
chmod -R u=rwX,go=rX "$fixture/hq"
COPYFILE_DISABLE=1 tar --format ustar -cf "$fixture/approved.tar" -C "$fixture" hq
sudo install -m 0644 -o root -g wheel "$fixture/approved.tar" "$stage/approved.tar"
sudo tar --no-same-owner -xf "$stage/approved.tar" -C "$stage"
clang -Wall -Werror -o "$fixture/runtime" "$ROOT/tests/fixtures/hq-launchd-runtime.c"
sudo install -m 0755 -o root -g wheel "$fixture/runtime" "$stage/node"
record="$WORK/hq-service.json"
jq -n --arg root "$stage" --arg a "$(shasum -a 256 "$stage/approved.tar" | awk '{print $1}')" \
    --arg n "$(shasum -a 256 "$stage/node" | awk '{print $1}')" \
    '{archive:($root+"/approved.tar"),release_dir:($root+"/hq"),artifact_sha256:$a,node:($root+"/node"),node_sha256:$n}' > "$record"
for count in 1 2; do
    out="$("$MM" members plan --hq-service "$record")"
    row="${out%%$'\n'*}"
    id="$(jq -r .plan_id <<<"$row")"
    if [[ "$count" == 2 ]]; then [[ "$(jq -r .changes <<<"$row")" == 0 ]] || fail 'unexpected reapply change'; fi
    approve "$id" "$(jq -r .plan_digest <<<"$row")"
    sudo "$MM" members apply "$id" || fail 'approved LaunchDaemon apply failed'
    [[ "$(sudo jq -r .result "$RECEIPTS/$id.json")" == applied ]]
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
