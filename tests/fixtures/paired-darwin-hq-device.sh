# Sourced after the existing hosted flow has paired the real dedicated role.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "${role:-}" == _agent-bot-hq &&
   "$DAEMON_ACCOUNT" == "$(id -un)" && "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
sudo install -o root -g wheel -m 0644 "$ROOT/tests/fixtures/paired-darwin-hq-device.mjs" "$stage/device-check.mjs"
sudo install -o root -g wheel -m 0644 "$ROOT/tests/fixtures/packaged-darwin-hq-device.mjs" "$stage/packaged-device.mjs"
packaged_reply() {
    local answer
    IFS= read -r -t 30 -u 6 answer && [[ "$answer" == "$1" ]] || fail "packaged HQ did not complete $1"
}
packaged_step() {
    printf '%s\n' "$1" >&5
    packaged_reply "$1"
}
packaged_cleanup() {
    exec 5>&- 6<&-
    stop_fixture_machine
    if [[ -n "${packaged_pid:-}" ]]; then wait "$packaged_pid" || true; fi
}
# The dedicated role has no ability to read or execute the administration helper.
! sudo -n -u "$role" test -r "$custody_dir/agent-bot-keyd" || fail 'role can read custody helper'
! sudo -n -u "$role" test -x "$custody_dir/agent-bot-keyd" || fail 'role can execute custody helper'
stop_fixture_machine
[[ "$MM" == "$custody_dir/managed-machine" ]] || fail 'qualification changed the Machine binary after initial pairing'
"$MM" daemon verify-identity | jq -e --arg pin "$machine_pin" '.state=="verified" and .fingerprint==$pin' >/dev/null
epoch="$(jq -er '.nonce' "$signer/pair.json")"
role_check() {
    (cd / && sudo -n -H -u "$role" -- /usr/bin/env GITHUB_ACTIONS=true "$stage/node" "$stage/device-check.mjs" "$1" "$channel" "$epoch" "${2:-}")
}
role_check outage
# Explicit native initialization runs once as the prefix owner on a throwaway
# runner/default Keychain. Failure (including unavailable hardware) fails the job.
"$custody_dir/agent-bot-keyd" hq-device-init
start_fixture_machine --require-identity "$machine_pin"
paired_status
thumb="$(role_check identity)"
[[ "$thumb" =~ ^[A-Za-z0-9_-]{43}$ ]] || fail 'native device identity unavailable'
proof_id_before="$(role_check prove "$thumb")" || fail 'native enrollment proof unavailable before restart'
# Keep one actual packaged HQ process in its own private state through the
# Machine transitions. The native verifier's thumbprint is the independent pin.
mkfifo -m 0600 "$signer/packaged-commands" "$signer/packaged-results"
(cd / && exec sudo -n -H -u "$role" -- /usr/bin/env -i PATH=/usr/bin:/bin HOME="$role_home" \
    GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted "$stage/node" "$stage/packaged-device.mjs" "$thumb") \
    <"$signer/packaged-commands" >"$signer/packaged-results" &
packaged_pid=$!
exec 5>"$signer/packaged-commands" 6<"$signer/packaged-results"
trap packaged_cleanup EXIT
packaged_reply ready
packaged_step prove
stop_fixture_machine
role_check outage
packaged_step outage
start_fixture_machine --require-identity "$machine_pin"
[[ "$(role_check identity)" == "$thumb" ]] || fail 'device identity changed after Machine restart'
proof_id_after="$(role_check prove "$thumb")" || fail 'native enrollment proof unavailable after restart'
[[ "$proof_id_before" =~ ^[0-9a-f]{64}$ && "$proof_id_after" =~ ^[0-9a-f]{64}$ && "$proof_id_before" != "$proof_id_after" ]] ||
    fail 'native enrollment proofs must have distinct verified IDs across Machine restart'
packaged_step recovered
# Establish a real connection before human administrator revocation. The role
# sends its normal signed enrollment request only after the command returns.
gate="$signer/device-gate"
mkfifo -m 0600 "$gate"
exec 3<>"$gate"
role_check deferred <&3 >"$signer/device-deferred" &
waiting=$!
for ((i=0;i<120;i++)); do
    grep -qx connected "$signer/device-deferred" && break
    kill -0 "$waiting" || fail 'waiting role closed early'
    sleep 0.02
done
grep -qx connected "$signer/device-deferred" || fail 'role did not establish its pending connection'
"$MM" daemon revoke-hq >/dev/null
printf 'send\n' >&3
wait "$waiting" || fail 'previously open request did not receive an authenticated refusal'
exec 3>&-
role_check refused
packaged_step revoked
printf 'stop\n' >&5
exec 5>&- 6<&-
wait "$packaged_pid" || fail 'packaged dedicated HQ did not exit cleanly'
packaged_pid=
trap stop_fixture_machine EXIT
ok 'packaged dedicated HQ confirmed the same hardware signer across restart and refused signing after revocation and HQ restart'
ok 'fresh native enrollment signatures verified across restart; outage and revocation cut off the dedicated role'
