# Sourced after the existing hosted flow has paired the real dedicated role.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "${role:-}" == _agent-bot-hq &&
   "$DAEMON_ACCOUNT" == "$(id -un)" && "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
sudo install -o root -g wheel -m 0644 "$ROOT/tests/fixtures/paired-darwin-hq-device.mjs" "$stage/device-check.mjs"
# The dedicated role has no ability to read or execute the administration helper.
! sudo -n -u "$role" test -r "$custody_dir/agent-bot-keyd" || fail 'role can read custody helper'
! sudo -n -u "$role" test -x "$custody_dir/agent-bot-keyd" || fail 'role can execute custody helper'
stop_fixture_machine
[[ "$MM" == "$custody_dir/managed-machine" ]] || fail 'qualification changed the Machine binary after initial pairing'
"$MM" daemon verify-identity | jq -e --arg pin "$machine_pin" '.state=="verified" and .fingerprint==$pin' >/dev/null
epoch="$(jq -er '.nonce' "$signer/pair.json")"
role_check() {
    (cd / && sudo -n -H -u "$role" -- /usr/bin/env GITHUB_ACTIONS=true "$stage/node" "$stage/device-check.mjs" "$1" "$channel" "$epoch")
}
role_check outage
# Explicit native initialization runs once as the prefix owner on a throwaway
# runner/default Keychain. Failure (including unavailable hardware) fails the job.
"$custody_dir/agent-bot-keyd" hq-device-init
start_fixture_machine --require-identity "$machine_pin"
paired_status
thumb="$(role_check identity)"
[[ "$thumb" =~ ^[A-Za-z0-9_-]{43}$ && "$(role_check prove)" == "$thumb" ]] || fail 'native enrollment assertion unavailable'
stop_fixture_machine
role_check outage
start_fixture_machine --require-identity "$machine_pin"
[[ "$(role_check identity)" == "$thumb" ]] || fail 'device identity changed after Machine restart'
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
ok 'native enrollment signature verified; Machine stop and trusted HQ revocation cut off the dedicated role'
