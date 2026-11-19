# Sourced only after the hosted first install and refused reapply pass.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_MEMBERS_REAL_ACCOUNTS:-}" == 1 && "${real_hq:-}" == true &&
   "$(uname -m)" == arm64 && "$(sw_vers -productVersion)" == 27.* ]] || exit 1
umask 077
subjects="$signer/review-subjects"
mkdir "$subjects"
checkout_review_source() {
    local name="$1" repo="$2" sha="$3"
    git init -q "$subjects/$name"
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 git -C "$subjects/$name" \
        -c credential.helper= fetch -q --depth=1 --no-tags "https://github.com/true-line/$repo.git" "$sha"
    git -C "$subjects/$name" checkout -q --detach FETCH_HEAD
    [[ "$(git -C "$subjects/$name" rev-parse HEAD)" == "$sha" ]]
}
checkout_review_source conformance soul-conformance e41baba741bab974fee19acb09b5edb446a3d1f0
suite="$subjects/conformance/suites/paired-hq-recovery"
identity_sha="$(jq -er '.identity | select(test("^[0-9a-f]{40}$"))' "$subjects/conformance/governance/paired-hq-recovery.json")"
checkout_review_source identity agent-bot-identity "$identity_sha"
presence="$subjects/identity/owner-presence-macos"
xcrun --sdk macosx swiftc -swift-version 5 -parse-as-library \
    "$presence/PairingChallenge.swift" "$presence/FirstHQChallenge.swift" "$suite/owner.swift" -o "$signer/review-owner"
# Supply the same one-run P-256 key used for the original owner pin in the
# raw encoding that the public conformance fixture accepts.
"$stage/node" --input-type=module - "$signer/key.pem" "$signer/owner.raw" <<'JS'
import { createPrivateKey } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
const [pem, raw] = process.argv.slice(2);
const key = createPrivateKey(readFileSync(pem)).export({format:'jwk'});
if (key.crv !== 'P-256') throw Error('expected the fixture P-256 key');
writeFileSync(raw, Buffer.from(key.d, 'base64url'), {mode:0o600, flag:'wx'});
JS

hq_machine() {
    (cd / && sudo -n -H -u "$role" -- "$stage/node" "$stage/hq/hq/main.mjs" machine "$@")
}
machine_key="$(jq -er '.machine_key' "$signer/challenge.json")"
machine_pin="$(printf '%s' "$machine_key" | xxd -r -p | shasum -a 256 | awk '{print $1}')"
channel="$(brew --prefix)/var/agent-machine/daemon.sock"
machine_pid=
machine_socket_id=
stop_fixture_machine() {
    [[ -n "$machine_pid" ]] || return 0
    kill "$machine_pid" 2>/dev/null || true
    wait "$machine_pid" 2>/dev/null || true
    machine_pid=
    if [[ -n "$machine_socket_id" && ! -L "$channel" && -S "$channel" && "$(stat -f '%d:%i' "$channel")" == "$machine_socket_id" ]]; then
        rm "$channel"
    fi
    machine_socket_id=
}
trap stop_fixture_machine EXIT
start_fixture_machine() {
    [[ ! -e "$channel" && ! -L "$channel" ]] || fail 'Machine channel already exists'
    "$MM" daemon run "$@" > "$signer/machine.log" 2>&1 &
    machine_pid=$!
    for ((i=0; i<100; i++)); do
        kill -0 "$machine_pid" || fail 'foreground Machine exited before opening the channel'
        [[ ! -S "$channel" ]] || break
        sleep 0.1
    done
    [[ ! -L "$channel" && -S "$channel" ]] || fail 'Machine channel did not open'
    machine_socket_id="$(stat -f '%d:%i' "$channel")"
}

# Terminal pairing established private custody. The first ordinary service
# startup publishes its public key before the role is enrolled.
start_fixture_machine
published="${channel%/*}/daemon.pub"
[[ ! -L "$published" && -f "$published" && "$(stat -f '%z' "$published")" == 32 ]] || fail 'Machine did not publish its public key'
[[ "$(od -An -tx1 -v "$published" | tr -d '[:space:]')" == "$machine_key" ]] || fail 'published key differs from first-HQ approval'
hq_identity="$(hq_machine identity)"
hq_key="$(jq -er '.public_key' <<<"$hq_identity")"
hq_pin="$(jq -er '.fingerprint' <<<"$hq_identity")"
enroll=(daemon pair --client agent-daemon --enroll "$hq_key" --fingerprint "$hq_pin")
"$MM" "${enroll[@]}" --owner-challenge > "$signer/pair.json"
jq -e --arg m "$machine_key" --arg h "$hq_key" '.action=="machine-pair" and .machine_key==$m and .hq_key==$h' "$signer/pair.json" >/dev/null
jq -j '["agent-bot-machine-owner/v1",.action,.machine_key,.hq_key,.nonce,(.expires_at|tostring),""]|join("\n")' \
    "$signer/pair.json" > "$signer/pair.transcript"
"$MM" "${enroll[@]}" --owner-proof "$(fixture_owner_proof "$signer/pair.transcript")" |
    jq -e --argjson uid "$(id -u "$role")" '.state=="paired" and .uid==$uid' >/dev/null
stop_fixture_machine
"$MM" daemon verify-identity | jq -e --arg pin "$machine_pin" '.state=="verified" and .fingerprint==$pin' >/dev/null

paired_status() {
    hq_machine status --socket "$channel" "$@" | jq -e --arg fp "$machine_pin" \
        '.client=="agent-daemon" and .channel=="signed" and .state=="reported" and .daemon_fingerprint==$fp' >/dev/null
}
start_fixture_machine --require-identity "$machine_pin"
paired_status --daemon-key "$machine_key"

# Remove only the service installed earlier. Keep its role, state and pairs.
endpoint_id="$(stat -f '%d:%i' "$socket")"
jq -j '.plan_canonical|fromjson|.steps[1].content|fromjson|.plist' "$signer/challenge.json" > "$signer/installed.plist"
cmp -s "$signer/installed.plist" "$plist" || fail 'installed plist changed'
sudo launchctl bootout "system/$label"
sudo rm "$plist"
if [[ -e "$socket" || -L "$socket" ]]; then
    [[ ! -L "$socket" && -S "$socket" && "$(stat -f '%d:%i' "$socket")" == "$endpoint_id" ]] || fail 'owner endpoint changed'
    sudo rm "$socket"
fi
paired_status
plan_output="$("$MM" members plan --hq-service "$record")"
row="${plan_output%%$'\n'*}"
repair_id="$(jq -er '.plan_id' <<<"$row")"
repair_digest="$(jq -er '.plan_digest' <<<"$row")"
hq_machine hq-service-recovery export "$repair_id" --socket "$channel" > "$signer/repair.json"
jq -e --arg id "$repair_id" --arg digest "$repair_digest" --arg machine "$machine_key" --arg hq "$hq_key" --arg owner "$pin" '
    .body | .action=="hq-service-recovery" and .plan_id==$id and .plan_digest==$digest and
    .machine_key==$machine and .hq_key==$hq and .owner_key==$owner and
    (.plan_canonical|fromjson|.members==[] and [.steps[].kind]==["hq-account","service"] and
      [.steps[].action]==["none","create"])
' "$signer/repair.json" >/dev/null
RECOVERY_SUBJECTS="$subjects" RECOVERY_OWNER="$signer/review-owner" \
    python3 "$suite/terminal.py" "$stage/node" "$suite/review.mjs" "$signer/repair.json" \
        "$machine_pin" "$signer/owner.raw" approve > "$signer/repair-proof.json"
transfer="$stage/role-transfer"
sudo install -d -o "$role" -g "$role" -m 0700 "$transfer"
for file in repair.json repair-proof.json; do sudo install -o "$role" -g "$role" -m 0600 "$signer/$file" "$transfer/$file"; done
hq_machine hq-service-recovery approve --challenge-file "$transfer/repair.json" --proof-file "$transfer/repair-proof.json" --socket "$channel" |
    jq -e --arg id "$repair_id" --arg digest "$repair_digest" '.state=="approved" and .plan_id==$id and .plan_digest==$digest' >/dev/null
(cd "$signer" && sudo "$MM" members apply "$repair_id")
sudo jq -e --arg id "$repair_id" --arg digest "$repair_digest" --arg role "$role" \
    '.result=="applied" and .changes==1 and .plan_id==$id and .plan_digest==$digest and .hq_account==$role' \
    "$RECEIPTS/$repair_id.json" >/dev/null
paired_status
[[ "$(hq_machine identity | jq -er '.public_key')" == "$hq_key" ]] || fail 'HQ identity changed during service repair'
(cd / && "$stage/node" "$stage/hq/hq/main.mjs" status --owner-control --json) | check_real_hq_status
repair_pid="$(sudo launchctl print "system/$label" | awk '$1=="pid" && $2=="=" {print $3}')"
[[ "$repair_pid" =~ ^[1-9][0-9]*$ && "$(ps -o uid= -p "$repair_pid" | tr -d ' ')" == "$(id -u "$role")" ]] || fail 'repaired job is not running as HQ'
ok 'the existing paired role recovered only its service through a signed owner review and root apply'
