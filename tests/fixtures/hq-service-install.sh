# Sourced by the approved-apply test on a disposable GitHub-hosted VM only.
# Reuse its built Machine binary, runner identity and synthetic UI approval.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${MM_MEMBERS_REAL_ACCOUNTS:-}" == 1 ]]
HQ_SOURCE=63a92211ead8a20015fe9070a4a695752b62c180
source_dir="$WORK/hq-source"
git init -q "$source_dir"
git -C "$source_dir" -c credential.helper= fetch -q --depth 1 --no-tags https://github.com/true-line/agent-bot-hq.git "$HQ_SOURCE"
git -C "$source_dir" checkout -q --detach FETCH_HEAD
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$HQ_SOURCE" ]]
(
    cd "$source_dir"
    node --input-type=module - "$WORK/contracts" <<'JS'
import { cpSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { readPin, verify } from './scripts/soul-contracts.mjs';
const pin = readPin();
const {dir} = verify(pin);
const target = process.argv[2];
mkdirSync(target);
for (const p of pin.paths) cpSync(join(dir,p),join(target,p),{recursive:true});
JS
    node scripts/build-interim-release.mjs "$HQ_SOURCE" "$WORK/contracts" "$WORK/hq-release.tar"
)
install_dir="/opt/machine-hq-ci/$HQ_SOURCE"
sudo install -d -m 0755 -o root -g root "$install_dir"
sudo tar --no-same-owner -xf "$WORK/hq-release.tar" -C "$install_dir"
sudo install -m 0755 -o root -g root "$(command -v node)" "$install_dir/node"
service_record="$WORK/hq-service.json"
jq -n --arg r "$install_dir/hq" --arg n "$install_dir/node" \
    --arg a "$(sha256sum "$WORK/hq-release.tar" | cut -d' ' -f1)" \
    --arg d "$(sha256sum "$install_dir/node" | cut -d' ' -f1)" \
    '{release_dir:$r,node:$n,artifact_sha256:$a,node_sha256:$d}' > "$service_record"
service_plan() {
    "$MM" members plan --members '' --hq-service "$service_record" > "$WORK/service-plan.jsonl"
    PLAN_ID="$(jq -sr '.[0].plan_id' "$WORK/service-plan.jsonl")"
    PLAN_DIGEST="$(jq -sr '.[0].plan_digest' "$WORK/service-plan.jsonl")"
}
service_plan
refused MM_MEMBERS_NOT_APPROVED sudo "$MM" members apply "$PLAN_ID"
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
[ "$(systemctl is-active agent-bot-hq.service)" = active ]
[ "$(systemctl is-enabled agent-bot-hq.socket)" = enabled ]
[ "$(stat -c '%u:%a' /run/agent-bot-hq/control.sock)" = "$(id -u):600" ]
pid="$(systemctl show -p MainPID --value agent-bot-hq.service)"
[ "$(stat -c %u "/proc/$pid")" = "$(id -u agent-bot-hq)" ]
"$install_dir/node" "$install_dir/hq/hq/main.mjs" status --owner-control --json | jq -e '.hq.account=="agent-bot-hq" and .admissions==false' >/dev/null
service_plan
approve "$PLAN_ID" "$PLAN_DIGEST"
sudo "$MM" members apply "$PLAN_ID" >/dev/null
[ "$(systemctl show -p MainPID --value agent-bot-hq.service)" = "$pid" ]
ok "the approved, verified HQ service answers the owner as its dedicated UID and preserves its process on reapply"
