#!/usr/bin/env bash
# Synthetic codesign verdicts exercise failure and retry for both release files.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin" "$work/tree"
touch "$work/tree/managed-machine" "$work/tree/agent-bot-keyd"

cat >"$work/bin/codesign" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
name="${5##*/}"
printf '%s\n' "$name" >>"$CALLS"
[[ $# -eq 5 && "$1" == --verify && "$2" == --strict && "$3" == --check-notarization && "$4" == -R=* && -f "$5" ]]
case "$name" in
    managed-machine) id=ai.true-line.agent-bot-machine ;;
    agent-bot-keyd) id=ai.true-line.agent-bot-keyd ;;
    *) exit 1 ;;
esac
req="${4#-R=}"
[[ "$req" == *"notarized and anchor apple generic"* ]]
[[ "$req" == *"certificate 1[field.1.2.840.113635.100.6.2.6] exists"* ]]
[[ "$req" == *"certificate leaf[field.1.2.840.113635.100.6.1.13] exists"* ]]
[[ "$req" == *'certificate leaf[subject.OU] = "EXAMPLE123"'* ]]
[[ "$req" == *"identifier \"$id\""* ]]
if [[ -x /usr/bin/csreq ]]; then
    /usr/bin/csreq -r="$req" -t >/dev/null
fi
# Even a success-looking diagnostic cannot override a failed requirement.
echo 'source=Notarized Developer ID (EXAMPLE123)' >&2
if [[ "$name" == "$REJECT" ]]; then
    (( $(grep -cx "$name" "$CALLS") > FAILURES ))
fi
STUB
cat >"$work/bin/sleep" <<'STUB'
#!/usr/bin/env bash
[[ "$1" == 15 ]]
STUB
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH" CALLS="$work/calls"
verify() {
    : >"$CALLS"
    REJECT="$1" FAILURES="$2" bash "$root/scripts/verify-darwin-clis" "$work/tree" EXAMPLE123
}

verify none 0
[[ "$(cat "$CALLS")" == $'managed-machine\nagent-bot-keyd' ]]
for name in managed-machine agent-bot-keyd; do
    if verify "$name" 5 >"$work/output" 2>&1; then
        echo "accepted a rejected $name" >&2
        exit 1
    fi
    grep -Fq "$name failed the notarized Developer ID signing requirement" "$work/output"
    [[ "$(grep -cx "$name" "$CALLS")" == 5 ]]
    verify "$name" 1
    [[ "$(grep -cx "$name" "$CALLS")" == 2 ]]
done
echo 'PASS: both standalone executables require a successful notarized Developer ID verdict'
