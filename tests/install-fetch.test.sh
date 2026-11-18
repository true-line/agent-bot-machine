#!/usr/bin/env bash
# Exercise the copyable install commands with offline GitHub responses (#227).
set -euo pipefail
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "$TEST_DIR"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$TEST_DIR/bin" "$TEST_DIR/temp files"

# Read the actual commands so a stale or unguarded copy fails this contract.
for doc in README.md skills/managed-machine/SKILL.md; do
    name="$(basename "$doc")"
    awk '/^```bash$/ {inside=1; next} inside && /^```$/ {exit} inside {print}' \
        "$ROOT/$doc" >"$TEST_DIR/$name.command"
done
sed -n '/^#   ($/,/^#   )$/s/^#   //p' "$ROOT/install.sh" >"$TEST_DIR/install.sh.command"
for command in "$TEST_DIR/"*.command; do
    grep -Fq 'https://raw.githubusercontent.com/true-line/agent-bot-machine/main/install.sh' "$command" || fail "missing command: $command"
    cmp -s "$TEST_DIR/README.md.command" "$command" || fail "install command copies disagree"
done

cat >"$TEST_DIR/bin/curl" <<'EOF'
#!/usr/bin/env bash
[[ "$1 $2 $3 $4" == "--proto =https --proto-redir =https" ]] || exit 98
shift 4
[[ $# == 4 && "$1" == -fsSL && "$2" == 'https://raw.githubusercontent.com/true-line/agent-bot-machine/main/install.sh' && "$3" == -o ]] || exit 99
exec >"$4"
case "$FETCH_CASE" in
    success|installer-failure)
        printf 'echo installed >>"$EXECUTION_MARKER"\nexit %s\n' "$INSTALLER_STATUS"
        ;;
    json-failure)
        printf '{\n  "message": "Unavailable",\n  "status": "503"\n}\n'
        echo 'curl: Unavailable (HTTP 503)' >&2
        exit 1
        ;;
    executable-failure)
        # A partial or otherwise failed response may itself be valid shell.
        printf 'echo unexpected >>"$EXECUTION_MARKER"\n'
        echo 'curl: failed download' >&2
        exit 7
        ;;
esac
EOF
chmod +x "$TEST_DIR/bin/curl"


# Keep zsh startup files from reordering PATH ahead of the offline curl stub.
shells=(bash)
if command -v zsh >/dev/null 2>&1; then shells+=(zsh); fi
for shell in "${shells[@]}"; do
    for command in "$TEST_DIR/"*.command; do
        for mode in success installer-failure json-failure executable-failure; do
            rm -f "$TEST_DIR/executed"
            installer_status=0
            expected_status=0
            case "$mode" in
                installer-failure) installer_status=23; expected_status=23 ;;
                json-failure) expected_status=1 ;;
                executable-failure) expected_status=7 ;;
            esac
            actual_status=0
            ZDOTDIR="$TEST_DIR" PATH="$TEST_DIR/bin:$PATH" TMPDIR="$TEST_DIR/temp files" \
                FETCH_CASE="$mode" INSTALLER_STATUS="$installer_status" EXECUTION_MARKER="$TEST_DIR/executed" \
                "$shell" "$command" >"$TEST_DIR/out" 2>"$TEST_DIR/err" || actual_status=$?
            [[ "$actual_status" -eq "$expected_status" ]] || fail "$shell $command $mode status: $actual_status"
            case "$mode" in
                success|installer-failure)
                    [[ "$(cat "$TEST_DIR/executed")" == installed ]] || fail "installer did not execute exactly once"
                    ;;
                *)
                    [[ ! -e "$TEST_DIR/executed" ]] || fail "failed response was executed"
                    grep -Fq 'curl:' "$TEST_DIR/err" || fail "original fetch error lost"
                    if grep -Eq 'command not found|syntax error' "$TEST_DIR/err"; then fail "JSON reached Bash"; fi
                    ;;
            esac
            [[ -z "$(ls -A "$TEST_DIR/temp files")" ]] || fail "temporary installer leaked ($mode)"
        done
        # A staging failure must also stop before any fetch or execution.
        actual_status=0
        ZDOTDIR="$TEST_DIR" PATH="$TEST_DIR/bin:$PATH" TMPDIR="$TEST_DIR/nonexistent" \
            FETCH_CASE=success INSTALLER_STATUS=0 EXECUTION_MARKER="$TEST_DIR/executed" \
            "$shell" "$command" >"$TEST_DIR/out" 2>"$TEST_DIR/err" || actual_status=$?
        [[ "$actual_status" -ne 0 && ! -e "$TEST_DIR/executed" ]] || fail "mktemp failure did not stop execution"
    done
done
echo 'install fetch tests passed'
