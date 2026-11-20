#!/usr/bin/env bash
# Exercise the public installer without a network, a real prefix or account changes.
set -euo pipefail
host_os="$(uname -s)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEST_DIR="$(mktemp -d)"
TEST_DIR="$(cd "$TEST_DIR" && pwd -P)"
trap 'rm -rf "$TEST_DIR"' EXIT
mkdir "$TEST_DIR/bin" "$TEST_DIR/Library"
export FIXTURE_LIBRARY="$TEST_DIR/Library"
export LOG="$TEST_DIR/brew.log"
export PATH="$TEST_DIR/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PREFIX="$TEST_DIR/homebrew"
export TAPDIR="$PREFIX/Library/Taps/true-line/homebrew-agent-bot-machine"
export UPSTREAM="$TEST_DIR/upstream"
export ORIGIN="https://github.com/true-line/agent-bot-machine.git"
export FORMULA="true-line/agent-bot-machine/managed-machine"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=fixture GIT_COMMITTER_NAME=fixture
export GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_EMAIL=fixture@example.invalid
/usr/bin/git init -q -b main "$UPSTREAM"
/usr/bin/git -C "$UPSTREAM" commit -q --allow-empty -m first
mkdir -p "$PREFIX/bin"
# Redirect Apple's fixed paths into this fixture on both macOS and Linux.
sed -e "s|\"/Library/Application Support|\"$FIXTURE_LIBRARY/Application Support|g" -e "s|/opt/homebrew|$PREFIX|g" -e "s|/usr/bin/osascript|$TEST_DIR/bin/osascript|g" -e "s|/usr/bin/git|$TEST_DIR/bin/git|g" -e "s|/usr/bin/stat|$TEST_DIR/bin/stat|g" "$ROOT/install.sh" > "$TEST_DIR/install.sh"

cat > "$TEST_DIR/bin/uname" <<'STUB'
#!/bin/sh
case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; *) exit 1 ;; esac
STUB
cat > "$TEST_DIR/bin/sw_vers" <<'STUB'
#!/bin/sh
echo 15.7
STUB
cat > "$TEST_DIR/bin/id" <<'STUB'
#!/bin/sh
case "$1" in
  -u) echo "${CALLER_UID:-501}" ;;
  -nu|-un) echo brewowner ;;
  -nG) echo "${ACCOUNT_GROUPS:-staff admin}" ;;
  *) exit 1 ;;
esac
STUB
cat > "$TEST_DIR/bin/stat" <<'STUB'
#!/bin/sh
[ "$1 $2" = "-f %u" ] || exit 1
case "$3" in
    "$PREFIX") echo "${OWNER_UID:-501}" ;;
    "$TAPDIR"|"$TAPDIR/.git") echo "${TAP_UID:-501}" ;;
    *) exit 1 ;;
esac
STUB
cat > "$TEST_DIR/bin/git" <<'STUB'
#!/bin/bash
# Exercise actual Git topology and fast-forward checks with a local remote.
args=("$@")
for i in "${!args[@]}"; do
    if [[ "${args[$i]}" == "$ORIGIN" ]]; then
        [[ "${FAIL_FETCH:-0}" == 0 ]] || exit 17
        args[$i]="$UPSTREAM"
    fi
done
exec /usr/bin/git "${args[@]}"
STUB
cat > "$PREFIX/bin/brew" <<'STUB'
#!/bin/sh
set -eu
[ "$HOMEBREW_NO_AUTO_UPDATE" = 1 ] && [ "$GIT_TERMINAL_PROMPT" = 0 ] || exit 92
if [ "${BREW_FAIL:-}" = "$1" ]; then exit 13; fi
record="$PREFIX/var/homebrew/linked/managed-machine"
case "$*" in
  --prefix|--repository) echo "$PREFIX" ;;
  'commands --quiet') echo trust ;;
  'list -1 --formula --full-name') [ ! -e "$PREFIX/installed" ] || echo "$FORMULA" ;;
  "outdated --formula --quiet $FORMULA") if [ "${PINNED:-0}" = 1 ]; then echo "$FORMULA"; exit 1; fi ;;
  "trust $ORIGIN") echo "$*" >> "$LOG" ;;
  "tap true-line/agent-bot-machine $ORIGIN")
     echo "$*" >> "$LOG"
     mkdir -p "$(dirname "$TAPDIR")"
     /usr/bin/git clone -q "$UPSTREAM" "$TAPDIR"
     /usr/bin/git -C "$TAPDIR" remote set-url origin "$ORIGIN" ;;
  "install $FORMULA")
     echo "$*" >> "$LOG"
     : > "$PREFIX/installed"
     keg="$PREFIX/opt/managed-machine/bin"
     mkdir -p "$keg" "$(dirname "$record")"
     ln -s "$PREFIX/opt/managed-machine" "$record"
     printf '#!/bin/sh\necho 0.12.0\n' > "$keg/managed-machine"
     chmod +x "$keg/managed-machine"
     ln -s managed-machine "$keg/agent-machine"
     cp "$keg/managed-machine" "$keg/agent-bot-keyd"
     for name in managed-machine agent-machine agent-bot-keyd; do ln -s "$keg/$name" "$PREFIX/bin/$name"; done ;;
  "upgrade $FORMULA") echo "$*" >> "$LOG" ;;
  "unlink $FORMULA")
     echo "$*" >> "$LOG"
     test "$record" -ef "$PREFIX/opt/managed-machine"
     for name in managed-machine agent-machine agent-bot-keyd; do
         cmd="$PREFIX/bin/$name"
         if [ -L "$cmd" ] && [ "$cmd" -ef "$PREFIX/opt/managed-machine/bin/$name" ]; then rm "$cmd"; fi
     done
     rm "$record" ;;
  "link $FORMULA")
     echo "$*" >> "$LOG"
     if [ -L "$record" ] || [ "${LINK_NOOP:-0}" = 1 ]; then exit 0; fi
     for name in managed-machine agent-machine agent-bot-keyd; do
         ln -s "$PREFIX/opt/managed-machine/bin/$name" "$PREFIX/bin/$name"
     done
     ln -s "$PREFIX/opt/managed-machine" "$record" ;;
  *) echo "unexpected brew invocation: $*" >&2; exit 9 ;;
esac
STUB
cat > "$TEST_DIR/bin/osascript" <<'STUB'
#!/bin/sh
set -eu
: > "$SCRIPT_FILE"
while [ "$1" = '-e' ]; do printf '%s\n' "$2" >> "$SCRIPT_FILE"; shift 2; done
if grep -Fq 'Permanently retire standalone HQ signing' "$SCRIPT_FILE"; then
    test -f "$FIXTURE_LIBRARY/Application Support/ai.true-line.agent-bot-hq/standalone/declaration-v1"
    [ "${RETIRE_RESPONSE:-deny}" = approve ] || exit 57
    rm "$FIXTURE_LIBRARY/Application Support/ai.true-line.agent-bot-hq/standalone/declaration-v1"
    touch "$FIXTURE_LIBRARY/Application Support/ai.true-line.agent-bot-hq/standalone/machine-retired-v1"
    exit 0
fi
if [ -x /usr/bin/osacompile ] && [ ! -e "$SCRIPT_FILE.scpt" ]; then
    /usr/bin/osacompile -o "$SCRIPT_FILE.scpt" "$SCRIPT_FILE"
fi
[ "$1" = '#501' ]
shift
printf '%s\n' approved >>"$AUTH_LOG"
# Run the real unprivileged shell fragment with a stub home. Its Homebrew
# path already points to this test's isolated prefix.
script=$1
shift
unset HOMEBREW_NO_AUTO_UPDATE GIT_TERMINAL_PROMPT
HOME="$PREFIX/absent" /bin/bash -c "$script" machine-brew "$@"
STUB
chmod +x "$TEST_DIR/bin/"* "$PREFIX/bin/brew"
export AUTH_LOG="$TEST_DIR/auth.log" SCRIPT_FILE="$TEST_DIR/prompt.applescript"
cat > "$TEST_DIR/expected" <<'EXPECTED'
trust https://github.com/true-line/agent-bot-machine.git
tap true-line/agent-bot-machine https://github.com/true-line/agent-bot-machine.git
install true-line/agent-bot-machine/managed-machine
EXPECTED

marker="$FIXTURE_LIBRARY/Application Support/ai.true-line.agent-bot-hq/standalone"
mkdir -p "$marker"
touch "$marker/declaration-v1"
if bash "$TEST_DIR/install.sh"; then echo "Installer ignored cancelled retirement" >&2; exit 1; fi
[[ -e "$marker/declaration-v1" && ! -e "$PREFIX/installed" && ! -e "$LOG" ]]
RETIRE_RESPONSE=approve bash "$TEST_DIR/install.sh"
[[ -e "$marker/machine-retired-v1" && ! -e "$marker/declaration-v1" ]]
cmp "$LOG" "$TEST_DIR/expected"
[[ ! -e "$AUTH_LOG" ]]
# The other account must refresh only public main, and only upgrade Machine.
/usr/bin/git -C "$UPSTREAM" commit -q --allow-empty -m second
: > "$LOG"
CALLER_UID=502 bash "$TEST_DIR/install.sh" --update
printf '%s\n' "trust $ORIGIN" "upgrade $FORMULA" > "$TEST_DIR/upgrade"
cmp "$LOG" "$TEST_DIR/upgrade"
[[ "$(wc -l < "$AUTH_LOG")" -eq 1 && -d "$PREFIX/var/mm-home" ]]
[[ "$(/usr/bin/git -C "$TAPDIR" rev-parse HEAD)" == "$(/usr/bin/git -C "$UPSTREAM" rev-parse HEAD)" ]]

# Ordinary install also refreshes an existing tap and lets Homebrew
# converge only this formula.
/usr/bin/git -C "$UPSTREAM" commit -q --allow-empty -m third
: > "$LOG"
bash "$TEST_DIR/install.sh"
cmp "$LOG" "$TEST_DIR/upgrade"
[[ "$(/usr/bin/git -C "$TAPDIR" rev-parse HEAD)" == "$(/usr/bin/git -C "$UPSTREAM" rev-parse HEAD)" ]]

# A current keg can be unlinked. Retry as the real prefix owner, and never
# execute or replace another package's command when the names conflict.
record="$PREFIX/var/homebrew/linked/managed-machine"
rm "$record"
for name in managed-machine agent-machine agent-bot-keyd; do rm "$PREFIX/bin/$name"; done
: > "$LOG"
CALLER_UID=502 bash "$TEST_DIR/install.sh" --update > "$TEST_DIR/result"
grep -Fxq "link $FORMULA" "$LOG"
for name in managed-machine agent-machine agent-bot-keyd; do
    test "$PREFIX/bin/$name" -ef "$PREFIX/opt/managed-machine/bin/$name"
done

# A missing individual link leaves Homebrew believing the current keg is linked.
rm "$PREFIX/bin/agent-bot-keyd"
: > "$LOG"
CALLER_UID=502 bash "$TEST_DIR/install.sh" --update > "$TEST_DIR/result"
printf '%s\n' "trust $ORIGIN" "upgrade $FORMULA" "unlink $FORMULA" "link $FORMULA" > "$TEST_DIR/relink"
cmp "$LOG" "$TEST_DIR/relink"
for name in managed-machine agent-machine agent-bot-keyd; do
    test "$PREFIX/bin/$name" -ef "$PREFIX/opt/managed-machine/bin/$name"
done

# If linking fails after unlinking, the next run starts with an unlinked keg.
rm "$PREFIX/bin/agent-bot-keyd"
if BREW_FAIL=link bash "$TEST_DIR/install.sh" > "$TEST_DIR/result" 2>&1; then exit 1; fi
test ! -L "$record"

if LINK_NOOP=1 bash "$TEST_DIR/install.sh" > "$TEST_DIR/result" 2>&1; then
    echo 'Unexpected success after Homebrew left the links missing' >&2; exit 1
fi
grep -Fq 'Homebrew did not link managed-machine' "$TEST_DIR/result"

ln -s "$PREFIX/opt/managed-machine" "$record"
for occupant in file dangling; do
    if [[ "$occupant" == file ]]; then
        printf 'unrelated command\n' > "$PREFIX/bin/agent-machine"
    else
        ln -s missing-target "$PREFIX/bin/agent-machine"
    fi
    : > "$LOG"
    if bash "$TEST_DIR/install.sh" > "$TEST_DIR/result" 2>&1; then
        echo "Unexpected success with a conflicting $occupant" >&2; exit 1
    fi
    grep -Fq 'agent-machine is occupied' "$TEST_DIR/result"
    if grep -Eq "^(un)?link " "$LOG"; then exit 1; fi
    test "$record" -ef "$PREFIX/opt/managed-machine"
    if [[ "$occupant" == file ]]; then
        test "$(cat "$PREFIX/bin/agent-machine")" = 'unrelated command'
    else
        test "$(readlink "$PREFIX/bin/agent-machine")" = missing-target
    fi
    rm "$PREFIX/bin/agent-machine"
done
bash "$TEST_DIR/install.sh" > "$TEST_DIR/result"

assert_update_refused() {
    : > "$LOG"
    if bash "$TEST_DIR/install.sh" --update >"$TEST_DIR/result" 2>&1; then
        echo "Unexpected update for $1" >&2; exit 1
    fi
    [[ ! -s "$LOG" ]]
}
touch "$TAPDIR/dirty"
assert_update_refused dirty
rm "$TAPDIR/dirty"
/usr/bin/git -C "$TAPDIR" remote set-url origin https://example.invalid/foreign.git
assert_update_refused foreign
/usr/bin/git -C "$TAPDIR" remote set-url origin "$ORIGIN"
/usr/bin/git -C "$TAPDIR" switch --detach -q
assert_update_refused detached
/usr/bin/git -C "$TAPDIR" switch -q main
TAP_UID=502 assert_update_refused foreign-owner
FAIL_FETCH=1 assert_update_refused failed-fetch
/usr/bin/git -C "$TAPDIR" commit -q --allow-empty -m local
assert_update_refused ahead
# This checkout is a disposable test fixture.
/usr/bin/git -C "$TAPDIR" reset -q --hard HEAD^
mv "$TAPDIR" "$TEST_DIR/moved-tap"
ln -s "$TEST_DIR/moved-tap" "$TAPDIR"
assert_update_refused symlinked
rm "$TAPDIR"
mv "$TEST_DIR/moved-tap" "$TAPDIR"

for refusal in 'CALLER_UID=0' 'OWNER_UID=0' 'ACCOUNT_GROUPS=staff'; do
    : > "$LOG"
    if env "$refusal" bash "$TEST_DIR/install.sh" >"$TEST_DIR/result" 2>&1; then
        echo "Unexpected success for $refusal" >&2; exit 1
    fi
    [[ ! -s "$LOG" ]]
done
if BREW_FAIL=upgrade bash "$TEST_DIR/install.sh" >"$TEST_DIR/result" 2>&1; then
    echo 'An installation error must propagate' >&2; exit 1
fi
! grep -Fq 'Machine 0.12.0 installed.' "$TEST_DIR/result" || exit 1
if PINNED=1 bash "$TEST_DIR/install.sh" --update >"$TEST_DIR/result" 2>&1; then
    echo "A pin blocking the update must not report success" >&2; exit 1
fi

# A new Mac obtains Homebrew only as the intended administrator. A failed
# fetch must not execute even a complete-looking script left in the temp file.
mv "$PREFIX/bin/brew" "$TEST_DIR/homebrew-fixture"
mv "$TAPDIR" "$TEST_DIR/prior-tap"
rm "$PREFIX/installed" "$PREFIX/bin/managed-machine" "$PREFIX/bin/agent-machine" "$PREFIX/bin/agent-bot-keyd"
rm -r "$PREFIX/opt/managed-machine"
cat > "$TEST_DIR/bin/curl" <<'STUB'
#!/bin/sh
set -eu
[ "$1 $2 $3 $4" = "--proto =https --proto-redir =https" ]
shift 4
[ "$1" = '-fsSL' ] && [ "$2" = 'https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh' ] && [ "$3" = '-o' ]
printf '%s\n' 'cp "$BREW_FIXTURE" "$PREFIX/bin/brew"' >"$4"
exit "${FETCH_EXIT:-0}"
STUB
chmod +x "$TEST_DIR/bin/curl"
export BREW_FIXTURE="$TEST_DIR/homebrew-fixture"
if FETCH_EXIT=7 bash "$TEST_DIR/install.sh" >"$TEST_DIR/result" 2>&1; then exit 1; fi
[[ ! -e "$PREFIX/bin/brew" ]]
if ACCOUNT_GROUPS=staff bash "$TEST_DIR/install.sh" >"$TEST_DIR/result" 2>&1; then exit 1; fi
[[ ! -e "$PREFIX/bin/brew" ]]
: > "$LOG"
bash "$TEST_DIR/install.sh"
cmp "$LOG" "$TEST_DIR/expected"

# Private configuration and credential management are optional legacy workflows.
if grep -nE 'qwts/|(^|[[:space:]])gh[[:space:]]|--bootstrap|local-bin' "$ROOT/install.sh"; then
    echo 'The public installer must work without organization setup' >&2; exit 1
fi

grep -q 'brew-github-auth-run' "$ROOT/legacy/lib/brew.sh"
if grep -n 'HOMEBREW_GITHUB_API_TOKEN=\${token}' "$ROOT/legacy/lib/brew.sh"; then
    echo 'GitHub token must not be interpolated into argv' >&2
    exit 1
fi

# Legacy helper processes may have an empty PATH. They must use absolute chown and export a usable PATH.
for f in "$ROOT/legacy/lib/brew-github-auth-run" "$ROOT/legacy/lib/npm-public-run" "$ROOT/legacy/lib/elevate-plan-run"; do
    grep -q '/usr/sbin/chown' "$f" || {
        echo "missing /usr/sbin/chown in $f" >&2
        exit 1
    }
    grep -q 'PATH=/usr/sbin:/usr/bin:/bin' "$f" || {
        echo "missing login-less PATH in $f" >&2
        exit 1
    }
    if grep -nE '^chown |[^/[:alnum:]_]chown "' "$f"; then
        echo "bare chown in $f would fail in an empty osascript PATH" >&2
        exit 1
    fi
    # Every absolute binary path the helper runs in its empty login-less shell
    # must exist on macOS (e.g. touch is /usr/bin/touch, never /bin/touch).
    while IFS= read -r tool; do
        [[ -n "$tool" ]] || continue
        if [[ "$host_os" == Darwin && ! -x "$tool" ]]; then
            echo "$f references $tool which does not exist (single tool was run natively)" >&2
            exit 1
        fi
    done < <(grep -oE '(^|[[:space:]])/(usr/sbin|usr/bin|bin)/[A-Za-z0-9._-]+' "$f" | grep -oE '^/(usr/sbin|usr/bin|bin)/[A-Za-z0-9._-]+$' | sort -u)
done
if grep -nE '/usr/bin/sudo -H -u' "$ROOT/legacy/lib/elevate.sh" "$ROOT/legacy/lib/brew-github-auth-run" "$ROOT/legacy/lib/npm-public-run"; then
    echo 'sudo -H -u resets a stub brew-owner home to an empty shell' >&2
    exit 1
fi

# After chown to the brew owner, that user cannot traverse the invoking
# user's /var/folders TMPDIR. The helper workdir must be created under /tmp.
for f in "$ROOT/legacy/lib/brew-github-auth-run" "$ROOT/legacy/lib/npm-public-run"; do
    grep -q 'TMPDIR=/tmp' "$f" || {
        echo "missing TMPDIR=/tmp in $f" >&2
        exit 1
    }
    grep -q 'mktemp -d /tmp/mm-gh-auth.XXXXXX' "$f" || grep -q 'mktemp -d /tmp/mm-npm-run.XXXXXX' "$f" || {
        echo "helper workdir in $f must be created under /tmp" >&2
        exit 1
    }
    if grep -nE '\$\{TMPDIR:-/tmp\}/mm-gh-auth' "$f"; then
        echo "helper workdir in $f inherits the invoking user TMPDIR" >&2
        exit 1
    fi
done
for f in "$ROOT/legacy/lib/brew-github-auth-run" "$ROOT/legacy/lib/npm-public-run" "$ROOT/legacy/lib/elevate-plan-run"; do
    grep -q '^cd /tmp$' "$f" || {
        echo "missing cd /tmp in $f (dropped-privilege commands fail when caller PWD is mode 0700)" >&2
        exit 1
    }
done

if ! grep -q "rm -f \"\$tokenfile\"; trap - RETURN" "$ROOT/legacy/lib/brew.sh"; then
    echo 'lib/brew.sh RETURN trap must clear itself after removing the token file' >&2
    exit 1
fi

# brew re-execs with env -i and drops GIT_CONFIG_*/GH_TOKEN. The helper must
# install a HOME .gitconfig so the private resource fetches can authenticate.
for f in "$ROOT/legacy/lib/brew-github-auth-run"; do
    grep -q 'gitconfig_home=$owner_home/.gitconfig' "$f" || {
        echo "missing owner HOME gitconfig install in $f" >&2
        exit 1
    }
    grep -q 'credential "https://github.com"' "$f" || {
        echo "missing GitHub credential helper gitconfig in $f" >&2
        exit 1
    }
    grep -q 'created_gitconfig' "$f" || {
        echo "missing gitconfig cleanup marker in $f" >&2
        exit 1
    }
done

echo 'install docs tests passed'
