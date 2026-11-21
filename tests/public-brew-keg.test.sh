#!/bin/bash
# Exercise the installed-binary checks with a temporary prefix and two shell fixtures.
set -euo pipefail
. "$(dirname "$0")/fixtures/verify-public-brew-keg.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
prefix="$work/prefix"
version=1.2.3
cellar="$prefix/Cellar"
keg="$cellar/managed-machine/$version"
mkdir -p "$keg/bin" "$prefix/bin" "$prefix/opt"
ln -s "$keg" "$prefix/opt/managed-machine"
cat > "$keg/bin/managed-machine" <<'BIN'
#!/bin/sh
test "$1" = --version && echo "${TEST_MACHINE_VERSION:-1.2.3}"
exit "${TEST_VERSION_RC:-0}"
BIN
cat > "$keg/bin/agent-bot-keyd" <<'BIN'
#!/bin/sh
test "$1" = --version && echo "agent-bot-keyd ${TEST_KEYD_VERSION:-0.2.1}"
BIN
chmod 0555 "$keg/bin/managed-machine"
chmod 0700 "$keg/bin/agent-bot-keyd"
for name in managed-machine agent-bot-keyd; do ln -s "$keg/bin/$name" "$prefix/bin/$name"; done
tar -czf "$work/release.tgz" -C "$keg/bin" managed-machine agent-bot-keyd
check() { verify_public_brew_keg "$prefix" "$cellar" "$version" 0.2.1 "$work/release.tgz" "$(id -u)"; }
refused() { if check; then echo "Accepted incorrect $1" >&2; exit 1; fi; }
check
TEST_MACHINE_VERSION=0.0.1 refused 'Machine version'
TEST_KEYD_VERSION=0.0.1 refused 'keyd version'
TEST_VERSION_RC=1 refused 'version exit status'
chmod 0755 "$keg/bin/agent-bot-keyd"
refused 'keyd mode'
chmod 0700 "$keg/bin/agent-bot-keyd"
rm "$prefix/bin/managed-machine"
cp "$keg/bin/managed-machine" "$prefix/bin/managed-machine"
refused 'command link'
rm "$prefix/bin/managed-machine"
ln -s "$keg/bin/managed-machine" "$prefix/bin/managed-machine"
rm "$prefix/opt/managed-machine"
mkdir -p "$prefix/opt/managed-machine/bin"
cp "$keg/bin/"* "$prefix/opt/managed-machine/bin"
refused 'opt link'
rm -r "$prefix/opt/managed-machine"
ln -s "$keg" "$prefix/opt/managed-machine"
check
echo '# changed bytes' >> "$keg/bin/agent-bot-keyd"
refused 'release bytes'
echo 'PASS public release CLI version, helper mode, stable links and byte checks'
