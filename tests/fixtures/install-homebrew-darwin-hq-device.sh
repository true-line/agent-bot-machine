# Shared by the guarded disposable macOS release fixtures.
tap_homebrew_device_release() (
    set -euo pipefail
    local brew="$1" prefix="$2"
    local tap=true-line/agent-bot-machine tapdir path
    [[ "$("$brew" --prefix)" == "$prefix" && "$("$brew" --cellar)" == "$prefix/Cellar" ]] || exit 1
    tapdir="$("$brew" --repository "$tap")"
    for path in "$tapdir" "$prefix/Cellar/managed-machine" "$prefix/opt/managed-machine" "$prefix/bin/managed-machine" "$prefix/bin/agent-bot-keyd"; do
        [[ ! -e "$path" && ! -L "$path" ]] || { echo 'Homebrew qualification requires a fresh installation' >&2; exit 1; }
    done
    # The surrounding temporary Keychain fixture uses 077. Install the public
    # formula with normal Homebrew permissions, leaving the parent umask intact.
    umask 022
    "$brew" tap "$tap" https://github.com/true-line/agent-bot-machine.git
)

install_homebrew_device_release() (
    set -euo pipefail
    local brew="$1" version="$2" digest="$3" tap=true-line/agent-bot-machine recipe archive
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 1
    umask 022
    recipe="$("$brew" --repository "$tap")/Formula/managed-machine.rb"
    archive="managed-machine_${version}_darwin_arm64.tar.gz"
    if ! grep -Fxq "  version \"$version\"" "$recipe" ||
       ! grep -Fxq "      tag:   \"v$version\"" "$recipe" ||
       ! grep -Fxq "    url \"https://github.com/$tap/releases/download/v$version/$archive\"" "$recipe" ||
       ! grep -Fxq "    sha256 \"$digest\"" "$recipe"; then
        echo 'The public Homebrew formula does not pin the requested release and archive' >&2
        exit 1
    fi
    if "$brew" commands --quiet | grep -x trust >/dev/null; then "$brew" trust --tap "$tap"; fi
    "$brew" install --formula "$tap/managed-machine"
)

verify_homebrew_device_binary() {
    local prefix="$1" version="$2" name="$3" mode="$4" expected="$5"
    local keg="$prefix/Cellar/managed-machine/$version/bin/$name"
    [[ -f "$keg" && ! -L "$keg" && "$prefix/bin/$name" -ef "$keg" &&
       "$prefix/opt/managed-machine/bin/$name" -ef "$keg" &&
       "$(stat -f '%u:%Mp%Lp' "$keg")" == "$(id -u):$mode" ]] && cmp -s "$expected" "$keg"
}

unpack_signed_device_release() {
    local archive="$1" digest="$2" unpack="$3"
    [[ "$digest" =~ ^[0-9a-f]{64}$ && -f "$archive" && ! -L "$archive" ]] || return 1
    [[ "$(shasum -a 256 "$archive" | awk '{print $1}')" == "$digest" ]] || return 1
    mkdir -m 0700 "$unpack" || return 1
    python3 - "$archive" "$unpack" <<'PY'
import pathlib,sys,tarfile
with tarfile.open(sys.argv[1],"r:gz") as archive:
    for name,mode in (("agent-bot-keyd",0o700),("managed-machine",0o755)):
        items=[f for f in archive if f.name==name]
        if len(items)!=1 or not items[0].isreg() or items[0].mode!=mode or not 0<items[0].size<=128*1024*1024:
            raise SystemExit("invalid signed release member")
        with archive.extractfile(items[0]) as src, (pathlib.Path(sys.argv[2])/name).open("xb") as dst:
            while chunk:=src.read(65536): dst.write(chunk)
PY
}
