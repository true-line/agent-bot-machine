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
    if [[ -n "${MM_HQ_TAP_REVISION:-}" ]]; then
        [[ "$MM_HQ_TAP_REVISION" =~ ^[0-9a-f]{40}$ && "${HOMEBREW_NO_AUTO_UPDATE:-}" == 1 ]] || exit 1
    fi
    umask 022
    "$brew" tap "$tap" https://github.com/true-line/agent-bot-machine.git || exit 1
    if [[ -n "${MM_HQ_TAP_REVISION:-}" ]]; then
        git -C "$tapdir" fetch --quiet --no-tags --depth=1 origin "$MM_HQ_TAP_REVISION" || exit 1
        git -C "$tapdir" checkout --quiet --detach "$MM_HQ_TAP_REVISION" || exit 1
        [[ "$(git -C "$tapdir" rev-parse HEAD)" == "$MM_HQ_TAP_REVISION" ]] || exit 1
    fi
)

install_homebrew_device_release() (
    set -euo pipefail
    local brew="$1" version="$2" digest="$3" tap=true-line/agent-bot-machine tapdir recipe
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 1
    umask 022
    tapdir="$("$brew" --repository "$tap")"
    recipe="$tapdir/Formula/managed-machine.rb"
    if [[ "$(python3 "$(dirname "${BASH_SOURCE[0]}")/homebrew-device-pin.py" "$recipe")" != "$version $digest" ]]; then
        echo 'The public Homebrew formula does not pin the requested release and archive' >&2
        exit 1
    fi
    if "$brew" commands --quiet | grep -x trust >/dev/null; then "$brew" trust --tap "$tap"; fi
    "$brew" install --formula "$tap/managed-machine"
    if [[ -n "${MM_HQ_TAP_REVISION:-}" ]]; then
        [[ "$(git -C "$tapdir" rev-parse HEAD)" == "$MM_HQ_TAP_REVISION" ]] || exit 1
    fi
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

download_device_release_asset() {
    curl -qfsSL --proto '=https' --proto-redir '=https' --retry 3 \
        "https://github.com/true-line/agent-bot-machine/releases/download/v$1/$2" -o "$3"
}

use_published_device_formula() (
    set -euo pipefail
    local version="$1" expected="$2" download="$3" recipe="$4"
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$expected" =~ ^[0-9a-f]{64}$ ]] || exit 1
    download_device_release_asset "$version" managed-machine.rb "$download" || exit 1
    [[ "$(shasum -a 256 "$download" | awk '{print $1}')" == "$expected" ]] || {
        echo 'The published Homebrew formula differs from the verified release recipe' >&2; exit 1
    }
    cp "$download" "$recipe"
)

fetch_public_device_archive() (
    set -euo pipefail
    local version="$1" work="$2" expected="$3" asset digest
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$expected" =~ ^[0-9a-f]{64}$ ]] || exit 1
    asset="managed-machine_${version}_darwin_arm64.tar.gz"
    download_device_release_asset "$version" SHA256SUMS "$work/SHA256SUMS"
    digest="$(awk -v asset="$asset" 'NF == 2 && $2 == asset {print $1}' "$work/SHA256SUMS")"
    [[ "$digest" == "$expected" ]] || { echo 'Published checksum disagrees with the selected release' >&2; exit 1; }
    download_device_release_asset "$version" "$asset" "$work/$asset"
    [[ "$(shasum -a 256 "$work/$asset" | awk '{print $1}')" == "$expected" ]] ||
        { echo 'Downloaded archive differs from its published checksum' >&2; exit 1; }
)
