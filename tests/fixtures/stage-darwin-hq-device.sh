# Sourced only by the explicit signed-release hardware qualification on a
# clean hosted runner, before it creates any Machine identity or owner pin.
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted &&
   "${MM_KEYD_CUSTODY_TEST:-}" == 1 && "$DAEMON_ACCOUNT" == "$(id -un)" &&
   "$(stat -f %u /opt/homebrew)" == "$(id -u)" ]] || exit 1
[[ "${MM_HQ_DEVICE_SHA256:-}" =~ ^[0-9a-f]{64}$ && -f "$MM_HQ_DEVICE_ARCHIVE" && ! -L "$MM_HQ_DEVICE_ARCHIVE" ]]
[[ "$(shasum -a 256 "$MM_HQ_DEVICE_ARCHIVE" | awk '{print $1}')" == "$MM_HQ_DEVICE_SHA256" ]] || fail 'wrong native release archive'
custody_dir="$stage/device-custody"
sudo install -d -o root -g wheel -m 0755 "$custody_dir"
# Use only the named regular release members. The complete archive is pinned.
unpack="$WORK/signed-device-release"
mkdir -m 0700 "$unpack"
python3 - "$MM_HQ_DEVICE_ARCHIVE" "$unpack" <<'PY'
import pathlib,sys,tarfile
with tarfile.open(sys.argv[1],"r:gz") as archive:
    for name,mode in (("agent-bot-keyd",0o700),("managed-machine",0o755)):
        items=[f for f in archive if f.name==name]
        if len(items)!=1 or not items[0].isreg() or items[0].mode!=mode or not 0<items[0].size<=128*1024*1024:
            raise SystemExit("invalid signed release member")
        with archive.extractfile(items[0]) as src, (pathlib.Path(sys.argv[2])/name).open("xb") as dst:
            while chunk:=src.read(65536): dst.write(chunk)
PY
for name in managed-machine agent-bot-keyd; do
    if [[ "$name" == managed-machine ]]; then mode=0755; identifier=ai.true-line.agent-bot-machine
    else mode=0700; identifier=ai.true-line.agent-bot-keyd; fi
    sudo install -o "$DAEMON_ACCOUNT" -g "$(id -gn)" -m "$mode" "$unpack/$name" "$custody_dir/$name"
    requirement="anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"Z5DM34QS5U\" and identifier \"$identifier\""
    /usr/bin/codesign --verify --strict "-R=$requirement" "$custody_dir/$name"
done
MM="$custody_dir/managed-machine"
