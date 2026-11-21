"""Observe the two LaunchAgents created by the hosted Homebrew lifecycle fixture."""
import json
import os
import plistlib
import re
import stat
import subprocess
import sys
from pathlib import Path


def jobs(label):
    for domain in ("gui", "user"):
        target = f"{domain}/{os.getuid()}/{label}"
        result = subprocess.run(["/bin/launchctl", "print", target], capture_output=True, text=True)
        if result.returncode == 0:
            yield result.stdout
        elif result.returncode not in (3, 112, 113):
            raise ValueError("could not determine launchd registration")


def inspect(agents, keg, previous):
    home = agents.parent.parent
    roles = {"managed-machine": ["daemon", "run"],
             "agent-bot-keyd": ["serve", "--state-dir", str(home / ".local/state/agent-bot")]}
    labels = {}
    created = set(agents.glob("*.plist")) - previous
    if len(created) != len(roles):
        raise ValueError("expected exactly two new LaunchAgents")
    for path in created:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
            raise ValueError("unexpected plist owner, mode or file type")
        with path.open("rb") as f:
            record = plistlib.load(f)
        label, args = record["Label"], record["ProgramArguments"]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,200}", label) or path.name != label + ".plist":
            raise ValueError("unexpected registered label")
        program = Path(args[0])
        role = program.name
        if (role in labels or role not in roles or args[1:] != roles[role] or
                not program.is_absolute() or not program.samefile(keg / "bin" / role)):
            raise ValueError("unexpected LaunchAgent executable or arguments")
        if role == "managed-machine" and record.get("EnvironmentVariables", {}).get("HOME") != str(home):
            raise ValueError("wrong Machine service home")
        loaded = False
        for job in jobs(label):
            # The top-level fields are indented once; nested launchd domains
            # may contain separate path or pid fields.
            def field(name):
                found = re.findall(r"^\t" + name + r" = (.+)$", job, flags=re.MULTILINE)
                if len(found) != 1:
                    raise ValueError("missing or ambiguous launchd " + name)
                return found[0]
            if not path.samefile(field("path")) or not program.samefile(field("program")):
                raise ValueError("unexpected loaded service path")
            pid = field("pid")
            if not re.fullmatch(r"[1-9][0-9]*", pid):
                raise ValueError("missing LaunchAgent process")
            uid = subprocess.check_output(["/bin/ps", "-p", pid, "-o", "uid="], text=True).strip()
            if uid != str(os.getuid()):
                raise ValueError("unexpected LaunchAgent process owner")
            loaded = True
        if not loaded:
            raise ValueError("service is not running in the prefix owner's session")
        labels[role] = label
    return labels


if __name__ == "__main__":
    action, directory, package, scratch = sys.argv[1:]
    agents, keg, work = map(Path, (directory, package, scratch))
    baseline, observed = work / "agents-before.json", work / "agent-labels.json"
    if action == "before":
        baseline.write_text(json.dumps(sorted(str(p) for p in agents.glob("*.plist"))))
    elif action == "active":
        labels = inspect(agents, keg, set(map(Path, json.loads(baseline.read_text()))))
        if observed.exists() and labels != json.loads(observed.read_text()):
            raise SystemExit("registered labels changed across reinstall")
        observed.write_text(json.dumps(labels))
    elif action == "absent":
        for label in json.loads(observed.read_text()).values():
            if os.path.lexists(agents / (label + ".plist")) or list(jobs(label)):
                raise SystemExit("observed LaunchAgent remains after uninstall")
    else:
        raise SystemExit("unsupported lifecycle observation")
