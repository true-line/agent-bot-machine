"""Prepare only the known test accounts on the disposable hosted runner."""
import os
from pathlib import Path
import pwd
import runpy
import sys

if not (sys.platform == "darwin" and os.geteuid() != 0 and
        os.environ.get("GITHUB_ACTIONS") == "true" and
        os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and
        os.environ.get("MM_HARNESS_TRANSACTION") == "1"):
    raise SystemExit("requires the disposable macOS harness transaction job")

# Reuse the account setup routines from the independently pinned HQ fixture.
helpers = runpy.run_path(sys.argv[1])
role = pwd.getpwnam("_agent-bot-hq")
names = ["_abm-ci-a", "_abm-ci-b"]
ipc = helpers["IPC"]
existing = helpers["names_in"]("Users") | helpers["names_in"]("Groups")
occupied = set()
for kind, field in [("Users", "UniqueID"), ("Users", "PrimaryGroupID"), ("Groups", "PrimaryGroupID")]:
    occupied.update(helpers["records"](kind, field).values())
free = sorted(set(range(300, 400)) - occupied)
homes = [Path("/var/agent-bot-harness-" + name) for name in names]
if (len(free) < 2 or role.pw_uid in (0, os.getuid()) or any(name in existing for name in names)
        or any(os.path.lexists(path) for path in [ipc, *homes])):
    raise SystemExit("requires two new accounts and an empty endpoint namespace")

from contextlib import ExitStack

with ExitStack() as cleanup:
    helpers["new_dir"](cleanup, ipc, "root:wheel", "0755")
    for name, uid, home in zip(names, free, homes):
        label = "Agent Bot Harness"
        helpers["new_record"](cleanup, "/Groups/" + name, PrimaryGroupID=uid, RealName=label, Password="*")
        helpers["new_record"](cleanup, "/Users/" + name, UniqueID=uid, PrimaryGroupID=uid, RealName=label,
                              NFSHomeDirectory=str(home), IsHidden="1", UserShell="/usr/bin/false", Password="*")
        helpers["new_dir"](cleanup, home, f"{uid}:{uid}", "0700")
        helpers["new_dir"](cleanup, ipc / name, f"{role.pw_uid}:{uid}", "2750")
    # The test verifies the accounts and populated homes survive retirement.
    # They remain owned by this ephemeral VM until GitHub discards it.
    cleanup.pop_all()
