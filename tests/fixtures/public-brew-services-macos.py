"""Check the two installed user LaunchAgents. Print only their kernel peer PIDs."""

import ctypes
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import subprocess
import sys
import time


def peer_pid(client):
    uid, gid = ctypes.c_uint(), ctypes.c_uint()
    if ctypes.CDLL(None).getpeereid(client.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
        raise OSError("getpeereid failed")
    assert uid.value == os.getuid()
    # Darwin sys/un.h: SOL_LOCAL, LOCAL_PEERPID.
    return client.getsockopt(0, 2)


def check_image(pid, expected):
    buf = ctypes.create_string_buffer(4096)  # PROC_PIDPATHINFO_MAXSIZE
    assert ctypes.CDLL("/usr/lib/libproc.dylib").proc_pidpath(pid, buf, len(buf)) > 0
    assert os.path.samefile(os.fsdecode(buf.value), expected)


def check_job(label, pid):
    for domain in ("gui", "user"):
        target = f"{domain}/{os.getuid()}/{label}"
        result = subprocess.run(["/bin/launchctl", "print", target], capture_output=True, text=True)
        if result.returncode == 0 and re.search(rf"^\s*pid = {pid}$", result.stdout, re.MULTILINE):
            return
    raise ValueError("socket peer is not the running user LaunchAgent")


def initialize(client, version):
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "release-check", "version": "1"}}}
    client.sendall(json.dumps(request).encode() + b"\n")
    with client.makefile("rb") as stream:
        reply = json.loads(stream.readline(8192))
    assert reply["jsonrpc"] == "2.0" and reply["id"] == 1
    assert reply["result"]["serverInfo"] == {"name": "agent-bot-keyd", "version": version}


def running_peer(label, executable, args, path, keyd_version=None):
    plist = Path.home() / "Library/LaunchAgents" / (label + ".plist")
    with plist.open("rb") as stream:
        unit = plistlib.load(stream)
    assert unit["Label"] == label and unit["ProgramArguments"][1:] == args
    assert os.path.samefile(unit["ProgramArguments"][0], executable)
    deadline = time.monotonic() + 15
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        while True:
            try:
                client.connect(os.fspath(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        assert path.stat().st_uid == os.getuid()
        pid = peer_pid(client)
        check_image(pid, executable)
        check_job(label, pid)
        if keyd_version is not None:
            initialize(client, keyd_version)
        return pid


if __name__ == "__main__":
    prefix, keg = map(Path, sys.argv[1:3])
    keyd_state = Path.home() / ".local/state/agent-bot"
    print(running_peer("dev.qwts.agent-machine", keg / "bin/managed-machine",
                       ["daemon", "run"], prefix / "var/agent-machine/daemon.sock"))
    print(running_peer("dev.qwts.agent-bot.keyd", keg / "bin/agent-bot-keyd",
                       ["serve", "--state-dir", str(keyd_state)], keyd_state / "keyd/keyd.sock",
                       sys.argv[3]))
