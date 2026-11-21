"""Run the installed Machine launcher as dedicated HQ on a disposable hosted Mac."""
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import subprocess
import sys
import selectors
from contextlib import ExitStack

BASE = Path("/Library/Application Support/ai.true-line.agent-bot-hq")
MAPPING = {"fixture-lead": "_abm-ci-a", "fixture-specialist": "_abm-ci-b"}
SOUL = "agent_01234567-0123-4567-0123-456789abcdef"
CONTEXT = "agent-bot-hq/bind/v1"


def send(stream, record):
    stream.write(json.dumps(record).encode() + b"\n")
    stream.flush()


def rpc(stream, op, expected, result, sequence):
    request = json.loads(stream.readline(4096))
    if request != {"id": sequence, "op": op, "payload": expected}:
        raise RuntimeError("fixture received an unexpected check-in")
    send(stream, {"id": sequence, "ok": True, "result": result})


def peer(server, uid, gid, resources):
    conn, _ = server.accept()
    resources.enter_context(conn)
    conn.settimeout(8)
    peer_uid, peer_gid = ctypes.c_uint(), ctypes.c_uint()
    if ctypes.CDLL(None).getpeereid(conn.fileno(), ctypes.byref(peer_uid), ctypes.byref(peer_gid)) != 0:
        raise RuntimeError("getpeereid failed")
    if (peer_uid.value, peer_gid.value) != (uid, gid):
        raise RuntimeError("check-in peer did not match the assigned role")
    return resources.enter_context(conn.makefile("rwb", buffering=0))


def socket_at(resources, path):
    sock = resources.enter_context(socket.socket(socket.AF_UNIX))
    sock.settimeout(10)
    sock.bind(str(path))
    observed = path.lstat()

    def unlink_created():
        if os.path.samestat(path.lstat(), observed):
            path.unlink()

    resources.callback(unlink_created)
    os.chmod(path, 0o660)
    sock.listen(1)
    return sock


def reachable(server, address, family):
    """Prove the target is live before asking the confined adapter to try it."""
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(address)
        conn, _ = server.accept()
        conn.close()


def member_path(root, launch):
    path = root / ("member-" + launch + ".sock")
    if len(bytes(path)) <= 103:
        return path
    value = int(launch, 16)
    name = ""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    while value:
        value, digit = divmod(value, 36)
        name = alphabet[digit] + name
    room = 103 - len(bytes(root)) - 1
    if room < 11:
        raise RuntimeError("unsupported role path")
    return root / name.rjust(19, "0")[-room:]


def check_one(digest, adapter, account):
    target = pwd.getpwnam(account)
    if target.pw_uid != target.pw_gid or not 300 <= target.pw_uid < 400:
        raise RuntimeError("unexpected fixture account")
    launch = secrets.token_hex(12)
    member_id = adapter
    token = secrets.token_hex(24)
    binding = secrets.token_hex(24)
    runtime = "rt_" + secrets.token_hex(12)
    nonce = secrets.token_hex(32)
    root = BASE / "ipc" / account
    with ExitStack() as resources:
        member = socket_at(resources, member_path(root, launch))
        broker = socket_at(resources, root / "broker.sock")
        sibling_path = member_path(root, secrets.token_hex(12))
        sibling = socket_at(resources, sibling_path)
        ipv4 = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        ipv4.bind(("127.0.0.1", 0))
        ipv4.listen(1)
        ipv4.settimeout(2)
        ipv6 = resources.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
        ipv6.bind(("::1", 0))
        ipv6.listen(1)
        ipv6.settimeout(2)
        for server, address, family in ((sibling, str(sibling_path), socket.AF_UNIX),
                                        (ipv4, ipv4.getsockname(), socket.AF_INET),
                                        (ipv6, ipv6.getsockname(), socket.AF_INET6)):
            reachable(server, address, family)
        cli = ["/usr/bin/sudo", "-n", "-u", account, "--", str(BASE / "harness-launch"), "harness-run"]
        process = subprocess.Popen(cli, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/")

        def stop():
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            try:
                process.wait(8)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(8)
            process.stdout.close()
            process.stderr.close()

        resources.callback(stop)
        send(process.stdin, dict(plan_digest=digest, adapter_id=adapter, launch_id="ln_" + launch,
                                 soul_id=SOUL, role="member", member_id=member_id, member_token=token))
        probes = {"ipv4_port": ipv4.getsockname()[1], "ipv6_port": ipv6.getsockname()[1],
                  "sibling": str(sibling_path)}
        requests = [("initialize", {}), ("session/new", {}),
                    ("session/prompt", {"sessionId":"fixture-session","prompt":[], "probe":probes})]
        for i, (method, params) in enumerate(requests, 1):
            send(process.stdin, dict(jsonrpc="2.0", id=i, method=method, params=params))
        m = peer(member, target.pw_uid, target.pw_gid, resources)
        rpc(m, "hello", {"token":token}, {"soul_id":SOUL,"member_id":member_id,"role":"member"}, 1)
        rpc(m, "runtime", {}, {"runtime_id":runtime,"channel_binding":binding,"installation_epoch":1,"lease_generation":1}, 2)
        b = peer(broker, target.pw_uid, target.pw_gid, resources)
        rpc(b, "bind.challenge", {"runtime_id":runtime}, {"runtime_id":runtime,"algorithm":"hmac-sha256","context":CONTEXT,"nonce":nonce}, 1)
        proof = hmac.new(binding.encode(), f"{CONTEXT}\n{nonce}\n{runtime}".encode(), hashlib.sha256).hexdigest()
        rpc(b, "bind", {"runtime_id":runtime,"proof":proof}, {"runtime_id":runtime}, 2)
        # Read all ACP replies before asking the supervisor to terminate its process group.
        with selectors.DefaultSelector() as ready:
            ready.register(process.stdout, selectors.EVENT_READ)
            buf = b""
            while buf.count(b"\n") < 3:
                if not ready.select(8):
                    raise RuntimeError("ACP response timed out")
                block = os.read(process.stdout.fileno(), 4096)
                if not block or len(buf) + len(block) > 16384:
                    raise RuntimeError("incomplete ACP response")
                buf += block
        replies = [json.loads(line) for line in buf.splitlines()]
        if ([r["id"] for r in replies] != [1,2,3] or replies[0]["result"]["protocolVersion"] != 1 or
                replies[1]["result"]["sessionId"] != "fixture-session" or replies[2]["result"]["stopReason"] != "end_turn"):
            raise RuntimeError("ACP operation failed")
        process.stdin.close()
        if process.wait(10) != 0:
            raise RuntimeError("Machine did not confirm supervised closure")
        events = [json.loads(line)["kind"] for line in process.stderr if line.strip()]
        if events != ["started","closed"]:
            raise RuntimeError("missing supervisor lifecycle records")
        print(f"PASS {adapter} entered its assigned account, denied direct IPv4/IPv6 and sibling socket, completed member + broker check-in and closed")


if __name__ == "__main__":
    if (sys.platform != "darwin" or os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or os.geteuid() != pwd.getpwnam("_agent-bot-hq").pw_uid or
            os.geteuid() == 0 or len(sys.argv) != 2 or not re.fullmatch("[a-f0-9]{64}", sys.argv[1])):
        raise SystemExit("requires the prepared dedicated role and exact installation digest")
    for adapter, account in MAPPING.items():
        check_one(sys.argv[1], adapter, account)
