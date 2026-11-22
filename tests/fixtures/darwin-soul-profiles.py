"""Native network sandbox fixture for the two proposed Soul process roles.

Both children run under this test account. This proves path rules only, not
kernel UID separation, an installed launch grant, broker authentication or T03.
"""

import errno
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from threading import Thread
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "internal/members/darwin/soul-runner-egress.sb"
BRIDGE = ROOT / "internal/members/darwin/soul-bridge-egress.sb"
REQUEST = b"GET fixture\n"
REPLY = b"fixture ready\n"


def exchange(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(address)
        client.sendall(REQUEST)
        with client.makefile("rb") as stream:
            return stream.readline(64)


def denied_connect(family, address):
    try:
        exchange(family, address)
    except PermissionError as error:
        if error.errno not in (errno.EPERM, errno.EACCES):
            raise
    else:
        raise AssertionError(f"unexpected outbound permission to {address}")


def denied_bind(family, address):
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(address)
        except PermissionError as error:
            if error.errno not in (errno.EPERM, errno.EACCES):
                raise
        else:
            raise AssertionError(f"unexpected listener permission to {address}")


def check_denials(port4, port6, *unix_paths):
    denied_connect(socket.AF_INET, ("127.0.0.1", int(port4)))
    denied_connect(socket.AF_INET6, ("::1", int(port6)))
    for path in unix_paths:
        denied_connect(socket.AF_UNIX, path)


def bridge_child(port4, port6, broker, member, sibling, relay, other_bind):
    check_denials(port4, port6, sibling)
    if exchange(socket.AF_UNIX, broker) != REPLY:
        raise AssertionError("bridge could not reach its assigned broker")
    denied_bind(socket.AF_INET, ("127.0.0.1", 0))
    denied_bind(socket.AF_INET6, ("::1", 0))
    denied_bind(socket.AF_UNIX, other_bind)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(relay)
        listener.listen(1)
        listener.settimeout(8)
        print("ready", flush=True)
        deadline = time.monotonic() + 5
        while not Path(member).exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if exchange(socket.AF_UNIX, member) != REPLY:
            raise AssertionError("bridge could not reach its assigned member")
        with listener.accept()[0] as connection:
            with connection.makefile("rb") as stream:
                if stream.readline(64) != REQUEST:
                    raise AssertionError("unexpected relay request")
            connection.sendall(REPLY)


def runner_child(port4, port6, broker, admission, member, sibling, relay, other_relay, other_bind):
    check_denials(port4, port6, broker, sibling, other_relay)
    denied_bind(socket.AF_UNIX, other_bind)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(member)
        listener.listen(1)
        listener.settimeout(8)
        if exchange(socket.AF_UNIX, admission) != REPLY:
            raise AssertionError("runner could not reach its assigned admission")
        with listener.accept()[0] as connection:
            with connection.makefile("rb") as stream:
                if stream.readline(64) != REQUEST:
                    raise AssertionError("unexpected member request")
            connection.sendall(REPLY)
        if exchange(socket.AF_UNIX, relay) != REPLY:
            raise AssertionError("runner could not reach its assigned relay")


class Listener:
    def __init__(self, family, address):
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.bind(address)
        self.address = self.socket.getsockname()
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.count = 0
        self.stop = False
        self.error = None
        self.thread = Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while not self.stop:
                try:
                    conn, _ = self.socket.accept()
                except socket.timeout:
                    continue
                with conn, conn.makefile("rb") as stream:
                    conn.settimeout(3)
                    if stream.readline(64) != REQUEST:
                        raise AssertionError("unexpected fixture request")
                    self.count += 1
                    conn.sendall(REPLY)
        except Exception as error:
            self.error = error

    def close(self):
        self.stop = True
        self.thread.join(5)
        self.socket.close()
        if self.error:
            raise self.error
        if self.thread.is_alive():
            raise AssertionError("fixture listener did not stop")


@unittest.skipUnless(sys.platform == "darwin", "requires the Darwin process sandbox")
class DarwinSoulProfiles(unittest.TestCase):
    def test_assigned_socket_symlink_replacement_is_refused(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp", prefix="soul replacement-") as tmp, ExitStack() as stack:
            sibling = Listener(socket.AF_UNIX, str(Path(tmp) / "sibling.sock"))
            stack.callback(sibling.close)
            assigned = Path(tmp) / "assigned.sock"
            relay = str(Path(tmp) / "relay.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as original:
                original.bind(str(assigned))
                original.listen(1)
                runner = ["/usr/bin/sandbox-exec", "-f", str(RUNNER),
                          "-D", "ADMISSION_SOCKET=" + str(Path(tmp) / "admission.sock"),
                          "-D", "MEMBER_SOCKET=" + str(assigned),
                          "-D", "RELAY_SOCKET=" + relay,
                          sys.executable, "-I", str(Path(__file__).resolve()),
                          "--replacement", str(assigned)]
                with subprocess.Popen(runner, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) as process:
                    assigned.unlink()
                    assigned.symlink_to(sibling.address)
                    stdout, stderr = process.communicate(input="go\n", timeout=10)
                    self.assertEqual(process.returncode, 0, (stdout, stderr))
            self.assertEqual(sibling.count, 0)

    def test_bridge_and_runner_exact_paths(self):
        # The installed runtime path contains "Application Support".
        with tempfile.TemporaryDirectory(dir="/private/tmp", prefix="soul egress-") as tmp, ExitStack() as stack:
            def listen(family, address):
                service = Listener(family, address)
                stack.callback(service.close)
                return service

            v4 = listen(socket.AF_INET, ("127.0.0.1", 0))
            v6 = listen(socket.AF_INET6, ("::1", 0))
            broker = listen(socket.AF_UNIX, str(Path(tmp) / "broker.sock"))
            admission = listen(socket.AF_UNIX, str(Path(tmp) / "admission.sock"))
            member = str(Path(tmp) / "member.sock")
            sibling = listen(socket.AF_UNIX, str(Path(tmp) / "sibling.sock"))
            other_relay = listen(socket.AF_UNIX, str(Path(tmp) / "other-relay.sock"))
            relay = str(Path(tmp) / "relay.sock")
            other_bind = str(Path(tmp) / "other-bind.sock")
            bridge = ["/usr/bin/sandbox-exec", "-f", str(BRIDGE),
                      "-D", "BROKER_SOCKET=" + broker.address,
                      "-D", "MEMBER_SOCKET=" + member,
                      "-D", "RELAY_SOCKET=" + relay,
                      sys.executable, "-I", str(Path(__file__).resolve()), "--bridge",
                      str(v4.address[1]), str(v6.address[1]), broker.address,
                      member, sibling.address, relay, other_bind]
            with subprocess.Popen(bridge, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                if not ready or process.stdout.readline().strip() != "ready":
                    stdout, stderr = process.communicate(timeout=5)
                    self.fail(f"bridge listener not ready: {process.returncode}: {stdout!r} {stderr!r}")
                deadline = time.monotonic() + 5
                while not Path(relay).exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                runner = ["/usr/bin/sandbox-exec", "-f", str(RUNNER),
                          "-D", "ADMISSION_SOCKET=" + admission.address,
                          "-D", "MEMBER_SOCKET=" + member,
                          "-D", "RELAY_SOCKET=" + relay,
                          sys.executable, "-I", str(Path(__file__).resolve()), "--runner",
                          str(v4.address[1]), str(v6.address[1]), broker.address,
                          admission.address, member, sibling.address, relay, other_relay.address, other_bind]
                subprocess.run(runner, check=True, timeout=10)
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
            self.assertEqual((broker.count, admission.count, sibling.count, other_relay.count, v4.count, v6.count),
                             (1, 1, 0, 0, 0, 0))
            self.assertFalse(Path(other_bind).exists())


if __name__ == "__main__":
    if sys.argv[1:2] == ["--bridge"]:
        bridge_child(*sys.argv[2:])
    elif sys.argv[1:2] == ["--runner"]:
        runner_child(*sys.argv[2:])
    elif sys.argv[1:2] == ["--replacement"]:
        sys.stdin.readline()
        denied_connect(socket.AF_UNIX, sys.argv[2])
    else:
        unittest.main()
