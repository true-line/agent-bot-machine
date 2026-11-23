"""Exercise the test process's egress policy with a local fixture service only."""

import errno
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from threading import Thread
import unittest


PROFILE = Path(__file__).resolve().parents[2] / "internal/members/darwin/harness-egress.sb"
SIDECAR_PROFILE = PROFILE.with_name("harness-sidecar.sb")
REQUEST = b"GET fixture-version\n"
REPLY = b"version 1\n"


def exchange(family, address, request=REQUEST):
    with socket.socket(family, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(address)
        client.sendall(request)
        with client.makefile("rb") as stream:
            return stream.readline(64)


def child(port4, port6, broker, member, member_reply, *unassigned):
    denied = [(socket.AF_INET, ("127.0.0.1", int(port4))),
              (socket.AF_INET6, ("::1", int(port6)))]
    denied.extend((socket.AF_UNIX, path) for path in unassigned)
    for family, addr in denied:
        try:
            exchange(family, addr)
        except PermissionError as error:
            if error.errno not in (errno.EPERM, errno.EACCES):
                raise
        else:
            raise AssertionError("expected a sandbox permission refusal")
    if exchange(socket.AF_UNIX, broker) != REPLY:
        raise AssertionError("brokered response did not match")
    if member and exchange(socket.AF_UNIX, member) != member_reply.encode():
        raise AssertionError("per-launch member response did not match")


def sidecar_child(port4, port6, broker, member, sibling, assigned, other_bind):
    child(port4, port6, broker, member, "member ready\n", sibling)
    for family, address in ((socket.AF_INET, ("127.0.0.1", 0)),
                            (socket.AF_INET6, ("::1", 0)),
                            (socket.AF_UNIX, other_bind)):
        with socket.socket(family, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(address)
            except PermissionError as error:
                if error.errno not in (errno.EPERM, errno.EACCES):
                    raise
            else:
                raise AssertionError("expected a sandbox bind refusal")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(assigned)
        listener.listen(1)
        listener.settimeout(5)
        with listener.accept()[0] as connection:
            connection.sendall(REPLY)


class Listener:
    def __init__(self, family, addr, handler):
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.bind(addr)
        self.address = self.socket.getsockname()
        self.socket.listen()
        self.socket.settimeout(0.1)
        self.handler = handler
        self.received = []
        self.error = None
        self.stopped = False
        self.thread = Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        try:
            while not self.stopped:
                try:
                    conn, _ = self.socket.accept()
                except socket.timeout:
                    continue
                with conn, conn.makefile("rb") as stream:
                    conn.settimeout(3)
                    request = stream.readline(64)
                    if request != REQUEST:
                        raise AssertionError("unexpected local fixture request")
                    self.received.append(request)
                    conn.sendall(self.handler(request))
        except Exception as error:
            self.error = error

    def close(self):
        self.stopped = True
        self.thread.join(5)
        self.socket.close()
        if self.error:
            raise self.error
        if self.thread.is_alive():
            raise AssertionError("listener did not stop")


@unittest.skipUnless(sys.platform == "darwin", "requires the Darwin process sandbox")
class DarwinHarnessEgress(unittest.TestCase):
    def test_direct_and_brokered_fixture_operation(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp", prefix="hq-egress-") as tmp, ExitStack() as stack:
            def listen(family, address, handler):
                listener = Listener(family, address, handler)
                stack.callback(listener.close)
                return listener

            v4 = listen(socket.AF_INET, ("127.0.0.1", 0), lambda request: REPLY)
            v6 = listen(socket.AF_INET6, ("::1", 0), lambda request: REPLY)
            broker = listen(socket.AF_UNIX, str(Path(tmp) / "broker.sock"),
                            lambda request: exchange(socket.AF_INET, v4.address, request))
            other = listen(socket.AF_UNIX, str(Path(tmp) / "other.sock"), lambda request: REPLY)

            # Two live callbacks in the same directory as the broker. Each is
            # used by its own launch and must remain unavailable to the other.
            first = listen(socket.AF_UNIX, str(Path(tmp) / "member-first.sock"), lambda _: b"first ready\n")
            second = listen(socket.AF_UNIX, str(Path(tmp) / "member-second.sock"), lambda _: b"second ready\n")

            def launch(member, member_reply, unassigned):
                args = ["/usr/bin/sandbox-exec", "-f", str(PROFILE), "-D", "BROKER_SOCKET=" + broker.address]
                if member:
                    args.extend(["-D", "MEMBER_SOCKET=" + member.address])
                subprocess.run([*args, sys.executable, "-I", str(Path(__file__).resolve()), "--child",
                                str(v4.address[1]), str(v6.address[1]), broker.address,
                                member.address if member else "", member_reply, other.address,
                                *(service.address for service in unassigned)], check=True, timeout=15)

            for family, service in ((socket.AF_INET, v4), (socket.AF_INET6, v6), (socket.AF_UNIX, other)):
                self.assertEqual(exchange(family, service.address), REPLY)
            launch(first, "first ready\n", [second])
            launch(second, "second ready\n", [first])
            launch(None, "", [first, second])
            for family, service in ((socket.AF_INET, v4), (socket.AF_INET6, v6), (socket.AF_UNIX, other)):
                self.assertEqual(exchange(family, service.address), REPLY)

            self.assertEqual(other.received, [REQUEST, REQUEST])
            self.assertEqual(first.received, [REQUEST])
            self.assertEqual(second.received, [REQUEST])
            self.assertEqual(broker.received, [REQUEST] * 3)
            self.assertEqual(v4.received, [REQUEST] * 5)
            self.assertEqual(v6.received, [REQUEST, REQUEST])

    def test_sidecar_exact_unix_listener(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp", prefix="hq-sidecar-") as tmp, ExitStack() as stack:
            def listen(family, address, reply):
                service = Listener(family, address, lambda _: reply)
                stack.callback(service.close)
                return service

            v4 = listen(socket.AF_INET, ("127.0.0.1", 0), REPLY)
            v6 = listen(socket.AF_INET6, ("::1", 0), REPLY)
            broker = listen(socket.AF_UNIX, str(Path(tmp) / "broker.sock"), REPLY)
            member = listen(socket.AF_UNIX, str(Path(tmp) / "member.sock"), b"member ready\n")
            sibling = listen(socket.AF_UNIX, str(Path(tmp) / "sibling.sock"), REPLY)
            assigned = str(Path(tmp) / "sidecar.sock")
            other_bind = str(Path(tmp) / "other-bind.sock")
            args = ["/usr/bin/sandbox-exec", "-f", str(SIDECAR_PROFILE),
                    "-D", "BROKER_SOCKET=" + broker.address,
                    "-D", "MEMBER_SOCKET=" + member.address,
                    "-D", "LISTEN_SOCKET=" + assigned,
                    sys.executable, "-I", str(Path(__file__).resolve()), "--sidecar-child",
                    str(v4.address[1]), str(v6.address[1]), broker.address,
                    member.address, sibling.address, assigned, other_bind]
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                deadline = time.monotonic() + 5
                while not Path(assigned).exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not Path(assigned).exists():
                    stdout, stderr = process.communicate(timeout=5)
                    raise AssertionError(f"sidecar listener not ready: {process.returncode}: {stdout!r} {stderr!r}")
                # bind publishes the pathname before listen accepts. A busy
                # hosted runner can expose that short interval to this probe.
                while True:
                    try:
                        response = exchange(socket.AF_UNIX, assigned)
                        break
                    except (ConnectionRefusedError, FileNotFoundError):
                        if time.monotonic() >= deadline or process.poll() is not None:
                            raise
                        time.sleep(0.02)
                self.assertEqual(response, REPLY)
                stdout, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, (stdout, stderr))
            self.assertEqual(broker.received, [REQUEST])
            self.assertEqual(member.received, [REQUEST])
            self.assertEqual(sibling.received, [])
            self.assertEqual(v4.received, [])
            self.assertEqual(v6.received, [])
            self.assertFalse(Path(other_bind).exists())


if __name__ == "__main__":
    if sys.argv[1:2] == ["--child"]:
        child(*sys.argv[2:])
    elif sys.argv[1:2] == ["--sidecar-child"]:
        sidecar_child(*sys.argv[2:])
    else:
        unittest.main()
