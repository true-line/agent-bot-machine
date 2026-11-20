"""Exercise the test process's egress policy with a local fixture service only."""

import errno
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from threading import Thread
import unittest


PROFILE = Path(__file__).resolve().parents[2] / "internal/members/darwin/harness-egress.sb"
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


if __name__ == "__main__":
    if sys.argv[1:2] == ["--child"]:
        child(*sys.argv[2:])
    else:
        unittest.main()
