#!/usr/bin/env python3
"""A hook-driven SOCKS5 server that authorizes against a (fake) DB, can block or
redirect targets, and meters per-user bytes through a custom pipe — the runnable
version of the sketch.

    python examples/server_metered.py --port 1080
    # then:  curl -x socks5h://alice:pw@127.0.0.1:1080 http://ifconfig.me

The protocol is the sans-IO ServerSession; this file only wires hooks. The
`AtomicDataCounter` is just an example of atomically tallying relayed bytes.
"""

from __future__ import annotations

import argparse
import socket
import threading
from dataclasses import dataclass, field

from optisocks5.core import Rep
from optisocks5.server import Server, ServerSession


class AtomicDataCounter:
    """Thread-safe byte tally for one user."""

    def __init__(self, user_id: int):
        self.user_id = user_id
        self._n = 0
        self._lock = threading.Lock()

    def incr(self, n: int) -> int:
        with self._lock:
            self._n += n
            return self._n

    def total(self) -> int:
        with self._lock:
            return self._n


@dataclass
class Context:
    user_id: int
    _dc: AtomicDataCounter | None = field(default=None, repr=False)

    def counter(self) -> AtomicDataCounter:
        if self._dc is None:
            self._dc = AtomicDataCounter(self.user_id)
        return self._dc


class Db:
    """Stand-in user store: returns a uid for known creds, else None."""

    _users = {("alice", "pw"): 42}

    def get(self, username: str, password: str) -> int | None:
        return self._users.get((username, password))


db = Db()
server = Server[Context]()


@server.authorize
def authorize(s: ServerSession, username, password):
    uid = db.get(username or "", password or "")
    if uid is None:
        s.reject()  # -> auth failure, connection closed
    else:
        s.ok(Context(uid))  # bind a fresh ctx to this session


@server.on_connect
def on_connect(s: ServerSession, host: str, port: int):
    # Block a destination outright:
    if host in ("169.254.169.254",):  # cloud metadata, say no
        s.reject(Rep.NOT_ALLOWED)
        return
    # Or redirect somewhere else: s.set_target("127.0.0.1", 9999)
    # Default is transparent (connect to host:port the client asked for).
    # Meter every byte relayed, under this user's atomic counter:
    s.pipe(metered_pipe)


def metered_pipe(s: ServerSession):
    """Custom relay that tallies bytes instead of a plain splice."""
    counter = s.ctx.counter()

    def copy(src: socket.socket, dst: socket.socket):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                counter.incr(len(data))
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=copy, args=(s.downstream, s.upstream), daemon=True)
    t.start()
    copy(s.upstream, s.downstream)
    t.join()


@server.on_disconnect
def on_disconnect(s: ServerSession):
    if s.ctx is not None:
        print(f"[disconnect] user {s.ctx.user_id}: {s.ctx.counter().total()} bytes relayed")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=1080)
    args = ap.parse_args()
    host, port = server.bind(args.host, args.port)
    print(f"socks5 server on {host}:{port}  (user alice / pw)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.close()


if __name__ == "__main__":
    main()
