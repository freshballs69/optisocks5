"""Server[Ctx] — decorator hook API + a threaded blocking reference driver.

The driver is deliberately thin: it owns sockets and runs the hooks, but all
protocol logic lives in the sans-IO :class:`ServerSession`. A selectors/asyncio
or C++ driver could replace it without touching the state machine.

    server = Server[Context]()

    @server.authorize
    def authorize(s, user, password):
        uid = db.get(user, password)
        s.ok(Context(uid)) if uid else s.reject()

    @server.on_connect
    def on_connect(s, host, port):
        if blocked(host): s.reject(Rep.NOT_ALLOWED)
        # else: transparent. Override with s.set_target(...) / s.pipe(...)

    server.serve("0.0.0.0", 1080)
"""

from __future__ import annotations

import errno
import socket
import threading
from typing import Callable, Generic, TypeVar

from ..core import Rep
from .events import Authorize, Close, Connect, NeedData, Relay, Send
from .session import ServerSession

Ctx = TypeVar("Ctx")

AuthHook = Callable[["ServerSession", "str | None", "str | None"], None]
ConnectHook = Callable[["ServerSession", str, int], None]
LifecycleHook = Callable[["ServerSession"], None]


class Server(Generic[Ctx]):
    def __init__(self, connect_timeout: float = 10.0, relay_timeout: float | None = None):
        self.connect_timeout = connect_timeout
        self.relay_timeout = relay_timeout  # idle teardown for the relay phase
        self._authorize: AuthHook | None = None
        self._on_connect: ConnectHook | None = None
        self._on_disconnect: LifecycleHook | None = None
        self._sock: socket.socket | None = None

    # ---- decorator hook registration ---------------------------------------

    def authorize(self, fn: AuthHook) -> AuthHook:
        """Register the auth hook. Its presence flips the server to require
        username/password; the hook must call ``s.ok(ctx)`` or ``s.reject()``."""
        self._authorize = fn
        return fn

    def on_connect(self, fn: ConnectHook) -> ConnectHook:
        """Register the per-request hook (block / redirect / override pipe)."""
        self._on_connect = fn
        return fn

    def on_disconnect(self, fn: LifecycleHook) -> LifecycleHook:
        """Register a teardown hook, run once the session ends."""
        self._on_disconnect = fn
        return fn

    def new_session(self) -> ServerSession[Ctx]:
        """A fresh sans-IO session with this server's auth policy (for custom
        drivers / tests)."""
        return ServerSession(self._authorize is not None)

    # ---- threaded blocking reference driver --------------------------------

    def bind(
        self, host: str, port: int, *, backlog: int = 128, reuse_port: bool = False
    ) -> tuple[str, int]:
        """Bind + listen; return the actual ``(host, port)`` (port 0 = ephemeral).
        Pair with :meth:`serve_forever` to run the accept loop in your own thread.
        ``reuse_port`` sets SO_REUSEPORT so several replicas can share the port."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if reuse_port and hasattr(socket, "SO_REUSEPORT"):
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        srv.bind((host, port))
        srv.listen(backlog)
        self._sock = srv
        return srv.getsockname()

    def serve_forever(self) -> None:
        srv = self._sock
        if srv is None:
            raise RuntimeError("call bind() first")
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError as e:
                    if self._sock is None or e.errno in (errno.EBADF, errno.EINVAL):
                        break  # listener was closed -> stop
                    continue  # transient (ECONNABORTED/EMFILE/EINTR) -> keep serving
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        finally:
            srv.close()
            self._sock = None

    def serve(
        self, host: str, port: int, *, backlog: int = 128, reuse_port: bool = False
    ) -> None:
        """Bind and run the accept loop (blocks). Convenience over bind/serve_forever."""
        self.bind(host, port, backlog=backlog, reuse_port=reuse_port)
        self.serve_forever()

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _handle(self, downstream: socket.socket) -> None:
        sess: ServerSession = ServerSession(self._authorize is not None)
        sess.downstream = downstream
        upstream: socket.socket | None = None
        try:
            while True:
                ev = sess.next_event()
                if isinstance(ev, Send):
                    downstream.sendall(ev.data)
                elif isinstance(ev, NeedData):
                    data = downstream.recv(4096)
                    if not data:
                        return
                    sess.receive(data)
                elif isinstance(ev, Authorize):
                    if self._authorize is not None:
                        try:
                            self._authorize(sess, ev.username, ev.password)
                        except Exception:  # noqa: BLE001 — a bad hook = auth failure
                            sess.reject()
                    else:
                        sess.ok(None)
                elif isinstance(ev, Connect):
                    if self._on_connect is not None:
                        try:
                            self._on_connect(sess, ev.host, ev.port)
                        except Exception:  # noqa: BLE001 — bad hook = general failure
                            sess.reject(Rep.GENERAL_FAILURE)
                    if sess.rejected:
                        pass  # state machine emits the error reply + Close
                    elif sess.intercepted:
                        sess.connected(ev.host, ev.port)  # serve in-memory, no dial
                    else:
                        upstream = self._dial(sess)
                elif isinstance(ev, Relay):
                    sess.upstream = upstream
                    self._relay(sess)
                    return
                elif isinstance(ev, Close):
                    return
        except (OSError, ConnectionError):
            pass
        finally:
            if self._on_disconnect is not None:
                try:
                    self._on_disconnect(sess)
                except Exception:  # noqa: BLE001 — teardown must not crash the thread
                    pass
            downstream.close()
            if upstream is not None:
                upstream.close()

    def _dial(self, sess: ServerSession) -> socket.socket | None:
        try:
            up = socket.create_connection(sess.target, timeout=self.connect_timeout)
            host, port = up.getsockname()[:2]  # IPv6 sockname has 4 fields
            sess.connected(host, port)
            return up
        except ConnectionRefusedError:
            sess.connect_failed(Rep.CONN_REFUSED)
        except (socket.timeout, TimeoutError):
            sess.connect_failed(Rep.TTL_EXPIRED)
        except OSError as e:
            sess.connect_failed(
                Rep.NET_UNREACHABLE if e.errno == errno.ENETUNREACH else Rep.HOST_UNREACHABLE
            )
        return None

    def _relay(self, sess: ServerSession) -> None:
        if sess.custom_pipe is not None:
            sess.custom_pipe(sess)  # user owns the exchange (e.g. metered copy)
            return
        splice(sess.downstream, sess.upstream, idle_timeout=self.relay_timeout)


def splice(a: socket.socket, b: socket.socket, idle_timeout: float | None = None) -> None:
    """Default bidirectional copy until either side closes (blocking sockets).
    `idle_timeout` (seconds) tears down a half-open silent peer instead of
    pinning the thread forever; None blocks until FIN."""
    if idle_timeout is not None:
        a.settimeout(idle_timeout)
        b.settimeout(idle_timeout)

    def copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:  # incl. socket.timeout on an idle stream
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=copy, args=(a, b), daemon=True)
    t.start()
    copy(b, a)
    t.join()
