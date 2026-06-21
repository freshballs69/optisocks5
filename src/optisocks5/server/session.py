"""Sans-IO SOCKS5 *server* state machine.

Feed it downstream bytes with :meth:`ServerSession.receive`; pull intents with
:meth:`ServerSession.next_event`. It parses the greeting/auth/request with the
C++ server codec and emits :mod:`~optisocks5.server.events`; the driver does the
socket I/O and runs the hooks, calling the decision methods (`ok`, `reject`,
`set_target`, `pipe`, `connected`, `connect_failed`) in between.

No sockets, no event loop — a blocking, selectors, asyncio, or C++ driver can
all run the same machine.
"""

from __future__ import annotations

from collections import deque
from typing import Generic, TypeVar

from ..core import Method, Rep
from .._core import (
    auth_reply,
    method_selection,
    parse_greeting,
    parse_request,
    parse_userpass,
    reply,
)
from .events import Authorize, Close, Connect, Event, NeedData, Relay, Send

Ctx = TypeVar("Ctx")


def _request_len(buf: bytes) -> int | None:
    """Byte length of the request at the front of `buf`, or None if not yet
    determinable (VER CMD RSV ATYP then address)."""
    if len(buf) < 4:
        return None
    atyp = buf[3]
    if atyp == 0x01:
        return 4 + 4 + 2
    if atyp == 0x04:
        return 4 + 16 + 2
    if atyp == 0x03:
        if len(buf) < 5:
            return None
        return 4 + 1 + buf[4] + 2
    return None


class ServerSession(Generic[Ctx]):
    def __init__(self, require_auth: bool):
        self._require_auth = require_auth
        self._buf = bytearray()
        self._state = "greeting"
        self._out: deque[Event] = deque()

        # Set by the driver once the sockets exist; the sans-IO core never reads
        # or touches them — they're here so hooks / custom pipes can.
        self.downstream = None  # the SOCKS client socket/stream
        self.upstream = None  # the target / next-hop socket/stream

        # filled by hooks / driver between events
        self.ctx: Ctx | None = None
        self.cmd: int = 0
        self.target: tuple[str, int] | None = None  # resolved upstream
        self._custom_pipe = None
        self._intercept = False
        self._rejected = False
        self._rep = Rep.GENERAL_FAILURE
        self._connected_bnd: tuple[str, int] | None = None
        self._connect_failed = False

    # ---- driver feeds bytes -------------------------------------------------

    def receive(self, data: bytes) -> None:
        self._buf += data

    # ---- decision API (hooks / driver call these between events) ------------

    def ok(self, ctx: Ctx | None = None) -> None:
        """Accept the auth phase, binding `ctx` to the session."""
        self.ctx = ctx
        self._rejected = False

    def reject(self, rep: int = Rep.NOT_ALLOWED) -> None:
        """Reject the current phase (auth fails / request denied with `rep`)."""
        self._rejected = True
        self._rep = rep

    def set_target(self, host: str, port: int) -> None:
        """Override the upstream the request connects to (block/redirect)."""
        self.target = (host, port)

    def pipe(self, fn) -> None:
        """Replace the default bidirectional splice with a custom relay fn."""
        self._custom_pipe = fn

    def intercept(self, fn) -> None:
        """Serve this request from an IN-MEMORY handler: the driver opens NO real
        upstream — `fn(session)` reads the client and writes the reply itself.
        Used to fake a destination (e.g. answer ifconfig.me locally)."""
        self._custom_pipe = fn
        self._intercept = True

    @property
    def custom_pipe(self):
        return self._custom_pipe

    @property
    def intercepted(self) -> bool:
        return self._intercept

    def connected(self, bnd_host: str = "0.0.0.0", bnd_port: int = 0) -> None:
        """Driver opened the upstream; `bnd` is what to advertise in the reply."""
        self._connected_bnd = (bnd_host, bnd_port)

    def connect_failed(self, rep: int = Rep.HOST_UNREACHABLE) -> None:
        """Driver could not open the upstream."""
        self._connect_failed = True
        self._rep = rep

    # ---- driver pulls intents ----------------------------------------------

    def next_event(self) -> Event:
        if self._out:
            return self._out.popleft()
        return self._step()

    def _emit(self, *events: Event) -> Event:
        self._out.extend(events)
        return self._out.popleft()

    def _step(self) -> Event:
        st = self._state

        if st == "greeting":
            methods = parse_greeting(bytes(self._buf))
            if methods is None:
                return NeedData()
            del self._buf[: 2 + self._buf[1]]
            if not self._require_auth:
                self._state = "request"
                return self._emit(Send(method_selection(Method.NO_AUTH)))
            if Method.USERPASS in methods:
                self._state = "auth"
                return self._emit(Send(method_selection(Method.USERPASS)))
            self._state = "closed"
            return self._emit(
                Send(method_selection(Method.NO_ACCEPTABLE)),
                Close("no acceptable auth method"),
            )

        if st == "auth":
            up = parse_userpass(bytes(self._buf))
            if up is None:
                return NeedData()
            ulen = self._buf[1]
            plen = self._buf[2 + ulen]
            del self._buf[: 3 + ulen + plen]
            self._rejected = False
            self._state = "auth_wait"
            return Authorize(up[0], up[1])

        if st == "auth_wait":
            if self._rejected:
                self._state = "closed"
                return self._emit(Send(auth_reply(1)), Close("auth rejected"))
            self._state = "request"
            return self._emit(Send(auth_reply(0)))

        if st == "request":
            n = _request_len(bytes(self._buf))
            if n is None or len(self._buf) < n:
                return NeedData()
            parsed = parse_request(bytes(self._buf[:n]))
            if parsed is None:
                self._state = "closed"
                return self._emit(Close("malformed request"))
            del self._buf[:n]
            self.cmd, host, port = parsed
            self.target = (host, port)  # default: transparent (hook may override)
            self._rejected = False
            self._connected_bnd = None
            self._connect_failed = False
            self._state = "connect_wait"
            return Connect(self.cmd, host, port)

        if st == "connect_wait":
            if self._rejected:
                self._state = "closed"
                return self._emit(
                    Send(reply(self._rep, "0.0.0.0", 0)), Close("request rejected")
                )
            if self._connect_failed:
                self._state = "closed"
                return self._emit(
                    Send(reply(self._rep, "0.0.0.0", 0)), Close("upstream failed")
                )
            if self._connected_bnd is not None:
                self._state = "relay"
                bh, bp = self._connected_bnd
                tg = self.target or (bh, bp)
                return self._emit(Send(reply(Rep.SUCCEEDED, bh, bp)), Relay(tg[0], tg[1]))
            # Driver must report connected()/connect_failed()/reject() first.
            raise RuntimeError("connect_wait: no upstream decision was made")

        if st == "relay":
            self._state = "closed"
            return Close("relay finished")

        return Close("closed")
