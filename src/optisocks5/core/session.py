"""Sans-IO state machine for the optimistic SOCKS5 handshake.

No sockets, no blocking — bring your own loop (see ``optisocks5.sync`` /
``optisocks5.aio``). Feed :meth:`Session.optimistic_pipeline` bytes to the
transport in one shot, then push every received chunk through :meth:`Session.feed`
until it returns a :class:`Reply`.
"""

from __future__ import annotations

from .codec import (
    client_greeting,
    parse_auth_reply,
    parse_method_selection,
    parse_reply,
    request,
    userpass_auth,
)
from .types import Cmd, Method, Reply, Socks5Error


def reply_size(buf: bytes) -> int | None:
    """Exact byte length of the reply at the front of `buf`, or None if not yet
    enough bytes to even tell (needs ≥5 for a domain ATYP, ≥4 otherwise)."""
    if len(buf) < 4:
        return None
    atyp = buf[3]
    if atyp == 0x01:  # IPv4
        return 4 + 4 + 2
    if atyp == 0x04:  # IPv6
        return 4 + 16 + 2
    if atyp == 0x03:  # domain
        if len(buf) < 5:
            return None
        return 4 + 1 + buf[4] + 2
    return None  # unknown ATYP


class Session:
    """Sans-IO driver for the optimistic handshake.

    Optimism = commit to a single auth method up front (so the server's choice is
    predictable) and pipeline greeting+auth+request in one send instead of paying
    an RTT per phase. A byte-exact proxy survives it; a ``recv()``-per-phase proxy
    desyncs.
    """

    def __init__(self, username: str | None = None, password: str | None = None):
        if (username is None) != (password is None):
            raise ValueError("username and password must be given together")
        self._user = username
        self._pass = password
        self._auth = username is not None
        self._buf = bytearray()
        self._state = "method"
        self._reply: Reply | None = None

    @property
    def method(self) -> Method:
        """The single auth method we optimistically commit to."""
        return Method.USERPASS if self._auth else Method.NO_AUTH

    def optimistic_pipeline(self, host: str, port: int, cmd: int = Cmd.CONNECT) -> bytes:
        """Greeting + (auth) + request, glued for a single ``send``."""
        out = bytearray(client_greeting(bytes([self.method])))
        if self._auth:
            out += userpass_auth(self._user, self._pass)
        out += request(cmd, host, port)
        return bytes(out)

    def feed(self, data: bytes) -> Reply | None:
        """Consume proxy reply bytes. Returns the final :class:`Reply` once the
        whole handshake is parsed, else ``None`` (need more bytes).

        Raises :class:`Socks5Error` if the proxy picks an unexpected method or
        rejects auth — the typical symptoms of a non-byte-exact reader desyncing
        on the pipelined bytes.
        """
        self._buf += data
        while True:
            if self._state == "method":
                if len(self._buf) < 2:
                    return None
                m = parse_method_selection(bytes(self._buf[:2]))
                if m is None:
                    raise Socks5Error("malformed method selection")
                if m != self.method:
                    raise Socks5Error(
                        f"proxy chose method {m}, we offered only {int(self.method)}"
                    )
                del self._buf[:2]
                self._state = "auth" if self._auth else "reply"
            elif self._state == "auth":
                if len(self._buf) < 2:
                    return None
                status = parse_auth_reply(bytes(self._buf[:2]))
                if status is None:
                    raise Socks5Error("malformed auth reply")
                if status != 0:
                    raise Socks5Error(f"auth rejected (status {status})")
                del self._buf[:2]
                self._state = "reply"
            elif self._state == "reply":
                n = reply_size(bytes(self._buf))
                if n is None or len(self._buf) < n:
                    return None  # reply not fully arrived yet
                parsed = parse_reply(bytes(self._buf[:n]))
                if parsed is None:
                    raise Socks5Error("malformed reply")
                del self._buf[:n]  # keep only bytes past the reply
                self._reply = Reply(*parsed)
                self._state = "done"
                return self._reply
            else:
                return self._reply

    @property
    def leftover(self) -> bytes:
        """Bytes received past the reply. Because the optimistic read is greedy,
        a server-speaks-first peer's first bytes can arrive glued behind the
        SOCKS reply; once :meth:`feed` returns a Reply, prepend this to the
        tunnel stream so none are lost. Empty for client-speaks-first peers."""
        return bytes(self._buf) if self._state == "done" else b""
