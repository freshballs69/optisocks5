"""Blocking-sockets SOCKS5 clients over the agnostic core.

Two flavours that differ by exactly one feature — whether they wait between
handshake phases:

* :class:`OptimisticClient` — one ``sendall`` ships greeting+auth+request, then
  reads. 1 RTT; needs a byte-exact proxy.
* :class:`Client` — normal staged handshake, one RTT per phase, offers multiple
  auth methods and adapts to the server's choice. Works against a
  ``recv()``-per-phase proxy.
"""

from __future__ import annotations

import socket

from ..core import (
    Cmd,
    Method,
    Reply,
    Session,
    Socks5Error,
    client_greeting,
    parse_auth_reply,
    parse_method_selection,
    parse_reply,
    rep_name,
    request,
    userpass_auth,
)

__all__ = ["Client", "OptimisticClient"]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Socks5Error("proxy closed connection during handshake")
        buf += chunk
    return bytes(buf)


def _recv_reply(sock: socket.socket) -> Reply:
    """Read EXACTLY one reply — never a byte more, so post-handshake tunnel data
    (e.g. a server-first banner glued behind the reply) is left on the socket."""
    head = _recv_exact(sock, 4)  # VER REP RSV ATYP
    atyp = head[3]
    if atyp == 0x01:  # IPv4
        body = _recv_exact(sock, 4 + 2)
    elif atyp == 0x04:  # IPv6
        body = _recv_exact(sock, 16 + 2)
    elif atyp == 0x03:  # domain: 1 length byte, then that many + port
        length = _recv_exact(sock, 1)
        body = length + _recv_exact(sock, length[0] + 2)
    else:
        raise Socks5Error(f"reply has unknown ATYP {atyp}")
    parsed = parse_reply(head + body)
    if parsed is None:
        raise Socks5Error("malformed reply")
    return Reply(*parsed)


class _BaseClient:
    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
    ):
        if (username is None) != (password is None):
            raise ValueError("username and password must be given together")
        self.proxy = (proxy_host, proxy_port)
        self._user = username
        self._pass = password
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.bound: tuple[str, int] | None = None
        # Bytes read past the reply (server-first peers). Prepend before reading
        # the tunnel; always empty for the staged Client (it reads exactly).
        self.leftover: bytes = b""

    def _finish(self, s: socket.socket, reply: Reply) -> Reply:
        if not reply.ok:
            s.close()
            raise Socks5Error(f"request failed: {rep_name(reply.rep)} ({reply.rep})")
        self.sock = s
        self.bound = (reply.host, reply.port)
        return reply

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class OptimisticClient(_BaseClient):
    """Pipelines the whole handshake in one ``sendall``, then reads."""

    def connect(self, host: str, port: int, cmd: int = Cmd.CONNECT) -> Reply:
        sess = Session(self._user, self._pass)
        s = socket.create_connection(self.proxy, timeout=self.timeout)
        try:
            s.settimeout(self.timeout)
            s.sendall(sess.optimistic_pipeline(host, port, cmd))  # one shot
            reply: Reply | None = None
            while reply is None:
                chunk = s.recv(4096)
                if not chunk:
                    raise Socks5Error("proxy closed connection during handshake")
                reply = sess.feed(chunk)
            self.leftover = sess.leftover  # tunnel bytes the greedy read grabbed
        except BaseException:
            s.close()
            raise
        return self._finish(s, reply)


class Client(_BaseClient):
    """Normal staged client — one RTT per phase, multi-method greeting."""

    def connect(self, host: str, port: int, cmd: int = Cmd.CONNECT) -> Reply:
        have_auth = self._user is not None
        offered = [Method.USERPASS, Method.NO_AUTH] if have_auth else [Method.NO_AUTH]
        s = socket.create_connection(self.proxy, timeout=self.timeout)
        try:
            s.settimeout(self.timeout)
            s.sendall(client_greeting(bytes(offered)))
            chosen = parse_method_selection(_recv_exact(s, 2))
            if chosen is None:
                raise Socks5Error("malformed method selection")
            if chosen == Method.USERPASS:
                if not have_auth:
                    raise Socks5Error("proxy demands userpass but no creds given")
                s.sendall(userpass_auth(self._user, self._pass))
                status = parse_auth_reply(_recv_exact(s, 2))
                if status != 0:
                    raise Socks5Error(f"auth rejected (status {status})")
            elif chosen != Method.NO_AUTH:
                raise Socks5Error(f"no acceptable method (proxy chose {chosen})")
            s.sendall(request(cmd, host, port))
            reply = _recv_reply(s)
        except BaseException:
            s.close()
            raise
        return self._finish(s, reply)
