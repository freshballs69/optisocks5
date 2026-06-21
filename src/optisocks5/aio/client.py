"""asyncio SOCKS5 clients over the agnostic core.

The async mirror of ``optisocks5.sync``: only the transport differs — the
optimistic one reuses the exact same sans-IO :class:`Session`. On success the
live tunnel is exposed as :attr:`reader` / :attr:`writer`.
"""

from __future__ import annotations

import asyncio
from typing import Self

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

__all__ = ["AsyncClient", "AsyncOptimisticClient"]


async def _read_reply(reader: asyncio.StreamReader) -> Reply:
    """Read EXACTLY one reply — no over-read, so post-handshake tunnel bytes stay
    buffered in the StreamReader for the caller."""
    head = await reader.readexactly(4)  # VER REP RSV ATYP
    atyp = head[3]
    if atyp == 0x01:  # IPv4
        body = await reader.readexactly(4 + 2)
    elif atyp == 0x04:  # IPv6
        body = await reader.readexactly(16 + 2)
    elif atyp == 0x03:  # domain
        length = await reader.readexactly(1)
        body = length + await reader.readexactly(length[0] + 2)
    else:
        raise Socks5Error(f"reply has unknown ATYP {atyp}")
    parsed = parse_reply(head + body)
    if parsed is None:
        raise Socks5Error("malformed reply")
    return Reply(*parsed)


class _BaseAsyncClient:
    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
        source_addr: tuple[str, int] | None = None,
    ):
        if (username is None) != (password is None):
            raise ValueError("username and password must be given together")
        self.proxy = (proxy_host, proxy_port)
        self._user = username
        self._pass = password
        self.timeout = timeout
        self._source_addr = source_addr  # bind the local end (e.g. spread src IPs)
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.bound: tuple[str, int] | None = None
        # Bytes read past the reply (server-first peers). Consume before reading
        # the tunnel; always empty for the staged AsyncClient (it reads exactly).
        self.leftover: bytes = b""

    async def _negotiate(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
        host: str, port: int, cmd: int,
    ) -> Reply:
        raise NotImplementedError

    async def connect(self, host: str, port: int, cmd: int = Cmd.CONNECT) -> Reply:
        if self.writer is not None:
            raise RuntimeError("client already connected; aclose() first")
        writer: asyncio.StreamWriter | None = None
        # One total budget over open + negotiate; a bound writer is always
        # reachable for cleanup, so a timeout mid-open can't leak the transport.
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_connection(
                    *self.proxy, local_addr=self._source_addr
                )
                reply = await self._negotiate(reader, writer, host, port, cmd)
        except BaseException:
            if writer is not None:
                await self._abort(writer)
            raise
        if not reply.ok:
            await self._abort(writer)
            raise Socks5Error(f"request failed: {rep_name(reply.rep)} ({reply.rep})")
        self.reader, self.writer = reader, writer
        self.bound = (reply.host, reply.port)
        return reply

    @staticmethod
    async def _abort(writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    async def aclose(self) -> None:
        if self.writer is not None:
            await self._abort(self.writer)
            self.writer = self.reader = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()


class AsyncOptimisticClient(_BaseAsyncClient):
    """Pipelines the whole handshake in one write — same Session as sync."""

    async def _negotiate(self, reader, writer, host, port, cmd) -> Reply:
        sess = Session(self._user, self._pass)
        writer.write(sess.optimistic_pipeline(host, port, cmd))  # one shot
        await writer.drain()
        reply: Reply | None = None
        while reply is None:
            chunk = await reader.read(4096)
            if not chunk:
                raise Socks5Error("proxy closed connection during handshake")
            reply = sess.feed(chunk)
        self.leftover = sess.leftover  # tunnel bytes the greedy read grabbed
        return reply


class AsyncClient(_BaseAsyncClient):
    """Normal staged async client — one RTT per phase, multi-method greeting."""

    async def _negotiate(self, reader, writer, host, port, cmd) -> Reply:
        have_auth = self._user is not None
        offered = [Method.USERPASS, Method.NO_AUTH] if have_auth else [Method.NO_AUTH]
        writer.write(client_greeting(bytes(offered)))
        await writer.drain()
        chosen = parse_method_selection(await reader.readexactly(2))
        if chosen is None:
            raise Socks5Error("malformed method selection")
        if chosen == Method.USERPASS:
            if not have_auth:
                raise Socks5Error("proxy demands userpass but no creds given")
            writer.write(userpass_auth(self._user, self._pass))
            await writer.drain()
            status = parse_auth_reply(await reader.readexactly(2))
            if status != 0:
                raise Socks5Error(f"auth rejected (status {status})")
        elif chosen != Method.NO_AUTH:
            raise Socks5Error(f"no acceptable method (proxy chose {chosen})")
        writer.write(request(cmd, host, port))
        await writer.drain()
        return await _read_reply(reader)
