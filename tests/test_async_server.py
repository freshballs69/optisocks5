"""AsyncServer end-to-end: our AsyncClient drives our asyncio server, whose
in-memory intercept fakes ifconfig.me and greets the authenticated user."""

import asyncio

import optisocks5 as s5
from optisocks5.aio import AsyncClient
from optisocks5.server import AsyncServer, ServerSession
from optisocks5.server import aio as _aio


def test_pump_survives_write_to_closed_transport():
    # uvloop raises RuntimeError ("handler is closed") when the peer dropped
    # while this side is still pumping; _pump must swallow it, not crash the task.
    class Reader:
        def __init__(self):
            self.n = 0

        async def read(self, _):
            self.n += 1
            return b"x" if self.n == 1 else b""

    class ClosedWriter:
        def is_closing(self):
            return False

        def write(self, data):
            raise RuntimeError("unable to perform operation; the handler is closed")

        async def drain(self):
            pass

        def write_eof(self):
            pass

    asyncio.run(_aio._pump(Reader(), ClosedWriter()))  # must not raise


def _build_server() -> AsyncServer:
    server = AsyncServer()

    @server.authorize
    async def authorize(s: ServerSession, username, password):
        if username:  # any non-empty user is valid
            s.ok({"user": username})
        else:
            s.reject()

    @server.on_connect
    async def on_connect(s: ServerSession, host, port):
        if host == "ifconfig.me":
            s.intercept(hello)

    async def hello(s: ServerSession):
        reader, writer = s.downstream
        try:
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        body = f"hello, {s.ctx['user']}".encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()

    return server


def test_async_server_intercepts_ifconfig():
    async def run() -> bytes:
        server = _build_server()
        srv = await server.serve("127.0.0.1", 0)
        host, port = srv.sockets[0].getsockname()

        client = AsyncClient(host, port, "bob", "whatever")
        reply = await client.connect("ifconfig.me", 80)  # domain -> intercepted
        assert reply.ok
        client.writer.write(b"GET / HTTP/1.0\r\nHost: ifconfig.me\r\n\r\n")
        await client.writer.drain()
        data = await client.reader.read(4096)
        await client.aclose()
        srv.close()
        await srv.wait_closed()
        return data

    data = asyncio.run(run())
    assert b"hello, bob" in data


def test_async_server_rejects_empty_user():
    async def run() -> bool:
        server = _build_server()
        srv = await server.serve("127.0.0.1", 0)
        host, port = srv.sockets[0].getsockname()
        # empty username -> authorize rejects -> auth failure
        client = AsyncClient(host, port, "", "")
        rejected = False
        try:
            await client.connect("ifconfig.me", 80)
        except s5.Socks5Error:
            rejected = True
        await client.aclose()
        srv.close()
        await srv.wait_closed()
        return rejected

    assert asyncio.run(run())
