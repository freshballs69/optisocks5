#!/usr/bin/env python3
"""A simple asyncio SOCKS5 server with an in-memory upstream.

  * any username + password is accepted (the ctx remembers who);
  * CONNECT to ifconfig.me:80 is INTERCEPTED — no real upstream is dialed; we
    answer in-memory with an HTTP `hello, <username>` as if from ifconfig.me;
  * everything else is relayed to the real internet.

    python examples/async_server.py --port 1080
    curl -x socks5h://bob:whatever@127.0.0.1:1080 http://ifconfig.me    # -> hello, bob
    curl -x socks5h://bob:whatever@127.0.0.1:1080 https://ifconfig.me   # -> real site (TLS)
    curl -x socks5h://bob:whatever@127.0.0.1:1080 http://example.com    # -> real site

Only HTTP (port 80) is faked: the client sends a plaintext request we can read
and answer. HTTPS (443) is the client speaking TLS first — faking that needs a
trusted TLS cert (a MITM), so 443 is passed through to the real internet.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass

from optisocks5.server import AsyncServer, ServerSession

INTERCEPT_HOSTS = {"ifconfig.me"}


@dataclass
class Context:
    username: str  # which user this session authenticated as


server = AsyncServer[Context]()


@server.authorize
async def authorize(s: ServerSession, username, password):
    # Any non-empty username/password is valid; remember the user in the ctx.
    if username:
        s.ok(Context(username))
    else:
        s.reject()


@server.on_connect
async def on_connect(s: ServerSession, host: str, port: int):
    # Only plaintext HTTP (port 80) can be faked in-memory: the client sends a
    # readable HTTP request we can answer. On 443 the client speaks TLS first —
    # we'd have to be a trusted TLS server (a MITM) to fake it — so let it pass
    # through to the real internet instead.
    if host in INTERCEPT_HOSTS and port == 80:
        s.intercept(hello_upstream)  # serve from memory, dial nothing
    # else: transparent — the driver dials host:port for real.


async def hello_upstream(s: ServerSession):
    """In-memory 'ifconfig.me': read the client's HTTP request, reply with a
    body that greets the authenticated user."""
    reader, writer = s.downstream
    try:  # consume the request headers (we don't need them)
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError):
        pass
    body = f"hello, {s.ctx.username}\n".encode()
    writer.write(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )
    await writer.drain()
    writer.close()


async def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=1080)
    args = ap.parse_args()
    srv = await server.serve(args.host, args.port)
    addr = srv.sockets[0].getsockname()
    print(f"async socks5 server on {addr[0]}:{addr[1]}  (any user/pass; ifconfig.me faked)")
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
