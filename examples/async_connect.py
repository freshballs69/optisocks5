"""Same optimistic handshake as OptimisticClient, but driven by asyncio — proof
that the Session core is event-loop-agnostic. The only code that changes between
blocking and async is the transport; the Session is identical.

    python examples/async_connect.py 127.0.0.1 1080 example.com 80
"""

import asyncio
import sys

import optisocks5 as s5


async def optimistic_connect(
    proxy_host: str,
    proxy_port: int,
    dst_host: str,
    dst_port: int,
    user: str | None = None,
    password: str | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, s5.Reply]:
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)
    sess = s5.Session(user, password)

    writer.write(sess.optimistic_pipeline(dst_host, dst_port))  # one shot
    await writer.drain()

    reply = None
    while reply is None:
        chunk = await reader.read(4096)
        if not chunk:
            raise s5.Socks5Error("proxy closed during handshake")
        reply = sess.feed(chunk)
    if not reply.ok:
        writer.close()
        raise s5.Socks5Error(f"request failed: {s5.rep_name(reply.rep)}")
    return reader, writer, reply


async def main() -> None:
    proxy_host, proxy_port, dst_host, dst_port = (
        sys.argv[1],
        int(sys.argv[2]),
        sys.argv[3],
        int(sys.argv[4]),
    )
    _reader, writer, reply = await optimistic_connect(
        proxy_host, proxy_port, dst_host, dst_port
    )
    print(f"tunnel up: bound={reply.host}:{reply.port}")
    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
