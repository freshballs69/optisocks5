"""AsyncServer — an asyncio driver over the sans-IO :class:`ServerSession`.

Same decorator hook API as the threaded :class:`~optisocks5.server.Server`, but
on Python's event loop. Hooks may be sync or ``async``. In the relay phase the
session's streams are exposed as ``(reader, writer)`` tuples:
``session.downstream`` always, ``session.upstream`` for a real dialled target
(``None`` for an in-memory ``session.intercept()``).
"""

from __future__ import annotations

import asyncio
import errno
import inspect
from typing import Callable, Generic, TypeVar

from ..core import Rep
from .events import Authorize, Close, Connect, NeedData, Relay, Send
from .session import ServerSession

Ctx = TypeVar("Ctx")


async def _maybe_await(result):
    if inspect.isawaitable(result):
        return await result
    return result


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            pass


async def async_splice(down, up) -> None:
    """Bidirectional copy between two (reader, writer) stream pairs."""
    dr, dw = down
    ur, uw = up
    await asyncio.gather(_pump(dr, uw), _pump(ur, dw))


class AsyncServer(Generic[Ctx]):
    def __init__(self, connect_timeout: float = 10.0):
        self.connect_timeout = connect_timeout
        self._authorize: Callable | None = None
        self._on_connect: Callable | None = None
        self._on_disconnect: Callable | None = None
        self._server: asyncio.Server | None = None

    # ---- decorator hooks (same API as the sync Server) ----------------------

    def authorize(self, fn):
        self._authorize = fn
        return fn

    def on_connect(self, fn):
        self._on_connect = fn
        return fn

    def on_disconnect(self, fn):
        self._on_disconnect = fn
        return fn

    def new_session(self) -> ServerSession[Ctx]:
        return ServerSession(self._authorize is not None)

    # ---- driver -------------------------------------------------------------

    async def serve(
        self, host: str, port: int, *, reuse_port: bool = False
    ) -> asyncio.Server:
        # reuse_port=True (SO_REUSEPORT) lets several proxy replicas bind the same
        # (host, port); the kernel load-balances accepts across them.
        self._server = await asyncio.start_server(
            self._handle, host, port, reuse_port=reuse_port
        )
        return self._server

    async def serve_forever(
        self, host: str, port: int, *, reuse_port: bool = False
    ) -> None:
        server = await self.serve(host, port, reuse_port=reuse_port)
        async with server:
            await server.serve_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sess: ServerSession = ServerSession(self._authorize is not None)
        sess.downstream = (reader, writer)
        upstream = None
        try:
            while True:
                ev = sess.next_event()
                if isinstance(ev, Send):
                    writer.write(ev.data)
                    await writer.drain()
                elif isinstance(ev, NeedData):
                    data = await reader.read(4096)
                    if not data:
                        return
                    sess.receive(data)
                elif isinstance(ev, Authorize):
                    if self._authorize is not None:
                        try:
                            await _maybe_await(self._authorize(sess, ev.username, ev.password))
                        except Exception:  # noqa: BLE001 — bad hook = auth failure
                            sess.reject()
                    else:
                        sess.ok(None)
                elif isinstance(ev, Connect):
                    if self._on_connect is not None:
                        try:
                            await _maybe_await(self._on_connect(sess, ev.host, ev.port))
                        except Exception:  # noqa: BLE001 — bad hook = general failure
                            sess.reject(Rep.GENERAL_FAILURE)
                    if sess.rejected:
                        pass  # next_event emits the error reply + Close
                    elif sess.intercepted:
                        sess.connected(ev.host, ev.port)  # no real dial
                    else:
                        upstream = await self._dial(sess)
                elif isinstance(ev, Relay):
                    sess.upstream = upstream
                    if sess.custom_pipe is not None:
                        await _maybe_await(sess.custom_pipe(sess))
                    elif upstream is not None:
                        await async_splice(sess.downstream, upstream)
                    return
                elif isinstance(ev, Close):
                    return
        except (OSError, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            if self._on_disconnect is not None:
                try:
                    await _maybe_await(self._on_disconnect(sess))
                except Exception:  # noqa: BLE001
                    pass
            writer.close()
            if upstream is not None:
                try:
                    upstream[1].close()
                except OSError:
                    pass

    async def _dial(self, sess: ServerSession):
        try:
            ur, uw = await asyncio.wait_for(
                asyncio.open_connection(*sess.target), self.connect_timeout
            )
            sess.connected(*uw.get_extra_info("sockname")[:2])
            return (ur, uw)
        except ConnectionRefusedError:
            sess.connect_failed(Rep.CONN_REFUSED)
        except (asyncio.TimeoutError, TimeoutError):
            sess.connect_failed(Rep.TTL_EXPIRED)
        except OSError as e:
            sess.connect_failed(
                Rep.NET_UNREACHABLE if e.errno == errno.ENETUNREACH else Rep.HOST_UNREACHABLE
            )
        return None
