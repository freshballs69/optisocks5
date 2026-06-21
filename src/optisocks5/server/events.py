"""Intents emitted by the sans-IO :class:`~optisocks5.server.ServerSession`.

The session never touches a socket; it returns these so a driver (a blocking
poll loop, selectors, asyncio, or a C++ loop) performs the actual I/O and runs
the user hooks. This is the server-side mirror of NEED_READ / NEED_WRITE.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Send:
    """Write these bytes to the downstream (client) socket."""

    data: bytes


@dataclass(frozen=True)
class NeedData:
    """Read more bytes from downstream and feed them via ``session.receive()``."""


@dataclass(frozen=True)
class Authorize:
    """Run the ``authorize`` hook with these creds (None/None if the client chose
    no-auth), which must call ``session.ok(ctx)`` or ``session.reject()``."""

    username: str | None
    password: str | None


@dataclass(frozen=True)
class Connect:
    """Run the ``on_connect`` hook for this request, then open the upstream and
    report back with ``session.connected(bnd)`` / ``session.connect_failed(rep)``
    (unless the hook called ``session.reject()`` or ``session.set_target()``)."""

    cmd: int
    host: str
    port: int


@dataclass(frozen=True)
class Relay:
    """Handshake done — pump bytes both ways (default splice, or the custom pipe
    set via ``session.pipe()``). ``host``/``port`` is the resolved upstream."""

    host: str
    port: int


@dataclass(frozen=True)
class Close:
    """Tear the session down (any final Send was already emitted before this)."""

    reason: str


Event = Send | NeedData | Authorize | Connect | Relay | Close
