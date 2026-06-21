"""optisocks5.server — a hook-driven SOCKS5 server.

The protocol is a sans-IO state machine (:class:`ServerSession`) that emits
:mod:`~optisocks5.server.events` intents; :class:`Server` adds a decorator hook
API and a threaded reference driver. Swap the driver (selectors / asyncio / C++)
without touching the state machine.
"""

from . import events
from .aio import AsyncServer, async_splice
from .events import Authorize, Close, Connect, NeedData, Relay, Send
from .server import Server, splice
from .session import ServerSession

__all__ = [
    "Server",
    "AsyncServer",
    "ServerSession",
    "splice",
    "async_splice",
    "events",
    "Send",
    "NeedData",
    "Authorize",
    "Connect",
    "Relay",
    "Close",
]
