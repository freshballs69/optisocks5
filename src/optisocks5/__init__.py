"""optisocks5 — a sans-IO SOCKS5 codec (C++ core) with an optimistic client.

Layout:

* :mod:`optisocks5.core` — transport-agnostic: the codec (`client_greeting`,
  `request`, `parse_reply`, `udp_encapsulate`, ...) and the sans-IO
  :class:`~optisocks5.core.Session` (the optimistic handshake state machine).
  Nothing here touches a socket.
* :mod:`optisocks5.sync` — blocking-sockets drivers: :class:`Client` (staged) and
  :class:`OptimisticClient` (one-shot pipeline).
* :mod:`optisocks5.aio` — asyncio drivers: :class:`AsyncClient` and
  :class:`AsyncOptimisticClient`.

Every public name is re-exported here for convenience, so ``import optisocks5 as
s5; s5.OptimisticClient`` keeps working, but you can also import from the layer
you want directly (``from optisocks5.aio import AsyncOptimisticClient``).
"""

from .core import (
    Cmd,
    Method,
    Rep,
    Reply,
    Session,
    Socks5Error,
    client_greeting,
    parse_auth_reply,
    parse_method_selection,
    parse_reply,
    rep_name,
    request,
    udp_decapsulate,
    udp_encapsulate,
    userpass_auth,
)
from .sync import Client, OptimisticClient

__all__ = [
    # core / agnostic
    "Cmd",
    "Method",
    "Rep",
    "Reply",
    "Socks5Error",
    "Session",
    "rep_name",
    "client_greeting",
    "parse_method_selection",
    "userpass_auth",
    "parse_auth_reply",
    "request",
    "parse_reply",
    "udp_encapsulate",
    "udp_decapsulate",
    # sync drivers
    "Client",
    "OptimisticClient",
]


# The async clients and the whole server layer are exposed lazily so a bare
# `import optisocks5` doesn't pull in asyncio or the server unless asked.
_LAZY = {
    "AsyncClient": "optisocks5.aio",
    "AsyncOptimisticClient": "optisocks5.aio",
    "Server": "optisocks5.server",
    "AsyncServer": "optisocks5.server",
    "ServerSession": "optisocks5.server",
}


def __getattr__(name: str):
    mod = _LAZY.get(name)
    if mod is not None:
        import importlib

        return getattr(importlib.import_module(mod), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted([*__all__, *_LAZY])
