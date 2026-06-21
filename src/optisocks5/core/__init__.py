"""optisocks5.core — the transport-agnostic protocol: codec + sans-IO Session.

Nothing here touches a socket or an event loop. The blocking driver lives in
``optisocks5.sync``; the asyncio driver in ``optisocks5.aio``.
"""

from .codec import (
    client_greeting,
    parse_auth_reply,
    parse_method_selection,
    parse_reply,
    request,
    udp_decapsulate,
    udp_encapsulate,
    userpass_auth,
)
from .session import Session
from .types import Cmd, Method, Rep, Reply, Socks5Error, rep_name

__all__ = [
    "Cmd",
    "Method",
    "Rep",
    "Reply",
    "Socks5Error",
    "rep_name",
    "Session",
    "client_greeting",
    "parse_method_selection",
    "userpass_auth",
    "parse_auth_reply",
    "request",
    "parse_reply",
    "udp_encapsulate",
    "udp_decapsulate",
]
