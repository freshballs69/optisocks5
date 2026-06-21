"""Pure SOCKS5 byte builders/parsers — thin wrappers over the C++ ``_core``.

No sockets, no event loop: every function turns structs into wire bytes or wire
bytes into structs. Drive them from any transport.
"""

from __future__ import annotations

from optisocks5 import _core

from .types import Cmd

# Direct re-exports (already keyword-arg-free, pure).
client_greeting = _core.client_greeting
parse_method_selection = _core.parse_method_selection
userpass_auth = _core.userpass_auth
parse_auth_reply = _core.parse_auth_reply
parse_reply = _core.parse_reply
udp_decapsulate = _core.udp_decapsulate


def request(cmd: int, host: str, port: int) -> bytes:
    """Build a SOCKS5 request (``VER CMD RSV ATYP ADDR PORT``)."""
    return _core.request(int(cmd), host, port)


def udp_encapsulate(host: str, port: int, payload: bytes, frag: int = 0) -> bytes:
    """Wrap `payload` for ``host:port`` (RFC 1928 §7 UDP request datagram)."""
    return _core.udp_encapsulate(host, port, payload, frag)


__all__ = [
    "client_greeting",
    "parse_method_selection",
    "userpass_auth",
    "parse_auth_reply",
    "parse_reply",
    "udp_decapsulate",
    "request",
    "udp_encapsulate",
    "Cmd",
]
