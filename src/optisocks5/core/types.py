"""Protocol enums, the parsed Reply, and the error type — all transport-agnostic."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Cmd(IntEnum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class Method(IntEnum):
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERPASS = 0x02
    NO_ACCEPTABLE = 0xFF


class Rep(IntEnum):
    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    NOT_ALLOWED = 0x02
    NET_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONN_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    CMD_NOT_SUPPORTED = 0x07
    ATYP_NOT_SUPPORTED = 0x08


def rep_name(rep: int) -> str:
    try:
        return Rep(rep).name
    except ValueError:
        return f"UNKNOWN({rep})"


class Socks5Error(Exception):
    """A SOCKS5 negotiation failed (bad method, auth rejected, error REP)."""


@dataclass(frozen=True)
class Reply:
    rep: int
    host: str  # BND.ADDR
    port: int  # BND.PORT

    @property
    def ok(self) -> bool:
        return self.rep == Rep.SUCCEEDED
