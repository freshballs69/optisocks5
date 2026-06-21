"""optisocks5.aio — asyncio SOCKS5 clients.

(Named ``aio`` rather than ``async`` because ``async`` is a Python keyword and
cannot be an importable module name.)
"""

from .client import AsyncClient, AsyncOptimisticClient

__all__ = ["AsyncClient", "AsyncOptimisticClient"]
