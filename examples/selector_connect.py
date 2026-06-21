"""Same optimistic handshake driven by a non-blocking socket + selectors — the
classic readiness loop. Only the transport differs from OptimisticClient; the
Session core is byte-identical.

Drives many proxies CONCURRENTLY on ONE thread: each connection carries its own
Session, and we pump whichever socket the selector reports ready.

    python examples/selector_connect.py example.com 80  127.0.0.1:1080 127.0.0.1:1081
"""

import selectors
import socket
import sys

import optisocks5 as s5


class PendingConnect:
    """One in-flight optimistic handshake on a non-blocking socket."""

    def __init__(self, proxy, dst, user=None, password=None):
        self.proxy = proxy
        self.sess = s5.Session(user, password)
        self.pipeline = self.sess.optimistic_pipeline(dst[0], dst[1])
        self.sent = 0
        self.reply: s5.Reply | None = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(False)
        # connect() on a non-blocking socket returns EINPROGRESS immediately.
        self.sock.connect_ex(proxy)

    def want(self) -> int:
        # Still flushing the one-shot pipeline -> wait writable; else readable.
        return selectors.EVENT_WRITE if self.sent < len(self.pipeline) else selectors.EVENT_READ

    def on_writable(self) -> None:
        self.sent += self.sock.send(self.pipeline[self.sent :])

    def on_readable(self) -> None:
        chunk = self.sock.recv(4096)
        if not chunk:
            raise s5.Socks5Error(f"{self.proxy} closed during handshake")
        self.reply = self.sess.feed(chunk)  # None until the reply is complete


def main() -> None:
    dst = (sys.argv[1], int(sys.argv[2]))
    proxies = [(h, int(p)) for h, p in (a.split(":") for a in sys.argv[3:])]

    sel = selectors.DefaultSelector()
    for proxy in proxies:
        pc = PendingConnect(proxy, dst)
        sel.register(pc.sock, pc.want(), pc)

    remaining = len(proxies)
    while remaining:
        for key, _ in sel.select(timeout=5.0):
            pc: PendingConnect = key.data
            try:
                if pc.want() & selectors.EVENT_WRITE:
                    pc.on_writable()
                else:
                    pc.on_readable()
            except (OSError, s5.Socks5Error) as e:
                print(f"{pc.proxy}: FAIL {e}")
                sel.unregister(pc.sock)
                pc.sock.close()
                remaining -= 1
                continue

            if pc.reply is not None:  # handshake done
                ok = "ok" if pc.reply.ok else s5.rep_name(pc.reply.rep)
                print(f"{pc.proxy}: {ok} bound={pc.reply.host}:{pc.reply.port}")
                sel.unregister(pc.sock)
                pc.sock.close()
                remaining -= 1
            else:
                sel.modify(pc.sock, pc.want(), pc)  # flip WRITE->READ as needed


if __name__ == "__main__":
    main()
