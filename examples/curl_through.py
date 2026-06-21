"""Optimistic equivalent of:

    curl -x socks5://user:pass@host:port http://TARGET/

Negotiates CONNECT through the proxy with the one-shot optimistic handshake
(greeting+auth+CONNECT in a single send), then does a plain HTTP/1.0 GET over
the tunnel and prints the response body — e.g. the egress IP from ifconfig.me.

    python examples/curl_through.py socks5://user:pass@141.11.99.3:12324 ifconfig.me
"""

import socket
import sys
from urllib.parse import urlparse

import optisocks5 as s5


def main() -> None:
    argv = sys.argv[1:]
    staged = "--staged" in argv
    argv = [a for a in argv if a != "--staged"]
    proxy_url, target = argv[0], argv[1]
    u = urlparse(proxy_url if "://" in proxy_url else "socks5://" + proxy_url)
    if u.hostname is None or u.port is None:
        raise SystemExit("proxy must be host:port (optionally socks5://user:pass@...)")

    path = "/"
    if "/" in target:
        target, path = target.split("/", 1)
        path = "/" + path

    # Resolve locally and hand the proxy an IP — this matches `curl -x socks5://`
    # (vs socks5h, which would ship the domain for the proxy to resolve). Some
    # proxies reply SUCCEEDED to a domain CONNECT yet never wire up the upstream.
    dst_ip = socket.gethostbyname(target)

    # --staged = normal RTT-per-phase client; default = optimistic one-shot.
    cls = s5.Client if staged else s5.OptimisticClient
    client = cls(u.hostname, u.port, u.username, u.password, timeout=15.0)
    reply = client.connect(dst_ip, 80)
    mode = "staged" if staged else "optimistic"
    print(f"[handshake/{mode}] {s5.rep_name(reply.rep)} bound={reply.host}:{reply.port}")

    with client:
        req = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {target}\r\n"  # keep the vhost name even though we dialed an IP
            "User-Agent: curl/8\r\n"  # ifconfig.me returns plain text for curl UA
            "Connection: close\r\n\r\n"
        )
        client.sock.sendall(req.encode())
        # Read what arrives; don't rely on EOF — many proxies hold the tunnel
        # open after the response instead of propagating the upstream close, so
        # a read timeout *with* a body in hand is success, not a dead upstream.
        client.sock.settimeout(5.0)
        body = bytearray()
        try:
            while True:
                chunk = client.sock.recv(4096)
                if not chunk:
                    break
                body += chunk
        except TimeoutError:
            if not body:
                print("[http] no response within 5s (upstream may be dead)")

    text = body.decode(errors="replace")
    head, _, payload = text.partition("\r\n\r\n")
    print(f"[http] {head.splitlines()[0] if head else '(no status line)'}")
    print(f"[body] {payload.strip()}")


if __name__ == "__main__":
    main()
