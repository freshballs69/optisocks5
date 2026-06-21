"""optisocks5 command-line interface.

Installed as the ``optisocks5`` console script (``pip install optisocks5[cli]``).
Three subcommands, all driving the library against a live SOCKS5 proxy:

    optisocks5 connect socks5://user:pass@HOST:PORT example.com:443
    optisocks5 fetch   socks5://user:pass@HOST:PORT ifconfig.me
    optisocks5 probe   socks5://user:pass@HOST:PORT example.com:80

`connect` runs one handshake (optimistic by default, `--staged` for RTT-per-phase)
and reports the reply, bound address, and timing. `fetch` does an HTTP/1.0 GET
over the tunnel (egress IP from ifconfig.me). `probe` runs BOTH handshakes and
reports which survive — the read-discipline fingerprint: a byte-exact proxy
passes optimistic, a recv()-per-phase one only passes staged.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from urllib.parse import urlparse

from .core import Cmd, Socks5Error, rep_name
from .sync import Client, OptimisticClient


def _parse_proxy(url: str) -> tuple[str, int, str | None, str | None]:
    u = urlparse(url if "://" in url else "socks5://" + url)
    if u.hostname is None or u.port is None:
        raise SystemExit(f"proxy must be host:port (got {url!r})")
    return u.hostname, u.port, u.username, u.password


def _split_target(target: str, default_port: int = 80) -> tuple[str, int]:
    if target.startswith("["):  # bracketed IPv6: [::1] or [::1]:443
        host, sep, rest = target[1:].partition("]")
        if sep and rest.startswith(":"):
            return host, int(rest[1:])
        return host, default_port
    if target.count(":") == 1:  # host:port (a bare IPv6 literal has many colons)
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, default_port


def _client(staged: bool, proxy: tuple, timeout: float):
    host, port, user, pw = proxy
    cls = Client if staged else OptimisticClient
    return cls(host, port, user, pw, timeout=timeout)


# ---- subcommands -----------------------------------------------------------


def cmd_connect(args: argparse.Namespace) -> int:
    proxy = _parse_proxy(args.proxy)
    host, port = _split_target(args.target, default_port=0)
    if port == 0:
        raise SystemExit("target must be host:port for `connect`")
    cmd = Cmd.UDP_ASSOCIATE if args.cmd == "associate" else Cmd.CONNECT
    client = _client(args.staged, proxy, args.timeout)
    mode = "staged" if args.staged else "optimistic"
    t0 = time.perf_counter()
    try:
        reply = client.connect(host, port, cmd)
    except (OSError, Socks5Error) as e:
        print(f"[{mode}] FAIL: {e}", file=sys.stderr)
        return 1
    dt = (time.perf_counter() - t0) * 1e3
    print(f"[{mode}] {rep_name(reply.rep)} bound={reply.host}:{reply.port} ({dt:.0f} ms)")
    client.close()
    return 0 if reply.ok else 1


def cmd_fetch(args: argparse.Namespace) -> int:
    proxy = _parse_proxy(args.proxy)
    hostport, _, rest = args.target.partition("/")  # split path off first
    path = "/" + rest
    host, dport = _split_target(hostport, default_port=80)
    client = _client(args.staged, proxy, args.timeout)
    try:
        dst_ip = socket.gethostbyname(host)  # gaierror is an OSError subclass
        reply = client.connect(dst_ip, dport)
    except (OSError, Socks5Error) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"[handshake] {rep_name(reply.rep)} bound={reply.host}:{reply.port}")
    with client:
        client.sock.sendall(
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
            f"User-Agent: curl/8\r\nConnection: close\r\n\r\n".encode()
        )
        client.sock.settimeout(5.0)  # don't rely on EOF; proxies hold tunnels open
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
    head, _, payload = body.decode(errors="replace").partition("\r\n\r\n")
    print(f"[http] {head.splitlines()[0] if head else '(no status line)'}")
    print(f"[body] {payload.strip()}")
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    proxy = _parse_proxy(args.proxy)
    host, port = _split_target(args.target, default_port=0)
    if port == 0:
        raise SystemExit("target must be host:port for `probe`")
    results = {}
    for mode, staged in (("optimistic", False), ("staged", True)):
        client = _client(staged, proxy, args.timeout)
        t0 = time.perf_counter()
        try:
            reply = client.connect(host, port)
            client.close()
            dt = (time.perf_counter() - t0) * 1e3
            results[mode] = (True, f"{rep_name(reply.rep)} ({dt:.0f} ms)")
        except (OSError, Socks5Error) as e:
            results[mode] = (False, str(e))
    for mode in ("optimistic", "staged"):
        ok, detail = results[mode]
        print(f"  {mode:<10} {'OK ' if ok else 'FAIL'} {detail}")
    opt_ok = results["optimistic"][0]
    staged_ok = results["staged"][0]
    if opt_ok and staged_ok:
        verdict = "byte-exact (optimistic pipelining safe)"
    elif staged_ok and not opt_ok:
        verdict = "recv-per-phase (desyncs on the pipeline; use staged)"
    elif opt_ok and not staged_ok:
        verdict = "anomalous (optimistic only — investigate)"
    else:
        verdict = "unreachable / both failed"
    print(f"  => {verdict}")
    return 0 if (opt_ok or staged_ok) else 1


# ---- argument parser -------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="optisocks5", description=(__doc__ or "optisocks5 CLI").splitlines()[0]
    )
    p.add_argument("--timeout", type=float, default=10.0, help="total handshake timeout (s)")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("connect", help="run one handshake and report the reply")
    c.add_argument("proxy", help="socks5://[user:pass@]host:port")
    c.add_argument("target", help="host:port")
    c.add_argument("--staged", action="store_true", help="RTT-per-phase handshake")
    c.add_argument("--cmd", choices=("connect", "associate"), default="connect")
    c.set_defaults(func=cmd_connect)

    f = sub.add_parser("fetch", help="HTTP/1.0 GET through the proxy (egress IP)")
    f.add_argument("proxy", help="socks5://[user:pass@]host:port")
    f.add_argument("target", help="host[/path] (port 80)")
    f.add_argument("--staged", action="store_true")
    f.set_defaults(func=cmd_fetch)

    pr = sub.add_parser("probe", help="optimistic vs staged read-discipline fingerprint")
    pr.add_argument("proxy", help="socks5://[user:pass@]host:port")
    pr.add_argument("target", help="host:port")
    pr.set_defaults(func=cmd_probe)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
