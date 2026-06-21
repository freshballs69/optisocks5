#!/usr/bin/env python3
"""proxy-test (optisocks5 edition) — a battery of SOCKS5 behaviour cases against
one proxy, each with a verdict + timings, built entirely on the optisocks5 lib.

Where a case is a single handshake it uses the high-level clients
(`optisocks5.sync.Client` / `OptimisticClient`); the multi-hop / multi-command
cases drive `optisocks5.core` codec bytes over one socket directly — which is the
whole point of the sans-IO core.

Cases (TCP / SOCKS5 control-channel only; the UDP/STUN cases live in the parent
udp-relay-intelligence toolkit):
  1 plain       does a staged CONNECT to --dst work at all
  2 optimistic  pipeline greeting+auth+CONNECT in ONE send (+HTTP) — all replies
                back => BYTE-EXACT reader; stall => RECV-DISCARD
  3 chain xN    pessimistic self-chain to --depth (proxy CONNECTs to itself)
  4 opt-chain   the same chain pipelined optimistically in one send
  5 commands    which commands it honours: CONNECT / BIND / UDP-ASSOCIATE
  6 loop-127    depth-2 self-chain whose inner hop CONNECTs to 127.0.0.1

    python examples/proxy_test.py --proxy user:pass@host:1080 --dst 1.1.1.1:80
"""

from __future__ import annotations

import argparse
import socket
import time

from optisocks5.core import (
    Cmd,
    Method,
    Socks5Error,
    client_greeting,
    parse_auth_reply,
    parse_method_selection,
    parse_reply,
    rep_name,
    request,
    userpass_auth,
)
from optisocks5.sync import Client, OptimisticClient


# ---- proxy spec / small socket helpers (codec does the SOCKS5 bytes) -------


def hostport(s: str) -> tuple[str, int]:
    h, p = s.rsplit(":", 1)
    return h, int(p)


def parse_proxy(spec: str, user: str, pw: str):
    if "@" in spec:
        cred, spec = spec.rsplit("@", 1)
        user, _, pw = cred.partition(":")
    h, p = hostport(spec)
    return h, p, user or None, pw or None


def recvn(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("peer closed")
        buf += chunk
    return bytes(buf)


def negotiate(sock: socket.socket, user, pw) -> None:
    """Greeting + auth on `sock`, using the codec. Reusable per chain hop."""
    offered = [Method.USERPASS, Method.NO_AUTH] if user else [Method.NO_AUTH]
    sock.sendall(client_greeting(bytes(offered)))
    method = parse_method_selection(recvn(sock, 2))
    if method == Method.USERPASS:
        sock.sendall(userpass_auth(user, pw))
        if parse_auth_reply(recvn(sock, 2)) != 0:
            raise Socks5Error("auth rejected")
    elif method != Method.NO_AUTH:
        raise Socks5Error(f"no acceptable method {method}")


def read_reply(sock: socket.socket):
    """Read EXACTLY one reply (no tunnel over-read) -> (rep, host, port)."""
    head = recvn(sock, 4)  # VER REP RSV ATYP
    atyp = head[3]
    if atyp == 0x01:
        rest = recvn(sock, 4 + 2)
    elif atyp == 0x04:
        rest = recvn(sock, 16 + 2)
    elif atyp == 0x03:
        ln = recvn(sock, 1)
        rest = ln + recvn(sock, ln[0] + 2)
    else:
        raise Socks5Error(f"bad reply ATYP {atyp}")
    parsed = parse_reply(head + rest)
    if parsed is None:
        raise Socks5Error("malformed reply")
    return parsed


def ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 1)


def http_get(host: str, path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
        "User-Agent: optisocks5-proxy-test\r\nConnection: close\r\n\r\n"
    ).encode()


def greet_blob(user, pw) -> bytes:
    """One auth method only — the optimistic commitment used in pipelined blobs."""
    method = Method.USERPASS if user else Method.NO_AUTH
    blob = bytearray(client_greeting(bytes([method])))
    if user:
        blob += userpass_auth(user, pw)
    return bytes(blob)


# ---- cases ------------------------------------------------------------------


def case_plain(P, dst, to):
    ph, pp, user, pw = P
    r = {"timings": {}}
    t0 = time.perf_counter()
    client = Client(ph, pp, user, pw, timeout=to)
    try:
        reply = client.connect(dst[0], dst[1])
        client.close()
        r["timings"]["est"] = ms(t0)
        r["ok"] = reply.ok
        r["verdict"] = "connects" if reply.ok else rep_name(reply.rep)
    except (OSError, Socks5Error) as e:
        r["ok"] = False
        r["verdict"] = f"FAIL: {e}"
    return r


def case_optimistic(P, dst, to, path):
    ph, pp, user, pw = P
    r = {"timings": {}}
    t0 = time.perf_counter()
    client = OptimisticClient(ph, pp, user, pw, timeout=to)
    try:
        reply = client.connect(dst[0], dst[1])  # one-shot pipeline
    except (OSError, Socks5Error) as e:
        r["timings"]["total"] = ms(t0)
        r["ok"] = False
        r["verdict"] = f"RECV-DISCARD / stalled ({e})"
        return r
    if not reply.ok:
        r["ok"] = False
        r["verdict"] = f"CONNECT {rep_name(reply.rep)}"
        client.close()
        return r
    r["timings"]["est"] = ms(t0)  # handshake done, all SOCKS replies in order
    # All replies came back => byte-exact reader. HTTP is just confirmation that
    # post-CONNECT glued bytes get forwarded.
    with client:
        client.sock.sendall(http_get(dst[0], path))
        client.sock.settimeout(min(to, 2.5))
        try:
            first = (client.leftover + recvn(client.sock, 12))[:12]
            r["verdict"] = (
                "BYTE-EXACT"
                if first.startswith(b"HTTP/")
                else f"BYTE-EXACT (non-HTTP dst: {first[:8]!r})"
            )
        except (TimeoutError, EOFError):
            r["verdict"] = "BYTE-EXACT (SOCKS replies OK; no HTTP — upstream slow/blocked)"
    r["timings"]["total"] = ms(t0)
    r["ok"] = True
    return r


def case_chain(P, self_addr, dst, depth, to):
    ph, pp, user, pw = P
    r = {"timings": {}, "layers": []}
    t0 = time.perf_counter()
    s = socket.create_connection((ph, pp), timeout=to)
    s.settimeout(to)
    reached = 0
    try:
        for i in range(depth):
            th, tp = self_addr if i < depth - 1 else dst
            negotiate(s, user, pw)
            t = time.perf_counter()
            s.sendall(request(Cmd.CONNECT, th, tp))
            rep, _, _ = read_reply(s)
            r["layers"].append(ms(t))
            if rep != 0:
                r["broke_rep"] = rep
                break
            reached = i + 1
    except (OSError, Socks5Error, EOFError) as e:
        r["broke_err"] = str(e)
    s.close()
    r["timings"]["est"] = ms(t0)
    r["timings"]["per_layer"] = r.pop("layers")
    r["ok"] = reached >= depth
    r["verdict"] = f"depth {reached}/{depth}" + (
        f" (broke {rep_name(r['broke_rep'])})" if "broke_rep" in r else ""
    )
    return r


def case_optimistic_chain(P, self_addr, dst, depth, to, path):
    ph, pp, user, pw = P
    r = {"timings": {}}
    t0 = time.perf_counter()
    s = socket.create_connection((ph, pp), timeout=to)
    s.settimeout(min(to, 2.5))
    blob = bytearray()
    for i in range(depth):
        th, tp = self_addr if i < depth - 1 else dst
        blob += greet_blob(user, pw)
        blob += request(Cmd.CONNECT, th, tp)
    blob += http_get(dst[0], path)
    s.sendall(bytes(blob))  # the whole nested chain in one send
    reached = 0
    try:
        for i in range(depth):
            method = parse_method_selection(recvn(s, 2))
            if method == Method.USERPASS and parse_auth_reply(recvn(s, 2)) != 0:
                raise Socks5Error("auth rejected")
            rep, _, _ = read_reply(s)
            if rep != 0:
                break
            reached = i + 1
        if reached == depth:
            r["timings"]["est"] = ms(t0)
            r["byte_exact"] = recvn(s, 12).startswith(b"HTTP/")
    except (OSError, Socks5Error, EOFError):
        pass
    s.close()
    r["timings"]["total"] = ms(t0)
    r["ok"] = reached >= depth
    be = " byte-exact" if r.get("byte_exact") else ""
    r["verdict"] = f"depth {reached}/{depth}{be}"
    return r


def case_commands(P, dst, to):
    ph, pp, user, pw = P
    r = {"timings": {}, "cmds": {}}
    names = {Cmd.CONNECT: "CONNECT", Cmd.BIND: "BIND", Cmd.UDP_ASSOCIATE: "ASSOCIATE"}
    for cmd, name in names.items():
        try:
            s = socket.create_connection((ph, pp), timeout=to)
            s.settimeout(to)
            negotiate(s, user, pw)
            t = time.perf_counter()
            # BIND/ASSOCIATE addr is where the client will send from: 0.0.0.0:0
            tgt = dst if cmd == Cmd.CONNECT else ("0.0.0.0", 0)
            s.sendall(request(cmd, tgt[0], tgt[1]))
            rep, bh, bp = read_reply(s)
            r["cmds"][name] = {"rep": rep, "bnd": f"{bh}:{bp}", "ms": ms(t)}
            s.close()
        except (OSError, Socks5Error, EOFError) as e:
            r["cmds"][name] = {"rep": None, "err": type(e).__name__, "ms": None}
    assoc = r["cmds"]["ASSOCIATE"]
    r["ok"] = assoc.get("rep") == 0
    r["verdict"] = "UDP-ASSOCIATE " + (
        "supported, BND=" + assoc["bnd"] if r["ok"] else f"{rep_name(assoc.get('rep') or 1)}"
    )
    return r


def case_loop127(P, self_addr, loop_dst, to):
    ph, pp, user, pw = P
    r = {"timings": {}}
    s = socket.create_connection((ph, pp), timeout=to)
    s.settimeout(to)
    try:
        negotiate(s, user, pw)
        t = time.perf_counter()
        s.sendall(request(Cmd.CONNECT, self_addr[0], self_addr[1]))  # hop1 -> self
        rep1, _, _ = read_reply(s)
        r["timings"]["hop1"] = ms(t)
        if rep1 != 0:
            r["ok"] = False
            r["verdict"] = f"self-hop {rep_name(rep1)}"
            return r
        negotiate(s, user, pw)  # now talking to the inner proxy
        t = time.perf_counter()
        s.sendall(request(Cmd.CONNECT, loop_dst[0], loop_dst[1]))
        rep2, _, _ = read_reply(s)
        r["timings"]["hop2_127"] = ms(t)
        r["ok"] = rep2 == 0
        r["verdict"] = (
            f"loopback {loop_dst[0]}:{loop_dst[1]} REACHABLE"
            if rep2 == 0
            else f"blocked ({rep_name(rep2)})"
        )
    except (OSError, Socks5Error, EOFError) as e:
        r["ok"] = False
        r["verdict"] = f"FAIL: {e}"
    finally:
        s.close()
    return r


# ---- driver -----------------------------------------------------------------


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--proxy", required=True, help="[user:pass@]host:port")
    ap.add_argument("--user", default="")
    ap.add_argument("--pass", dest="pw", default="")
    ap.add_argument("--dst", default="www.gstatic.com:80", help="HTTP dst for plain/optimistic")
    ap.add_argument("--self", dest="self_addr", help="how the proxy reaches itself (default --proxy)")
    ap.add_argument("--loop-dst", help="2nd-hop loopback target (default 127.0.0.1:<proxy-port>)")
    ap.add_argument("--depth", type=int, default=3)
    ap.add_argument("--path", default="/generate_204", help="HTTP path for byte-exact probes")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--only", help="comma list of case numbers (e.g. 2,5)")
    args = ap.parse_args()

    P = parse_proxy(args.proxy, args.user, args.pw)
    dst = hostport(args.dst)
    self_addr = hostport(args.self_addr) if args.self_addr else (P[0], P[1])
    loop_dst = hostport(args.loop_dst) if args.loop_dst else ("127.0.0.1", P[1])
    to = args.timeout

    print(f"proxy {P[0]}:{P[1]}  auth={'user/pass' if P[2] else 'none'}  dst {dst[0]}:{dst[1]}\n")

    cases = [
        ("1 plain", lambda: case_plain(P, dst, to)),
        ("2 optimistic", lambda: case_optimistic(P, dst, to, args.path)),
        (f"3 chain x{args.depth}", lambda: case_chain(P, self_addr, dst, args.depth, to)),
        (f"4 opt-chain x{args.depth}", lambda: case_optimistic_chain(P, self_addr, dst, args.depth, to, args.path)),
        ("5 commands", lambda: case_commands(P, dst, to)),
        ("6 loop-127", lambda: case_loop127(P, self_addr, loop_dst, to)),
    ]
    only = set(args.only.split(",")) if args.only else None

    est = {}
    for label, fn in cases:
        num = label.split()[0]
        if only and num not in only:
            continue
        try:
            t0 = time.perf_counter()
            r = fn()
            wall = ms(t0)
            est[num] = (r["timings"].get("est"), r.get("ok"))
            mark = "OK " if r.get("ok") else "-- "
            tim = "  ".join(
                f"{k}={v}" for k, v in r["timings"].items() if not isinstance(v, list)
            )
            pl = r["timings"].get("per_layer")
            if pl:
                tim += "  layers=" + "/".join(str(x) for x in pl)
            print(f"[{mark}] {label:<16} {r['verdict']:<46} {tim} ms  (wall {wall})")
            for name, c in r.get("cmds", {}).items():
                print(
                    f"          {name:<10} rep={c.get('rep')} "
                    f"{c.get('bnd', c.get('err', ''))} ({c.get('ms')} ms)"
                )
        except Exception as e:  # noqa: BLE001
            print(f"[ERR] {label:<16} {type(e).__name__}: {e}")

    def speedup(pess, opt, name):
        if pess in est and opt in est:
            pe, _ = est[pess]
            oe, ook = est[opt]
            if ook and pe and oe and oe > 0:
                print(f"{name}: pessimistic {pe}ms -> optimistic {oe}ms  =>  {pe / oe:.1f}x faster")

    print()
    speedup("1", "2", "single connection")
    speedup("3", "4", "chaining")


if __name__ == "__main__":
    main()
