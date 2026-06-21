"""Optimistic handshake — sans-IO Session + the blocking client, driven against
an in-process byte-exact SOCKS5 server (reads exactly each message's length, so
the one-shot pipeline survives)."""

import asyncio
import socket
import threading

import optisocks5 as s5
from optisocks5.aio import AsyncClient, AsyncOptimisticClient


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def _read_address(conn: socket.socket) -> tuple[str, int]:
    atyp = _recv_exact(conn, 1)[0]
    if atyp == 0x01:
        addr = _recv_exact(conn, 4)
        host = ".".join(str(b) for b in addr)
    elif atyp == 0x04:
        _recv_exact(conn, 16)
        host = "::"
    elif atyp == 0x03:
        ln = _recv_exact(conn, 1)[0]
        host = _recv_exact(conn, ln).decode()
    else:
        raise ValueError(f"bad ATYP {atyp}")
    port = int.from_bytes(_recv_exact(conn, 2), "big")
    return host, port


def _byte_exact_server(require_auth: bool, rep: int = 0x00, banner: bytes = b""):
    """Spawn a one-shot byte-exact SOCKS5 server. `banner` is sent glued behind
    the reply in one segment (simulates a server-speaks-first peer). Returns
    (host, port, listening socket)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def serve():
        conn, _ = srv.accept()
        with conn:
            ver = _recv_exact(conn, 1)[0]
            nmethods = _recv_exact(conn, 1)[0]
            methods = _recv_exact(conn, nmethods)
            assert ver == 0x05
            if require_auth:
                assert 0x02 in methods
                conn.sendall(b"\x05\x02")  # choose USERPASS
                ulen = _recv_exact(conn, 1 + 1)[1]  # VER ULEN
                _recv_exact(conn, ulen)
                plen = _recv_exact(conn, 1)[0]
                _recv_exact(conn, plen)
                conn.sendall(b"\x01\x00")  # auth OK
            else:
                conn.sendall(b"\x05\x00")  # choose NO_AUTH
            # request: VER CMD RSV ATYP ADDR PORT
            _recv_exact(conn, 3)
            _read_address(conn)
            # reply bound to 1.2.3.4:5678, optionally with a banner glued on
            conn.sendall(bytes([0x05, rep, 0x00, 0x01, 1, 2, 3, 4, 0x16, 0x2E]) + banner)
            try:
                conn.recv(1)  # hold until client closes
            except OSError:
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return host, port, srv


def test_optimistic_connect_no_auth():
    host, port, srv = _byte_exact_server(require_auth=False)
    with srv:
        with s5.OptimisticClient(host, port) as client:
            reply = client.connect("example.com", 80)
            assert reply.ok
            assert client.bound == ("1.2.3.4", 0x162E)


def test_optimistic_connect_userpass():
    host, port, srv = _byte_exact_server(require_auth=True)
    with srv:
        with s5.OptimisticClient(host, port, "alice", "s3cr3t") as client:
            reply = client.connect("10.0.0.1", 443)
            assert reply.rep == s5.Rep.SUCCEEDED


def test_optimistic_connect_error_rep_raises():
    host, port, srv = _byte_exact_server(require_auth=False, rep=0x05)
    with srv:
        client = s5.OptimisticClient(host, port)
        try:
            client.connect("example.com", 80)
            assert False, "expected Socks5Error"
        except s5.Socks5Error as e:
            assert "CONN_REFUSED" in str(e)


def test_staged_client_no_auth():
    host, port, srv = _byte_exact_server(require_auth=False)
    with srv:
        with s5.Client(host, port) as client:
            reply = client.connect("example.com", 80)
            assert reply.ok and client.bound == ("1.2.3.4", 0x162E)


def test_staged_client_userpass():
    host, port, srv = _byte_exact_server(require_auth=True)
    with srv:
        with s5.Client(host, port, "alice", "s3cr3t") as client:
            assert client.connect("10.0.0.1", 443).rep == s5.Rep.SUCCEEDED


def test_staged_client_error_rep_raises():
    host, port, srv = _byte_exact_server(require_auth=False, rep=0x04)
    with srv:
        try:
            s5.Client(host, port).connect("example.com", 80)
            assert False, "expected Socks5Error"
        except s5.Socks5Error as e:
            assert "HOST_UNREACHABLE" in str(e)


def test_staged_client_does_not_overread_tunnel():
    # A server-first banner glued behind the reply must stay on the socket: the
    # staged client reads the reply exactly, so the banner is the next recv.
    host, port, srv = _byte_exact_server(require_auth=False, banner=b"BANNER220")
    with srv:
        with s5.Client(host, port) as client:
            client.connect("example.com", 80)
            assert client.leftover == b""
            client.sock.settimeout(2.0)
            assert client.sock.recv(64) == b"BANNER220"


def test_optimistic_client_preserves_leftover():
    # The optimistic read is greedy, so the glued banner lands in .leftover
    # instead of being lost.
    host, port, srv = _byte_exact_server(require_auth=False, banner=b"BANNER220")
    with srv:
        with s5.OptimisticClient(host, port) as client:
            client.connect("example.com", 80)
            assert client.leftover == b"BANNER220"


def test_session_sans_io_drip_feed():
    """The sans-IO Session must reassemble replies fed one byte at a time."""
    sess = s5.Session()
    pipe = sess.optimistic_pipeline("127.0.0.1", 8080)
    # greeting(NO_AUTH) + request
    assert pipe == b"\x05\x01\x00" + s5.request(s5.Cmd.CONNECT, "127.0.0.1", 8080)
    replies = b"\x05\x00" + b"\x05\x00\x00\x01\x04\x03\x02\x01\x00\x50"
    out = None
    for i in range(len(replies)):
        out = sess.feed(replies[i : i + 1])
        if i < len(replies) - 1:
            assert out is None  # incomplete until the last byte
    assert out == s5.Reply(0, "4.3.2.1", 80)
    assert out.ok


def test_async_optimistic_no_auth():
    host, port, srv = _byte_exact_server(require_auth=False)
    with srv:

        async def run():
            async with AsyncOptimisticClient(host, port) as c:
                return await c.connect("example.com", 80)

        reply = asyncio.run(run())
        assert reply.ok and reply.host == "1.2.3.4"


def test_async_staged_userpass():
    host, port, srv = _byte_exact_server(require_auth=True)
    with srv:

        async def run():
            async with AsyncClient(host, port, "alice", "s3cr3t") as c:
                return await c.connect("10.0.0.1", 443)

        assert asyncio.run(run()).rep == s5.Rep.SUCCEEDED


def test_session_wrong_method_raises():
    sess = s5.Session()  # offers NO_AUTH only
    try:
        sess.feed(b"\x05\x02")  # server picked USERPASS
        assert False, "expected Socks5Error"
    except s5.Socks5Error as e:
        assert "method" in str(e)
