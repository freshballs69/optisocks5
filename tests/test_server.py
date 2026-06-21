"""Server: the sans-IO ServerSession state machine + an end-to-end run of our
own Client/OptimisticClient through the threaded reference Server."""

import socket
import threading
import time

import pytest

import optisocks5 as s5
from optisocks5.core import Cmd, Method, client_greeting, parse_reply, request, userpass_auth
from optisocks5.server import (
    Authorize,
    Close,
    Connect,
    NeedData,
    Relay,
    Send,
    Server,
    ServerSession,
)


# ---- sans-IO state machine (no sockets) ------------------------------------


def test_server_session_no_auth_connect():
    s = ServerSession(require_auth=False)
    assert isinstance(s.next_event(), NeedData)
    s.receive(client_greeting(bytes([Method.NO_AUTH])))
    ev = s.next_event()
    assert isinstance(ev, Send) and ev.data == b"\x05\x00"
    assert isinstance(s.next_event(), NeedData)  # awaiting request
    s.receive(request(Cmd.CONNECT, "1.2.3.4", 80))
    ev = s.next_event()
    assert isinstance(ev, Connect) and (ev.host, ev.port) == ("1.2.3.4", 80)
    s.connected("9.9.9.9", 1234)  # driver "opened" the upstream
    ev = s.next_event()
    assert isinstance(ev, Send) and parse_reply(ev.data) == (0, "9.9.9.9", 1234)
    ev = s.next_event()
    assert isinstance(ev, Relay) and (ev.host, ev.port) == ("1.2.3.4", 80)


def test_server_session_auth_reject():
    s = ServerSession(require_auth=True)
    s.next_event()  # NeedData
    s.receive(client_greeting(bytes([Method.USERPASS])))
    assert s.next_event().data == b"\x05\x02"  # selected USERPASS
    s.next_event()  # NeedData (auth)
    s.receive(userpass_auth("u", "bad"))
    ev = s.next_event()
    assert isinstance(ev, Authorize) and ev.username == "u"
    s.reject()
    ev = s.next_event()
    assert isinstance(ev, Send) and ev.data == b"\x01\x01"  # auth failure
    assert isinstance(s.next_event(), Close)


def test_server_session_request_reject_sends_error_reply():
    s = ServerSession(require_auth=False)
    s.next_event()
    s.receive(client_greeting(bytes([Method.NO_AUTH])))
    s.next_event()  # method select
    s.next_event()  # NeedData
    s.receive(request(Cmd.CONNECT, "10.0.0.1", 25))
    ev = s.next_event()
    assert isinstance(ev, Connect)
    s.reject(s5.Rep.NOT_ALLOWED)
    ev = s.next_event()
    assert isinstance(ev, Send) and parse_reply(ev.data)[0] == s5.Rep.NOT_ALLOWED
    assert isinstance(s.next_event(), Close)


# ---- end-to-end through the threaded driver --------------------------------


def _echo_target():
    """A one-shot TCP echo server. Returns (host, port, listening socket)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)

    threading.Thread(target=serve, daemon=True).start()
    return (*srv.getsockname(), srv)


def _run_server(server: Server) -> tuple[str, int]:
    host, port = server.bind("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return host, port


def test_end_to_end_roundtrip_no_auth():
    eh, ep, esrv = _echo_target()
    server = Server()
    disconnected = threading.Event()
    server.on_disconnect(lambda s: disconnected.set())
    with esrv:
        sh, sp = _run_server(server)
        try:
            with s5.OptimisticClient(sh, sp) as c:
                c.connect(eh, ep)
                c.sock.sendall(b"ping through my socks server")
                assert c.sock.recv(64) == b"ping through my socks server"
        finally:
            server.close()
        assert disconnected.wait(2.0)


def test_end_to_end_auth_and_metered_pipe():
    eh, ep, esrv = _echo_target()
    server = Server()
    counts: dict[str, int] = {}

    @server.authorize
    def authorize(s, user, password):
        if user == "alice" and password == "pw":
            s.ok({"user": user})
        else:
            s.reject()

    @server.on_connect
    def on_connect(s, host, port):
        def metered(sess):
            total = [0]

            def copy(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        total[0] += len(data)
                        dst.sendall(data)
                except OSError:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            t = threading.Thread(target=copy, args=(sess.downstream, sess.upstream), daemon=True)
            t.start()
            copy(sess.upstream, sess.downstream)
            t.join()
            counts[sess.ctx["user"]] = total[0]

        s.pipe(metered)

    with esrv:
        sh, sp = _run_server(server)
        try:
            # wrong creds rejected
            try:
                s5.Client(sh, sp, "alice", "nope").connect(eh, ep)
                assert False, "expected auth failure"
            except s5.Socks5Error:
                pass
            # correct creds: round-trip + byte count recorded by the metered pipe
            with s5.Client(sh, sp, "alice", "pw") as c:
                c.connect(eh, ep)
                c.sock.sendall(b"x" * 100)
                assert c.sock.recv(200) == b"x" * 100
        finally:
            server.close()
        for _ in range(20):
            if counts:
                break
            time.sleep(0.05)
        assert counts.get("alice", 0) >= 100  # at least the upstream-bound bytes


# ---- sans-IO hardening (rank 5 / 12) ---------------------------------------


def test_server_session_rejects_bad_version():
    s = ServerSession(require_auth=False)
    s.receive(b"\x04\x01\x00")  # SOCKS4, not SOCKS5
    assert isinstance(s.next_event(), Close)


def test_server_session_unknown_atyp_rejected():
    s = ServerSession(require_auth=False)
    s.receive(client_greeting(bytes([s5.Method.NO_AUTH])))
    s.next_event()  # Send method
    s.next_event()  # NeedData
    s.receive(b"\x05\x01\x00\x09\x01\x02")  # ATYP 0x09 + >=5 bytes
    ev = s.next_event()
    assert isinstance(ev, Send) and parse_reply(ev.data)[0] == s5.Rep.ATYP_NOT_SUPPORTED
    assert isinstance(s.next_event(), Close)


def test_server_session_rejects_non_connect():
    s = ServerSession(require_auth=False)
    s.receive(client_greeting(bytes([s5.Method.NO_AUTH])))
    s.next_event()
    s.next_event()
    s.receive(request(s5.Cmd.UDP_ASSOCIATE, "1.2.3.4", 80))
    ev = s.next_event()
    assert isinstance(ev, Send) and parse_reply(ev.data)[0] == s5.Rep.CMD_NOT_SUPPORTED
    assert isinstance(s.next_event(), Close)


# ---- threaded driver end-to-end (rank 1 / 8 / 12) --------------------------


def test_threaded_intercept_does_not_dial():
    server = Server()

    @server.on_connect
    def on_connect(s, host, port):
        def handler(sess):
            sess.downstream.recv(4096)
            sess.downstream.sendall(b"INMEM")

        s.intercept(handler)  # unroutable host must NOT be dialed

    sh, sp = _run_server(server)
    try:
        with s5.Client(sh, sp) as c:
            c.connect("fake.invalid", 80)
            c.sock.sendall(b"hi")
            assert c.sock.recv(16) == b"INMEM"
    finally:
        server.close()


def test_optimistic_client_through_server():
    # the server must drain greeting+request arriving glued in one packet
    eh, ep, esrv = _echo_target()
    server = Server()
    with esrv:
        sh, sp = _run_server(server)
        try:
            with s5.OptimisticClient(sh, sp) as c:
                c.connect(eh, ep)
                c.sock.sendall(b"opt")
                assert c.sock.recv(16) == b"opt"
        finally:
            server.close()


def test_set_target_redirect():
    eh, ep, esrv = _echo_target()
    server = Server()

    @server.on_connect
    def on_connect(s, host, port):
        s.set_target(eh, ep)  # redirect anywhere to the echo server

    with esrv:
        sh, sp = _run_server(server)
        try:
            with s5.Client(sh, sp) as c:
                c.connect("nowhere.invalid", 1)
                c.sock.sendall(b"redir")
                assert c.sock.recv(16) == b"redir"
        finally:
            server.close()


def test_connect_refused_maps_to_conn_refused():
    server = Server()
    tmp = socket.socket()
    tmp.bind(("127.0.0.1", 0))
    refused_port = tmp.getsockname()[1]
    tmp.close()  # nothing listens here now -> RST
    sh, sp = _run_server(server)
    try:
        with pytest.raises(s5.Socks5Error) as ei:
            s5.Client(sh, sp).connect("127.0.0.1", refused_port)
        assert "CONN_REFUSED" in str(ei.value)
    finally:
        server.close()


def test_hook_exception_yields_general_failure_reply():
    server = Server()

    @server.on_connect
    def on_connect(s, host, port):
        raise ValueError("boom")

    sh, sp = _run_server(server)
    try:
        with pytest.raises(s5.Socks5Error) as ei:
            s5.Client(sh, sp).connect("1.2.3.4", 80)
        assert "GENERAL_FAILURE" in str(ei.value)
    finally:
        server.close()
