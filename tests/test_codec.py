"""Pure codec round-trips — no sockets, no event loop."""

import pytest

import optisocks5 as s5
from optisocks5 import _core


def test_greeting_and_method_selection():
    g = s5.client_greeting(bytes([s5.Method.NO_AUTH, s5.Method.USERPASS]))
    assert g == b"\x05\x02\x00\x02"
    assert s5.parse_method_selection(b"\x05\x02") == s5.Method.USERPASS
    assert s5.parse_method_selection(b"\x05") is None  # truncated
    assert s5.parse_method_selection(b"\x04\x00") is None  # wrong version


def test_userpass_auth_roundtrip():
    a = s5.userpass_auth("alice", "s3cr3t")
    assert a == b"\x01\x05alice\x06s3cr3t"
    assert s5.parse_auth_reply(b"\x01\x00") == 0
    assert s5.parse_auth_reply(b"\x01\x01") == 1
    assert s5.parse_auth_reply(b"\x01") is None


def test_request_ipv4():
    req = s5.request(s5.Cmd.CONNECT, "127.0.0.1", 0x1F90)  # 8080
    assert req == b"\x05\x01\x00\x01\x7f\x00\x00\x01\x1f\x90"


def test_request_domain():
    req = s5.request(s5.Cmd.CONNECT, "example.com", 443)
    # VER CMD RSV ATYP=domain LEN "example.com" PORT
    assert req == b"\x05\x01\x00\x03\x0bexample.com\x01\xbb"


def test_request_ipv6():
    req = s5.request(s5.Cmd.UDP_ASSOCIATE, "::1", 53)
    assert req[:4] == b"\x05\x03\x00\x04"
    assert req[4:20] == b"\x00" * 15 + b"\x01"
    assert req[20:] == b"\x00\x35"


def test_parse_reply_roundtrips():
    # succeeded, bound to 10.0.0.5:4660
    wire = b"\x05\x00\x00\x01\x0a\x00\x00\x05\x12\x34"
    assert s5.parse_reply(wire) == (0, "10.0.0.5", 0x1234)
    # error rep still parses (server reports 0.0.0.0:0)
    err = b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00"
    assert s5.parse_reply(err) == (5, "0.0.0.0", 0)
    assert s5.parse_reply(b"\x05\x00\x00\x01\x0a") is None  # truncated addr


def test_udp_encapsulate_decapsulate():
    payload = b"hello relay"
    dg = s5.udp_encapsulate("8.8.8.8", 53, payload)
    assert dg[:3] == b"\x00\x00\x00"  # RSV RSV FRAG
    frag, host, port, data = s5.udp_decapsulate(dg)
    assert (frag, host, port, data) == (0, "8.8.8.8", 53, payload)


def test_udp_decapsulate_domain_and_frag():
    dg = s5.udp_encapsulate("relay.local", 9999, b"x", frag=7)
    frag, host, port, data = s5.udp_decapsulate(dg)
    assert frag == 7 and host == "relay.local" and port == 9999 and data == b"x"
    assert s5.udp_decapsulate(b"\x00\x00") is None  # truncated


def test_udp_ipv6_roundtrip():
    dg = s5.udp_encapsulate("::1", 53, b"q")
    assert s5.udp_decapsulate(dg) == (0, "::1", 53, b"q")


def test_builders_reject_oversize_length_prefixed_fields():
    with pytest.raises(ValueError):
        s5.request(s5.Cmd.CONNECT, "a" * 256, 80)
    with pytest.raises(ValueError):
        s5.userpass_auth("u" * 256, "p")
    with pytest.raises(ValueError):
        s5.client_greeting(bytes(256))


def test_builders_reject_out_of_range_ints():
    with pytest.raises(ValueError):
        s5.request(s5.Cmd.CONNECT, "1.2.3.4", 70000)  # port
    with pytest.raises(ValueError):
        s5.request(256, "1.2.3.4", 80)  # cmd
    with pytest.raises(ValueError):
        _core.reply(0, "h", -1)  # negative port
    with pytest.raises(ValueError):
        _core.method_selection(999)


def test_parse_preserves_embedded_nul():
    # domain host with an embedded NUL must round-trip, not truncate
    wire = bytes([5, 0, 0, 3, 3]) + b"a\x00b" + bytes([0, 80])
    assert _core.parse_reply(wire) == (0, "a\x00b", 80)
    auth = bytes([1, 1]) + b"u" + bytes([3]) + b"p\x00q"
    assert _core.parse_userpass(auth) == ("u", "p\x00q")


def test_reply_parse_ipv6_and_domain():
    v6 = bytes([5, 0, 0, 4]) + bytes(15) + bytes([1]) + bytes([0, 53])
    assert _core.parse_reply(v6) == (0, "::1", 53)
    dom = bytes([5, 0, 0, 3, 6]) + b"ex.com" + bytes([1, 187])
    assert _core.parse_reply(dom) == (0, "ex.com", 443)


def test_server_codec_roundtrip():
    # greeting -> methods, request -> (cmd, host, port), reply build/parse
    assert _core.parse_greeting(s5.client_greeting(b"\x00\x02")) == b"\x00\x02"
    req = s5.request(s5.Cmd.CONNECT, "1.2.3.4", 80)
    assert _core.parse_request(req) == (1, "1.2.3.4", 80)
    assert s5.parse_reply(_core.reply(0, "9.9.9.9", 53)) == (0, "9.9.9.9", 53)
    assert _core.parse_userpass(s5.userpass_auth("a", "b")) == ("a", "b")
