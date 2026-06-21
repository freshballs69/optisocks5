"""CLI argument parsing + top-level API surface (no network)."""

import pytest

import optisocks5 as s5
from optisocks5 import cli


def test_parse_proxy():
    assert cli._parse_proxy("socks5://u:p@h:1080") == ("h", 1080, "u", "p")
    assert cli._parse_proxy("h:1080") == ("h", 1080, None, None)


def test_parse_proxy_rejects_hostonly():
    with pytest.raises(SystemExit):
        cli._parse_proxy("hostonly")


def test_split_target():
    assert cli._split_target("example.com:443") == ("example.com", 443)
    assert cli._split_target("example.com") == ("example.com", 80)
    assert cli._split_target("[::1]:443") == ("::1", 443)
    assert cli._split_target("[::1]") == ("::1", 80)


def test_build_parser_smoke():
    # build_parser must not crash even without __doc__ (python -OO)
    p = cli.build_parser()
    args = p.parse_args(["connect", "socks5://u:p@h:1080", "1.2.3.4:80"])
    assert args.command == "connect"


def test_rep_name():
    assert s5.rep_name(0x00) == "SUCCEEDED"
    assert s5.rep_name(0x02) == "NOT_ALLOWED"
    assert s5.rep_name(0xFF) == "UNKNOWN(255)"


def test_top_level_lazy_exports():
    # server + async names resolve lazily and appear in dir()
    from optisocks5.server import Server as DirectServer

    assert s5.Server is DirectServer
    assert s5.AsyncOptimisticClient is not None
    names = dir(s5)
    assert "Server" in names and "AsyncClient" in names and "OptimisticClient" in names


def test_reply_size_exported():
    assert "reply_size" in s5.core.__all__
    assert s5.core.reply_size(bytes([5, 0, 0, 1, 1, 2, 3, 4, 0, 80])) == 10
