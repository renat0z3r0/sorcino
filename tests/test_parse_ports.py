import pytest
import typer

from cli import parse_ports, parse_targets


def test_valid_ports():
    assert parse_ports("18789, 8080 , 443") == [18789, 8080, 443]


def test_empty_tokens_skipped():
    assert parse_ports("80,,443") == [80, 443]


def test_invalid_token_raises():
    with pytest.raises(typer.BadParameter):
        parse_ports("18789,xyz")


def test_out_of_range_raises():
    with pytest.raises(typer.BadParameter):
        parse_ports("99999")
    with pytest.raises(typer.BadParameter):
        parse_ports("0")


def test_shodan_ip_port_line_strips_port():
    # "ip:port" (what shodan-import writes) must scan the bare IP, not fail.
    assert parse_targets("1.2.3.4:18789") == ["1.2.3.4"]


def test_plain_ip_unchanged():
    assert parse_targets("1.2.3.4") == ["1.2.3.4"]
