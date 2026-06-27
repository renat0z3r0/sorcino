from cli import parse_targets, parse_ports


def test_single_ip():
    assert parse_targets("192.168.1.10") == ["192.168.1.10"]


def test_cidr_expands_hosts():
    targets = parse_targets("192.168.1.0/30")
    # /30 -> 2 usable hosts (.1, .2)
    assert targets == ["192.168.1.1", "192.168.1.2"]


def test_full_ip_range():
    assert parse_targets("10.0.0.1-10.0.0.3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_compact_range():
    assert parse_targets("10.0.0.5-7") == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_domain_passthrough():
    # A hostname that is not an existing file is returned verbatim.
    assert parse_targets("gateway.example.com") == ["gateway.example.com"]


def test_empty_target_returns_empty():
    # Must not crash on empty/whitespace input.
    assert parse_targets("") == []
    assert parse_targets("   ") == []


def test_at_file(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# comment\n10.0.0.1\n\n10.0.0.2-10.0.0.3\n")
    assert parse_targets(f"@{f}") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_parse_ports_valid():
    assert parse_ports("18789, 8080 , 443") == [18789, 8080, 443]
