from Argus.intents import parse_intent, ToolCall


def test_scan_file():
    tc = parse_intent(r"scan C:\Users\me\thing.exe")
    assert tc == ToolCall("scan_file", r"C:\Users\me\thing.exe")


def test_show_threats():
    for m in ("show threats", "active threats", "what threats are active"):
        assert parse_intent(m) == ToolCall("get_threats", "")


def test_modules():
    assert parse_intent("show modules") == ToolCall("get_modules", "")


def test_protection_level():
    assert parse_intent("what is the protection level") == ToolCall("get_protection_level", "")


def test_block_ip():
    assert parse_intent("block 1.2.3.4") == ToolCall("block_ip", "1.2.3.4")


def test_lookup_ip_vs_hash():
    assert parse_intent("lookup 8.8.8.8") == ToolCall("lookup_ip", "8.8.8.8")
    h = "a" * 64
    assert parse_intent(f"lookup {h}") == ToolCall("lookup_hash", h)


def test_whitelist_ip():
    assert parse_intent("whitelist ip 9.9.9.9") == ToolCall("whitelist_ip", "9.9.9.9")


def test_read_log():
    assert parse_intent("read psds log") == ToolCall("read_log", "psds")


def test_resolve_threat():
    assert parse_intent("resolve threat ab12cd34") == ToolCall("resolve_threat", "ab12cd34")


def test_affirmation_is_not_an_intent():
    for m in ("yes", "y", "confirm", "do it", "hello there", "what should I do?"):
        assert parse_intent(m) is None
