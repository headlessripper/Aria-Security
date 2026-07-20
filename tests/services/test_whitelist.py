from Services.SentinelWhitelist import SentinelWhitelist, norm_path


def test_norm_path_case_and_slashes():
    assert norm_path(r"C:\Users\X\file.EXE") == norm_path("c:/users/x/file.exe")


def test_file_whitelist_normalized(tmp_path, monkeypatch):
    wl = SentinelWhitelist(path=str(tmp_path / "wl.json"))
    wl.add_file(r"C:\Temp\App.exe")
    assert wl.is_whitelisted_file(r"c:\temp\app.exe") is True     # case-insensitive match
    assert wl.is_whitelisted_file(r"C:\Temp\Other.exe") is False


def test_hash_whitelist_lowercased(tmp_path):
    wl = SentinelWhitelist(path=str(tmp_path / "wl.json"))
    wl.add_hash("ABCDEF")
    assert wl.is_whitelisted_hash("abcdef") is True


def test_dir_prefix_not_over_permissive(tmp_path):
    wl = SentinelWhitelist(path=str(tmp_path / "wl.json"))
    wl.add_dir(r"C:\Foo")
    assert wl.is_whitelisted_file(r"C:\Foo\ok.exe") is True
    assert wl.is_whitelisted_file(r"C:\FooBar\evil.exe") is False


def test_dir_prefix_survives_reload(tmp_path):
    p = str(tmp_path / "wl.json")
    SentinelWhitelist(path=p).add_dir(r"C:\Foo")
    wl2 = SentinelWhitelist(path=p)   # reload from disk
    assert wl2.is_whitelisted_file(r"C:\Foo\ok.exe") is True
    assert wl2.is_whitelisted_file(r"C:\FooBar\evil.exe") is False   # the bug: was True


def test_empty_dir_rejected(tmp_path):
    wl = SentinelWhitelist(path=str(tmp_path / "wl.json"))
    assert wl.add_dir("") is False
    assert wl.is_whitelisted_file(r"C:\Windows\System32\evil.exe") is False
