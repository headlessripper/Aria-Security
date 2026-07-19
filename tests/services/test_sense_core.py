from Services.Sense.SentinelSense import diff_installs, classify_install, _clean_exe_path

def test_diff_installs_detects_add_and_remove():
    before = {"AppA": {"name": "AppA"}}
    after = {"AppA": {"name": "AppA"}, "AppB": {"name": "AppB"}}
    installed, uninstalled = diff_installs(before, after)
    assert [a["name"] for a in installed] == ["AppB"] and uninstalled == []
    installed, uninstalled = diff_installs(after, before)
    assert installed == [] and [a["name"] for a in uninstalled] == ["AppB"]

def test_classify_unsigned_exe_suspicious():
    info = {"name": "x", "publisher": "Acme", "install_location": r"C:\Program Files\X", "main_exe": r"C:\Program Files\X\x.exe"}
    sus, reason = classify_install(info, is_trusted_exe=lambda e: False)   # untrusted
    assert sus is True and "unsigned" in reason.lower()

def test_classify_signed_programfiles_clean():
    info = {"name": "x", "publisher": "Acme", "install_location": r"C:\Program Files\X", "main_exe": r"C:\Program Files\X\x.exe"}
    sus, _ = classify_install(info, is_trusted_exe=lambda e: True)
    assert sus is False

def test_classify_temp_location_no_publisher_suspicious():
    info = {"name": "x", "publisher": "", "install_location": r"C:\Users\u\AppData\Local\Temp\x", "main_exe": None}
    sus, reason = classify_install(info, is_trusted_exe=None)
    assert sus is True

def test_classify_clean_no_signals():
    info = {"name": "x", "publisher": "Acme", "install_location": r"C:\Program Files\X", "main_exe": None}
    sus, _ = classify_install(info, is_trusted_exe=None)
    assert sus is False

def test_clean_exe_path_strips_icon_index():
    assert _clean_exe_path(r"C:\App\app.exe,0") == r"C:\App\app.exe"
    assert _clean_exe_path(r'"C:\App\app.exe"') == r"C:\App\app.exe"
    assert _clean_exe_path(r"C:\App\app.exe") == r"C:\App\app.exe"
    assert _clean_exe_path(r"C:\App\app.exe,-1") == r"C:\App\app.exe"
    assert _clean_exe_path(None) is None
    assert _clean_exe_path("") is None
