def test_argus_package_imports_and_wires():
    from Argus import get_argus
    from Argus import tools
    tools.set_scanner_provider(lambda: None)
    assert get_argus() is not None

def test_argus_modules_have_no_flask():
    import Argus.assistant as a, Argus.tools as t, Argus.context as c
    for m in (a, t, c):
        assert not hasattr(m, "jsonify") and not hasattr(m, "socketio")
