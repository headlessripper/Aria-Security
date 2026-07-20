def test_monitors_package_imports():
    from Services.monitors import (
        system_monitor, process_monitor, netstat, console_logs, geo_blocks, mem_scan,
    )
    for m in (system_monitor, process_monitor, netstat, console_logs, geo_blocks, mem_scan):
        assert m is not None

def test_monitors_have_no_flask_import():
    import Services.monitors.system_monitor as sm
    import Services.monitors.mem_scan as ms
    import sys
    # these modules must not have pulled flask into their own namespace
    assert not hasattr(sm, "jsonify")
    assert not hasattr(ms, "socketio")
