import types
from Services.monitors import netstat


def test_connections_shape(monkeypatch):
    conn = types.SimpleNamespace(
        pid=1234, type=1, status="ESTABLISHED",
        laddr=types.SimpleNamespace(ip="127.0.0.1", port=50000),
        raddr=types.SimpleNamespace(ip="1.2.3.4", port=443),
    )
    monkeypatch.setattr(netstat.psutil, "net_connections", lambda kind="inet": [conn])
    monkeypatch.setattr(netstat.psutil, "Process",
                        lambda pid: types.SimpleNamespace(name=lambda: "chrome.exe"))
    out = netstat.connections()
    assert out[0]["proc"] == "chrome.exe"
    assert out[0]["laddr"] == "127.0.0.1:50000"
    assert out[0]["raddr"] == "1.2.3.4:443"
    assert out[0]["family"] == "TCP"
    assert set(out[0].keys()) == {"pid", "proc", "laddr", "raddr", "status", "family"}


def test_interface_counters_shape(monkeypatch):
    s = types.SimpleNamespace(bytes_sent=10, bytes_recv=20, packets_sent=1,
                              packets_recv=2, dropin=0, dropout=0)
    monkeypatch.setattr(netstat.psutil, "net_io_counters",
                        lambda pernic=True, nowrap=True: {"Ethernet": s})
    out = netstat.interface_counters()
    assert out["Ethernet"]["bytes_sent"] == 10
    assert set(out["Ethernet"].keys()) == {"bytes_sent", "bytes_recv", "packets_sent",
                                           "packets_recv", "dropin", "dropout"}
