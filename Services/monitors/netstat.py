"""Network inspection: live connection table + per-NIC IO counters.
No Flask; returns JSON-ready structures."""
from __future__ import annotations
import psutil


def connections() -> list:
    conns = []
    for c in psutil.net_connections(kind="inet"):
        try:
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:  # noqa: BLE001
                    pass
            conns.append({
                "pid": c.pid,
                "proc": proc_name,
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "—",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "—",
                "status": c.status,
                "family": "TCP" if c.type == 1 else "UDP",
            })
        except Exception:  # noqa: BLE001
            pass
    return conns[:200]


def interface_counters() -> dict:
    ifaces = psutil.net_io_counters(pernic=True, nowrap=True)
    out = {}
    for name, s in ifaces.items():
        out[name] = {
            "bytes_sent": s.bytes_sent, "bytes_recv": s.bytes_recv,
            "packets_sent": s.packets_sent, "packets_recv": s.packets_recv,
            "dropin": getattr(s, "dropin", 0), "dropout": getattr(s, "dropout", 0),
        }
    return out
