"""Assemble a compact live-state block for Argus's system prompt.
Reads only real telemetry. Deliberately makes NO claim about an
IsolationForest / ML anomaly model (that capability is not real)."""
from __future__ import annotations


def _brain():
    from Services.SentinelBrain import get_brain
    return get_brain()

def _avbrain():
    from Services.AVBrain import get_avbrain
    return get_avbrain()


def build_context() -> str:
    try:
        av = _avbrain()
        level = av.get_protection_level()
        active = av.get_active_threats()
    except Exception:
        level, active = "unknown", []
    try:
        mods = _brain().get_module_statuses()
    except Exception:
        mods = []

    up = sum(1 for m in mods if getattr(m, "running", False))
    lines = [
        f"Protection level: {level}%",
        f"Modules online: {up}/{len(mods)}",
        f"Active threats: {len(active)}",
    ]
    for r in active[:5]:
        try:
            lines.append(f"  [{r.id}] {r.event.severity.name} — {r.event.title}")
        except Exception:
            pass
    return "\n".join(lines)
