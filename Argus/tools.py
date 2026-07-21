"""Argus tool registry. Each tool is read (runs immediately) or action
(the orchestrator gates it behind confirmation). Handlers lazy-import the
app's singletons so this module has no heavy import cost and no Flask.
The running scanner is injected via set_scanner_provider (the Flask layer
owns the live service instance)."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

# ── singleton accessors (wrapped so tests can monkeypatch) ────────────────────
def _brain():
    from Services.SentinelBrain import get_brain
    return get_brain()

def _avbrain():
    from Services.AVBrain import get_avbrain
    return get_avbrain()

def _whitelist():
    from Services.SentinelWhitelist import get_whitelist
    return get_whitelist()

def _cloud():
    from Services.SentinelCloudAnalysis import get_vt_client
    return get_vt_client()

def _intel():
    from Services.Protection.threat_intel_store import get_intel_store
    return get_intel_store()

_scanner_provider: Callable[[], Optional[object]] = lambda: None

def set_scanner_provider(fn: Callable[[], Optional[object]]) -> None:
    global _scanner_provider
    _scanner_provider = fn


@dataclass
class Tool:
    name: str
    description: str
    kind: str                       # "read" | "action"
    handler: Callable[[str], str]


# ── read handlers ─────────────────────────────────────────────────────────────
def _h_get_threats(arg):
    active = _avbrain().get_active_threats()
    if not active:
        return "No active threats."
    return "\n".join(
        f"[{r.id}] {r.event.severity.name} {r.event.category.name} — {r.event.title}"
        for r in active[:10]
    )

def _h_get_modules(arg):
    mods = _brain().get_module_statuses()
    return "\n".join(f"{'UP' if m.running else 'DOWN'} {m.name}" for m in mods) or "No modules."

def _h_get_protection_level(arg):
    return f"Protection level: {_avbrain().get_protection_level()}%"

def _h_get_stats(arg):
    b = _brain()
    counts = b.get_threat_counts()
    lines = [f"Total threats: {b.get_total_threats()}", f"IPs blocked: {b.get_blocked_count()}"]
    lines += [f"  {c}: {n}" for c, n in counts.items() if n > 0]
    return "\n".join(lines)

def _h_get_recent_events(arg):
    try:
        n = int(arg) if arg else 10
    except ValueError:
        n = 10
    events = _brain().get_recent_events(n)
    if not events:
        return "No recent events."
    return "\n".join(f"[{e.severity.name}][{e.category.name}] {e.title}: {e.detail}" for e in events)

def _h_read_log(arg):
    log_map = {
        "psds": "logs/psds.log", "ransom": "logs/Ransom.log", "netpro": "logs/NetPro.log",
        "exploit": "logs/ExploitPro.log", "behavioral": "logs/Behavioral.log",
        "brain": "logs/SentinelBrain.log", "avbrain": "logs/AVBrain.log",
        "threatintel": "logs/ThreatIntel.log",
    }
    path = log_map.get(arg.strip().lower())
    if not path:
        return f"Unknown log '{arg}'. Available: {', '.join(log_map)}"
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        return text[-600:].strip() or "(empty)"
    except Exception as e:
        return f"Could not read {path}: {e}"

def _h_scan_file(arg):
    svc = _scanner_provider()
    if svc is None or not hasattr(svc, "scan_file"):
        return "Scanner not available (service not loaded)."
    path = arg.strip().strip('"')
    if not Path(path).exists():
        return f"File not found: {path}"
    result = svc.scan_file(path) or {}
    verdict = result.get("verdict", "UNKNOWN")
    reasons = ", ".join(result.get("reasons", [])[:3])
    return f"{verdict} — {path}" + (f" ({reasons})" if reasons else "")

def _h_lookup_ip(arg):
    ip = arg.strip()
    intel = _intel()
    bad = intel.is_bad_ip(ip)
    rep = intel.ip_reputation(ip)
    return f"{ip}: {'KNOWN-BAD' if bad else 'not in IOC feeds'}; reputation={rep}"

def _h_lookup_hash(arg):
    h = arg.strip().lower()
    v = _cloud().check_hash(h)
    return f"{h[:16]}…: {v.verdict_str} (status={v.status})"

# ── action handlers (executed only after confirmation, by the orchestrator) ───
def _h_block_ip(arg):
    ip = arg.strip()
    if not ip:
        return "Error: no IP provided."
    _brain().emit_block(ip, "Blocked by Argus (user confirmed)")
    return f"Firewall block applied to {ip} (both directions)."

def _h_resolve_threat(arg):
    tid = arg.strip()
    if not tid:
        return "Error: no threat ID provided."
    _avbrain().resolve_threat(tid, action="Resolved via Argus")
    return f"Threat {tid} marked resolved."

def _h_whitelist_ip(arg):
    ip = arg.strip()
    _whitelist().add_ip(ip)
    return f"Whitelisted IP {ip}."

def _h_whitelist_hash(arg):
    h = arg.strip().lower()
    _whitelist().add_hash(h)
    return f"Whitelisted hash {h[:16]}…"


REGISTRY = {t.name: t for t in [
    Tool("get_threats", "List active threats", "read", _h_get_threats),
    Tool("get_modules", "Show protection module status", "read", _h_get_modules),
    Tool("get_protection_level", "Current protection level", "read", _h_get_protection_level),
    Tool("get_stats", "Threat statistics", "read", _h_get_stats),
    Tool("get_recent_events", "Recent security events", "read", _h_get_recent_events),
    Tool("read_log", "Read the tail of a module log", "read", _h_read_log),
    Tool("scan_file", "Scan a file with the engine", "read", _h_scan_file),
    Tool("lookup_ip", "Check an IP against IOC feeds", "read", _h_lookup_ip),
    Tool("lookup_hash", "Check a SHA-256 against VirusTotal", "read", _h_lookup_hash),
    Tool("block_ip", "Firewall-block an IP", "action", _h_block_ip),
    Tool("resolve_threat", "Mark a threat resolved", "action", _h_resolve_threat),
    Tool("whitelist_ip", "Whitelist an IP", "action", _h_whitelist_ip),
    Tool("whitelist_hash", "Whitelist a file hash", "action", _h_whitelist_hash),
]}


def kind(name: str):
    t = REGISTRY.get(name)
    return t.kind if t else None


def describe() -> str:
    return "\n".join(f"- {t.name}: {t.description}" for t in REGISTRY.values())


def run(name: str, arg: str) -> str:
    tool = REGISTRY.get(name)
    if not tool:
        return f"Unknown command: {name}"
    try:
        return tool.handler(arg)
    except Exception as e:  # noqa: BLE001
        return f"⚠ {name} failed: {e}"
