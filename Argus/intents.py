"""Model-free intent parser: map a plain-text command to a ToolCall.
Pure function, no side effects. Returns None when nothing matches — the
caller then falls back to the LLM (or a grounded deterministic reply)."""
from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolCall:
    name: str
    arg: str


_IPV4 = r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
_SHA256 = r"\b([a-fA-F0-9]{64})\b"


def parse_intent(message: str):
    m = (message or "").strip()
    low = m.lower()
    if not m:
        return None

    # scan <path>  (keep original case for the path)
    sc = re.match(r"scan\s+(.+)", m, re.IGNORECASE)
    if sc:
        return ToolCall("scan_file", sc.group(1).strip())

    # whitelist ip/hash <value>
    wl = re.search(r"whitelist\s+(ip|hash)\s+(\S+)", low)
    if wl:
        kind = "whitelist_ip" if wl.group(1) == "ip" else "whitelist_hash"
        return ToolCall(kind, wl.group(2))

    # block <ip>
    if "block" in low:
        ip = re.search(_IPV4, m)
        if ip:
            return ToolCall("block_ip", ip.group(1))

    # resolve threat <id>
    rt = re.search(r"resolve\s+threat\s+(\w+)", low)
    if rt:
        return ToolCall("resolve_threat", rt.group(1))

    # lookup <ip|hash>
    if "lookup" in low or "reputation" in low:
        h = re.search(_SHA256, m)
        if h:
            return ToolCall("lookup_hash", h.group(1))
        ip = re.search(_IPV4, m)
        if ip:
            return ToolCall("lookup_ip", ip.group(1))

    # read <name> log
    rl = re.search(r"read\s+(\w+)\s+log", low)
    if rl:
        return ToolCall("read_log", rl.group(1))

    # status-type reads
    if "threat" in low and ("show" in low or "active" in low or "list" in low or "what" in low):
        return ToolCall("get_threats", "")
    if "module" in low:
        return ToolCall("get_modules", "")
    if "protection level" in low or low in ("level", "status"):
        return ToolCall("get_protection_level", "")
    if "stats" in low or "statistics" in low or "summary" in low:
        return ToolCall("get_stats", "")
    if "recent events" in low or "recent" in low and "event" in low:
        return ToolCall("get_recent_events", "")

    return None
