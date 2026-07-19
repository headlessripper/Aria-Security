# SentinelBehavioralEngine.py
# JSON-configurable behavioral rules engine, rewritten as a BaseService.
#
# A "live event stream" (currently: psutil-polled process starts and network
# connections) is fed through a set of declarative JSON rules. Each rule
# matches on an event type + a list of field conditions, and can require a
# threshold of matching events within a time window before it fires (e.g.
# "5 connects to a 185.x IP within 30s"). Single-event rules (threshold <= 1)
# fire immediately on the first match.
#
# Rule schema (Engine/Rules/behavioral_rules.json):
# {
#   "rules": [
#     {
#       "id": "encoded_powershell",
#       "name": "Encoded PowerShell Execution",
#       "event": "process_start",
#       "severity": "HIGH",
#       "conditions": [
#         {"field": "image", "op": "contains", "value": "powershell"},
#         {"field": "cmdline", "op": "regex", "value": "-[eE]nc"}
#       ],
#       "threshold": 1,
#       "window_seconds": null
#     }
#   ]
# }
#
# `event` matches against event["type"]. `conditions` are ANDed; each
# condition reads event[field] and compares it against `value` via `op`.
#
# `load_rules`, `event_matches`, and `RuleState` are PURE (no psutil calls)
# so they can be driven directly by tests. `BehavioralEngine._run` is the
# psutil-polling BaseService loop that turns live system activity into
# events and feeds them through the rules.

from __future__ import annotations

import json
import re
import time
from collections import deque
from typing import Optional

from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

try:
    import psutil
except Exception:  # keep importable in isolation / test environments without psutil
    psutil = None


DEFAULT_RULES_PATH = "Engine/Rules/behavioral_rules.json"


# ---------------------------------------------------------------------------
# Pure rule evaluation
# ---------------------------------------------------------------------------

_OPS = {
    "eq": lambda a, b: a == b,
    "contains": lambda a, b: b in (a or ""),
    "startswith": lambda a, b: (a or "").startswith(b),
    "regex": lambda a, b: re.search(b, a or "") is not None,
    "in": lambda a, b: a in b,
}


def event_matches(rule: dict, event: dict) -> bool:
    """True if `event` satisfies `rule`'s event type + all conditions (AND)."""
    if rule.get("event") != event.get("type"):
        return False
    for cond in rule.get("conditions", []):
        op = _OPS.get(cond.get("op"))
        if op is None:
            return False
        if not op(event.get(cond.get("field")), cond.get("value")):
            return False
    return True


def load_rules(path: str) -> list:
    """Load rules from a JSON file, skipping malformed entries.

    A rule is kept only if it is a dict with a truthy 'event' and a
    'conditions' key present (even if empty).
    """
    try:
        raw = json.loads(open(path, encoding="utf-8").read())
    except Exception:
        return []
    out = []
    for r in raw.get("rules", []):
        if isinstance(r, dict) and r.get("event") and "conditions" in r:
            out.append(r)
    return out


class RuleState:
    """Tracks per-rule burst state for windowed thresholds.

    - threshold <= 1 (or no window): fires on every matching event.
    - threshold > 1 with a window: fires once when `threshold` matching
      events land within `window_seconds` of each other (a "burst"), then
      stays quiet until the window count drops back below threshold and a
      new burst accumulates.
    """

    def __init__(self, rule: dict):
        self._hits: deque = deque()
        self._fired = False

    def feed(self, rule: dict, event: dict, now: float) -> bool:
        if not event_matches(rule, event):
            return False
        threshold = int(rule.get("threshold", 1))
        window = rule.get("window_seconds")
        if window is None or threshold <= 1:
            return True
        cutoff = now - float(window)
        self._hits.append(now)
        while self._hits and self._hits[0] <= cutoff:
            self._hits.popleft()
        if len(self._hits) >= threshold and not self._fired:
            self._fired = True
            return True
        if len(self._hits) < threshold:
            self._fired = False
        return False


# ---------------------------------------------------------------------------
# BaseService: polls live system activity, feeds events through rules
# ---------------------------------------------------------------------------

class BehavioralEngine(BaseService):
    name = "BehavioralEngine"

    def __init__(self, config=None, brain=None):
        cfg = dict(config or {})
        cfg.setdefault("rules_path", DEFAULT_RULES_PATH)
        cfg.setdefault("poll_interval", 2.0)
        super().__init__(cfg, brain)
        self.rules = load_rules(self.config["rules_path"])
        self._states = {id(rule): RuleState(rule) for rule in self.rules}
        self._known_pids: set = set()
        self._seeded = False

    def reload_rules(self) -> None:
        self.rules = load_rules(self.config["rules_path"])
        self._states = {id(rule): RuleState(rule) for rule in self.rules}

    # --- event feeding (pure-ish glue; drives the rule engine) ---
    def _feed_event(self, event: dict, now: float) -> None:
        for rule in self.rules:
            state = self._states[id(rule)]
            try:
                fired = state.feed(rule, event, now)
            except Exception:
                continue
            if fired:
                self._on_fire(rule, event)

    def _on_fire(self, rule: dict, event: dict) -> None:
        severity_name = rule.get("severity", "MEDIUM")
        try:
            severity = ThreatSeverity[severity_name]
        except KeyError:
            severity = ThreatSeverity.MEDIUM
        title = rule.get("name", rule.get("id", "Behavioral rule"))
        detail = self._summarize_event(event)
        self.emit_threat(
            ThreatCategory.BEHAVIORAL,
            severity,
            title,
            detail=detail,
            pid=event.get("pid"),
            ip_address=event.get("remote_ip"),
            extra=event,
        )

    @staticmethod
    def _summarize_event(event: dict) -> str:
        etype = event.get("type", "event")
        if etype == "process_start":
            return f"process_start: image={event.get('image')} cmdline={event.get('cmdline')} parent={event.get('parent')}"
        if etype == "net_connect":
            return f"net_connect: remote_ip={event.get('remote_ip')} pid={event.get('pid')}"
        return f"{etype}: {event}"

    # --- psutil-driven polling loop ---
    def _run(self) -> None:
        self._heartbeat()
        while not self._stopping():
            try:
                self._poll_once()
            except Exception:
                pass
            self._heartbeat()
            if not self._sleep(self.config.get("poll_interval", 2.0)):
                break

    def _poll_once(self) -> None:
        if psutil is None:
            return
        now = time.time()
        self._poll_process_starts(now)
        self._poll_net_connections(now)

    def _poll_process_starts(self, now: float) -> None:
        seen_pids = set()
        try:
            iterator = psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"])
        except Exception:
            return

        is_first_pass = not self._seeded
        for p in iterator:
            try:
                info = p.info
                pid = info.get("pid")
                if pid is None:
                    continue
                seen_pids.add(pid)
                if pid in self._known_pids:
                    continue
                # Don't fire on every process already running when the
                # engine starts up -- only newly created processes.
                if not is_first_pass:
                    parent_name = ""
                    ppid = info.get("ppid")
                    if ppid:
                        try:
                            parent_name = psutil.Process(ppid).name() or ""
                        except Exception:
                            parent_name = ""
                    event = {
                        "type": "process_start",
                        "image": info.get("name") or "",
                        "exe": info.get("exe") or "",
                        "cmdline": " ".join(info.get("cmdline") or []),
                        "parent": parent_name,
                        "pid": pid,
                    }
                    self._feed_event(event, now)
            except Exception:
                continue

        self._known_pids = seen_pids
        self._seeded = True

    def _poll_net_connections(self, now: float) -> None:
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return
        for c in conns:
            try:
                if not c.raddr:
                    continue
                event = {
                    "type": "net_connect",
                    "remote_ip": c.raddr.ip,
                    "remote_port": c.raddr.port,
                    "pid": c.pid,
                }
                self._feed_event(event, now)
            except Exception:
                continue


if __name__ == "__main__":
    svc = BehavioralEngine()
    svc.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        svc.stop()
