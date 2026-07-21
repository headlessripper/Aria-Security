# Phase 4 — Argus Assistant Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the Argus conversational assistant out of the 1,006-line `Services/AVBrain.py` monolith into a clean, standalone `Argus/` package with a hybrid tool model (model-free intent routing + optional grounded LLM chat), a single persisted conversation store, and confirmation-gated actions.

**Architecture:** New `Argus/` package of six focused modules. The assistant reads live state through existing public singletons (`get_brain()`, `get_avbrain()`) and shares the already-loaded GGUF model via a new `AVBrain.llm_chat()` accessor (no double model load). Tool execution is deterministic (intent layer) and works with zero model; the LLM adds grounded free-form conversation only. AVBrain keeps its scoring engine; its assistant-only code is removed.

**Tech Stack:** Python 3, stdlib (`json`, `os`, `re`, `pathlib`, `threading`, `dataclasses`), the app's existing singletons (`Services.SentinelBrain`, `Services.AVBrain`, `Services.SentinelWhitelist`, `Services.SentinelCloudAnalysis`, `Services.Protection.threat_intel_store`), Flask (route layer only), pytest + monkeypatch. **No new dependencies.**

## Global Constraints

- Use `.venv/Scripts/python.exe` for ALL python/pytest invocations.
- No new dependencies (stdlib + existing singletons only).
- **No module under `Argus/` may import `flask`, `flask_socketio`/`socketio`, or `SentinelUI_Flask`.** Cross-cutting wiring (socketio emit, the running scanner) is injected or lives in the Flask layer.
- **Argus must never claim or use the IsolationForest / any ML anomaly score.** `context.build_context()` must contain no "IsolationForest"/"anomaly" text; `mind.md` is corrected to describe the real protection-level inputs.
- Action tools (block/whitelist/resolve) NEVER execute on first mention — they require an explicit in-chat confirmation. Read tools run immediately.
- Single source of truth for chat history: the `ConversationStore`. The Flask `_ARIA_HISTORY` global is removed.
- Never `git add` any `.exe`/`.ips`/`.onnx`/PE binary. Stage only the specific files each task changes.
- Do not touch `.venv/`, `cleanup/`, `.superpowers/`, `Config/sentinel_whitelist.json`. Run `git checkout -- Config/sentinel_whitelist.json` before committing if it shows as modified.
- Commit trailer on every commit: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Behavior of the scoring engine (IFEngine, `_recompute`, assessment/recovery loops) must not change.

---

## File Structure

- `Argus/__init__.py` — package marker; later holds `get_argus()` (Task 5).
- `Argus/history.py` — `ConversationStore` (persisted, atomic). [Task 1]
- `Argus/intents.py` — `ToolCall` + `parse_intent()` (pure model-free command grammar). [Task 2]
- `Argus/tools.py` — `Tool` + registry + read/action handlers + scanner-provider hook. [Task 3]
- `Argus/context.py` — `build_context()` live-state block. [Task 4]
- `Argus/assistant.py` — `Argus` orchestrator + `get_argus()` in `__init__`. [Task 5]
- `Services/AVBrain.py` — add `llm_chat()`, remove assistant-only members. [Task 6]
- `Argus/mind.md`, `Argus/soul.md` — persona/knowledge corrections. [Task 7]
- `SentinelUI_Flask.py` — route rewrite + remove `_ARIA_HISTORY` + wire scanner provider; `scripts/verify_reachability.py` bump. [Task 8]
- `tests/services/test_argus_*.py` — one test file per module.

---

### Task 1: `Argus/history.py` — persisted conversation store

**Files:**
- Create: `Argus/__init__.py` (empty)
- Create: `Argus/history.py`
- Test: `tests/services/test_argus_history.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ConversationStore(path)` with `append(role: str, content: str) -> None`, `recent(n: int = 40) -> list[dict]` (each `{"role","content"}`), `pairs(n: int = 8) -> list[tuple[str,str]]` (consecutive user→assistant pairs, newest-last), `clear() -> None`. Atomic JSON persist to `path`.

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_argus_history.py
from Argus.history import ConversationStore


def test_append_and_recent_roundtrip(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    s.append("user", "hi")
    s.append("assistant", "hello")
    r = s.recent(10)
    assert r == [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]


def test_persists_across_instances(tmp_path):
    p = tmp_path / "h.json"
    ConversationStore(p).append("user", "remember me")
    assert ConversationStore(p).recent(10) == [{"role": "user", "content": "remember me"}]


def test_recent_limit(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    for i in range(50):
        s.append("user", str(i))
    assert len(s.recent(5)) == 5
    assert s.recent(5)[-1]["content"] == "49"


def test_pairs_builds_user_assistant_tuples(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    s.append("user", "q1"); s.append("assistant", "a1")
    s.append("user", "q2"); s.append("assistant", "a2")
    assert s.pairs(8) == [("q1", "a1"), ("q2", "a2")]


def test_clear(tmp_path):
    s = ConversationStore(tmp_path / "h.json")
    s.append("user", "x")
    s.clear()
    assert s.recent(10) == []


def test_corrupt_file_starts_empty(tmp_path):
    p = tmp_path / "h.json"
    p.write_text("{ not json", encoding="utf-8")
    assert ConversationStore(p).recent(10) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_history.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'Argus.history'`

- [ ] **Step 3: Write minimal implementation**

Create empty `Argus/__init__.py`, then:

```python
# Argus/history.py
"""Argus conversation history — the single persisted source of truth.
Atomic JSON write so a crash can't corrupt it. No Flask."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import List, Tuple


class ConversationStore:
    def __init__(self, path):
        self._path = Path(path)
        self._turns: List[dict] = []
        self._load()

    def _load(self) -> None:
        try:
            if self._path.exists():
                data = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self._turns = [t for t in data if isinstance(t, dict)
                                   and "role" in t and "content" in t]
        except Exception:
            self._turns = []

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(self._path.name + f".{os.getpid()}.tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(self._turns, f, indent=2)
            os.replace(tmp, self._path)
        except Exception:
            pass

    def append(self, role: str, content: str) -> None:
        self._turns.append({"role": role, "content": content})
        self._save()

    def recent(self, n: int = 40) -> List[dict]:
        return self._turns[-n:]

    def pairs(self, n: int = 8) -> List[Tuple[str, str]]:
        """Rebuild the last n user→assistant exchanges as (user, assistant) tuples."""
        out: List[Tuple[str, str]] = []
        pending_user = None
        for t in self._turns:
            if t["role"] == "user":
                pending_user = t["content"]
            elif t["role"] == "assistant" and pending_user is not None:
                out.append((pending_user, t["content"]))
                pending_user = None
        return out[-n:]

    def clear(self) -> None:
        self._turns = []
        self._save()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_history.py -q`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add Argus/__init__.py Argus/history.py tests/services/test_argus_history.py
git commit -m "Phase 4 Task 1: Argus/history — single persisted conversation store

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `Argus/intents.py` — model-free command grammar

**Files:**
- Create: `Argus/intents.py`
- Test: `tests/services/test_argus_intents.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ToolCall` dataclass `(name: str, arg: str)`; `parse_intent(message: str) -> ToolCall | None`. Recognized commands map to tool names used by Task 3's registry: `scan_file`, `get_threats`, `get_modules`, `get_protection_level`, `get_stats`, `get_recent_events`, `read_log`, `lookup_ip`, `lookup_hash`, `block_ip`, `whitelist_ip`, `whitelist_hash`, `resolve_threat`. Returns `None` when nothing matches (including bare affirmations like "yes").

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_argus_intents.py
from Argus.intents import parse_intent, ToolCall


def test_scan_file():
    tc = parse_intent(r"scan C:\Users\me\thing.exe")
    assert tc == ToolCall("scan_file", r"C:\Users\me\thing.exe")


def test_show_threats():
    for m in ("show threats", "active threats", "what threats are active"):
        assert parse_intent(m) == ToolCall("get_threats", "")


def test_modules():
    assert parse_intent("show modules") == ToolCall("get_modules", "")


def test_protection_level():
    assert parse_intent("what is the protection level") == ToolCall("get_protection_level", "")


def test_block_ip():
    assert parse_intent("block 1.2.3.4") == ToolCall("block_ip", "1.2.3.4")


def test_lookup_ip_vs_hash():
    assert parse_intent("lookup 8.8.8.8") == ToolCall("lookup_ip", "8.8.8.8")
    h = "a" * 64
    assert parse_intent(f"lookup {h}") == ToolCall("lookup_hash", h)


def test_whitelist_ip():
    assert parse_intent("whitelist ip 9.9.9.9") == ToolCall("whitelist_ip", "9.9.9.9")


def test_read_log():
    assert parse_intent("read psds log") == ToolCall("read_log", "psds")


def test_resolve_threat():
    assert parse_intent("resolve threat ab12cd34") == ToolCall("resolve_threat", "ab12cd34")


def test_affirmation_is_not_an_intent():
    for m in ("yes", "y", "confirm", "do it", "hello there", "what should I do?"):
        assert parse_intent(m) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_intents.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'Argus.intents'`

- [ ] **Step 3: Write minimal implementation**

```python
# Argus/intents.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_intents.py -q`
Expected: PASS (10 passed). If a matcher order causes a miss, adjust ordering (more-specific patterns first) — the ToolCall names above are authoritative.

- [ ] **Step 5: Commit**

```bash
git add Argus/intents.py tests/services/test_argus_intents.py
git commit -m "Phase 4 Task 2: Argus/intents — pure model-free command grammar

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `Argus/tools.py` — tool registry + handlers

**Files:**
- Create: `Argus/tools.py`
- Test: `tests/services/test_argus_tools.py`

**Interfaces:**
- Consumes: nothing at import (handlers lazy-import singletons).
- Produces:
  - `Tool` dataclass `(name, description, kind, handler)` where `kind in {"read","action"}`.
  - `REGISTRY: dict[str, Tool]`.
  - `kind(name) -> str | None`.
  - `describe() -> str` (one line per tool, for prompts/help).
  - `run(name: str, arg: str) -> str` — execute a tool's handler; unknown name → `"Unknown command: <name>"`; handler exceptions → `"⚠ <name> failed: <err>"`.
  - `set_scanner_provider(fn)` — `fn() -> object with .scan_file(path) -> dict|None` (injected by the Flask layer; default returns None → "Scanner not available").

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_argus_tools.py
import types
from Argus import tools


def test_kind_lookup():
    assert tools.kind("get_threats") == "read"
    assert tools.kind("block_ip") == "action"
    assert tools.kind("nope") is None


def test_run_unknown():
    assert tools.run("nope", "") == "Unknown command: nope"


def test_get_protection_level(monkeypatch):
    fake_av = types.SimpleNamespace(get_protection_level=lambda: 87)
    monkeypatch.setattr(tools, "_avbrain", lambda: fake_av)
    assert "87" in tools.run("get_protection_level", "")


def test_get_threats_none(monkeypatch):
    monkeypatch.setattr(tools, "_avbrain", lambda: types.SimpleNamespace(get_active_threats=lambda: []))
    assert tools.run("get_threats", "") == "No active threats."


def test_block_ip_executes(monkeypatch):
    calls = {}
    fake_brain = types.SimpleNamespace(emit_block=lambda ip, reason: calls.update(ip=ip, reason=reason))
    monkeypatch.setattr(tools, "_brain", lambda: fake_brain)
    out = tools.run("block_ip", "1.2.3.4")
    assert calls["ip"] == "1.2.3.4"
    assert "1.2.3.4" in out


def test_scan_file_no_scanner():
    tools.set_scanner_provider(lambda: None)
    assert "not available" in tools.run("scan_file", r"C:\x.exe").lower()


def test_scan_file_with_scanner(monkeypatch):
    svc = types.SimpleNamespace(scan_file=lambda p: {"verdict": "MALWARE", "reasons": ["yara:x"]})
    tools.set_scanner_provider(lambda: svc)
    out = tools.run("scan_file", r"C:\evil.exe")
    assert "MALWARE" in out


def test_handler_exception_is_safe(monkeypatch):
    def boom():
        raise RuntimeError("kaboom")
    monkeypatch.setattr(tools, "_avbrain", lambda: (_ for _ in ()).throw(RuntimeError("kaboom")))
    out = tools.run("get_protection_level", "")
    assert out.startswith("⚠") and "get_protection_level" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_tools.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'Argus.tools'`

- [ ] **Step 3: Write minimal implementation**

```python
# Argus/tools.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_tools.py -q`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add Argus/tools.py tests/services/test_argus_tools.py
git commit -m "Phase 4 Task 3: Argus/tools — read/action registry with confirm-gated actions

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: `Argus/context.py` — live-state grounding

**Files:**
- Create: `Argus/context.py`
- Test: `tests/services/test_argus_context.py`

**Interfaces:**
- Consumes: `get_brain()`, `get_avbrain()` (wrapped for monkeypatch).
- Produces: `build_context() -> str` — a compact live-state block: protection level, active-threat count + top few, module up/down counts. **Contains no "IsolationForest"/"anomaly" text.**

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_argus_context.py
import types
from Argus import context


def _wire(monkeypatch, level=90, threats=None, modules=None):
    threats = threats or []
    modules = modules or []
    monkeypatch.setattr(context, "_avbrain", lambda: types.SimpleNamespace(
        get_protection_level=lambda: level,
        get_active_threats=lambda: threats,
    ))
    monkeypatch.setattr(context, "_brain", lambda: types.SimpleNamespace(
        get_module_statuses=lambda: modules,
    ))


def test_context_reports_level_and_counts(monkeypatch):
    mods = [types.SimpleNamespace(name="A", running=True),
            types.SimpleNamespace(name="B", running=False)]
    _wire(monkeypatch, level=72, threats=[], modules=mods)
    out = context.build_context()
    assert "72" in out
    assert "1/2" in out or "1 of 2" in out  # modules up


def test_context_never_mentions_isolationforest(monkeypatch):
    _wire(monkeypatch)
    out = context.build_context().lower()
    assert "isolationforest" not in out and "isolation forest" not in out and "anomaly" not in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_context.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'Argus.context'`

- [ ] **Step 3: Write minimal implementation**

```python
# Argus/context.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_context.py -q`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add Argus/context.py tests/services/test_argus_context.py
git commit -m "Phase 4 Task 4: Argus/context — grounded live-state block (no IF claim)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: `Argus/assistant.py` — orchestrator + `get_argus()`

**Files:**
- Create: `Argus/assistant.py`
- Modify: `Argus/__init__.py` (add `get_argus()`)
- Test: `tests/services/test_argus_assistant.py`

**Interfaces:**
- Consumes: `Argus.history.ConversationStore`, `Argus.intents.parse_intent`, `Argus.tools` (`kind`, `run`, `describe`), `Argus.context.build_context`. LLM via an injectable `llm_fn(system, pairs, message) -> str | None` (default wraps `get_avbrain().llm_chat`). Soul/mind read from `Argus/soul.md`, `Argus/mind.md`.
- Produces: `Argus(store=None, llm_fn=None)` with `chat(message: str) -> str`, `clear() -> None`, `reload_prompts() -> None`, and a `history` attribute (the store). Package accessor `get_argus() -> Argus` (thread-safe singleton).

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_argus_assistant.py
import types
import Argus.assistant as A
from Argus.history import ConversationStore
from Argus.intents import ToolCall


def _make(tmp_path, llm_fn=None, monkeypatch=None):
    store = ConversationStore(tmp_path / "h.json")
    return A.Argus(store=store, llm_fn=llm_fn or (lambda s, p, m: None))


def test_read_intent_runs_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: ToolCall("get_threats", ""))
    monkeypatch.setattr(A.tools, "run", lambda n, a: "TOOL_OUTPUT")
    ag = _make(tmp_path)
    assert ag.chat("show threats") == "TOOL_OUTPUT"


def test_action_intent_asks_confirmation_and_does_not_execute(tmp_path, monkeypatch):
    ran = {"n": 0}
    monkeypatch.setattr(A, "parse_intent", lambda m: ToolCall("block_ip", "1.2.3.4"))
    monkeypatch.setattr(A.tools, "run", lambda n, a: ran.update(n=ran["n"] + 1) or "BLOCKED")
    ag = _make(tmp_path)
    reply = ag.chat("block 1.2.3.4")
    assert "confirm" in reply.lower() and ran["n"] == 0


def test_confirmation_executes_pending(tmp_path, monkeypatch):
    seq = iter([ToolCall("block_ip", "1.2.3.4"), None])
    monkeypatch.setattr(A, "parse_intent", lambda m: next(seq))
    monkeypatch.setattr(A.tools, "run", lambda n, a: "BLOCKED " + a)
    ag = _make(tmp_path)
    ag.chat("block 1.2.3.4")            # arms pending
    out = ag.chat("yes")                # confirms
    assert out == "BLOCKED 1.2.3.4"


def test_negative_cancels_pending(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: ToolCall("block_ip", "1.2.3.4") if "block" in m else None)
    monkeypatch.setattr(A.tools, "run", lambda n, a: "SHOULD_NOT_RUN")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: None)
    ag.chat("block 1.2.3.4")
    out = ag.chat("no")
    assert "SHOULD_NOT_RUN" not in out and "cancel" in out.lower()


def test_no_model_no_intent_gives_grounded_reply(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: None)
    monkeypatch.setattr(A, "build_context", lambda: "Protection level: 88%")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: None)   # no model
    out = ag.chat("how are things?")
    assert "88%" in out and "scan" in out.lower()       # grounded + lists commands


def test_llm_path_returns_conversational_reply(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: None)
    monkeypatch.setattr(A, "build_context", lambda: "ctx")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: "Here is my analysis.")
    assert ag.chat("what do you think?") == "Here is my analysis."


def test_history_is_persisted(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "parse_intent", lambda m: None)
    monkeypatch.setattr(A, "build_context", lambda: "ctx")
    ag = _make(tmp_path, llm_fn=lambda s, p, m: "reply")
    ag.chat("hi")
    assert ag.history.recent(10)[-1] == {"role": "assistant", "content": "reply"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_assistant.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'Argus.assistant'`

- [ ] **Step 3: Write minimal implementation**

```python
# Argus/assistant.py
"""Argus orchestrator. Intent-first (deterministic, model-free) with an
optional grounded LLM for free-form conversation. Actions are confirmation-
gated. No Flask/socketio here."""
from __future__ import annotations
import threading
from pathlib import Path
from typing import Callable, Optional, Tuple

from Argus import tools
from Argus.intents import parse_intent
from Argus.context import build_context
from Argus.history import ConversationStore

_DATA_DIR = Path.home() / ".AriaSecurity"
_HISTORY_PATH = _DATA_DIR / "argus_history.json"
_SOUL_FILE = Path("Argus") / "soul.md"
_MIND_FILE = Path("Argus") / "mind.md"
_AFFIRM = {"yes", "y", "confirm", "do it", "go ahead", "yep", "sure", "ok", "okay"}


def _default_llm(system, pairs, message):
    try:
        from Services.AVBrain import get_avbrain
        return get_avbrain().llm_chat(system, pairs, message)
    except Exception:
        return None


class Argus:
    def __init__(self, store: Optional[ConversationStore] = None,
                 llm_fn: Optional[Callable] = None):
        self.history = store or ConversationStore(_HISTORY_PATH)
        self._llm_fn = llm_fn or _default_llm
        self._pending: Optional[Tuple[str, str]] = None
        self._soul = ""
        self._mind = ""
        self.reload_prompts()

    def reload_prompts(self) -> None:
        for attr, path in (("_soul", _SOUL_FILE), ("_mind", _MIND_FILE)):
            try:
                setattr(self, attr, path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                setattr(self, attr, "")

    def clear(self) -> None:
        self._pending = None
        self.history.clear()

    def _system(self) -> str:
        soul = f"# Personality\n{self._soul}\n\n" if self._soul else ""
        mind = f"# Knowledge\n{self._mind}\n\n" if self._mind else ""
        return f"{soul}{mind}# Live System State\n{build_context()}"

    def chat(self, message: str) -> str:
        message = (message or "").strip()
        self.history.append("user", message)
        reply = self._route(message)
        self.history.append("assistant", reply)
        return reply

    def _route(self, message: str) -> str:
        # 1) resolve a pending confirmation
        if self._pending is not None:
            name, arg = self._pending
            if message.lower() in _AFFIRM:
                self._pending = None
                return tools.run(name, arg)
            self._pending = None
            # fall through: treat this message as new input (cancel the action)
            cancelled = f"Cancelled. "
        else:
            cancelled = ""

        # 2) deterministic intent routing
        tc = parse_intent(message)
        if tc is not None:
            k = tools.kind(tc.name)
            if k == "read":
                return cancelled + tools.run(tc.name, tc.arg)
            if k == "action":
                self._pending = (tc.name, tc.arg)
                return (cancelled +
                        f"This will run `{tc.name} {tc.arg}`. Confirm? (yes/no)")

        # 3) no intent — LLM conversation, else grounded fallback
        ctx = build_context()
        llm = None
        try:
            llm = self._llm_fn(self._system(), self.history.pairs(8), message)
        except Exception:
            llm = None
        if llm:
            return cancelled + llm
        return cancelled + (
            f"{ctx.splitlines()[0] if ctx else ''}\n"
            "I can run these without the AI model: scan <path>, show threats, "
            "block <ip>, lookup <ip|hash>, read <log>. "
            "Download the AI model in Settings for full conversation."
        )


_instance: Optional[Argus] = None
_lock = threading.Lock()


def get_argus() -> Argus:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = Argus()
    return _instance
```

Then add to `Argus/__init__.py`:
```python
from Argus.assistant import get_argus, Argus   # noqa: F401
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_assistant.py -q`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add Argus/assistant.py Argus/__init__.py tests/services/test_argus_assistant.py
git commit -m "Phase 4 Task 5: Argus/assistant — intent-first orchestrator + confirm flow

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: AVBrain surgery — add `llm_chat`, remove assistant code

**Files:**
- Modify: `Services/AVBrain.py`
- Test: `tests/services/test_avbrain_llmchat.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `AVBrain.llm_chat(system: str, history: list, user_msg: str) -> str | None` — delegates to the already-loaded `self._llm.chat(system, history, user_msg)`; returns `None` when no engine is loaded. Removes the assistant-only members (they now live in `Argus/`).

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_avbrain_llmchat.py
from Services.AVBrain import AVBrain


def test_llm_chat_none_when_no_engine():
    av = AVBrain.__new__(AVBrain)   # bypass __init__/model load
    av._llm = None
    assert av.llm_chat("sys", [], "hi") is None


def test_llm_chat_delegates_when_engine_present():
    av = AVBrain.__new__(AVBrain)
    class _Eng:
        available = True
        def chat(self, system, history, user_msg, **k):
            return f"reply:{user_msg}"
    av._llm = _Eng()
    assert av.llm_chat("sys", [], "ping") == "reply:ping"


def test_assistant_members_removed():
    # the assistant code moved to Argus/ — these must no longer exist on AVBrain
    for gone in ("_build_aria_system", "_execute_tool", "_load_aria_prompts",
                 "clear_chat_history", "reload_aria_prompts"):
        assert not hasattr(AVBrain, gone), f"{gone} should have moved to Argus/"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_avbrain_llmchat.py -q`
Expected: FAIL — `llm_chat` missing / assistant members still present.

- [ ] **Step 3: Implement**

In `Services/AVBrain.py`:
1. Add the accessor method to the `AVBrain` class (near `is_llm_available`):
```python
    def llm_chat(self, system: str, history: list, user_msg: str):
        """Shared access to the single loaded LLM for the Argus assistant.
        Returns None when no model is loaded (Argus then falls back)."""
        if not self._llm or not getattr(self._llm, "available", False):
            return None
        try:
            return self._llm.chat(system, history, user_msg)
        except Exception:
            return None
```
2. **Delete** the assistant-only members from `AVBrain`: `chat()`, `_build_aria_system()`, `_execute_tool()`, `_load_aria_prompts()`, `reload_aria_prompts()`, `clear_chat_history()`; and the instance fields `self._soul`, `self._mind`, `self._chat_history`, `self._chat_lock` (remove their initialisation in `__init__` and the `self._load_aria_prompts()` call). Remove the module-level `_TOOL_RE` regex and the `_SOUL_FILE`/`_MIND_FILE`/`_ARIA_DIR` constants **only if** nothing else references them (grep first; `LLMEngine` and scoring must be untouched). Keep `is_llm_available()`, `LLMEngine`, `IFEngine`, `_recompute`, `_llm_loop`, `_recovery_loop`, `get_active_threats`, `get_all_threats`, `resolve_threat`, `get_protection_level`.
3. Verify no remaining references to the removed names inside `AVBrain.py`.

- [ ] **Step 4: Run tests**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_avbrain_llmchat.py -q`
Expected: PASS (3 passed).
Then confirm AVBrain still imports and scoring is intact:
Run: `.venv/Scripts/python.exe -c "import Services.AVBrain as a; b=a.AVBrain.__new__(a.AVBrain); print('ok', hasattr(a.AVBrain,'llm_chat'), hasattr(a.AVBrain,'_recompute'))"`
Expected: `ok True True`

- [ ] **Step 5: Commit**

```bash
git checkout -- Config/sentinel_whitelist.json 2>/dev/null || true
git add Services/AVBrain.py tests/services/test_avbrain_llmchat.py
git commit -m "Phase 4 Task 6: AVBrain — add shared llm_chat, remove assistant code (moved to Argus/)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Persona correction — `mind.md` + `soul.md`

**Files:**
- Modify: `Argus/mind.md`
- Modify: `Argus/soul.md`
- Test: `tests/services/test_argus_persona.py`

**Interfaces:**
- Consumes: nothing.
- Produces: corrected persona files. `mind.md` no longer claims an IsolationForest/ML-anomaly capability and lists the real tools; `soul.md`'s "real tools" claim matches the registry.

- [ ] **Step 1: Write the failing test**

```python
# tests/services/test_argus_persona.py
from pathlib import Path


def test_mind_does_not_claim_isolationforest():
    txt = Path("Argus/mind.md").read_text(encoding="utf-8").lower()
    assert "isolationforest" not in txt and "isolation forest" not in txt
    assert "if_anomaly_score" not in txt


def test_mind_lists_real_protection_level_inputs():
    txt = Path("Argus/mind.md").read_text(encoding="utf-8").lower()
    assert "module" in txt and "threat" in txt and "llm" in txt


def test_mind_lists_new_tools():
    txt = Path("Argus/mind.md").read_text(encoding="utf-8")
    for tool in ("scan_file", "lookup_ip", "lookup_hash", "block_ip"):
        assert tool in txt
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_persona.py -q`
Expected: FAIL — `mind.md` still contains IsolationForest text / lacks tool names.

- [ ] **Step 3: Edit the persona files**

In `Argus/mind.md`:
- Remove the "IsolationForest update → protection level recompute" pipeline line and the entire "### IsolationForest (IF)" section.
- Replace the protection-level inputs line with: `Inputs: module_online_ratio, active_threat_penalties, mitigated_threat_penalties (fading), LLM_delta.`
- Remove the "IF anomaly + multiple HIGH events" pattern line (replace with a rule that doesn't reference IF, e.g. "multiple HIGH/CRITICAL events in a short window: possible coordinated attack").
- Add/replace a tools section listing the real registry:
  ```
  ## Tools I can run
  Read (immediate): get_threats, get_modules, get_protection_level, get_stats,
    get_recent_events, read_log, scan_file, lookup_ip, lookup_hash
  Action (require your confirmation): block_ip, resolve_threat, whitelist_ip, whitelist_hash
  ```

In `Argus/soul.md`: ensure the "real tools / real actions" wording remains accurate (it now is, since `scan_file` etc. exist). No IsolationForest claim exists in `soul.md`; leave the persona otherwise intact.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/Scripts/python.exe -m pytest tests/services/test_argus_persona.py -q`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add Argus/mind.md Argus/soul.md tests/services/test_argus_persona.py
git commit -m "Phase 4 Task 7: correct Argus persona — drop IsolationForest claim, list real tools

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Flask integration + reachability + boot

**Files:**
- Modify: `SentinelUI_Flask.py` (aria routes + remove `_ARIA_HISTORY` + wire scanner provider)
- Modify: `scripts/verify_reachability.py` (`EXPECTED_LIVE`)
- Test: `tests/services/test_argus_flask_smoke.py`

**Interfaces:**
- Consumes: `Argus` package (`get_argus`, `tools.set_scanner_provider`).
- Produces: unchanged/clarified HTTP contracts: `/api/aria/chat` (POST) async → `aria_reply`; `/api/aria/history` (GET) → list of `{role,content}`; `/api/aria/clear` (POST) → `{status}`.

- [ ] **Step 1: Add the Argus import + wire the scanner provider** near the other Services imports in `SentinelUI_Flask.py`:
```python
from Argus import get_argus
from Argus import tools as _argus_tools
_argus_tools.set_scanner_provider(lambda: _state.get_service())
```

- [ ] **Step 2: Rewrite the aria routes.** Replace the current `/api/aria/chat` + `/api/aria/history` block (and remove the `_ARIA_HISTORY` global) with:
```python
@app.route("/api/aria/chat", methods=["POST"])
def api_aria_chat():
    msg = (request.json or {}).get("message", "")
    if not msg:
        return jsonify({"error": "empty message"}), 400

    def _respond():
        try:
            reply = get_argus().chat(msg)
        except Exception as exc:
            reply = f"⚠ Argus error: {exc}"
        socketio.emit("aria_reply", {"reply": reply})

    threading.Thread(target=_respond, daemon=True, name="ArgusChat").start()
    return jsonify({"status": "processing"})

@app.route("/api/aria/history")
def api_aria_history():
    return jsonify(get_argus().history.recent(40))

@app.route("/api/aria/clear", methods=["POST"])
def api_aria_clear():
    get_argus().clear()
    return jsonify({"status": "cleared"})
```
Delete the old `_ARIA_HISTORY = []` line and any remaining references to it.

- [ ] **Step 3: Write the smoke test**

```python
# tests/services/test_argus_flask_smoke.py
def test_argus_package_imports_and_wires():
    from Argus import get_argus
    from Argus import tools
    tools.set_scanner_provider(lambda: None)
    assert get_argus() is not None

def test_argus_modules_have_no_flask():
    import Argus.assistant as a, Argus.tools as t, Argus.context as c
    for m in (a, t, c):
        assert not hasattr(m, "jsonify") and not hasattr(m, "socketio")
```

- [ ] **Step 4: Run the full services suite**

Run: `.venv/Scripts/python.exe -m pytest tests/services/ -q`
Expected: PASS (existing 125 + all new Argus tests).

- [ ] **Step 5: Update reachability gate**

Run: `.venv/Scripts/python.exe scripts/verify_reachability.py`
The new `Argus/*` modules (imported via `from Argus import get_argus`, and `Argus/__init__` imports `assistant`, which imports `tools`/`intents`/`context`/`history`) become live. Set `EXPECTED_LIVE` in `scripts/verify_reachability.py` to the printed value, re-run:
Run: `.venv/Scripts/python.exe scripts/verify_reachability.py`
Expected: PASS. Report old→new value.

- [ ] **Step 6: Headless boot smoke (HTTP 200)**

Run:
```bash
git checkout -- Config/sentinel_whitelist.json 2>/dev/null || true
SENTINEL_NO_ELEVATE=1 timeout 120 .venv/Scripts/python.exe -c "
import os,sys,threading,time,urllib.request,importlib.util
os.environ['SENTINEL_NO_ELEVATE']='1'; sys.argv=['x','--no-elevate']
os.chdir(r'D:/ZashironSentinel'); sys.path.insert(0,r'D:/ZashironSentinel')
spec=importlib.util.spec_from_file_location('e','SentinelUI_Flask.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
threading.Thread(target=m._start_flask,daemon=True).start()
st=None
for _ in range(30):
    time.sleep(1)
    try: st=urllib.request.urlopen('http://127.0.0.1:8765',timeout=3).status; break
    except Exception as e: st='ERR:'+type(e).__name__
sys.stdout.write('BOOT_RESULT HTTP=%s\n'%st); sys.stdout.flush(); time.sleep(0.3); os._exit(0)
" 2>&1 | grep -E "BOOT_RESULT|Traceback"
```
Expected: `BOOT_RESULT HTTP=200`, no traceback.

- [ ] **Step 7: Commit**

```bash
git checkout -- Config/sentinel_whitelist.json 2>/dev/null || true
git add SentinelUI_Flask.py scripts/verify_reachability.py tests/services/test_argus_flask_smoke.py
git commit -m "Phase 4 Task 8: wire Argus into Flask, drop _ARIA_HISTORY, reachability + boot

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Package extraction (§3.1) → Tasks 1–5. `history` → T1; `intents` → T2; `tools` (read/action registry incl. new scan_file/lookup/whitelist) → T3; `context` (no IF) → T4; `assistant` + `get_argus` + confirm flow + no-model fallback → T5.
- Shared LLM accessor + AVBrain assistant-code removal (§5) → T6.
- IsolationForest correction (§2, §3.4) → T4 (context asserts no IF text) + T7 (mind.md).
- Flask integration + single history + `/clear` (§4) → T8; `_ARIA_HISTORY` removed → T8.
- Testing (§7) → per-task tests; Verification (§8) → T8 steps 4–6.

**Placeholder scan:** None. T6 step 3 gives explicit member-removal list; T7 gives explicit edits; no "TBD/handle edge cases".

**Type consistency:** `ConversationStore.pairs()` (T1) consumed by `assistant` (T5) and `AVBrain.llm_chat(system, history, user_msg)` (T6) — history param is the `pairs()` list of `(user, assistant)` tuples, matching `LLMEngine.chat(system, history, user_msg)`'s existing signature. `parse_intent → ToolCall(name, arg)` (T2) consumed by `tools.kind/run(name, arg)` (T3) and `assistant` (T5) — names match. `set_scanner_provider(fn)` (T3) called in Flask (T8). `get_argus()` (T5) used in Flask (T8). Consistent.
