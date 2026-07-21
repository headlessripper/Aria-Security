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
