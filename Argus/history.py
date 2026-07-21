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
