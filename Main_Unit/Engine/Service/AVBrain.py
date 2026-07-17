# AVBrain.py
"""
AVBrain — Central AI Intelligence for AriaSecurity

Components:
  IFEngine       IsolationForest anomaly scorer  (real-time, every 60s window)
  LogReader      Tails engine log files for LLM context
  LLMEngine      llama-cpp-python Phi-3.5-mini-instruct-Q4_K_M
  ThreatTracker  Active / mitigated / resolved threat registry
  AVBrain        Orchestrator — owns the protection level number

Protection level dynamics
  100  = all modules running, no active threats, IF normal
  Falls when: module goes offline, HIGH/CRITICAL threat is active, IF anomaly
  Rises when: threat is mitigated or resolved (gradual recovery over ~90 s)
  LLM override: level_delta ∈ [-30, +10] applied on top of rule score

Model (auto-detected, download separately):
  Phi-3.5-mini-instruct-Q4_K_M.gguf (~2.2 GB)
  Stored in: ~/.AriaSecurity/avbrain/
  GPU: n_gpu_layers=-1  (full VRAM offload — NVIDIA/AMD)
  CPU: n_gpu_layers=0   (fallback, ~3-6 tok/s on modern CPU)

llama-cpp-python install:
  CPU only  : pip install llama-cpp-python
  CUDA GPU  : CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --force-reinstall
  Pre-built : https://github.com/abetlen/llama-cpp-python/releases
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional heavy imports
# ---------------------------------------------------------------------------

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest as _SKIForest
    _SK_AVAILABLE = True
except ImportError:
    _SK_AVAILABLE = False

try:
    from llama_cpp import Llama
    _LLAMA_AVAILABLE = True
except ImportError:
    _LLAMA_AVAILABLE = False

from Main_Unit.Engine.Service.SentinelBrain import (
    get_brain, ThreatEvent, ThreatCategory, ThreatSeverity,
)
from Main_Unit.Service.write_to_log import write_to_log

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_LOG = "logs/AVBrain.log"
_MODEL_DIR = Path.home() / ".AriaSecurity" / "avbrain"

# Argus personality files — editable by the user
_ARIA_DIR   = Path("Argus")
_SOUL_FILE  = _ARIA_DIR / "soul.md"
_MIND_FILE  = _ARIA_DIR / "mind.md"

# Agentic tool-call pattern emitted by the LLM: [TOOL:name:optional_arg]
_TOOL_RE = re.compile(r"\[TOOL:(\w+)(?::([^\]]*))?\]")

N_CTX            = 8192   # LLM context window (Phi-3.5 supports up to 128k)
MAX_PROMPT_TOK   = 6000   # safety budget for the assembled prompt (leaves room for reply)
IF_WINDOW_SECS   = 60     # feature aggregation window (seconds)
IF_TRAIN_MIN     = 50     # minimum samples before IF switches to predict mode
LLM_INTERVAL     = 30     # seconds between LLM inference passes
RECOVERY_SECS    = 90     # seconds to fully recover level after threat resolves
AUTO_RESOLVE = {          # auto-expire active threats after N seconds
    ThreatSeverity.INFO:     120,
    ThreatSeverity.LOW:      300,
    ThreatSeverity.MEDIUM:   600,
    ThreatSeverity.HIGH:    1800,
    ThreatSeverity.CRITICAL: 3600,
}
SEVERITY_IMPACT = {
    ThreatSeverity.INFO:     0,
    ThreatSeverity.LOW:      3,
    ThreatSeverity.MEDIUM:   8,
    ThreatSeverity.HIGH:    15,
    ThreatSeverity.CRITICAL: 25,
}
MAX_LOG_TAIL = 250   # chars tailed per log file for LLM context


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ThreatRecord:
    id: str
    event: ThreatEvent
    status: Literal["active", "mitigated", "resolved"] = "active"
    level_impact: int = 0
    created_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None
    action_taken: Optional[str] = None

    def age(self) -> float:
        return time.time() - self.created_at

    def recovery_fraction(self) -> float:
        """0.0 → 1.0 over RECOVERY_SECS after resolution / mitigation."""
        if self.resolved_at is None:
            return 0.0
        return min(1.0, (time.time() - self.resolved_at) / RECOVERY_SECS)


@dataclass
class AVAssessment:
    threat_level: int = 0          # 0–100 overall threat score
    level_delta: int = 0           # protection level adjustment (-30 … +10)
    summary: str = ""
    recommended_action: str = ""
    false_positive_ids: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# IFEngine — IsolationForest wrapper
# ---------------------------------------------------------------------------

class IFEngine:
    """
    Real-time anomaly scorer.
    Collects feature vectors from 60-second windows.
    Trains silently on the first IF_TRAIN_MIN samples, then predicts.

    Feature vector (8 dimensions):
      [0] events / sec         — total event rate
      [1] network_events / sec — network-category event rate
      [2] high_count           — HIGH severity events in window
      [3] critical_count       — CRITICAL severity events in window
      [4] ransom_count         — RANSOMWARE events in window
      [5] exploit_count        — EXPLOIT events in window
      [6] module_ratio         — active_modules / total_modules
      [7] blocked_count        — cumulative IPs blocked (from Brain)
    """

    def __init__(self):
        self._samples: List[List[float]] = []
        self._model: Optional[_SKIForest] = None
        self._trained = False
        self._score: float = 1.0   # 1.0 = normal, -1.0 = anomalous
        self._lock = threading.Lock()

    @property
    def trained(self) -> bool:
        return self._trained

    @property
    def score(self) -> float:
        return self._score

    def update(self, features: List[float]) -> float:
        if not _SK_AVAILABLE:
            return 1.0
        with self._lock:
            self._samples.append(features)
            if not self._trained:
                if len(self._samples) >= IF_TRAIN_MIN:
                    self._model = _SKIForest(
                        n_estimators=100,
                        contamination=0.1,
                        random_state=42,
                    )
                    self._model.fit(self._samples)
                    self._trained = True
                    write_to_log(
                        f"IFEngine trained on {len(self._samples)} samples", _LOG
                    )
                return 1.0

            pred = int(self._model.predict([features])[0])
            self._score = float(pred)
            return self._score

    def anomaly_penalty(self) -> int:
        """Return protection-level penalty based on current score."""
        if not self._trained:
            return 0
        return 0 if self._score >= 1.0 else 15


# ---------------------------------------------------------------------------
# LogReader
# ---------------------------------------------------------------------------

class LogReader:
    """Tails the last MAX_LOG_TAIL chars of each engine log."""

    FILES = [
        "logs/psds.log",
        "logs/Ransom.log",
        "logs/ExploitPro.log",
        "logs/NetPro.log",
        "logs/Behavioral.log",
        "logs/SentinelBrain.log",
        "logs/ThreatIntel.log",
        "logs/AVBrain.log",
    ]

    def tails(self) -> str:
        parts = []
        for path in self.FILES:
            try:
                p = Path(path)
                if not p.exists():
                    continue
                text = p.read_text(encoding="utf-8", errors="ignore")
                tail = text[-MAX_LOG_TAIL:].strip()
                if tail:
                    parts.append(f"[{p.stem}]\n{tail}")
            except Exception:
                pass
        return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# LLMEngine
# ---------------------------------------------------------------------------

class LLMEngine:
    """
    llama-cpp-python wrapper.
    Tries full GPU offload first, falls back to CPU automatically.
    Produces structured JSON assessments using Phi-3.5-mini chat format.
    """

    _SYSTEM = (
        "You are AVBrain, the embedded AI security analyst of AriaSecurity. "
        "Analyze the security state and respond ONLY with a valid JSON object. "
        "Required keys:\n"
        "  threat_level        (int, 0-100)\n"
        "  level_delta         (int, -30 to 10)  protection level adjustment\n"
        "  summary             (str, max 80 chars)\n"
        "  recommended_action  (str, max 120 chars)\n"
        "  false_positive_ids  (list of threat IDs that are likely false positives)\n"
        "Be concise and security-focused. Output JSON only, no markdown."
    )

    def __init__(self, model_path: str):
        self._path = model_path
        self._llm: Optional[Llama] = None
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if not _LLAMA_AVAILABLE:
            write_to_log("llama-cpp-python not installed — LLM disabled", _LOG)
            return
        # Phi-3.5-mini supports up to 128k context. 2048 was far too small — Argus's
        # system prompt (soul + mind + live state) alone can exceed it. Use 8192,
        # which comfortably fits the prompt while staying light on VRAM/RAM.
        # Try GPU offload first, then CPU.
        for gpu_layers in (-1, 0):
            try:
                self._llm = Llama(
                    model_path=self._path,
                    n_ctx=N_CTX,
                    n_gpu_layers=gpu_layers,
                    verbose=False,
                )
                mode = "GPU (full offload)" if gpu_layers == -1 else "CPU"
                write_to_log(f"LLMEngine loaded on {mode} (n_ctx={N_CTX}): {self._path}", _LOG)
                return
            except Exception as e:
                write_to_log(
                    f"LLMEngine load attempt (gpu_layers={gpu_layers}) failed: {e}", _LOG
                )
        write_to_log("LLMEngine could not load — running without LLM", _LOG)

    @property
    def available(self) -> bool:
        return self._llm is not None

    def assess(self, context: str) -> Optional[AVAssessment]:
        if not self._llm:
            return None
        with self._lock:
            try:
                prompt = (
                    f"<|system|>\n{self._SYSTEM}<|end|>\n"
                    f"<|user|>\n{context}<|end|>\n"
                    f"<|assistant|>\n"
                )
                out = self._llm(
                    prompt,
                    max_tokens=256,
                    stop=["<|end|>", "<|user|>"],
                    temperature=0.1,
                )
                text = out["choices"][0]["text"].strip()
                start = text.find("{")
                end   = text.rfind("}") + 1
                if start == -1 or end == 0:
                    write_to_log(f"LLMEngine: no JSON in response: {text[:80]}", _LOG)
                    return None
                data = json.loads(text[start:end])
                return AVAssessment(
                    threat_level       = int(data.get("threat_level", 0)),
                    level_delta        = int(data.get("level_delta", 0)),
                    summary            = str(data.get("summary", ""))[:80],
                    recommended_action = str(data.get("recommended_action", ""))[:120],
                    false_positive_ids = list(data.get("false_positive_ids", [])),
                )
            except Exception as e:
                write_to_log(f"LLMEngine assess error: {e}", _LOG)
                return None

    def chat(
        self,
        system: str,
        history: List[tuple],   # [(user_msg, aria_response), ...]
        user_msg: str,
        max_tokens: int = 512,
    ) -> str:
        """
        Free-form conversational response — plain text, not JSON.
        history: last N (user, assistant) pairs for conversation memory.
        Runs under the LLM lock — call from a background thread.
        """
        if not self._llm:
            return "LLM model not loaded. Download the AVBrain model from Settings → Plugins."
        with self._lock:
            try:
                # Phi-3.5-mini chat template
                prompt = f"<|system|>\n{system}<|end|>\n"
                for u, a in history[-4:]:   # keep last 4 turns in context
                    prompt += f"<|user|>\n{u}<|end|>\n<|assistant|>\n{a}<|end|>\n"
                prompt += f"<|user|>\n{user_msg}<|end|>\n<|assistant|>\n"

                # Guard against context-window overflow: tokenize, and if the prompt
                # plus the reply budget would exceed n_ctx, trim the SYSTEM block
                # (the largest, most compressible part) and rebuild. This prevents
                # "Requested tokens (N) exceed context window" crashes.
                prompt = self._fit_to_context(prompt, system, history, user_msg, max_tokens)

                out = self._llm(
                    prompt,
                    max_tokens=max_tokens,
                    stop=["<|end|>", "<|user|>"],
                    temperature=0.3,
                )
                return out["choices"][0]["text"].strip()
            except Exception as e:
                write_to_log(f"LLMEngine chat error: {e}", _LOG)
                return f"⚠ LLM error: {e}"

    def _fit_to_context(self, prompt: str, system: str, history: List[tuple],
                        user_msg: str, max_tokens: int) -> str:
        """
        Ensure prompt_tokens + max_tokens <= n_ctx. If not, shrink the system
        block and drop older history until it fits. Pure-token-count based, so it
        works regardless of how large soul.md / mind.md / live-state grow.
        """
        try:
            n_ctx = int(self._llm.n_ctx())
        except Exception:
            n_ctx = N_CTX
        budget = n_ctx - max_tokens - 64   # reserve for reply + template overhead
        if budget <= 0:
            budget = max(256, n_ctx // 2)

        def _count(text: str) -> int:
            try:
                return len(self._llm.tokenize(text.encode("utf-8", errors="ignore")))
            except Exception:
                return len(text) // 4   # rough fallback: ~4 chars/token

        if _count(prompt) <= budget:
            return prompt

        # 1) Drop history turns oldest-first.
        for keep in (3, 2, 1, 0):
            p = f"<|system|>\n{system}<|end|>\n"
            for u, a in history[-keep:] if keep else []:
                p += f"<|user|>\n{u}<|end|>\n<|assistant|>\n{a}<|end|>\n"
            p += f"<|user|>\n{user_msg}<|end|>\n<|assistant|>\n"
            if _count(p) <= budget:
                return p

        # 2) Still too big — truncate the system block by characters until it fits.
        sys_text = system
        while sys_text and _count(
            f"<|system|>\n{sys_text}<|end|>\n<|user|>\n{user_msg}<|end|>\n<|assistant|>\n"
        ) > budget:
            sys_text = sys_text[: int(len(sys_text) * 0.8)]   # chop 20% each pass
        write_to_log(
            f"LLMEngine: prompt trimmed to fit context (n_ctx={n_ctx}, budget={budget})",
            _LOG,
        )
        return (f"<|system|>\n{sys_text}\n[context truncated]<|end|>\n"
                f"<|user|>\n{user_msg}<|end|>\n<|assistant|>\n")


# ---------------------------------------------------------------------------
# AVBrain
# ---------------------------------------------------------------------------

class AVBrain:
    """
    Singleton central AI intelligence.

    Lifecycle:
        from Main_Unit.Engine.Service.AVBrain import get_avbrain
        avbrain = get_avbrain()
        avbrain.start()   # call after SentinelService starts
        avbrain.stop()    # call on app quit
    """

    _instance: Optional[AVBrain] = None
    _inst_lock = threading.Lock()

    def __init__(self):
        self._if       = IFEngine()
        self._logs     = LogReader()
        self._llm: Optional[LLMEngine] = None

        self._threats: Dict[str, ThreatRecord] = {}
        self._t_lock   = threading.Lock()

        self._events: deque[ThreatEvent] = deque(maxlen=200)
        self._e_lock   = threading.Lock()

        self._level    = 100
        self._l_lock   = threading.Lock()

        self._last_assessment: Optional[AVAssessment] = None

        # Argus chat state
        self._soul: str = ""
        self._mind: str = ""
        self._chat_history: List[Tuple[str, str]] = []   # [(user, aria), ...]
        self._chat_lock = threading.Lock()
        self._load_aria_prompts()

        # IF feature window state
        self._win_start  = time.time()
        self._win_counts = self._blank_counts()

        self._running = False
        self._llm_thread: Optional[threading.Thread] = None
        self._recovery_thread: Optional[threading.Thread] = None

    @classmethod
    def get(cls) -> AVBrain:
        if cls._instance is None:
            with cls._inst_lock:
                if cls._instance is None:
                    cls._instance = AVBrain()
        return cls._instance

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        if self._running:
            return
        self._running = True

        # Wire to SentinelBrain event bus
        brain = get_brain()
        brain.signals.threat_detected.connect(self._on_threat)

        # Locate and load model (non-blocking — LLM loads in background)
        threading.Thread(target=self._load_llm, daemon=True, name="AVBrainLLMLoad").start()

        # LLM assessment loop
        self._llm_thread = threading.Thread(
            target=self._llm_loop, daemon=True, name="AVBrainLLM"
        )
        self._llm_thread.start()

        # Recovery + auto-resolve loop
        self._recovery_thread = threading.Thread(
            target=self._recovery_loop, daemon=True, name="AVBrainRecovery"
        )
        self._recovery_thread.start()

        write_to_log("AVBrain started", _LOG)

    def stop(self):
        self._running = False
        write_to_log("AVBrain stopped", _LOG)

    # ------------------------------------------------------------------
    # Event ingestion (called via Qt signal, thread-safe)
    # ------------------------------------------------------------------

    def _on_threat(self, event: ThreatEvent):
        with self._e_lock:
            self._events.append(event)

        impact = SEVERITY_IMPACT.get(event.severity, 0)

        # Network blocks are already dealt with — start as mitigated
        is_block = (
            "blocked" in event.title.lower()
            or "block" in event.detail.lower()
        )
        status: Literal["active", "mitigated", "resolved"] = (
            "mitigated" if is_block else "active"
        )
        resolved_at = time.time() if is_block else None

        tid = uuid.uuid4().hex[:8]
        rec = ThreatRecord(
            id          = tid,
            event       = event,
            status      = status,
            level_impact= impact,
            resolved_at = resolved_at,
            action_taken= "firewall block applied" if is_block else None,
        )
        with self._t_lock:
            self._threats[tid] = rec

        # Update IF feature window
        self._tick_window(event)

        # Immediate level recompute
        self._recompute()

    # ------------------------------------------------------------------
    # Manual threat resolution (callable by engines)
    # ------------------------------------------------------------------

    def resolve_threat(self, threat_id: str, action: str = "resolved by engine"):
        with self._t_lock:
            rec = self._threats.get(threat_id)
            if rec and rec.status == "active":
                rec.status      = "mitigated"
                rec.resolved_at = time.time()
                rec.action_taken = action
        self._recompute()

    # ------------------------------------------------------------------
    # Protection level
    # ------------------------------------------------------------------

    def get_protection_level(self) -> int:
        with self._l_lock:
            return self._level

    def get_last_assessment(self) -> Optional[AVAssessment]:
        return self._last_assessment

    def get_active_threats(self) -> List[ThreatRecord]:
        with self._t_lock:
            return [r for r in self._threats.values() if r.status == "active"]

    def get_all_threats(self) -> List[ThreatRecord]:
        with self._t_lock:
            return list(self._threats.values())

    def _recompute(self):
        brain   = get_brain()
        modules = brain.get_module_statuses()

        # 1 — Module score
        if modules:
            active       = sum(1 for m in modules if m.running)
            module_score = int(active / len(modules) * 100)
        else:
            module_score = 100

        # 2 — Active threat penalty (full impact)
        # 3 — Mitigated threat penalty (fades out as recovery_fraction rises)
        with self._t_lock:
            active_penalty = sum(
                r.level_impact
                for r in self._threats.values()
                if r.status == "active"
            )
            recovering_penalty = sum(
                int(r.level_impact * (1.0 - r.recovery_fraction()))
                for r in self._threats.values()
                if r.status == "mitigated"
            )

        # 4 — Anomaly penalty from IsolationForest
        anomaly_penalty = self._if.anomaly_penalty()

        # 5 — LLM delta (valid for 2 min)
        llm_delta = 0
        if self._last_assessment:
            age = time.time() - self._last_assessment.timestamp
            if age < 120:
                llm_delta = self._last_assessment.level_delta

        raw   = module_score - active_penalty - recovering_penalty - anomaly_penalty + llm_delta
        level = max(0, min(100, raw))

        with self._l_lock:
            self._level = level

        # Push to SentinelBrain so the existing UI wiring still works
        try:
            brain.set_protection_level(level)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # IF feature window
    # ------------------------------------------------------------------

    @staticmethod
    def _blank_counts() -> dict:
        return {
            "total": 0, "network": 0, "high": 0,
            "critical": 0, "ransom": 0, "exploit": 0,
        }

    def _tick_window(self, event: ThreatEvent):
        c = self._win_counts
        c["total"] += 1
        if event.category == ThreatCategory.NETWORK:
            c["network"] += 1
        if event.severity == ThreatSeverity.HIGH:
            c["high"] += 1
        if event.severity == ThreatSeverity.CRITICAL:
            c["critical"] += 1
        if event.category == ThreatCategory.RANSOMWARE:
            c["ransom"] += 1
        if event.category == ThreatCategory.EXPLOIT:
            c["exploit"] += 1

        elapsed = max(0.001, time.time() - self._win_start)
        if elapsed >= IF_WINDOW_SECS:
            brain   = get_brain()
            modules = brain.get_module_statuses()
            active  = sum(1 for m in modules if m.running)
            total   = max(1, len(modules))

            features = [
                c["total"]   / elapsed,
                c["network"] / elapsed,
                float(c["high"]),
                float(c["critical"]),
                float(c["ransom"]),
                float(c["exploit"]),
                active / total,
                float(brain.get_blocked_count()),
            ]
            score = self._if.update(features)
            write_to_log(
                f"IFEngine window closed: score={score} "
                f"(trained={self._if.trained})", _LOG
            )
            self._win_counts = self._blank_counts()
            self._win_start  = time.time()

    # ------------------------------------------------------------------
    # LLM loop
    # ------------------------------------------------------------------

    def _load_llm(self):
        model_path = self._find_model()
        if model_path:
            self._llm = LLMEngine(model_path)
        else:
            write_to_log(
                "AVBrain: no GGUF model found in ~/.AriaSecurity/avbrain/ "
                "— LLM disabled. Run AVBrainModelDownloader to install.", _LOG
            )

    def is_llm_available(self) -> bool:
        """True when a GGUF model is loaded and ready for inference."""
        return bool(self._llm and self._llm.available)

    def reload_model(self) -> bool:
        """
        (Re)load the GGUF model from disk after a download completes — lets the
        'Download Model' button activate Argus without restarting the app.
        Returns True if a model is loaded afterwards.
        """
        try:
            model_path = self._find_model()
            if not model_path:
                write_to_log("reload_model: no GGUF found on disk", _LOG)
                return False
            engine = LLMEngine(model_path)
            if engine.available:
                self._llm = engine
                write_to_log(f"reload_model: LLM now active ({model_path})", _LOG)
                return True
            write_to_log("reload_model: engine built but model unavailable", _LOG)
            return False
        except Exception as e:
            write_to_log(f"reload_model error: {e}", _LOG)
            return False

    def _llm_loop(self):
        # Wait for LLM to load
        time.sleep(10)
        while self._running:
            if self._llm and self._llm.available:
                try:
                    ctx = self._build_context()
                    assessment = self._llm.assess(ctx)
                    if assessment:
                        self._last_assessment = assessment
                        write_to_log(
                            f"AVBrain assessment: "
                            f"threat={assessment.threat_level} "
                            f"delta={assessment.level_delta:+d} "
                            f"| {assessment.summary}",
                            _LOG,
                        )
                        # Mark LLM-identified false positives as resolved
                        if assessment.false_positive_ids:
                            with self._t_lock:
                                for fid in assessment.false_positive_ids:
                                    if fid in self._threats:
                                        rec = self._threats[fid]
                                        rec.status      = "resolved"
                                        rec.resolved_at = time.time()
                                        rec.action_taken = "LLM: false positive"
                        self._recompute()
                except Exception as e:
                    write_to_log(f"AVBrain LLM loop error: {e}", _LOG)

            # Sleep LLM_INTERVAL but check _running every second
            for _ in range(LLM_INTERVAL):
                if not self._running:
                    return
                time.sleep(1)

    def _build_context(self) -> str:
        brain   = get_brain()
        modules = brain.get_module_statuses()

        mod_str = ", ".join(
            f"{m.name}={'ON' if m.running else 'OFF'}" for m in modules
        )

        with self._e_lock:
            recent = list(self._events)[-10:]
        events_str = "\n".join(
            f"  [{e.severity.name}][{e.category.name}] {e.title}: {e.detail}"
            for e in recent
        ) or "  (none)"

        with self._t_lock:
            active_recs = [r for r in self._threats.values() if r.status == "active"]
        active_str = "\n".join(
            f"  [{r.id}] {r.event.title} "
            f"(sev={r.event.severity.name}, age={r.age():.0f}s)"
            for r in active_recs[:10]
        ) or "  (none)"

        log_tail = self._logs.tails()

        return (
            f"MODULES: {mod_str}\n\n"
            f"ACTIVE THREATS:\n{active_str}\n\n"
            f"RECENT EVENTS (last 10):\n{events_str}\n\n"
            f"IF ANOMALY SCORE: {self._if.score} "
            f"(1=normal, -1=anomalous, trained={self._if.trained})\n"
            f"CURRENT PROTECTION LEVEL: {self.get_protection_level()}\n\n"
            f"LOG EXCERPTS (last {MAX_LOG_TAIL} chars each):\n{log_tail[:2000]}"
        )

    # ------------------------------------------------------------------
    # Recovery loop — periodic auto-resolve + recompute
    # ------------------------------------------------------------------

    def _recovery_loop(self):
        while self._running:
            time.sleep(5)
            self._auto_resolve()
            self._recompute()

    def _auto_resolve(self):
        """Expire active threats that have exceeded their auto-resolve timeout."""
        now = time.time()
        with self._t_lock:
            for rec in self._threats.values():
                if rec.status == "active":
                    cutoff = AUTO_RESOLVE.get(rec.event.severity, 600)
                    if now - rec.created_at > cutoff:
                        rec.status      = "resolved"
                        rec.resolved_at = now
                        rec.action_taken = "auto-expired (timeout)"

    # ------------------------------------------------------------------
    # Argus personality loading
    # ------------------------------------------------------------------

    def _load_aria_prompts(self):
        """Load soul.md and mind.md from the Argus directory."""
        for attr, path in (("_soul", _SOUL_FILE), ("_mind", _MIND_FILE)):
            try:
                setattr(self, attr, path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                setattr(self, attr, "")
        if self._soul or self._mind:
            write_to_log("Argus prompts loaded (soul + mind)", _LOG)

    def reload_aria_prompts(self):
        """Hot-reload soul.md / mind.md without restarting."""
        self._load_aria_prompts()

    # ------------------------------------------------------------------
    # Argus chat (agentic, called from CopilotPage worker thread)
    # ------------------------------------------------------------------

    def chat(self, user_message: str) -> str:
        """
        Main entry point for the Copilot UI.
        Runs the LLM, parses any [TOOL:...] calls, executes them, then
        runs a second LLM pass with the results to produce the final reply.

        MUST be called from a background thread — LLM inference blocks.
        """
        if not self._llm or not self._llm.available:
            return (
                "⚠ AVBrain LLM is not loaded.\n"
                "Download the Phi-3.5-mini model from **Settings → Plugins → Download AVBrain Model**."
            )

        system = self._build_aria_system()

        with self._chat_lock:
            history = list(self._chat_history)

        # --- First LLM pass ---
        raw = self._llm.chat(system, history, user_message)

        # --- Parse and execute any tool calls ---
        tool_calls = _TOOL_RE.findall(raw)
        if tool_calls:
            tool_results = []
            clean_msg = _TOOL_RE.sub("", raw).strip()   # text without [TOOL:...] tags

            for name, arg in tool_calls:
                result = self._execute_tool(name, arg.strip())
                tool_results.append(f"[{name}({arg})] → {result}")

            # --- Second LLM pass: incorporate tool results ---
            augmented_user = (
                f"{user_message}\n\n"
                f"[Tool results]\n" + "\n".join(tool_results)
            )
            final = self._llm.chat(system, history, augmented_user)
        else:
            final = raw

        # Persist to chat history
        with self._chat_lock:
            self._chat_history.append((user_message, final))
            if len(self._chat_history) > 20:    # rolling window — keep last 20 turns
                self._chat_history = self._chat_history[-20:]

        return final

    def clear_chat_history(self):
        with self._chat_lock:
            self._chat_history.clear()

    def _build_aria_system(self) -> str:
        """Combine soul + mind + live security context into the system prompt."""
        soul_block = f"# Personality\n{self._soul}\n\n" if self._soul else ""
        mind_block = f"# Knowledge Base\n{self._mind}\n\n" if self._mind else ""
        ctx_block  = f"# Live System State\n{self._build_context()}"
        return soul_block + mind_block + ctx_block

    # ------------------------------------------------------------------
    # Agentic tool dispatch
    # ------------------------------------------------------------------

    def _execute_tool(self, name: str, arg: str) -> str:
        """Execute a tool by name, return a string result for the LLM."""
        try:
            brain = get_brain()

            if name == "get_threats":
                with self._t_lock:
                    active = [r for r in self._threats.values() if r.status == "active"]
                if not active:
                    return "No active threats."
                return "\n".join(
                    f"[{r.id}] {r.event.severity.name} {r.event.category.name} — "
                    f"{r.event.title} ({r.age():.0f}s ago)"
                    for r in active[:10]
                )

            elif name == "get_modules":
                modules = brain.get_module_statuses()
                return "\n".join(
                    f"{'✅' if m.running else '❌'} {m.name} — "
                    f"events={m.event_count}, note={m.health_note}"
                    for m in modules
                )

            elif name == "get_protection_level":
                return f"Protection level: {self.get_protection_level()}%"

            elif name == "get_recent_events":
                try:
                    n = int(arg) if arg else 10
                except ValueError:
                    n = 10
                events = brain.get_recent_events(n)
                if not events:
                    return "No recent events."
                return "\n".join(
                    f"[{e.severity.name}][{e.category.name}] {e.title}: {e.detail}"
                    for e in events
                )

            elif name == "get_stats":
                counts  = brain.get_threat_counts()
                blocked = brain.get_blocked_count()
                total   = brain.get_total_threats()
                lines   = [f"Total threats: {total}", f"IPs blocked: {blocked}"]
                lines  += [f"  {cat}: {cnt}" for cat, cnt in counts.items() if cnt > 0]
                return "\n".join(lines)

            elif name == "block_ip":
                ip = arg.strip()
                if not ip:
                    return "Error: no IP address provided."
                brain.emit_block(ip, "Blocked by Argus (user request)")
                return f"Firewall block applied to {ip} (both directions)."

            elif name == "resolve_threat":
                tid = arg.strip()
                if not tid:
                    return "Error: no threat ID provided."
                self.resolve_threat(tid, action="Resolved via Argus")
                return f"Threat {tid} marked as resolved."

            elif name == "read_log":
                log_map = {
                    "psds":       "logs/psds.log",
                    "ransom":     "logs/Ransom.log",
                    "netpro":     "logs/NetPro.log",
                    "exploit":    "logs/ExploitPro.log",
                    "behavioral": "logs/Behavioral.log",
                    "brain":      "logs/SentinelBrain.log",
                    "avbrain":    "logs/AVBrain.log",
                    "threatintel":"logs/ThreatIntel.log",
                }
                key  = arg.strip().lower()
                path = log_map.get(key)
                if not path:
                    return f"Unknown log '{arg}'. Available: {', '.join(log_map)}"
                try:
                    text = Path(path).read_text(encoding="utf-8", errors="ignore")
                    return text[-600:].strip() or "(empty)"
                except Exception as e:
                    return f"Could not read {path}: {e}"

            else:
                return f"Unknown tool: {name}"

        except Exception as e:
            write_to_log(f"Tool '{name}' error: {e}", _LOG)
            return f"Tool error: {e}"

    # ------------------------------------------------------------------
    # Model finder
    # ------------------------------------------------------------------

    @staticmethod
    def _find_model() -> Optional[str]:
        search = [
            _MODEL_DIR,
            Path("models/avbrain"),
            Path("models"),
            Path("."),
        ]
        for d in search:
            if not d.exists():
                continue
            for f in d.glob("*.gguf"):
                return str(f)
        return None


# ---------------------------------------------------------------------------
# Public accessor
# ---------------------------------------------------------------------------

def get_avbrain() -> AVBrain:
    return AVBrain.get()
