#!/usr/bin/env python3
"""
SentinelAiSenseService.py

AI assistant service for AriaSecurity.

Simplified design:
- No rolling buffer, no strict per-line parsing.
- For analysis: reads only the last 10 lines from each log file at /ask time.
- For notifications: background loop scans last 10 lines and fires rules.
- Uses llama.cpp (.gguf) via llama-cpp-python with streaming responses.
- Exposes an internal FastAPI API with auth token:
    POST /ask           -> streamed answer
    GET  /notifications -> list of notifications
- Rate-limits AI invocations to avoid overload.

Requirements (pip):
    fastapi
    uvicorn
    llama-cpp-python
"""

import os
import time
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Deque, Tuple, Iterator, Any, Set

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel
import uvicorn
from llama_cpp import Llama

# =========================
# CONFIG
# =========================

MODEL_CTX = 6096
MODEL_MAX_TOKENS = 5000
MODEL_TEMPERATURE = 0.2

# Internal API
API_HOST = "127.0.0.1"
API_PORT = 8765

# Simple shared auth token (change this)
API_AUTH_TOKEN = "Sentinel_!-2026@360!"

# Rate limiting for model calls
MAX_REQUESTS_PER_MINUTE = 10

# Log files (adjust to your environment)
LOG_PATHS = [
    # Production
     Path(r"C:\Program Files\AriaSecurity\logs\NetPro.log"),
    Path(r"C:\Program Files\AriaSecurity\logs\psds.log"),
    Path(r"C:\Program Files\AriaSecurity\logs\Sense.log"),
    Path(r"C:\Program Files\AriaSecurity\logs\sys.log"),
    Path(r"C:\Program Files\AriaSecurity\Sentinel.log"),  # Added /logs/
    Path(r"C:\Program Files\AriaSecurity\logs\RansomPro.log"),
    Path(r"C:\Program Files\AriaSecurity\zashiron_exploit_log.txt"),  # Added /logs/
    Path.home() / ".AriaSecurity" / ".SentinelSense" / "sense_core.log",
    Path.home() / ".AriaSecurity" / ".SentinelSense" / "sense_gui.log",
    
    # Test
    #Path("./logs/NetPro.log"),
    #Path("./logs/psds.log"),
    #Path("./logs/Sense.log"),
    #Path("./logs/Sys.log"),
]

MODEL_DIR = Path.home() / ".AriaSecurity" / "model"
MODEL_FILE = MODEL_DIR / "Sentinel-R1.gguf"
MODEL_PATH = str(MODEL_FILE)
print(f"Using model path: {MODEL_PATH}")

# =========================
# SIMPLE TAIL UTILITY
# =========================

def tail_lines(path: Path, n: int = 10) -> List[str]:
    """
    Return the last n lines of a text file (UTF-8, ignore errors).
    If file does not exist, return [].
    """
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return [line.rstrip("\n") for line in lines[-n:]]
    except Exception:
        return []

def build_recent_logs_context() -> str:
    """
    Reads the last 10 lines from each configured log file
    and builds a single text block for the model.
    """
    chunks: List[str] = []
    for path in LOG_PATHS:
        lines = tail_lines(path, n=10)
        if not lines:
            continue
        chunks.append(f"=== {path.name} (last {len(lines)} lines) ===")
        chunks.extend(lines)
        chunks.append("")  # blank line between files
    return "\n".join(chunks)

# =========================
# NOTIFICATION ENGINE
# =========================

NOTIFICATIONS: Deque[Dict[str, Any]] = deque(maxlen=200)

# For dedup: remember a small set of "event signatures" we've already notified on
SEEN_EVENTS: Set[str] = set()
SEEN_EVENTS_LIMIT = 1000

def add_notification(title: str, body: str, severity: str = "info"):
    NOTIFICATIONS.append({
        "time": datetime.utcnow().isoformat() + "Z",
        "title": title,
        "body": body,
        "severity": severity,
    })

def scan_logs_for_notifications():
    """
    Periodically scan last 10 lines of each log and fire notifications
    based on simple keyword rules:
      - Sense.log: INSTALL / UNINSTALL / Leftovers detected
      - psds.log: HARD BLOCK applied
      - NetPro.log: AUTO-BLOCK
    """
    global SEEN_EVENTS
    while True:
        for path in LOG_PATHS:
            lines = tail_lines(path, n=10)
            if not lines:
                continue

            fname = path.name.lower()

            for line in lines:
                sig = f"{fname}|{line}"
                if sig in SEEN_EVENTS:
                    continue

                low = line.lower()

                # Sense logs (install / uninstall / leftovers)
                if "sense" in fname:
                    if "install" in low:
                        add_notification("Install event detected", f"{path.name}: {line}", "low")
                    elif "uninstall" in low:
                        add_notification("Uninstall event detected", f"{path.name}: {line}", "medium")
                    elif "leftovers detected" in low:
                        add_notification("Leftovers detected", f"{path.name}: {line}", "medium")

                # PSDS logs: HARD BLOCK applied
                elif "psds" in fname:
                    if "hard block applied" in low:
                        add_notification("Hard block applied", f"{path.name}: {line}", "high")

                # NetPro logs: AUTO-BLOCK
                elif "netpro" in fname or ("net" in fname and "pro" in fname):
                    if "auto-block" in low or "auto block" in low:
                        add_notification("Network auto-block", f"{path.name}: {line}", "high")

                SEEN_EVENTS.add(sig)
                if len(SEEN_EVENTS) > SEEN_EVENTS_LIMIT:
                    # crude pruning to keep memory bounded
                    SEEN_EVENTS = set(list(SEEN_EVENTS)[-SEEN_EVENTS_LIMIT:])

        time.sleep(5)  # adjust polling interval

# =========================
# LLaMA ENGINE (llama-cpp-python)
# =========================

class LlamaEngine:
    def __init__(self, model_path: str, n_ctx: int = MODEL_CTX, n_gpu_layers: int = 0):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        self.llm = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            logits_all=False,
            embedding=False,
            verbose=False,
        )

    def stream_chat(self, system_prompt: str, user_prompt: str) -> Iterator[str]:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        for token in self.llm.create_chat_completion(
            messages=messages,
            max_tokens=MODEL_MAX_TOKENS,
            stream=True,
            temperature=MODEL_TEMPERATURE,
        ):
            delta = token["choices"][0]["delta"].get("content", "")
            if delta:
                yield delta

SYSTEM_PROMPT = (
    "You are Aria Security's AI assistant running as a local security copilot.\n"
    "You analyze AriaSecurity logs and provide:\n"
    "- concise, technically accurate explanations\n"
    "- risk assessments (low/medium/high/critical)\n"
    "- concrete remediation and hardening suggestions\n"
    "If logs don't contain enough information to answer, clearly say what is missing.\n"
    "Prefer short, direct answers. Avoid speculation.\n"
)

# =========================
# RATE LIMITING
# =========================

class RateLimiter:
    """
    Simple sliding-window rate limiter:
    allows up to MAX_REQUESTS_PER_MINUTE successful model calls per minute.
    """

    def __init__(self, max_per_minute: int):
        self.max_per_minute = max_per_minute
        self.timestamps: Deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            while self.timestamps and self.timestamps[0] < cutoff:
                self.timestamps.popleft()
            if len(self.timestamps) >= self.max_per_minute:
                return False
            self.timestamps.append(now)
            return True

# =========================
# FASTAPI APP & AUTH
# =========================

app = FastAPI()

LLAMA_ENGINE: LlamaEngine | None = None
RATE_LIMITER = RateLimiter(MAX_REQUESTS_PER_MINUTE)

class AskRequest(BaseModel):
    question: str

def check_auth(request: Request):
    token = request.headers.get("X-Auth-Token") or request.headers.get("Authorization")
    if token is None:
        raise HTTPException(status_code=401, detail="Missing auth token")
    if token.startswith("Bearer "):
        token = token[7:]
    if token != API_AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid auth token")

@app.post("/ask")
async def ask(req: AskRequest, request: Request):
    check_auth(request)

    if not RATE_LIMITER.allow():
        raise HTTPException(status_code=429, detail="Too many requests, try later")

    if LLAMA_ENGINE is None:
        raise HTTPException(status_code=500, detail="Service not initialized")

    recent_logs = build_recent_logs_context()

    user_prompt = (
        "You are assisting an expert security engineer using AriaSecurity.\n\n"
        "Recent raw logs (only the last entries from each file):\n"
        f"{recent_logs}\n\n"
        f"User question: {req.question}\n\n"
        "Using only this context and general security knowledge, answer:\n"
        "- What is happening (if clear)?\n"
        "- Risk level (low/medium/high/critical) and why.\n"
        "- Recommended next steps (concrete, prioritized).\n"
    )

    def token_stream():
        for token in LLAMA_ENGINE.stream_chat(SYSTEM_PROMPT, user_prompt):
            yield token

    return StreamingResponse(token_stream(), media_type="text/plain")

@app.get("/notifications")
async def get_notifications(request: Request):
    check_auth(request)
    return JSONResponse(list(NOTIFICATIONS))

@app.get("/health")
async def health():
    return {"status": "ok"}

# =========================
# SERVICE MAIN
# =========================

import ctypes
from ctypes import wintypes

def hide_console_window():
    """
    Hide this process's console window on Windows.
    If no console is attached, this is a no-op.
    """
    kernel32 = ctypes.WinDLL("kernel32")
    user32 = ctypes.WinDLL("user32")

    SW_HIDE = 0

    kernel32.GetConsoleWindow.restype = wintypes.HWND
    hWnd = kernel32.GetConsoleWindow()
    if hWnd:
        user32.ShowWindow(hWnd, SW_HIDE)


def main():
    global LLAMA_ENGINE

    # Hide console window as soon as we start
    hide_console_window()

    LLAMA_ENGINE = LlamaEngine(model_path=MODEL_PATH, n_ctx=MODEL_CTX, n_gpu_layers=0)

    # Start background notification scanner
    t_notif = threading.Thread(target=scan_logs_for_notifications, daemon=True)
    t_notif.start()

    # Start FastAPI server (internal only)
    uvicorn.run(app, host=API_HOST, port=API_PORT)

if __name__ == "__main__":
    main()
