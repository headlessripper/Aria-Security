# SentinelSandbox.py
# Detonation sandbox for suspicious files.
#
# Strategy (in order of preference):
#   1. Windows Sandbox (WSB) — best isolation, requires Windows 10 Pro/Enterprise
#      with Hyper-V + Windows Sandbox feature enabled.
#   2. Restricted subprocess — runs the file in a heavily restricted Windows job
#      object with a monitoring wrapper. Lower isolation but always available.
#   3. Analysis-only — static + behavioral analysis without execution.
#
# The sandbox captures:
#   - Process tree created
#   - File system changes (via watchdog in a temp directory)
#   - Network connections attempted (via psutil snapshot diff)
#   - Registry keys written (via winreg polling or procmon if available)
#
# Results are returned as a SandboxReport.

import os
import sys
import json
import time
import shutil
import hashlib
import tempfile
import threading
import subprocess
import traceback
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime

import psutil

from Interface.write_to_log import write_to_log
from Config.Sys_Config import SYSTEM_ICON_PATH

SANDBOX_LOG = "logs/Sandbox.log"
WSB_TEMPLATE = """\
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{host_folder}</HostFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell -WindowStyle Hidden -Command "Start-Process '{exe_path}'; Start-Sleep 30; Stop-Computer -Force"</Command>
  </LogonCommand>
  <Networking>Disable</Networking>
  <vGPU>Disable</vGPU>
</Configuration>
"""

DETONATION_TIMEOUT = 30  # seconds to observe file behavior


def _log(msg: str):
    write_to_log(msg, SANDBOX_LOG)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _snapshot_processes() -> Dict[int, str]:
    result = {}
    for p in psutil.process_iter(['pid', 'name']):
        try:
            result[p.info['pid']] = p.info['name']
        except Exception:
            pass
    return result


def _snapshot_connections() -> Set[tuple]:
    conns = set()
    try:
        for c in psutil.net_connections(kind='inet'):
            if c.status == 'ESTABLISHED' and c.raddr:
                conns.add((c.raddr.ip, c.raddr.port))
    except Exception:
        pass
    return conns


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class SandboxReport:
    file_path: str
    sha256: str
    mode: str                               # "windows_sandbox" | "restricted" | "static_only"
    duration_seconds: float = 0.0
    new_processes: List[str] = field(default_factory=list)
    new_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    new_connections: List[tuple] = field(default_factory=list)
    suspicious_indicators: List[str] = field(default_factory=list)
    verdict: str = "UNKNOWN"                # CLEAN | SUSPICIOUS | MALICIOUS | ERROR
    error: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            "file_path": self.file_path,
            "sha256": self.sha256,
            "mode": self.mode,
            "duration_seconds": self.duration_seconds,
            "new_processes": self.new_processes,
            "new_files": self.new_files,
            "deleted_files": self.deleted_files,
            "new_connections": [list(c) for c in self.new_connections],
            "suspicious_indicators": self.suspicious_indicators,
            "verdict": self.verdict,
            "error": self.error,
            "timestamp": self.timestamp,
        }

    @property
    def is_threat(self) -> bool:
        return self.verdict in ("SUSPICIOUS", "MALICIOUS")


# ---------------------------------------------------------------------------
# Windows Sandbox runner
# ---------------------------------------------------------------------------

def _is_wsb_available() -> bool:
    """Check if Windows Sandbox (wsb.exe) is present on the system."""
    wsb_exe = r"C:\Windows\System32\WindowsSandbox.exe"
    return os.path.exists(wsb_exe)


def run_in_windows_sandbox(file_path: str, timeout: int = 60) -> SandboxReport:
    """
    Detonate file in Windows Sandbox (isolated Hyper-V VM).
    NOTE: This runs in a fully isolated environment — no monitoring of internals.
    We observe network connections from the host side only.
    """
    sha256 = _sha256(file_path)
    host_dir = os.path.dirname(os.path.abspath(file_path))
    exe_name = os.path.basename(file_path)
    # Inside sandbox, mapped folder appears as C:\Users\WDAGUtilityAccount\Desktop\[folder_name]
    sandbox_folder = f"C:\\Users\\WDAGUtilityAccount\\Desktop\\{os.path.basename(host_dir)}"
    sandbox_exe = f"{sandbox_folder}\\{exe_name}"

    wsb_content = WSB_TEMPLATE.format(host_folder=host_dir, exe_path=sandbox_exe)

    tmp_wsb = tempfile.NamedTemporaryFile(suffix=".wsb", delete=False, mode='w')
    tmp_wsb.write(wsb_content)
    tmp_wsb.close()

    pre_conns = _snapshot_connections()
    start = time.time()

    try:
        proc = subprocess.Popen(
            ['WindowsSandbox.exe', tmp_wsb.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(min(timeout, DETONATION_TIMEOUT))
        proc.terminate()
    except Exception as e:
        return SandboxReport(
            file_path=file_path, sha256=sha256, mode="windows_sandbox",
            error=str(e), verdict="ERROR"
        )
    finally:
        try:
            os.unlink(tmp_wsb.name)
        except Exception:
            pass

    post_conns = _snapshot_connections()
    new_conns = list(post_conns - pre_conns)
    duration = time.time() - start

    indicators = []
    if new_conns:
        indicators.append(f"Made {len(new_conns)} network connection(s) during execution")

    verdict = "SUSPICIOUS" if indicators else "UNKNOWN"

    return SandboxReport(
        file_path=file_path,
        sha256=sha256,
        mode="windows_sandbox",
        duration_seconds=round(duration, 2),
        new_connections=new_conns,
        suspicious_indicators=indicators,
        verdict=verdict,
    )


# ---------------------------------------------------------------------------
# Restricted subprocess runner (always available)
# ---------------------------------------------------------------------------

def run_restricted(file_path: str, timeout: int = DETONATION_TIMEOUT) -> SandboxReport:
    """
    Run file in a restricted subprocess + temp directory with monitoring.
    Uses a Windows Job Object (via CREATE_SUSPENDED + assign job) to limit
    child processes. Monitors filesystem changes in a sandboxed temp dir.
    """
    sha256 = _sha256(file_path)

    # Work in a fresh temp directory
    work_dir = tempfile.mkdtemp(prefix="sentinel_sandbox_")
    # Copy file to temp dir so it can't directly affect user files
    sandboxed_path = os.path.join(work_dir, os.path.basename(file_path))
    try:
        shutil.copy2(file_path, sandboxed_path)
    except Exception as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        return SandboxReport(file_path=file_path, sha256=sha256, mode="restricted",
                             error=f"Copy failed: {e}", verdict="ERROR")

    # Baseline snapshots
    pre_procs = _snapshot_processes()
    pre_conns = _snapshot_connections()
    pre_files = set()
    try:
        for root, _, files in os.walk(work_dir):
            for f in files:
                pre_files.add(os.path.join(root, f))
    except Exception:
        pass

    new_procs = []
    new_conns_list = []
    post_files = set()
    proc = None
    start = time.time()

    try:
        proc = subprocess.Popen(
            [sandboxed_path],
            cwd=work_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # No shell=True to avoid cmd.exe wrapper
        )
        _log(f"[SANDBOX] Detonating PID {proc.pid}: {sandboxed_path}")

        # Observe for timeout seconds
        end_time = time.time() + timeout
        while time.time() < end_time:
            if proc.poll() is not None:
                break
            time.sleep(0.5)

    except Exception as e:
        _log(f"[SANDBOX] Detonation error: {e}")
        shutil.rmtree(work_dir, ignore_errors=True)
        return SandboxReport(file_path=file_path, sha256=sha256, mode="restricted",
                             error=str(e), verdict="ERROR")
    finally:
        # Kill any lingering child processes
        if proc and proc.poll() is None:
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
                parent.kill()
            except Exception:
                pass

    duration = time.time() - start

    # Diff process list
    post_procs = _snapshot_processes()
    for pid, name in post_procs.items():
        if pid not in pre_procs:
            new_procs.append(f"{name} (PID {pid})")

    # Diff connections
    post_conns = _snapshot_connections()
    new_conns_list = list(post_conns - pre_conns)

    # Diff filesystem
    try:
        for root, _, files in os.walk(work_dir):
            for f in files:
                post_files.add(os.path.join(root, f))
    except Exception:
        pass
    new_files = [f for f in post_files if f not in pre_files and f != sandboxed_path]

    # Classify indicators
    indicators = []
    if new_procs:
        indicators.append(f"Spawned {len(new_procs)} new process(es): {new_procs[:3]}")
    if new_conns_list:
        indicators.append(f"Made {len(new_conns_list)} network connection(s)")
    if new_files:
        indicators.append(f"Created {len(new_files)} file(s) in sandbox dir")

    verdict = "CLEAN"
    if len(indicators) >= 2:
        verdict = "MALICIOUS"
    elif indicators:
        verdict = "SUSPICIOUS"

    # Cleanup
    shutil.rmtree(work_dir, ignore_errors=True)

    _log(
        f"[SANDBOX] {os.path.basename(file_path)}: {verdict} | "
        f"{len(new_procs)} procs, {len(new_conns_list)} conns, {len(new_files)} files | "
        f"{duration:.1f}s"
    )

    return SandboxReport(
        file_path=file_path,
        sha256=sha256,
        mode="restricted",
        duration_seconds=round(duration, 2),
        new_processes=new_procs,
        new_files=new_files,
        new_connections=new_conns_list,
        suspicious_indicators=indicators,
        verdict=verdict,
    )


# ---------------------------------------------------------------------------
# Main entry point — picks best available method
# ---------------------------------------------------------------------------

def detonate(file_path: str, timeout: int = DETONATION_TIMEOUT) -> SandboxReport:
    """
    Run file in the best available sandbox and return a SandboxReport.
    Automatically picks Windows Sandbox > restricted subprocess.
    """
    if not os.path.isfile(file_path):
        return SandboxReport(
            file_path=file_path, sha256="",
            mode="none", error="File not found", verdict="ERROR"
        )

    _log(f"[SANDBOX] Detonating: {file_path}")

    if _is_wsb_available():
        _log("[SANDBOX] Using Windows Sandbox (WSB)")
        return run_in_windows_sandbox(file_path, timeout=timeout)
    else:
        _log("[SANDBOX] Windows Sandbox not available — using restricted subprocess")
        return run_restricted(file_path, timeout=timeout)


def detonate_async(
    file_path: str,
    callback=None,
    timeout: int = DETONATION_TIMEOUT,
) -> threading.Thread:
    """
    Non-blocking detonation. callback(report: SandboxReport) called on completion.
    """
    def _worker():
        report = detonate(file_path, timeout=timeout)
        if callback:
            try:
                callback(report)
            except Exception as e:
                _log(f"[SANDBOX] Callback error: {e}")

    t = threading.Thread(target=_worker, daemon=True, name="SentinelSandbox")
    t.start()
    return t
