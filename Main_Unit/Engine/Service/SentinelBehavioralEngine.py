# SentinelBehavioralEngine.py
# JSON-configurable behavioral rules engine.
# Defines multi-step threat patterns as composable conditions → action.
#
# Rule schema (behavioral_rules.json):
# {
#   "rules": [
#     {
#       "name": "LOLBin URL Download",
#       "enabled": true,
#       "severity": "high",
#       "description": "certutil.exe used to download files (common malware technique)",
#       "conditions": [
#         {"type": "process_name", "value": "certutil.exe"},
#         {"type": "cmdline_contains", "value": "-urlcache"}
#       ],
#       "condition_mode": "all",   // "all" = AND,  "any" = OR
#       "action": "alert_and_kill"
#     }
#   ]
# }
#
# Supported condition types:
#   process_name        — exact match (case-insensitive)
#   process_name_in     — value is a list
#   cmdline_contains    — substring in command line
#   parent_name         — parent process name
#   file_path_contains  — exe path contains substring
#   user_writable_path  — exe is in a user-writable directory
#   high_thread_count   — num_threads > value
#   high_memory_mb      — RSS memory MB > value
#   network_connection  — process has established network connections
#   child_of_browser    — parent is a browser process
#
# Supported actions:
#   alert           — log + toast notification
#   alert_and_kill  — log + toast + kill process
#   quarantine      — kill + quarantine the executable

import os
import sys
import json
import time
import threading
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import defaultdict

import psutil
import wmi
from winotify import Notification, audio

from Main_Unit.Service.write_to_log import write_to_log
from Main_Unit.Config.Sys_Config import SYSTEM_ICON_PATH
from Main_Unit.find_items import find_items

def _get_brain():
    from Main_Unit.Engine.Service.SentinelBrain import get_brain, ThreatEvent, ThreatCategory, ThreatSeverity
    return get_brain(), ThreatEvent, ThreatCategory, ThreatSeverity

BEHAV_LOG = "logs/Behavioral.log"
DEFAULT_RULES_PATH = "Main_Unit/Engine/Rules/behavioral_rules.json"

BROWSER_PROCESS_NAMES = {
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
    'brave.exe', 'opera.exe', 'vivaldi.exe', 'safari.exe',
}

SYSTEM_PATHS = [
    r'c:\windows\\',
    r'c:\windows\system32',
    r'c:\windows\syswow64',
    r'c:\windows\winsxs',
    r'c:\program files\\',
    r'c:\program files (x86)\\',
    r'c:\programdata\\',
]


def _log(msg: str):
    write_to_log(msg, BEHAV_LOG)


def _toast(title: str, msg: str):
    icon = find_items(SYSTEM_ICON_PATH)
    try:
        toast = Notification(app_id="Aria Security", title=title, msg=msg,
                             icon=icon, duration="long")
        toast.set_audio(audio.Reminder, loop=False)
        toast.show()
    except Exception:
        pass


def _is_user_writable(path: str) -> bool:
    if not path:
        return False
    low = path.lower()
    return not any(low.startswith(sp) for sp in SYSTEM_PATHS)


def _get_parent_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Default rules shipped with the product
# ---------------------------------------------------------------------------

DEFAULT_RULES = {
    "rules": [
        {
            "name": "LOLBin URL Download via certutil",
            "enabled": True,
            "severity": "high",
            "description": "certutil.exe used to download files — classic malware dropper technique",
            "conditions": [
                {"type": "process_name", "value": "certutil.exe"},
                {"type": "cmdline_contains", "value": "-urlcache"}
            ],
            "condition_mode": "all",
            "action": "alert_and_kill"
        },
        {
            "name": "PowerShell Encoded Command",
            "enabled": True,
            "severity": "high",
            "description": "PowerShell running encoded (obfuscated) commands",
            "conditions": [
                {"type": "process_name", "value": "powershell.exe"},
                {"type": "cmdline_contains", "value": "-EncodedCommand"}
            ],
            "condition_mode": "all",
            "action": "alert"
        },
        {
            "name": "PowerShell Download Cradle",
            "enabled": True,
            "severity": "high",
            "description": "PowerShell downloading and executing remote content (IEX / Invoke-Expression)",
            "conditions": [
                {"type": "process_name", "value": "powershell.exe"},
                {"type": "cmdline_contains", "value": "IEX"}
            ],
            "condition_mode": "all",
            "action": "alert"
        },
        {
            "name": "Mshta Scriptlet Execution",
            "enabled": True,
            "severity": "high",
            "description": "mshta.exe executing a remote script — common for JS/VBS malware",
            "conditions": [
                {"type": "process_name", "value": "mshta.exe"},
                {"type": "cmdline_contains", "value": "http"}
            ],
            "condition_mode": "all",
            "action": "alert_and_kill"
        },
        {
            "name": "Regsvr32 Remote COM Execution (Squiblydoo)",
            "enabled": True,
            "severity": "critical",
            "description": "regsvr32.exe loading a remote COM scriptlet — Squiblydoo bypass",
            "conditions": [
                {"type": "process_name", "value": "regsvr32.exe"},
                {"type": "cmdline_contains", "value": "/s"},
                {"type": "cmdline_contains", "value": "http"}
            ],
            "condition_mode": "all",
            "action": "alert_and_kill"
        },
        {
            "name": "Browser Spawning Script Interpreter",
            "enabled": True,
            "severity": "high",
            "description": "Browser launched cmd/powershell/wscript — malicious iframe or drive-by",
            "conditions": [
                {"type": "child_of_browser", "value": True},
                {"type": "process_name_in", "value": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"]}
            ],
            "condition_mode": "all",
            "action": "alert_and_kill"
        },
        {
            "name": "WMI Spawning Shell",
            "enabled": True,
            "severity": "high",
            "description": "WMI provider host spawning a shell — WMI-based lateral movement",
            "conditions": [
                {"type": "parent_name", "value": "WmiPrvSE.exe"},
                {"type": "process_name_in", "value": ["cmd.exe", "powershell.exe", "wscript.exe"]}
            ],
            "condition_mode": "all",
            "action": "alert_and_kill"
        },
        {
            "name": "RunDLL32 Remote Payload",
            "enabled": True,
            "severity": "high",
            "description": "rundll32.exe loading a remote or temp-directory DLL",
            "conditions": [
                {"type": "process_name", "value": "rundll32.exe"},
                {"type": "cmdline_contains", "value": "\\temp\\"}
            ],
            "condition_mode": "all",
            "action": "alert"
        },
        {
            "name": "Suspicious Process from Temp Directory",
            "enabled": True,
            "severity": "medium",
            "description": "Executable launched directly from %TEMP% — typical malware dropper",
            "conditions": [
                {"type": "file_path_contains", "value": "\\temp\\"},
                {"type": "user_writable_path", "value": True}
            ],
            "condition_mode": "all",
            "action": "alert"
        },
        {
            "name": "Process with Extremely High Thread Count",
            "enabled": True,
            "severity": "medium",
            "description": "Possible process hollowing or thread injection",
            "conditions": [
                {"type": "high_thread_count", "value": 200},
                {"type": "user_writable_path", "value": True}
            ],
            "condition_mode": "all",
            "action": "alert"
        },
        {
            "name": "LSASS Memory Access Attempt",
            "enabled": True,
            "severity": "critical",
            "description": "Non-system process attempting to open LSASS — credential dumping",
            "conditions": [
                {"type": "process_name_in", "value": ["procdump.exe", "mimikatz.exe", "wce.exe",
                                                        "fgdump.exe", "pwdump.exe", "gsecdump.exe"]}
            ],
            "condition_mode": "any",
            "action": "alert_and_kill"
        },
    ]
}


# ---------------------------------------------------------------------------
# Rule evaluator
# ---------------------------------------------------------------------------

class RuleEvaluator:

    @staticmethod
    def evaluate_condition(cond: Dict, proc: psutil.Process, wmi_proc=None) -> bool:
        ctype = cond.get("type", "")
        value = cond.get("value")

        try:
            if ctype == "process_name":
                return proc.name().lower() == str(value).lower()

            elif ctype == "process_name_in":
                names = [v.lower() for v in (value or [])]
                return proc.name().lower() in names

            elif ctype == "cmdline_contains":
                cmdline = " ".join(proc.cmdline()).lower()
                return str(value).lower() in cmdline

            elif ctype == "parent_name":
                parent_pid = proc.ppid()
                parent_name = _get_parent_name(parent_pid)
                return parent_name.lower() == str(value).lower()

            elif ctype == "file_path_contains":
                exe = (proc.exe() or "").lower()
                return str(value).lower() in exe

            elif ctype == "user_writable_path":
                exe = proc.exe() or ""
                result = _is_user_writable(exe)
                return result == bool(value)

            elif ctype == "high_thread_count":
                return proc.num_threads() > int(value)

            elif ctype == "high_memory_mb":
                rss_mb = proc.memory_info().rss / (1024 * 1024)
                return rss_mb > float(value)

            elif ctype == "network_connection":
                conns = proc.connections()
                established = [c for c in conns if c.status == 'ESTABLISHED']
                return len(established) > 0

            elif ctype == "child_of_browser":
                parent_pid = proc.ppid()
                parent_name = _get_parent_name(parent_pid).lower()
                result = parent_name in BROWSER_PROCESS_NAMES
                return result == bool(value)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False
        except Exception:
            return False

        return False

    @classmethod
    def matches_rule(cls, rule: Dict, proc: psutil.Process, wmi_proc=None) -> bool:
        conditions = rule.get("conditions", [])
        if not conditions:
            return False
        mode = rule.get("condition_mode", "all")

        if mode == "all":
            return all(cls.evaluate_condition(c, proc, wmi_proc) for c in conditions)
        elif mode == "any":
            return any(cls.evaluate_condition(c, proc, wmi_proc) for c in conditions)
        return False


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class SentinelBehavioralEngine(threading.Thread):
    """
    WMI-based process creation monitor applying behavioral rules.
    """

    def __init__(self, rules_path: str = DEFAULT_RULES_PATH, executioner=None):
        super().__init__(daemon=True, name="SentinelBehavioral")
        self.rules_path = rules_path
        self.executioner = executioner
        self.running = False
        self.rules: List[Dict] = []
        self._alerted_pids: Dict[int, float] = {}  # pid -> timestamp (cooldown)
        self._lock = threading.Lock()
        self._load_rules()

    def _load_rules(self):
        rules_data = DEFAULT_RULES.copy()

        # Ensure rules file exists with defaults
        if not os.path.exists(self.rules_path):
            try:
                os.makedirs(os.path.dirname(self.rules_path), exist_ok=True)
                with open(self.rules_path, 'w') as f:
                    json.dump(DEFAULT_RULES, f, indent=2)
                _log(f"Created default behavioral rules at {self.rules_path}")
            except Exception as e:
                _log(f"Could not create rules file: {e}")
        else:
            try:
                with open(self.rules_path, 'r') as f:
                    rules_data = json.load(f)
                _log(f"Loaded behavioral rules from {self.rules_path}")
            except Exception as e:
                _log(f"Rules load failed, using defaults: {e}")

        self.rules = [r for r in rules_data.get("rules", []) if r.get("enabled", True)]
        _log(f"Active behavioral rules: {len(self.rules)}")

    def reload_rules(self):
        self._load_rules()

    def run(self):
        self.running = True
        _log("Behavioral Engine started")
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("BehavioralEngine", True)
        except Exception:
            pass
        try:
            c = wmi.WMI()
            watcher = c.Win32_Process.watch_for("creation")
            while self.running:
                try:
                    wmi_proc = watcher()
                    if not self.running:
                        break
                    self._evaluate_new_process(wmi_proc)
                except Exception as e:
                    if self.running:
                        _log(f"Watcher error: {e}")
                        time.sleep(1)
                        try:
                            watcher = c.Win32_Process.watch_for("creation")
                        except Exception:
                            time.sleep(3)
        except Exception as e:
            _log(f"Behavioral Engine fatal: {e}\n{traceback.format_exc()}")

    def stop(self):
        self.running = False
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("BehavioralEngine", False)
        except Exception:
            pass

    def _evaluate_new_process(self, wmi_proc):
        pid = wmi_proc.ProcessId
        if not pid:
            return

        # Cooldown: don't re-alert same PID within 60s
        with self._lock:
            last_alert = self._alerted_pids.get(pid, 0)
            if time.time() - last_alert < 60:
                return

        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return

        for rule in self.rules:
            try:
                if RuleEvaluator.matches_rule(rule, proc, wmi_proc):
                    self._handle_match(rule, proc)
                    with self._lock:
                        self._alerted_pids[pid] = time.time()
                    break  # one match per process creation event
            except Exception as e:
                _log(f"Rule eval error [{rule.get('name')}]: {e}")

    def _handle_match(self, rule: Dict, proc: psutil.Process):
        name = rule.get("name", "Unknown Rule")
        severity = rule.get("severity", "medium")
        action = rule.get("action", "alert")
        desc = rule.get("description", "")

        try:
            proc_name = proc.name()
            proc_pid = proc.pid
            exe = proc.exe()
        except Exception:
            proc_name, proc_pid, exe = "unknown", 0, ""

        _log(
            f"[BEHAVIORAL] MATCH: '{name}' | Severity: {severity} | "
            f"Process: {proc_name} (PID {proc_pid}) | Action: {action}"
        )

        _toast(
            f"Behavioral Alert [{severity.upper()}]",
            f"Rule: {name}\nProcess: {proc_name}\n{desc[:80]}"
        )

        try:
            brain, ThreatEvent, ThreatCategory, ThreatSeverity = _get_brain()
            _sev_map = {
                "info": ThreatSeverity.INFO, "low": ThreatSeverity.LOW,
                "medium": ThreatSeverity.MEDIUM, "high": ThreatSeverity.HIGH,
                "critical": ThreatSeverity.CRITICAL,
            }
            brain.emit_event(ThreatEvent(
                category=ThreatCategory.BEHAVIORAL,
                severity=_sev_map.get(severity.lower(), ThreatSeverity.MEDIUM),
                title=f"Behavioral rule matched: {name}",
                detail=f"Process: {proc_name} (PID {proc_pid}) — {desc}",
                source_module="BehavioralEngine",
                file_path=exe,
                pid=proc_pid,
                extra={"rule": name, "action": action},
            ))
        except Exception:
            pass

        if action in ("alert_and_kill", "quarantine"):
            try:
                proc.kill()
                _log(f"[BEHAVIORAL] KILLED PID {proc_pid} ({proc_name})")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                _log(f"[BEHAVIORAL] Kill failed for PID {proc_pid}: {e}")

        if action == "quarantine" and exe and os.path.exists(exe) and self.executioner:
            try:
                self.executioner.handle_threat(exe)
            except Exception as e:
                _log(f"[BEHAVIORAL] Quarantine failed: {e}")

    def scan_running_processes(self):
        """One-time scan of currently running processes against all rules."""
        _log("Running behavioral scan of active processes...")
        hits = 0
        for proc in psutil.process_iter(['pid', 'name']):
            for rule in self.rules:
                try:
                    if RuleEvaluator.matches_rule(rule, proc):
                        self._handle_match(rule, proc)
                        hits += 1
                        break
                except Exception:
                    continue
        _log(f"Behavioral scan complete: {hits} matches")
        return hits
