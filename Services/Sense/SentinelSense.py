"""
SentinelSense.py — install/uninstall diff + suspicious-install classification core.

Pure detection logic for diffing two registry install snapshots (before/after)
and classifying a newly-installed application as suspicious based on its
install location, publisher, and executable trust.

The service wrapper (registry polling, state persistence, leftover residue
detection) is built on top of this core in a later task.
"""
from __future__ import annotations

_SUSPICIOUS_LOC = ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp", "\\appdata\\roaming")


def diff_installs(before: dict, after: dict) -> tuple:
    """Return (installed, uninstalled) app_info lists between two snapshots.

    before/after: {app_key: app_info_dict}. installed = entries present in
    after but not before; uninstalled = entries present in before but not after.
    """
    installed = [after[k] for k in after.keys() - before.keys()]
    uninstalled = [before[k] for k in before.keys() - after.keys()]
    return installed, uninstalled


def classify_install(app_info: dict, is_trusted_exe=None) -> tuple:
    """Classify an app_info dict as suspicious or clean.

    Suspicious when the main exe is untrusted (is_trusted_exe(exe) is False),
    OR (suspicious install location AND no publisher). A signed app in
    Program Files with a publisher is clean.
    """
    loc = (app_info.get("install_location") or "").lower()
    susp_loc = any(s in loc for s in _SUSPICIOUS_LOC)
    no_pub = not (app_info.get("publisher") or "").strip()
    exe = app_info.get("main_exe")
    untrusted = bool(is_trusted_exe and exe and not is_trusted_exe(exe))
    reasons = []
    if untrusted:
        reasons.append("unsigned/untrusted executable")
    if susp_loc:
        reasons.append("suspicious install location")
    if no_pub:
        reasons.append("no publisher")
    suspicious = untrusted or (susp_loc and no_pub)
    return suspicious, "; ".join(reasons)


# ---------------------------------------------------------------------------
# SentinelSense service — system-change monitor over the detection core above.
#
# Polls the three Windows "Uninstall" registry hives, diffs successive
# snapshots, flags suspicious new installs (BEHAVIORAL) and reports leftover
# residue from uninstalled apps (SYSTEM).
# ---------------------------------------------------------------------------
import json
import os
import threading
import time

from pathlib import Path

try:  # keep the pure core importable in isolation (e.g. non-Windows CI)
    import winreg  # type: ignore
except Exception:  # pragma: no cover - non-Windows
    winreg = None  # type: ignore

try:
    from Services.framework.base_service import BaseService
except Exception:  # keep the pure core importable in isolation
    BaseService = object  # type: ignore

try:
    from Services.SentinelBrain import ThreatCategory, ThreatSeverity
except Exception:  # pragma: no cover - defensive
    ThreatCategory = None  # type: ignore
    ThreatSeverity = None  # type: ignore

try:
    from Engine.Detection.cert_reputation import CertReputation
except Exception:  # pragma: no cover - defensive
    CertReputation = None  # type: ignore

_ARIA_HOME = Path.home() / ".AriaSecurity"
_STATE_PATH = _ARIA_HOME / "sense_state.json"
_SENSE_SINGLETON = None

# The three "Uninstall" registry hives Windows records installed programs under.
_UNINSTALL_KEYS = ()
if winreg is not None:
    _UNINSTALL_KEYS = (
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    )


def _reg_value(key, name):
    """Read a single registry value; missing value / any failure -> None."""
    try:
        val, _type = winreg.QueryValueEx(key, name)
        return val
    except Exception:
        return None


class SentinelSense(BaseService):
    """System-change monitor: install/uninstall diffing + residue detection.

    Snapshots the Uninstall registry hives on an interval; new installs are
    classified via the pure core and emitted as BEHAVIORAL threats when
    suspicious, while uninstalled apps whose install directory survives on disk
    are reported as SYSTEM (leftovers).
    """

    name = "SentinelSense"

    def __init__(self, config=None, brain=None):
        cfg = {"scan_interval": 30.0}
        cfg.update(config or {})
        super().__init__(cfg, brain)
        self._cert = None
        self._state_lock = threading.Lock()
        self._last_snapshot = {}
        global _SENSE_SINGLETON
        _SENSE_SINGLETON = self

    # -- trust ---------------------------------------------------------------
    def _trusted(self, exe) -> bool:
        """Wrap CertReputation().evaluate(exe)['trusted'] (guarded -> False)."""
        if not exe or CertReputation is None:
            return False
        try:
            if self._cert is None:
                self._cert = CertReputation()
            return bool(self._cert.evaluate(exe).get("trusted", False))
        except Exception:
            return False

    # -- registry snapshot ---------------------------------------------------
    def _snapshot_installed(self) -> dict:
        """Walk the three Uninstall hives -> {subkey: app_info}. Guarded."""
        snapshot = {}
        if winreg is None:
            return snapshot
        for hive, path in _UNINSTALL_KEYS:
            try:
                root = winreg.OpenKey(hive, path)
            except Exception:
                continue
            try:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, i)
                    except OSError:
                        break  # no more subkeys
                    except Exception:
                        break
                    i += 1
                    try:
                        with winreg.OpenKey(root, sub) as k:
                            snapshot[sub] = {
                                "name": _reg_value(k, "DisplayName"),
                                "publisher": _reg_value(k, "Publisher"),
                                "install_location": _reg_value(k, "InstallLocation"),
                                "main_exe": _reg_value(k, "DisplayIcon"),
                                "uninstall_string": _reg_value(k, "UninstallString"),
                            }
                    except Exception:
                        continue
            except Exception:
                continue
            finally:
                try:
                    root.Close()
                except Exception:
                    pass
        return snapshot

    # -- diff + emit ---------------------------------------------------------
    def _process_snapshot(self, before: dict, after: dict) -> None:
        """Diff two snapshots; emit threats for suspicious installs + leftovers."""
        installed, uninstalled = diff_installs(before, after)
        for info in installed:
            try:
                sus, reason = classify_install(info, is_trusted_exe=self._trusted)
                if sus:
                    self.emit_threat(
                        ThreatCategory.BEHAVIORAL, ThreatSeverity.MEDIUM,
                        "Suspicious software install",
                        f"{info.get('name')}: {reason}",
                        extra={"publisher": info.get("publisher"),
                               "install_location": info.get("install_location")},
                    )
            except Exception as e:
                self._log(f"install classify error: {e}", "ERROR")
        for info in uninstalled:
            try:
                loc = info.get("install_location")
                if loc and os.path.isdir(loc):
                    self.emit_threat(
                        ThreatCategory.SYSTEM, ThreatSeverity.INFO,
                        "Uninstall leftovers",
                        f"{info.get('name')}: residual files remain at {loc}",
                        file_path=loc,
                    )
            except Exception as e:
                self._log(f"leftover check error: {e}", "ERROR")

    # -- state persistence ---------------------------------------------------
    def _persist(self, snapshot: dict) -> None:
        with self._state_lock:
            self._last_snapshot = snapshot
        summary = {
            "count": len(snapshot),
            "ts": time.time(),
            "apps": sorted(
                v.get("name") for v in snapshot.values() if v.get("name")
            ),
        }
        try:
            _ARIA_HOME.mkdir(parents=True, exist_ok=True)
            _STATE_PATH.write_text(json.dumps(summary), encoding="utf-8")
        except Exception as e:
            self._log(f"state persist error: {e}", "ERROR")

    # -- main loop -----------------------------------------------------------
    def _run(self) -> None:
        snap = self._snapshot_installed()
        self._persist(snap)
        while not self._stopping():
            self._heartbeat()
            if not self._sleep(float(self.config.get("scan_interval", 30.0))):
                break
            try:
                new = self._snapshot_installed()
                self._process_snapshot(snap, new)
                snap = new
                self._persist(snap)
            except Exception as e:
                self._log(f"scan loop error: {e}", "ERROR")


# ---------------------------------------------------------------------------
# Module-level API (imported by the UI / service registry).
# ---------------------------------------------------------------------------
def get_state() -> dict:
    """Read the persisted last-snapshot summary from _STATE_PATH."""
    try:
        if _STATE_PATH.exists():
            return json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def get_sense():
    """Return the SentinelSense singleton, or None if not yet created."""
    return _SENSE_SINGLETON
