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
