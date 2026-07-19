# Sentinelpsds.py
# PSDS -- Port Scan Defense System, rewritten as a BaseService.
#
# Kernel-level SYN-flood / port-scan defense via WinDivert (pydivert).
# Detection is a pure per-IP SYN-rate tracker (SynRateTracker) so it can be
# driven directly by tests without opening a live WinDivert handle. `_run` is
# the packet-capture loop that feeds it live SYN packets and reacts (drop
# packet, firewall block, Brain alert).
#
# Gracefully degrades (stays RUNNING, inert) when WinDivert (pydivert) is not
# importable, the driver can't be opened, or the process isn't elevated --
# WinDivert requires an administrator-privileged driver handle. It NEVER
# raises out of `_run`; a degraded PSDS idles instead of erroring out.

from __future__ import annotations
import copy
import ctypes
import os
import subprocess
import time
from collections import defaultdict, deque

from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

try:
    import pydivert  # WinDivert
except Exception:  # keep importable in isolation / non-Windows / no driver
    pydivert = None


# CREATE_NO_WINDOW keeps netsh from flashing a console when launched from a
# GUI build. Defined defensively so the module imports on non-Windows too.
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_DEFAULTS = {
    "syn_rate_threshold": 50,
    "window": 1.0,
}

# Cap on how many netsh block rules PSDS will accumulate over its lifetime --
# keeps a long-running service from growing the firewall rule set (and the
# in-memory _blocked_ips set) without bound.
MAX_BLOCKED = 1000

# Match only unsolicited inbound SYNs -- excludes SYN-ACK replies to our own
# outbound connections (tcp.Ack == 0), so a busy legit remote host's replies
# are never mistaken for a SYN flood and dropped/blocked.
SYN_FILTER = "inbound and tcp.Syn == 1 and tcp.Ack == 0"


def _is_admin() -> bool:
    """Best-effort elevation check -- WinDivert needs an admin driver handle."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Pure SYN-rate tracker (pinned by tests -- transcribed verbatim from the task
# brief). No I/O, no WinDivert -- driven directly by (ip, ts) pairs.
# ---------------------------------------------------------------------------
class SynRateTracker:
    def __init__(self, threshold=50, window=1.0, max_ips=5000):
        self.threshold = threshold
        self.window = window
        self.max_ips = max_ips
        self._syns = defaultdict(deque)

    def record(self, ip, ts):
        if ip not in self._syns and len(self._syns) >= self.max_ips:
            # Bound memory on a long-running service: evict the
            # least-recently-active tracked IP before adding a new one.
            oldest_ip = min(
                self._syns,
                key=lambda k: self._syns[k][-1] if self._syns[k] else -1,
            )
            del self._syns[oldest_ip]
        self._syns[ip].append(ts)

    def exceeded(self, ip, now):
        q = self._syns.get(ip)
        if not q:
            return False
        cutoff = now - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        if not q:
            del self._syns[ip]
            return False
        return len(q) >= self.threshold


class PSDS(BaseService):
    name = "PSDS"

    def __init__(self, config=None, brain=None):
        cfg = copy.deepcopy(_DEFAULTS)
        cfg.update(config or {})
        super().__init__(cfg, brain)
        self.tracker = SynRateTracker(
            threshold=self.config.get("syn_rate_threshold", 50),
            window=self.config.get("window", 1.0),
        )
        self._divert = None
        self._blocked_ips: set = set()
        self._alerted_ips: set = set()
        self._degraded_logged = False

    # ------------------------------------------------------------------ #
    # Firewall block (salvaged netsh advfirewall logic -- both directions).
    # ------------------------------------------------------------------ #
    def _firewall_block(self, ip: str) -> bool:
        if ip in self._blocked_ips:
            return True
        if len(self._blocked_ips) >= MAX_BLOCKED:
            self._log(
                f"MAX_BLOCKED ({MAX_BLOCKED}) reached; skipping netsh block for {ip}",
                "WARN",
            )
            return False
        try:
            ts = int(time.time())
            base_name = f"PSDS_BLOCK_{ip}_{ts}"
            for suffix, dir_flag in (("IN", "in"), ("OUT", "out")):
                rule_name = f"{base_name}_{suffix}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    f"dir={dir_flag}",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                    "profile=any",
                ]
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=5,
                        creationflags=_CREATE_NO_WINDOW,
                    )
                    if result.returncode != 0:
                        self._log(
                            f"netsh block failed for {ip} {dir_flag}: "
                            f"{(result.stdout or '').strip()}", "ERROR")
                except Exception as e_inner:
                    self._log(f"netsh exception for {ip}: {e_inner}", "ERROR")
            self._blocked_ips.add(ip)
            self.emit_block(ip, "SYN flood / port scan detected -- hard block applied")
            return True
        except Exception as e:
            self._log(f"_firewall_block error for {ip}: {e}", "ERROR")
            return False

    # ------------------------------------------------------------------ #
    # BaseService loop.
    # ------------------------------------------------------------------ #
    def _run(self) -> None:
        self._heartbeat()

        if pydivert is None or not _is_admin():
            self._degrade_and_idle()
            return

        try:
            divert = pydivert.WinDivert(SYN_FILTER)
            divert.open()
            self._divert = divert
        except Exception as e:
            self._divert = None
            self._log(f"WinDivert open failed ({e}); PSDS idle", "WARN")
            self._degrade_and_idle()
            return

        self._log("WinDivert packet defender started", "INFO")
        while not self._stopping():
            try:
                packet = self._divert.recv()
            except Exception as e:
                if self._stopping():
                    break
                self._log(f"packet loop error: {e}", "ERROR")
                self._sleep(0.5)
                continue

            try:
                self._handle_packet(packet)
            except Exception as e:
                if self._stopping():
                    break
                self._log(f"packet loop error: {e}", "ERROR")
                self._sleep(0.5)
                continue

            self._heartbeat()

    def _handle_packet(self, packet) -> None:
        """One SYN packet: record it, block+drop if the source IP is flooding,
        otherwise reinject it unchanged."""
        ip = packet.src_addr

        if ip in self._blocked_ips:
            # Already blocked -- drop silently without re-running the
            # record/exceeded path (and without reinjecting the packet).
            return

        now = time.time()
        self.tracker.record(ip, now)

        if self.tracker.exceeded(ip, now):
            # DROP -- do not reinject.
            self._firewall_block(ip)
            if ip not in self._alerted_ips:
                self._alerted_ips.add(ip)
                self.emit_threat(
                    ThreatCategory.NETWORK, ThreatSeverity.HIGH,
                    "SYN flood / port scan",
                    f"SYN rate from {ip} exceeded {self.tracker.threshold} "
                    f"per {self.tracker.window}s window",
                    ip_address=ip,
                )
            return

        # SAFE packet -- reinject so the connection proceeds normally.
        try:
            self._divert.send(packet)
        except Exception as e:
            self._log(f"WinDivert send error: {e}", "ERROR")

    def _degrade_and_idle(self) -> None:
        """No WinDivert / no elevation: stay RUNNING but inert. Never raise."""
        if not self._degraded_logged:
            self._degraded_logged = True
            self._log("WinDivert/admin unavailable; PSDS idle", "WARN")
            if self._brain:
                try:
                    self._brain.set_module_running(
                        self.name, True, "WinDivert/admin unavailable; PSDS idle")
                except Exception as e:
                    self._log(f"set_module_running failed: {e}", "ERROR")
        while not self._stopping():
            if not self._sleep(1.0):
                break

    def _teardown(self) -> None:
        if self._divert is not None:
            try:
                self._divert.close()
            except Exception as e:
                self._log(f"WinDivert close error: {e}", "ERROR")
            finally:
                self._divert = None
        self._alerted_ips.clear()


if __name__ == "__main__":
    svc = PSDS()
    svc.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        svc.stop()
