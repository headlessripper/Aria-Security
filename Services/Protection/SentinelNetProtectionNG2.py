# SentinelNetProtectionNG2.py
# Network protection rewritten as a BaseService.
#
# Detection is a reputation / IOC / heuristic classifier -- no machine-learning
# model zoo, no dataframe/CSV feature-building. Every ML model, scaler, encoder,
# anomaly detector, and packet-training pipeline the previous implementation
# carried has been deleted.
#
# `classify_connection` is a PURE classifier (no psutil / no I/O) so it can be
# driven directly by tests. `_run` is the psutil-polling BaseService loop that
# feeds it live connections and reacts (firewall block / Brain alert).

from __future__ import annotations
import copy
import ipaddress
import os
import subprocess
import threading
import time
from collections import deque

from Services.framework.base_service import BaseService
from Services.Protection.threat_intel_store import get_intel_store
from Services.SentinelBrain import ThreatCategory, ThreatSeverity

try:
    import psutil
except Exception:  # keep importable in isolation / environments without psutil
    psutil = None


# CREATE_NO_WINDOW keeps netsh from flashing a console when launched from a GUI
# build. Defined defensively so the module imports on non-Windows too.
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


_DEFAULTS = {
    "whitelist": set(),
    "rep_block_threshold": 80,
    "rep_alert_threshold": 50,
    # Destination ports strongly associated with RATs / remote-control / cleartext
    # admin exposure. A public connection to one of these is at least alert-worthy.
    "suspicious_ports": {4444, 1337, 3389, 5900, 23, 5901, 6660, 6661, 6662,
                         6663, 6664, 6665, 6666, 6667, 31337},
    "poll_interval": 5.0,
    # "auto" -> block on classifier "block"; "alert" -> alert-only (never blocks).
    "action": "auto",
    # Connection-velocity heuristic: more than this many *distinct new* public
    # remote IPs within the rolling window raises a single alert.
    "velocity_window_s": 10.0,
    "velocity_threshold": 40,
}


# ---------------------------------------------------------------------------
# Pure helpers (pinned by tests -- transcribed verbatim from the task brief).
# ---------------------------------------------------------------------------
def is_private_or_local(ip):
    try:
        a = ipaddress.ip_address(ip)
        return (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return True   # unparseable -> non-actionable


def classify_connection(conn, intel, cfg):
    ip = conn.get("raddr_ip")
    if not ip or is_private_or_local(ip) or ip in cfg.get("whitelist", set()):
        return ("clean", "", ThreatSeverity.INFO)
    if intel.is_bad_ip(ip):
        return ("block", f"IOC feed match: {ip}", ThreatSeverity.HIGH)
    rep = intel.ip_reputation(ip)
    if rep is not None:
        if rep >= cfg.get("rep_block_threshold", 80):
            return ("block", f"AbuseIPDB reputation {rep}%", ThreatSeverity.HIGH)
        if rep >= cfg.get("rep_alert_threshold", 50):
            return ("alert", f"AbuseIPDB reputation {rep}%", ThreatSeverity.MEDIUM)
    port = conn.get("raddr_port")
    if port in cfg.get("suspicious_ports", set()):
        return ("alert", f"suspicious destination port {port}", ThreatSeverity.MEDIUM)
    return ("clean", "", ThreatSeverity.INFO)


class NetworkProtection(BaseService):
    name = "NetProtection"

    def __init__(self, config=None, brain=None):
        cfg = copy.deepcopy(_DEFAULTS)
        cfg.update(config or {})
        # Normalise the whitelist to a set regardless of how it was supplied.
        cfg["whitelist"] = set(cfg.get("whitelist") or set())
        cfg["suspicious_ports"] = set(cfg.get("suspicious_ports") or set())
        super().__init__(cfg, brain)

        self.store = get_intel_store()
        self._blocked_ips: set = set()          # IPs we've already firewalled
        self._alerted_ips: set = set()          # IPs we've already alerted on
        self._block_alerted: set = set()        # IPs we've already reported a block for
        self._lookup_pending: set = set()        # IPs with an in-flight AbuseIPDB lookup
        self._lookup_lock = threading.Lock()
        self._abuse_key_cached = None            # None = not yet loaded
        self._net_access_denied_logged = False   # log the AccessDenied degrade once
        # Rolling window of (timestamp, ip) for the connection-velocity heuristic.
        self._recent_ips = deque()
        self._velocity_alerted_until = 0.0
        self._wl_version = -1                    # forces a sync on first poll

    # ------------------------------------------------------------------ #
    # AbuseIPDB key loading (salvaged from the previous implementation).
    # ------------------------------------------------------------------ #
    def _load_abuseipdb_key(self) -> str:
        if self._abuse_key_cached is not None:
            return self._abuse_key_cached
        key = ""
        try:
            from Interface.find_items import find_items
            from Config.Sys_Config import CONFIG_PATH
            import json as _json
            cfg_path = find_items(CONFIG_PATH)
            if cfg_path and os.path.exists(cfg_path):
                with open(cfg_path, "r") as f:
                    key = _json.load(f).get("abuseipdb_api_key", "") or ""
        except Exception:
            key = ""
        self._abuse_key_cached = key
        return key

    # ------------------------------------------------------------------ #
    # On-demand reputation lookup for unknown public IPs (best effort).
    # ------------------------------------------------------------------ #
    def _kick_reputation_lookup(self, ip: str) -> None:
        api_key = self._load_abuseipdb_key()
        if not api_key:
            return
        with self._lookup_lock:
            if ip in self._lookup_pending:
                return
            self._lookup_pending.add(ip)

        def _do():
            try:
                from Services.SentinelThreatIntelligence import lookup_ip_abuseipdb
                data = lookup_ip_abuseipdb(ip, api_key)
                if data:
                    score = int(data.get("abuseConfidenceScore", 0))
                    self.store.set_reputation(ip, score, ttl_s=3600)
            except Exception:
                pass
            finally:
                with self._lookup_lock:
                    self._lookup_pending.discard(ip)

        threading.Thread(target=_do, daemon=True).start()

    # ------------------------------------------------------------------ #
    # Firewall block (salvaged netsh advfirewall logic -- both directions).
    # ------------------------------------------------------------------ #
    def _firewall_block(self, ip: str) -> bool:
        if ip in self._blocked_ips:
            return True
        try:
            ts = int(time.time())
            base_name = f"Sentinel_BLOCK_{ip}_{ts}"
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
            self.emit_block(ip, "Malicious connection blocked (inbound + outbound)")
            return True
        except Exception as e:
            self._log(f"_firewall_block error for {ip}: {e}", "ERROR")
            return False

    # ------------------------------------------------------------------ #
    # BaseService loop.
    # ------------------------------------------------------------------ #
    def _run(self) -> None:
        self._heartbeat()
        while not self._stopping():
            self._poll_once()
            self._heartbeat()
            if not self._sleep(self.config.get("poll_interval", 5.0)):
                break

    def _snapshot_connections(self) -> list:
        """psutil.net_connections guarded: AccessDenied under non-admin degrades
        (logged once) instead of spamming / crashing the loop."""
        if psutil is None:
            return []
        try:
            return psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            if not self._net_access_denied_logged:
                self._net_access_denied_logged = True
                self._log("net_connections access denied (need admin) -- "
                          "network polling degraded", "WARN")
            return []
        except Exception as e:
            self._log(f"net_connections error: {e}", "ERROR")
            return []

    def _poll_once(self) -> None:
        self._sync_whitelist()      # pick up whitelist edits without a restart
        conns = self._snapshot_connections()
        seen_this_cycle: set = set()
        now = time.time()

        for c in conns:
            try:
                raddr = getattr(c, "raddr", None)
                if not raddr:
                    continue
                # raddr is a namedtuple (ip, port); empty tuple when no remote.
                ip = raddr.ip if hasattr(raddr, "ip") else (raddr[0] if raddr else None)
                rport = raddr.port if hasattr(raddr, "port") else (raddr[1] if len(raddr) > 1 else None)
                if not ip:
                    continue
                # Dedupe by remote IP per cycle.
                if ip in seen_this_cycle:
                    continue
                seen_this_cycle.add(ip)

                laddr = getattr(c, "laddr", None)
                lport = None
                if laddr:
                    lport = laddr.port if hasattr(laddr, "port") else (laddr[1] if len(laddr) > 1 else None)

                conn = {
                    "raddr_ip": ip,
                    "raddr_port": rport,
                    "laddr_port": lport,
                    "pid": getattr(c, "pid", None),
                    "status": getattr(c, "status", None),
                }

                self._handle_conn(conn, now)
            except Exception:
                continue

        self._velocity_check(now)

    def _sync_whitelist(self) -> None:
        """Pull the live whitelist into the config the classifier reads.

        The IP whitelist used to be a snapshot taken at construction, so
        whitelisting an IP had no effect until the app restarted. Syncing
        on the singleton's version counter keeps classify_connection pure
        while making edits take effect on the next poll.
        """
        try:
            from Services.SentinelWhitelist import get_whitelist
            wl = get_whitelist()
            if wl.version != self._wl_version:
                self.config["whitelist"] = set(wl.list_ips())
                self._wl_version = wl.version
        except Exception:
            pass

    def _handle_conn(self, conn: dict, now: float) -> None:
        ip = conn["raddr_ip"]

        # Track velocity only for actionable (public, non-whitelisted) IPs.
        actionable = (ip and not is_private_or_local(ip)
                      and ip not in self.config.get("whitelist", set()))
        if actionable and ip not in self._recent_ips_set():
            self._recent_ips.append((now, ip))

        action, reason, severity = classify_connection(conn, self.store, self.config)

        if action == "block":
            if self.config.get("action", "auto") == "auto":
                self._firewall_block(ip)
            # Emit ONCE per IP. A firewall rule doesn't tear down the connection
            # that is already open, so the same connection keeps re-classifying
            # as "block" on every poll — without this gate one incident produced
            # an event every few seconds forever, flooding the feed and driving
            # the protection level to zero. Mirrors the "alert" branch below.
            if ip not in self._block_alerted:
                self._block_alerted.add(ip)
                self.emit_threat(
                    ThreatCategory.NETWORK, severity,
                    "Malicious connection blocked", reason,
                    ip_address=ip, pid=conn.get("pid"),
                    extra={"raddr_port": conn.get("raddr_port"), "status": conn.get("status")},
                )
        elif action == "alert":
            if ip not in self._alerted_ips:
                self._alerted_ips.add(ip)
                self.emit_threat(
                    ThreatCategory.NETWORK, severity,
                    "Suspicious connection", reason,
                    ip_address=ip, pid=conn.get("pid"),
                    extra={"raddr_port": conn.get("raddr_port"), "status": conn.get("status")},
                )
        elif actionable:
            # Unknown public IP with no verdict yet -> best-effort reputation lookup.
            if self.store.ip_reputation(ip) is None and not self.store.is_bad_ip(ip):
                self._kick_reputation_lookup(ip)

    def _recent_ips_set(self) -> set:
        return {ip for _, ip in self._recent_ips}

    def _velocity_check(self, now: float) -> None:
        window = self.config.get("velocity_window_s", 10.0)
        # Evict entries older than the window.
        while self._recent_ips and (now - self._recent_ips[0][0]) > window:
            self._recent_ips.popleft()

        distinct = len({ip for _, ip in self._recent_ips})
        threshold = self.config.get("velocity_threshold", 40)
        if distinct >= threshold and now >= self._velocity_alerted_until:
            # Rate-limit the velocity alert to once per window.
            self._velocity_alerted_until = now + window
            self.emit_threat(
                ThreatCategory.NETWORK, ThreatSeverity.MEDIUM,
                "High outbound connection velocity",
                f"{distinct} distinct new public destinations within {window:.0f}s",
            )

    def _teardown(self) -> None:
        # Best-effort removal of the firewall rules we installed this session.
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15,
                creationflags=_CREATE_NO_WINDOW,
            )
            import re as _re
            rule_names = _re.findall(
                r'^Rule Name:\s+(Sentinel_BLOCK_.+)$', result.stdout or "", _re.MULTILINE)
            for rule_name in rule_names:
                try:
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_name.strip()}"],
                        capture_output=True, timeout=5,
                        creationflags=_CREATE_NO_WINDOW,
                    )
                except Exception:
                    continue
            self._blocked_ips.clear()
            self._block_alerted.clear()   # rules gone -> allow re-reporting
        except Exception as e:
            self._log(f"teardown firewall cleanup error: {e}", "ERROR")


if __name__ == "__main__":
    svc = NetworkProtection()
    svc.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        svc.stop()
