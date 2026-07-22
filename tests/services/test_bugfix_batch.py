"""Regressions for the reported bug batch.

Each test pins a specific reported symptom:
  * one network block producing an event every poll forever
  * protection level staying suppressed 90s after a countermeasure
  * a WHITELISTED file being announced as malware
  * whitelist edits not applying until restart
"""
import time
import types

import pytest

from Services.Protection.SentinelNetProtectionNG2 import NetworkProtection
from Services.AVBrain import ThreatRecord, RECOVERY_SECS
from Services.SentinelBrain import ThreatEvent, ThreatCategory, ThreatSeverity


# ── 1. block-spam gate ───────────────────────────────────────────────────────

def _bad_ip_conn(ip="34.107.243.93"):
    return {"raddr_ip": ip, "raddr_port": 443, "status": "ESTABLISHED", "pid": 1}


def test_repeated_block_emits_only_once(fake_brain, monkeypatch):
    """A still-open malicious connection re-classifies every poll; the event
    must be emitted once, not once per poll (this drove the level to 0)."""
    svc = NetworkProtection(brain=fake_brain)
    monkeypatch.setattr(svc, "_firewall_block", lambda ip: True)
    monkeypatch.setattr(svc.store, "is_bad_ip", lambda ip: True)

    for _ in range(20):                      # 20 polls of the same connection
        svc._handle_conn(_bad_ip_conn(), time.time())

    blocks = [t for t in fake_brain.threats
              if "blocked" in (t.get("title", "").lower())]
    assert len(blocks) == 1, f"expected 1 block event, got {len(blocks)}"


def test_distinct_ips_each_emit_once(fake_brain, monkeypatch):
    svc = NetworkProtection(brain=fake_brain)
    monkeypatch.setattr(svc, "_firewall_block", lambda ip: True)
    monkeypatch.setattr(svc.store, "is_bad_ip", lambda ip: True)

    for ip in ("1.2.3.4", "5.6.7.8"):
        for _ in range(5):
            svc._handle_conn(_bad_ip_conn(ip), time.time())

    blocks = [t for t in fake_brain.threats if "blocked" in t.get("title", "").lower()]
    assert len(blocks) == 2


def test_clearing_rules_allows_reporting_again(fake_brain, monkeypatch):
    svc = NetworkProtection(brain=fake_brain)
    monkeypatch.setattr(svc, "_firewall_block", lambda ip: True)
    monkeypatch.setattr(svc.store, "is_bad_ip", lambda ip: True)
    svc._handle_conn(_bad_ip_conn(), time.time())
    svc._block_alerted.clear()               # what _firewall_clear does
    svc._handle_conn(_bad_ip_conn(), time.time())
    blocks = [t for t in fake_brain.threats if "blocked" in t.get("title", "").lower()]
    assert len(blocks) == 2


# ── 2. protection level recovery ─────────────────────────────────────────────

def _rec(**kw):
    ev = ThreatEvent(category=ThreatCategory.NETWORK, severity=ThreatSeverity.HIGH,
                     title="t", detail="d", source_module="m")
    return ThreatRecord(id="x", event=ev, level_impact=15, **kw)


def test_countered_threat_recovers_immediately():
    """Firewalled/quarantined => danger gone => no residual penalty."""
    r = _rec(status="mitigated", resolved_at=time.time(), countered=True)
    assert r.recovery_fraction() == 1.0


def test_uncountered_threat_still_fades_gradually():
    r = _rec(status="mitigated", resolved_at=time.time(), countered=False)
    assert r.recovery_fraction() < 0.1          # only just resolved


def test_uncountered_threat_fully_recovers_after_window():
    r = _rec(status="mitigated",
             resolved_at=time.time() - (RECOVERY_SECS + 1), countered=False)
    assert r.recovery_fraction() == 1.0


def test_active_threat_has_no_recovery():
    assert _rec().recovery_fraction() == 0.0


# ── 3. whitelisted file must not be reported as malware ──────────────────────

def test_benign_verdicts_are_not_detections():
    from Engine.Compiler.SentinelCompiler_v5 import _BENIGN_VERDICTS
    assert "WHITELISTED" in _BENIGN_VERDICTS
    assert "CLEAN" in _BENIGN_VERDICTS
    assert "IGNORED" in _BENIGN_VERDICTS
    assert "MALWARE" not in _BENIGN_VERDICTS
    assert "SUSPICIOUS" not in _BENIGN_VERDICTS


# ── 4. whitelist: location, migration, immediate effect ──────────────────────

def test_whitelist_lives_in_aria_home():
    from Services.SentinelWhitelist import _WHITELIST_PATH
    p = str(_WHITELIST_PATH).lower()
    assert ".ariasecurity" in p, "whitelist must live in the user's Aria data dir"
    assert "config" not in p.split(".ariasecurity")[0], "must not sit in the repo Config/"


def test_version_bumps_on_change(tmp_path):
    from Services.SentinelWhitelist import SentinelWhitelist
    wl = SentinelWhitelist(tmp_path / "wl.json")
    before = wl.version
    wl.add_ip("9.9.9.9")
    assert wl.version > before, "version must bump so consumers refresh"


def test_netprotection_picks_up_whitelist_without_restart(fake_brain, monkeypatch, tmp_path):
    """The IP whitelist used to be a startup snapshot -> edits needed a restart."""
    from Services.SentinelWhitelist import SentinelWhitelist
    import Services.SentinelWhitelist as wl_mod

    wl = SentinelWhitelist(tmp_path / "wl.json")
    monkeypatch.setattr(wl_mod, "get_whitelist", lambda: wl)

    svc = NetworkProtection(brain=fake_brain)
    svc._sync_whitelist()
    assert "8.8.8.8" not in svc.config["whitelist"]

    wl.add_ip("8.8.8.8")            # user whitelists it while running
    svc._sync_whitelist()
    assert "8.8.8.8" in svc.config["whitelist"]
