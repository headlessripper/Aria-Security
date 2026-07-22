# SentinelThreatIntelligence.py
# Pulls live threat data from free public feeds and feeds the shared
# ThreatIntelStore (consumed by NetworkProtection / IOC matching).
#
# Feeds used (all free, no API key required for basic use):
#   - URLhaus (abuse.ch): malware URLs and hashes
#   - MalwareBazaar (abuse.ch): malware hash database
#   - Feodo Tracker (abuse.ch): botnet C2 IP blocklist
#   - CINS Score: community IP reputation
#   - Emerging Threats: compromised IP list
#   - AbuseIPDB: IP reputation (requires free API key for >1k/day)
#
# Runs as a BaseService: `_run` loads any persisted blocklist, then loops,
# pulling each feed on its own refresh cadence and pushing IOCs into the
# shared ThreatIntelStore.

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Dict, Optional, Set, Tuple
from datetime import datetime, timedelta

import requests

from Services.framework.base_service import BaseService
from Services.SentinelBrain import ThreatCategory, ThreatSeverity
from Services.Protection.threat_intel_store import get_intel_store

from Interface.write_to_log import write_to_log
from Config.Sys_Config import (
    HASH_FILE_PATH, HASH256_FILE_PATH,
    IPS_FILE_PATH, WHITE_LIST_FILE_PATH,
)
from Interface.find_items import find_items
from Config import paths as _paths

INTEL_LOG = "logs/ThreatIntel.log"
INTEL_CACHE_DIR = _paths.sub("ThreatIntel")
INTEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)

UPDATE_INTERVAL_HOURS = 4  # default refresh cadence when a feed doesn't override it
REQUEST_TIMEOUT = 30


def _log(msg: str):
    write_to_log(msg, INTEL_LOG)


# ---------------------------------------------------------------------------
# Feed definitions
# ---------------------------------------------------------------------------

FEEDS = {
    "feodo_ip": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "type": "ip_list",
        "description": "Feodo Tracker botnet C2 IPs",
        "update_hours": 6,
    },
    "urlhaus_hashes": {
        "url": "https://urlhaus-api.abuse.ch/v1/downloads/",
        "type": "urlhaus_hash_json",
        "description": "URLhaus malware file hashes",
        "update_hours": 12,
    },
    "malwarebazaar_recent": {
        "url": "https://mb-api.abuse.ch/api/v1/",
        "type": "malwarebazaar_api",
        "description": "MalwareBazaar recent malware samples",
        "update_hours": 8,
    },
    "cins_score": {
        "url": "http://cinsscore.com/list/ci-badguys.txt",
        "type": "ip_list",
        "description": "CINS Score bad actor IPs",
        "update_hours": 24,
    },
    "emerging_threats_ips": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip_list",
        "description": "Emerging Threats compromised IPs",
        "update_hours": 24,
    },
}


# ---------------------------------------------------------------------------
# Pure feed parsers (pinned by tests/services/test_threat_intelligence.py)
# ---------------------------------------------------------------------------

def parse_ip_list(text: str) -> Set[str]:
    """Parse a plaintext IP-list feed: skips blank lines and '#'/';' comments,
    tolerates trailing comma-separated junk, validates each first token as
    an actual IP address."""
    ips = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        tok = line.replace(",", " ").split()[0]
        try:
            ipaddress.ip_address(tok)
            ips.add(tok)
        except ValueError:
            pass
    return ips


def parse_hashes(content) -> Tuple[Set[str], Set[str]]:
    """Parse hash feed content (bytes or str). JSON-tolerant with a hex-regex
    fallback so arbitrary feed text still yields any SHA256/MD5 hashes present.
    Returns (sha256_set, md5_set)."""
    text = content.decode("utf-8", "ignore") if isinstance(content, (bytes, bytearray)) else (content or "")
    sha = {m.lower() for m in re.findall(r"\b[a-fA-F0-9]{64}\b", text)}
    md5 = {m.lower() for m in re.findall(r"\b[a-fA-F0-9]{32}\b", text)}
    return sha, md5


def _parse_urlhaus_hash_json(content) -> Tuple[Set[str], Set[str]]:
    """URLhaus downloads endpoint returns a JSON array of entries with their
    own sha256_hash/md5_hash keys; fall back to the generic regex parser if
    the payload isn't the expected shape."""
    sha256s: Set[str] = set()
    md5s: Set[str] = set()
    try:
        data = json.loads(content)
        for entry in data:
            if isinstance(entry, dict):
                h = entry.get('sha256_hash') or entry.get('sha256', '')
                if h and len(h) == 64:
                    sha256s.add(h.lower())
                m = entry.get('md5_hash') or entry.get('md5', '')
                if m and len(m) == 32:
                    md5s.add(m.lower())
        if sha256s or md5s:
            return sha256s, md5s
    except Exception as e:
        _log(f"URLhaus JSON parse error, falling back to regex: {e}")
    return parse_hashes(content)


# ---------------------------------------------------------------------------
# Persisted "last update" bookkeeping (per-feed cadence tracking)
# ---------------------------------------------------------------------------

def _load_last_update() -> Dict:
    path = INTEL_CACHE_DIR / "last_update.json"
    try:
        if path.exists():
            with open(path) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_last_update(data: Dict):
    path = INTEL_CACHE_DIR / "last_update.json"
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _needs_update(feed_name: str, update_hours: int, last_update: Dict) -> bool:
    ts = last_update.get(feed_name)
    if not ts:
        return True
    try:
        last = datetime.fromisoformat(ts)
    except Exception:
        return True
    return datetime.now() - last > timedelta(hours=update_hours)


# ---------------------------------------------------------------------------
# On-disk blocklist persistence (kept for continuity with older consumers /
# offline restarts — the in-memory ThreatIntelStore is the live source of
# truth for lookups).
# ---------------------------------------------------------------------------

def _append_unique_lines(path: str, new_entries: Set[str], comment_header: str = "") -> int:
    """Append only new entries to a file, avoiding duplicates."""
    try:
        existing: Set[str] = set()
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    existing.add(line.strip().lower())

        to_add = [e for e in sorted(new_entries) if e.lower() not in existing]
        if not to_add:
            return 0

        with open(path, 'a', encoding='utf-8') as f:
            if comment_header:
                f.write(f"\n# {comment_header} — {datetime.now().isoformat()}\n")
            for entry in to_add:
                f.write(entry + "\n")

        return len(to_add)
    except Exception as e:
        _log(f"File update error ({path}): {e}")
        return 0


def _load_ip_file(path: str) -> Set[str]:
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return parse_ip_list(f.read())
    except Exception as e:
        _log(f"Blocklist load error ({path}): {e}")
    return set()


# ---------------------------------------------------------------------------
# AbuseIPDB on-demand lookup (kept as a module-level helper; not part of the
# scheduled feed loop since it requires a per-IP call and an API key)
# ---------------------------------------------------------------------------

def lookup_ip_abuseipdb(ip: str, api_key: str) -> Optional[Dict]:
    """
    Query AbuseIPDB for an IP's reputation (requires free API key).
    Returns dict with abuseConfidenceScore, totalReports, etc.
    """
    if not api_key:
        return None
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json().get("data")
    except Exception as e:
        _log(f"AbuseIPDB lookup error for {ip}: {e}")
    return None


def lookup_hash_malwarebazaar(sha256: str) -> Optional[Dict]:
    """Query MalwareBazaar for a specific hash. Returns threat info dict or None."""
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok":
            return data.get("data", [{}])[0]
    except Exception as e:
        _log(f"MalwareBazaar hash lookup error: {e}")
    return None


# ---------------------------------------------------------------------------
# Main intelligence service
# ---------------------------------------------------------------------------

class ThreatIntelligence(BaseService):
    """
    Keeps the shared ThreatIntelStore (and, for continuity, the on-disk
    blocklist files) fresh from public threat feeds.
    """
    name = "ThreatIntelligence"

    def __init__(self, config: Optional[dict] = None, brain=None, abuseipdb_key: str = ""):
        super().__init__(config, brain)
        self.store = get_intel_store()
        self.abuseipdb_key = abuseipdb_key or self.config.get("abuseipdb_key", "")
        self._last_update = _load_last_update()

        # Resolve actual paths (fall back to configured defaults if not found on disk).
        self.hash_md5_path = find_items(HASH_FILE_PATH) or HASH_FILE_PATH
        self.hash_sha256_path = find_items(HASH256_FILE_PATH) or HASH256_FILE_PATH
        self.ip_blocklist_path = find_items(IPS_FILE_PATH) or IPS_FILE_PATH

    def _run(self) -> None:
        _log("Threat Intelligence service started")

        # Seed the in-memory store from whatever is already persisted on disk
        # so consumers (NetworkProtection) have IOCs immediately, even before
        # the first live feed fetch completes.
        persisted_ips = _load_ip_file(self.ip_blocklist_path)
        if persisted_ips:
            self.store.add_bad_ips(persisted_ips, source="persisted_blocklist")

        self._heartbeat()

        # Run an update cycle immediately, then on the configured cadence.
        self._update_cycle()

        check_interval = self.config.get("check_interval", 60)
        while not self._stopping():
            if not self._sleep(check_interval):
                break
            self._update_cycle()
            self._heartbeat()

    def _update_cycle(self) -> None:
        _log(f"Starting threat intel update cycle — {datetime.now().isoformat()}")
        total_new_ips = 0
        total_new_sha256 = 0
        total_new_md5 = 0

        for feed_name, feed in FEEDS.items():
            if self._stopping():
                break
            update_hours = feed.get("update_hours", UPDATE_INTERVAL_HOURS)
            if not _needs_update(feed_name, update_hours, self._last_update):
                continue

            feed_type = feed["type"]
            try:
                if feed_type == "ip_list":
                    new_ips = self._fetch_ip_feed(feed_name, feed["url"])
                    if new_ips:
                        self.store.add_bad_ips(new_ips, source=feed_name)
                        added = _append_unique_lines(
                            self.ip_blocklist_path, new_ips, feed["description"]
                        )
                        total_new_ips += added
                        _log(f"{feed_name}: +{added} new IPs")

                elif feed_type == "urlhaus_hash_json":
                    sha256s, md5s = self._fetch_urlhaus_hashes()
                    if sha256s or md5s:
                        self.store.add_bad_hashes(sha256s | md5s, source=feed_name)
                    if sha256s:
                        total_new_sha256 += _append_unique_lines(
                            self.hash_sha256_path, sha256s, feed["description"]
                        )
                    if md5s:
                        total_new_md5 += _append_unique_lines(
                            self.hash_md5_path, md5s, feed["description"]
                        )

                elif feed_type == "malwarebazaar_api":
                    sha256s, md5s = self._fetch_malwarebazaar_recent()
                    if sha256s or md5s:
                        self.store.add_bad_hashes(sha256s | md5s, source=feed_name)
                    if sha256s:
                        total_new_sha256 += _append_unique_lines(
                            self.hash_sha256_path, sha256s, feed["description"]
                        )
                    if md5s:
                        total_new_md5 += _append_unique_lines(
                            self.hash_md5_path, md5s, feed["description"]
                        )

                else:
                    _log(f"{feed_name}: unknown feed type '{feed_type}', skipped")
                    continue

                self._last_update[feed_name] = datetime.now().isoformat()

            except Exception as e:
                # A dead/unreachable feed must never crash the service loop.
                _log(f"{feed_name} update error: {e}")
                continue

        _save_last_update(self._last_update)

        summary = (
            f"Intel update complete: +{total_new_ips} IPs, "
            f"+{total_new_sha256} SHA256, +{total_new_md5} MD5"
        )
        _log(summary)

        if total_new_ips + total_new_sha256 + total_new_md5 > 0:
            self.emit_threat(
                ThreatCategory.SYSTEM,
                ThreatSeverity.INFO,
                "Threat feed updated",
                summary,
                extra={
                    "new_ips": total_new_ips,
                    "new_sha256": total_new_sha256,
                    "new_md5": total_new_md5,
                    "store_stats": self.store.stats(),
                },
            )

    # --- guarded per-feed fetchers: any failure is caught, logged, and skipped ---

    def _fetch_ip_feed(self, feed_name: str, url: str) -> Set[str]:
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return parse_ip_list(resp.text)
        except Exception as e:
            _log(f"{feed_name} fetch error: {e}")
            return set()

    def _fetch_urlhaus_hashes(self) -> Tuple[Set[str], Set[str]]:
        try:
            resp = requests.get(
                FEEDS["urlhaus_hashes"]["url"],
                timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            return _parse_urlhaus_hash_json(resp.content)
        except Exception as e:
            _log(f"urlhaus_hashes fetch error: {e}")
            return set(), set()

    def _fetch_malwarebazaar_recent(self) -> Tuple[Set[str], Set[str]]:
        try:
            resp = requests.post(
                FEEDS["malwarebazaar_recent"]["url"],
                data={"query": "get_recent", "selector": "100"},
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            sha256s: Set[str] = set()
            md5s: Set[str] = set()
            if data.get("query_status") == "ok":
                for entry in data.get("data", []):
                    h = entry.get("sha256_hash", "")
                    if h:
                        sha256s.add(h.lower())
                    m = entry.get("md5_hash", "")
                    if m:
                        md5s.add(m.lower())
            return sha256s, md5s
        except Exception as e:
            _log(f"malwarebazaar_recent fetch error: {e}")
            return set(), set()


if __name__ == "__main__":
    import time as _time
    svc = ThreatIntelligence()
    svc.start()
    try:
        while True:
            _time.sleep(1)
    except KeyboardInterrupt:
        svc.stop()
