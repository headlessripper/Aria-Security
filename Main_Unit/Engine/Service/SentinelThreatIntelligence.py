# SentinelThreatIntelligence.py
# Pulls live threat data from free public feeds and updates the local blacklists.
#
# Feeds used (all free, no API key required for basic use):
#   - URLhaus (abuse.ch): malware URLs and hashes
#   - MalwareBazaar (abuse.ch): malware hash database
#   - Feodo Tracker (abuse.ch): botnet C2 IP blocklist
#   - CINS Score: community IP reputation
#   - AbuseIPDB: IP reputation (requires free API key for >1k/day)
#
# Runs on a background thread, updates local files, notifies via HOT_SWAP.

import os
import re
import csv
import gzip
import time
import json
import hashlib
import threading
import io
from pathlib import Path
from typing import Set, Dict, Optional, List
from datetime import datetime, timedelta

import requests

from Main_Unit.Service.write_to_log import write_to_log
from Main_Unit.Config.Sys_Config import (
    HASH_FILE_PATH, HASH256_FILE_PATH,
    IPS_FILE_PATH, WHITE_LIST_FILE_PATH,
)
from Main_Unit.find_items import find_items

def _get_brain():
    from Main_Unit.Engine.Service.SentinelBrain import get_brain, ThreatEvent, ThreatCategory, ThreatSeverity
    return get_brain(), ThreatEvent, ThreatCategory, ThreatSeverity

INTEL_LOG = "logs/ThreatIntel.log"
INTEL_CACHE_DIR = Path.home() / ".AriaSecurity" / "ThreatIntel"
INTEL_CACHE_DIR.mkdir(parents=True, exist_ok=True)

UPDATE_INTERVAL_HOURS = 4  # refresh feeds every 4 hours
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

_IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b'
)
_SHA256_RE = re.compile(r'\b[0-9a-fA-F]{64}\b')
_MD5_RE = re.compile(r'\b[0-9a-fA-F]{32}\b')


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
    last = datetime.fromisoformat(ts)
    return datetime.now() - last > timedelta(hours=update_hours)


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------

def _parse_ip_list(text: str) -> Set[str]:
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = _IP_RE.search(line)
        if m:
            ips.add(m.group())
    return ips


def _parse_urlhaus_hash_json(content: bytes) -> tuple[Set[str], Set[str]]:
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
    except Exception as e:
        _log(f"URLhaus parse error: {e}")
    return sha256s, md5s


def _fetch_malwarebazaar_recent() -> tuple[Set[str], Set[str]]:
    sha256s: Set[str] = set()
    md5s: Set[str] = set()
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "100"},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok":
            for entry in data.get("data", []):
                h = entry.get("sha256_hash", "")
                if h:
                    sha256s.add(h.lower())
                m = entry.get("md5_hash", "")
                if m:
                    md5s.add(m.lower())
    except Exception as e:
        _log(f"MalwareBazaar fetch error: {e}")
    return sha256s, md5s


def lookup_hash_malwarebazaar(sha256: str) -> Optional[Dict]:
    """
    Query MalwareBazaar for a specific hash.
    Returns threat info dict or None if not found.
    """
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


# ---------------------------------------------------------------------------
# File updater
# ---------------------------------------------------------------------------

def _append_unique_lines(path: str, new_entries: Set[str], comment_header: str = ""):
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


def _overwrite_with_merged(path: str, new_entries: Set[str]):
    """Merge new entries with existing, dedup, write back."""
    existing: Set[str] = set()
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        existing.add(line.lower())
        merged = existing | {e.lower() for e in new_entries}
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# Updated: {datetime.now().isoformat()}\n")
            for entry in sorted(merged):
                f.write(entry + "\n")
        return len(merged) - len(existing)
    except Exception as e:
        _log(f"Merge error ({path}): {e}")
        return 0


# ---------------------------------------------------------------------------
# Main intelligence service
# ---------------------------------------------------------------------------

class SentinelThreatIntelligence(threading.Thread):
    """
    Background thread that keeps local blocklists fresh from public threat feeds.
    """

    def __init__(self, abuseipdb_key: str = ""):
        super().__init__(daemon=True, name="SentinelThreatIntel")
        self.abuseipdb_key = abuseipdb_key
        self.running = False
        self._last_update = _load_last_update()

        # Resolve actual paths
        self.hash_md5_path = find_items(HASH_FILE_PATH) or HASH_FILE_PATH
        self.hash_sha256_path = find_items(HASH256_FILE_PATH) or HASH256_FILE_PATH
        self.ip_blocklist_path = find_items(IPS_FILE_PATH) or IPS_FILE_PATH

    def run(self):
        self.running = True
        _log("Threat Intelligence service started")
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("ThreatIntelligence", True)
        except Exception:
            pass

        # Initial update immediately
        self._do_update_cycle()

        while self.running:
            # Sleep in small steps for responsiveness
            elapsed = 0
            interval = UPDATE_INTERVAL_HOURS * 3600
            while elapsed < interval and self.running:
                time.sleep(60)
                elapsed += 60

            if self.running:
                self._do_update_cycle()

    def stop(self):
        self.running = False
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("ThreatIntelligence", False)
        except Exception:
            pass

    def _do_update_cycle(self):
        _log(f"Starting threat intel update cycle — {datetime.now().isoformat()}")
        total_new_ips = 0
        total_new_sha256 = 0
        total_new_md5 = 0

        # --- Feodo botnet IPs ---
        if _needs_update("feodo_ip", FEEDS["feodo_ip"]["update_hours"], self._last_update):
            new_ips = self._fetch_ip_feed("feodo_ip", FEEDS["feodo_ip"]["url"])
            if new_ips:
                added = _append_unique_lines(
                    self.ip_blocklist_path, new_ips,
                    "Feodo Tracker botnet C2 IPs"
                )
                total_new_ips += added
                _log(f"Feodo: +{added} new IPs")
                self._last_update["feodo_ip"] = datetime.now().isoformat()

        # --- CINS Score bad IPs ---
        if _needs_update("cins_score", FEEDS["cins_score"]["update_hours"], self._last_update):
            new_ips = self._fetch_ip_feed("cins_score", FEEDS["cins_score"]["url"])
            if new_ips:
                added = _append_unique_lines(
                    self.ip_blocklist_path, new_ips,
                    "CINS Score bad actors"
                )
                total_new_ips += added
                _log(f"CINS: +{added} new IPs")
                self._last_update["cins_score"] = datetime.now().isoformat()

        # --- Emerging Threats IPs ---
        if _needs_update("emerging_threats_ips", FEEDS["emerging_threats_ips"]["update_hours"], self._last_update):
            new_ips = self._fetch_ip_feed("emerging_threats_ips", FEEDS["emerging_threats_ips"]["url"])
            if new_ips:
                added = _append_unique_lines(
                    self.ip_blocklist_path, new_ips,
                    "Emerging Threats compromised IPs"
                )
                total_new_ips += added
                _log(f"Emerging Threats: +{added} new IPs")
                self._last_update["emerging_threats_ips"] = datetime.now().isoformat()

        # --- URLhaus hashes ---
        if _needs_update("urlhaus_hashes", FEEDS["urlhaus_hashes"]["update_hours"], self._last_update):
            sha256s, md5s = self._fetch_urlhaus_hashes()
            if sha256s:
                added = _append_unique_lines(
                    self.hash_sha256_path, sha256s,
                    "URLhaus malware hashes"
                )
                total_new_sha256 += added
            if md5s:
                added = _append_unique_lines(
                    self.hash_md5_path, md5s,
                    "URLhaus MD5 hashes"
                )
                total_new_md5 += added
            self._last_update["urlhaus_hashes"] = datetime.now().isoformat()

        # --- MalwareBazaar recent ---
        if _needs_update("malwarebazaar_recent", FEEDS["malwarebazaar_recent"]["update_hours"], self._last_update):
            sha256s, md5s = _fetch_malwarebazaar_recent()
            if sha256s:
                added = _append_unique_lines(
                    self.hash_sha256_path, sha256s,
                    "MalwareBazaar recent"
                )
                total_new_sha256 += added
            if md5s:
                added = _append_unique_lines(
                    self.hash_md5_path, md5s,
                    "MalwareBazaar MD5"
                )
                total_new_md5 += added
            self._last_update["malwarebazaar_recent"] = datetime.now().isoformat()

        _save_last_update(self._last_update)
        summary = (
            f"Intel update complete: +{total_new_ips} IPs, "
            f"+{total_new_sha256} SHA256, +{total_new_md5} MD5"
        )
        _log(summary)

        if total_new_ips + total_new_sha256 + total_new_md5 > 0:
            try:
                brain, ThreatEvent, ThreatCategory, ThreatSeverity = _get_brain()
                brain.emit_event(ThreatEvent(
                    category=ThreatCategory.SYSTEM,
                    severity=ThreatSeverity.INFO,
                    title="Threat intelligence feeds updated",
                    detail=summary,
                    source_module="ThreatIntelligence",
                    extra={
                        "new_ips": total_new_ips,
                        "new_sha256": total_new_sha256,
                        "new_md5": total_new_md5,
                    },
                ))
            except Exception:
                pass

        # Notify running NIDS to reload its blacklist
        if total_new_ips > 0:
            self._notify_nids_reload()

    def _fetch_ip_feed(self, feed_name: str, url: str) -> Set[str]:
        try:
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            return _parse_ip_list(resp.text)
        except Exception as e:
            _log(f"{feed_name} fetch error: {e}")
            return set()

    def _fetch_urlhaus_hashes(self) -> tuple[Set[str], Set[str]]:
        try:
            resp = requests.get(
                "https://urlhaus-api.abuse.ch/v1/downloads/",
                timeout=REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            return _parse_urlhaus_hash_json(resp.content)
        except Exception as e:
            _log(f"URLhaus fetch error: {e}")
            return set(), set()

    def _notify_nids_reload(self):
        try:
            from Main_Unit.Engine.Service.SentinelServices.SentinelNetProtectionNG2 import (
                BLACKLIST, LOCKS
            )
            import re as _re
            new_ips: Set[str] = set()
            if os.path.exists(self.ip_blocklist_path):
                with open(self.ip_blocklist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                new_ips = set(_IP_RE.findall(text))
            with LOCKS['blacklist']:
                BLACKLIST.clear()
                BLACKLIST.update(new_ips)
            _log(f"NIDS blacklist hot-reloaded: {len(new_ips)} IPs")
        except Exception as e:
            _log(f"NIDS reload failed: {e}")
