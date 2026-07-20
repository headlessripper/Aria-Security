# SentinelCloudAnalysis.py
# VirusTotal API v3 integration for cloud-based file/hash/URL analysis.
#
# API key goes in Config.json under "virustotal_api_key".
# Free tier: 4 requests/minute, 500/day.
# The scanner checks the hash first (1 req) before uploading the file.

import os
import json
import time
import hashlib
import threading
from pathlib import Path
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
from collections import deque

import requests

from Interface.write_to_log import write_to_log
from Config.Sys_Config import CONFIG_PATH
from Interface.find_items import find_items

CLOUD_LOG = "logs/CloudAnalysis.log"
VT_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 30
MAX_UPLOAD_SIZE = 32 * 1024 * 1024  # 32 MB VT free limit

# VirusTotal free tier: 4 requests/minute.
RATE_LIMIT_MAX_CALLS = 4
RATE_LIMIT_PER_SECONDS = 60

# Sentinel so we can tell "api_key not passed" (→ load from config) apart
# from "api_key explicitly passed as empty string" (→ stay keyless, used by
# tests / graceful-degradation callers).
_UNSET = object()


def _log(msg: str):
    write_to_log(msg, CLOUD_LOG)


class RateLimiter:
    """Pure sliding-window rate limiter. No I/O, no clock access — the
    caller supplies `now` so this is trivially unit-testable."""

    def __init__(self, max_calls: int, per_seconds: float):
        self.max_calls = max_calls
        self.per = per_seconds
        self._calls: deque = deque()

    def allow(self, now: float) -> bool:
        while self._calls and self._calls[0] <= now - self.per:
            self._calls.popleft()
        if len(self._calls) >= self.max_calls:
            return False
        self._calls.append(now)
        return True


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _load_api_key() -> str:
    try:
        config_path = find_items(CONFIG_PATH)
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                cfg = json.load(f)
            return cfg.get("virustotal_api_key", "")
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

class CloudVerdict:
    def __init__(
        self,
        sha256: str,
        found: bool,
        malicious: int = 0,
        suspicious: int = 0,
        harmless: int = 0,
        total_engines: int = 0,
        threat_names: list = None,
        permalink: str = "",
        error: str = "",
        status: Optional[str] = None,
    ):
        self.sha256 = sha256
        self.found = found
        self.malicious = malicious
        self.suspicious = suspicious
        self.harmless = harmless
        self.total_engines = total_engines
        self.threat_names = threat_names or []
        self.permalink = permalink
        self.error = error
        self.timestamp = datetime.now().isoformat()
        if status is None:
            # Back-compat auto-derivation for call sites that predate the
            # `status` field: an explicit error wins, otherwise found/not-found.
            status = "error" if error else ("ok" if found else "not_found")
        self.status = status

    @property
    def is_threat(self) -> bool:
        if not self.found:
            return False
        return self.malicious >= 3 or (self.malicious >= 1 and self.suspicious >= 5)

    @property
    def confidence_pct(self) -> float:
        if self.total_engines == 0:
            return 0.0
        return round((self.malicious / self.total_engines) * 100, 1)

    @property
    def verdict_str(self) -> str:
        if not self.found:
            return "UNKNOWN"
        if self.is_threat:
            return "MALICIOUS"
        if self.suspicious > 0:
            return "SUSPICIOUS"
        return "CLEAN"

    def to_dict(self) -> Dict:
        return {
            "sha256": self.sha256,
            "found": self.found,
            "status": self.status,
            "verdict": self.verdict_str,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "total_engines": self.total_engines,
            "confidence_pct": self.confidence_pct,
            "threat_names": self.threat_names,
            "permalink": self.permalink,
            "timestamp": self.timestamp,
            "error": self.error,
        }

    def __repr__(self):
        return (
            f"CloudVerdict(verdict={self.verdict_str}, "
            f"malicious={self.malicious}/{self.total_engines}, "
            f"sha256={self.sha256[:16]}...)"
        )


# ---------------------------------------------------------------------------
# VirusTotal client
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """
    Thin VirusTotal API v3 client.

    Usage:
        vt = VirusTotalClient()
        verdict = vt.check_hash("abc123...")
        if verdict.is_threat:
            ...
    """

    def __init__(self, api_key=_UNSET):
        # `api_key` omitted entirely → load from config (legacy default
        # behavior). `api_key=""` passed explicitly → stay keyless; this is
        # how callers (and tests) force graceful no-key handling without
        # touching the on-disk config.
        if api_key is _UNSET:
            self._api_key = _load_api_key()
        else:
            self._api_key = api_key or ""
        self._session = requests.Session()
        self._cache: Dict[str, CloudVerdict] = {}
        self._cache_ttl = timedelta(hours=24)
        self._rate_limiter = RateLimiter(RATE_LIMIT_MAX_CALLS, RATE_LIMIT_PER_SECONDS)

    def _headers(self) -> Dict:
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    def _is_configured(self) -> bool:
        return bool(self._api_key)

    def _wait_for_rate_limit(self):
        """Block (in short increments) until the RateLimiter permits a call."""
        while not self._rate_limiter.allow(time.time()):
            time.sleep(0.5)

    def _get_cached(self, sha256: str) -> Optional[CloudVerdict]:
        cached = self._cache.get(sha256)
        if cached:
            try:
                ts = datetime.fromisoformat(cached.timestamp)
                if datetime.now() - ts < self._cache_ttl:
                    return cached
            except Exception:
                pass
        return None

    # ------------------------------------------------------------------
    # Hash lookup (1 API request)
    # ------------------------------------------------------------------

    def check_hash(self, sha256: str) -> CloudVerdict:
        """Look up a SHA256 hash in VirusTotal."""
        if not self._is_configured():
            return CloudVerdict(sha256, found=False, error="No API key configured",
                                 status="unavailable")

        cached = self._get_cached(sha256)
        if cached:
            _log(f"VT cache hit: {sha256[:16]}")
            return cached

        self._wait_for_rate_limit()
        try:
            resp = self._session.get(
                f"{VT_BASE}/files/{sha256}",
                headers=self._headers(),
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code == 404:
                verdict = CloudVerdict(sha256, found=False)
                self._cache[sha256] = verdict
                return verdict

            resp.raise_for_status()
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            threat_names = list({
                r.get("result", "")
                for r in results.values()
                if r.get("category") in ("malicious", "suspicious") and r.get("result")
            })

            verdict = CloudVerdict(
                sha256=sha256,
                found=True,
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                harmless=stats.get("harmless", 0) + stats.get("undetected", 0),
                total_engines=sum(stats.values()),
                threat_names=threat_names[:10],
                permalink=f"https://www.virustotal.com/gui/file/{sha256}",
            )
            self._cache[sha256] = verdict
            _log(
                f"VT result: {sha256[:16]} | {verdict.malicious}/{verdict.total_engines} "
                f"malicious | {verdict.verdict_str}"
            )
            return verdict

        except requests.HTTPError as e:
            _log(f"VT HTTP error for {sha256}: {e}")
            return CloudVerdict(sha256, found=False, error=str(e))
        except Exception as e:
            _log(f"VT error for {sha256}: {e}")
            return CloudVerdict(sha256, found=False, error=str(e))

    # ------------------------------------------------------------------
    # File upload (for files not yet in VT database)
    # ------------------------------------------------------------------

    def upload_file(self, file_path: str) -> Optional[str]:
        """
        Upload a file to VirusTotal for analysis.
        Returns analysis ID or None on failure.
        """
        if not self._is_configured():
            return None

        size = os.path.getsize(file_path)
        if size > MAX_UPLOAD_SIZE:
            _log(f"VT upload skipped — file too large: {size} bytes")
            return None

        self._wait_for_rate_limit()
        try:
            with open(file_path, 'rb') as f:
                resp = self._session.post(
                    f"{VT_BASE}/files",
                    headers=self._headers(),
                    files={"file": (os.path.basename(file_path), f)},
                    timeout=60,
                )
            resp.raise_for_status()
            analysis_id = resp.json().get("data", {}).get("id")
            _log(f"VT upload: {file_path} → analysis_id={analysis_id}")
            return analysis_id
        except Exception as e:
            _log(f"VT upload failed: {e}")
            return None

    def get_analysis_result(self, analysis_id: str) -> Optional[CloudVerdict]:
        """Poll for analysis results from an upload."""
        self._wait_for_rate_limit()
        try:
            resp = self._session.get(
                f"{VT_BASE}/analyses/{analysis_id}",
                headers=self._headers(),
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            status = attrs.get("status", "")
            if status != "completed":
                return None  # not ready yet

            stats = attrs.get("stats", {})
            meta_sha256 = data.get("meta", {}).get("file_info", {}).get("sha256", "")

            return CloudVerdict(
                sha256=meta_sha256,
                found=True,
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                harmless=stats.get("harmless", 0) + stats.get("undetected", 0),
                total_engines=sum(stats.values()),
            )
        except Exception as e:
            _log(f"VT analysis poll error: {e}")
            return None

    # ------------------------------------------------------------------
    # High-level: check-or-upload
    # ------------------------------------------------------------------

    def analyze_file(self, file_path: str, wait_for_result: bool = False) -> CloudVerdict:
        """
        Check hash first; upload if not found.
        If wait_for_result=True, polls up to 90s for analysis.
        """
        try:
            sha256 = _sha256(file_path)
        except Exception as e:
            return CloudVerdict("", found=False, error=f"Hash failed: {e}")

        verdict = self.check_hash(sha256)
        if verdict.found or not self._is_configured():
            return verdict

        # Not in VT yet — upload it
        analysis_id = self.upload_file(file_path)
        if not analysis_id:
            return verdict  # return "not found" verdict

        if wait_for_result:
            for _ in range(9):  # up to ~90s
                time.sleep(10)
                result = self.get_analysis_result(analysis_id)
                if result:
                    return result
            _log(f"VT analysis timed out for {file_path}")

        return CloudVerdict(sha256, found=False,
                            permalink=f"https://www.virustotal.com/gui/file/{sha256}")

    def check_url(self, url: str) -> CloudVerdict:
        """Check a URL in VirusTotal."""
        if not self._is_configured():
            return CloudVerdict("", found=False, error="No API key configured",
                                 status="unavailable")

        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        self._wait_for_rate_limit()
        try:
            resp = self._session.get(
                f"{VT_BASE}/urls/{url_id}",
                headers=self._headers(),
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 404:
                return CloudVerdict("", found=False)
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return CloudVerdict(
                sha256="",
                found=True,
                malicious=stats.get("malicious", 0),
                suspicious=stats.get("suspicious", 0),
                harmless=stats.get("harmless", 0) + stats.get("undetected", 0),
                total_engines=sum(stats.values()),
                permalink=f"https://www.virustotal.com/gui/url/{url_id}",
            )
        except Exception as e:
            _log(f"VT URL check error: {e}")
            return CloudVerdict("", found=False, error=str(e))


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_vt_instance: Optional[VirusTotalClient] = None
_vt_lock = threading.Lock()


def get_vt_client() -> VirusTotalClient:
    global _vt_instance
    with _vt_lock:
        if _vt_instance is None:
            _vt_instance = VirusTotalClient()
    return _vt_instance
