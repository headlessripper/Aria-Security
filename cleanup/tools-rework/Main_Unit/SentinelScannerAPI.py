# SentinelScannerAPI.py
# Clean, dependency-light scanner interface for external integrations.
#
# Designed for use by SwiftDrop Relay System and any future service that
# needs file scanning without coupling to the Qt UI or internal modules.
#
# Usage:
#   from Main_Unit.SentinelScannerAPI import scan_file, scan_bytes, ThreatVerdict
#
#   verdict = scan_file("C:/path/to/file.exe")
#   if verdict.is_threat:
#       quarantine_or_reject(file)
#
#   # From bytes (e.g. received over network):
#   verdict = scan_bytes(data, filename="received.exe")

from __future__ import annotations

import os
import io
import sys
import hashlib
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime

from Main_Unit.Service.write_to_log import write_to_log

SCANNER_LOG = "logs/ScannerAPI.log"

# Detection layers available
LAYER_HASH = "hash_match"
LAYER_YARA = "yara"
LAYER_ML = "ml"
LAYER_SIGNATURE = "code_signing"
LAYER_CLOUD = "cloud_vt"
LAYER_BEHAVIORAL = "behavioral_static"


def _log(msg: str):
    write_to_log(msg, SCANNER_LOG)


# ---------------------------------------------------------------------------
# Verdict type
# ---------------------------------------------------------------------------

@dataclass
class ThreatVerdict:
    """
    Unified scan result returned by scan_file() and scan_bytes().

    Fields:
        is_threat      — True if the file should be blocked/quarantined
        verdict        — "CLEAN" | "SUSPICIOUS" | "MALWARE" | "IGNORED" | "ERROR"
        confidence     — 0.0–1.0 confidence in the verdict
        reasons        — human-readable list explaining the verdict
        details        — raw layer outputs (hashes, YARA matches, ML label, etc.)
        filename       — original filename (for bytes scan)
        sha256         — SHA256 of the scanned data
        scan_layers    — which detection layers ran
        elapsed_ms     — time taken in milliseconds
        timestamp      — ISO8601 scan time
    """
    is_threat: bool
    verdict: str
    confidence: float
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    filename: str = ""
    sha256: str = ""
    scan_layers: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            "is_threat": self.is_threat,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "details": self.details,
            "filename": self.filename,
            "sha256": self.sha256,
            "scan_layers": self.scan_layers,
            "elapsed_ms": self.elapsed_ms,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return (
            f"ThreatVerdict(verdict={self.verdict}, confidence={self.confidence:.0%}, "
            f"sha256={self.sha256[:12]}..., reasons={self.reasons})"
        )


_CLEAN = ThreatVerdict(is_threat=False, verdict="CLEAN", confidence=1.0)
_ERROR = ThreatVerdict(is_threat=False, verdict="ERROR", confidence=0.0)


# ---------------------------------------------------------------------------
# Internal scanner builder — lazy-loads VirusScanner once
# ---------------------------------------------------------------------------

_scanner_lock = threading.Lock()
_scanner_instance = None


def _get_scanner():
    global _scanner_instance
    if _scanner_instance is not None:
        return _scanner_instance

    with _scanner_lock:
        if _scanner_instance is not None:
            return _scanner_instance
        try:
            from Main_Unit.Engine.Compiler.SentinelCompiler_v5 import VirusScanner
            _scanner_instance = VirusScanner(max_workers=2)
            _log("VirusScanner loaded for API use")
        except Exception as e:
            _log(f"VirusScanner load failed: {e}")
            _scanner_instance = None

    return _scanner_instance


def _internal_result_to_verdict(
    result: Dict,
    filename: str,
    sha256: str,
    layers: List[str],
    elapsed_ms: float,
) -> ThreatVerdict:
    """Convert VirusScanner's result dict to a ThreatVerdict."""
    raw_verdict = result.get("verdict", "CLEAN")
    reasons = result.get("reasons", [])
    details = result.get("details", {})

    confidence_map = {
        "MALWARE":    0.95,
        "SUSPICIOUS": 0.60,
        "CLEAN":      0.95,
        "IGNORED":    1.0,
    }
    confidence = confidence_map.get(raw_verdict, 0.5)

    # Adjust confidence by number of layer hits
    layer_hits = details.get("layer_hits", 0)
    if raw_verdict == "MALWARE" and layer_hits >= 3:
        confidence = 0.99
    elif raw_verdict == "MALWARE" and layer_hits == 2:
        confidence = 0.92

    return ThreatVerdict(
        is_threat=raw_verdict in ("MALWARE", "SUSPICIOUS"),
        verdict=raw_verdict,
        confidence=confidence,
        reasons=reasons,
        details=details,
        filename=filename,
        sha256=sha256,
        scan_layers=layers,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_file(
    file_path: str,
    use_cloud: bool = False,
    cloud_client=None,
) -> ThreatVerdict:
    """
    Scan a file on disk.

    Args:
        file_path   — absolute or relative path to file
        use_cloud   — if True, additionally query VirusTotal (requires API key)
        cloud_client — VirusTotalClient instance; auto-created if None and use_cloud=True

    Returns:
        ThreatVerdict
    """
    t0 = time.perf_counter()

    if not os.path.isfile(file_path):
        return ThreatVerdict(
            is_threat=False, verdict="ERROR", confidence=0.0,
            reasons=["File not found"],
            filename=os.path.basename(file_path),
            elapsed_ms=0.0,
        )

    filename = os.path.basename(file_path)

    # Compute SHA256 upfront
    sha256 = ""
    try:
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        sha256 = h.hexdigest()
    except Exception as e:
        _log(f"SHA256 failed for {file_path}: {e}")

    layers_run: List[str] = []
    scanner = _get_scanner()

    if scanner is None:
        return ThreatVerdict(
            is_threat=False, verdict="ERROR", confidence=0.0,
            reasons=["Scanner not available"],
            filename=filename, sha256=sha256,
            elapsed_ms=round((time.perf_counter() - t0) * 1000, 2),
        )

    try:
        result = scanner.scan_file(file_path)
    except Exception as e:
        _log(f"scan_file error for {file_path}: {e}")
        return ThreatVerdict(
            is_threat=False, verdict="ERROR", confidence=0.0,
            reasons=[f"Scanner error: {e}"],
            filename=filename, sha256=sha256,
            elapsed_ms=round((time.perf_counter() - t0) * 1000, 2),
        )

    layers_run = [LAYER_HASH, LAYER_YARA, LAYER_ML, LAYER_SIGNATURE]

    verdict = _internal_result_to_verdict(
        result, filename, sha256, layers_run,
        elapsed_ms=round((time.perf_counter() - t0) * 1000, 2),
    )

    # Optional cloud cross-check
    if use_cloud and sha256:
        try:
            if cloud_client is None:
                from Main_Unit.Engine.Service.SentinelCloudAnalysis import get_vt_client
                cloud_client = get_vt_client()
            cloud_verdict = cloud_client.check_hash(sha256)
            verdict.details["cloud_vt"] = cloud_verdict.to_dict()
            verdict.scan_layers.append(LAYER_CLOUD)

            if cloud_verdict.is_threat and verdict.verdict == "CLEAN":
                verdict.verdict = "SUSPICIOUS"
                verdict.is_threat = True
                verdict.confidence = max(verdict.confidence, 0.75)
                verdict.reasons.append(
                    f"VirusTotal: {cloud_verdict.malicious}/{cloud_verdict.total_engines} engines"
                )
            elif cloud_verdict.is_threat:
                verdict.confidence = min(0.99, verdict.confidence + 0.1)
                verdict.reasons.append(
                    f"Confirmed by VT: {cloud_verdict.malicious}/{cloud_verdict.total_engines} engines"
                )
        except Exception as e:
            _log(f"Cloud analysis error: {e}")

    verdict.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    _log(
        f"scan_file: {filename} | {verdict.verdict} | "
        f"conf={verdict.confidence:.0%} | {verdict.elapsed_ms:.0f}ms"
    )
    return verdict


def scan_bytes(
    data: bytes,
    filename: str = "unknown",
    use_cloud: bool = False,
    cloud_client=None,
) -> ThreatVerdict:
    """
    Scan raw bytes (e.g. received over network, in-memory file).

    Writes to a secure temp file, scans, then cleans up.

    Args:
        data        — raw file bytes
        filename    — original filename hint (used for extension detection)
        use_cloud   — additionally query VirusTotal
        cloud_client — VirusTotalClient instance

    Returns:
        ThreatVerdict
    """
    t0 = time.perf_counter()

    if not data:
        return ThreatVerdict(
            is_threat=False, verdict="IGNORED", confidence=1.0,
            reasons=["Empty data"],
            filename=filename,
            elapsed_ms=0.0,
        )

    # Preserve extension so scanner extension-check works
    suffix = Path(filename).suffix or ".bin"
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="sentinel_scan_")
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
    except Exception as e:
        _log(f"scan_bytes temp write failed: {e}")
        return ThreatVerdict(
            is_threat=False, verdict="ERROR", confidence=0.0,
            reasons=[f"Temp file error: {e}"],
            filename=filename,
            elapsed_ms=round((time.perf_counter() - t0) * 1000, 2),
        )

    try:
        verdict = scan_file(tmp_path, use_cloud=use_cloud, cloud_client=cloud_client)
        verdict.filename = filename  # restore original name
        return verdict
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def scan_bytes_quick(data: bytes, filename: str = "unknown") -> ThreatVerdict:
    """
    Hash-only scan — fastest possible check, no YARA/ML.
    Use for high-throughput relay scenarios where latency matters.

    Returns MALWARE if hash matches known database, UNKNOWN otherwise.
    This is NOT a full scan — use scan_bytes() for definitive results.
    """
    t0 = time.perf_counter()
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    scanner = _get_scanner()
    if scanner is None:
        return ThreatVerdict(
            is_threat=False, verdict="UNKNOWN", confidence=0.0,
            reasons=["Scanner unavailable"],
            filename=filename, sha256=sha256,
            scan_layers=[], elapsed_ms=0.0,
        )

    is_md5_hit = md5 in scanner.known_virus_hashes_md5
    is_sha256_hit = sha256 in scanner.known_virus_hashes_sha256

    elapsed = round((time.perf_counter() - t0) * 1000, 2)

    if is_md5_hit or is_sha256_hit:
        return ThreatVerdict(
            is_threat=True, verdict="MALWARE", confidence=0.98,
            reasons=["Known virus hash match (quick scan)"],
            details={"md5_hit": is_md5_hit, "sha256_hit": is_sha256_hit},
            filename=filename, sha256=sha256,
            scan_layers=[LAYER_HASH], elapsed_ms=elapsed,
        )

    return ThreatVerdict(
        is_threat=False, verdict="UNKNOWN", confidence=0.5,
        reasons=["Hash not in known-malware database — run full scan for conclusive result"],
        filename=filename, sha256=sha256,
        scan_layers=[LAYER_HASH], elapsed_ms=elapsed,
    )


# ---------------------------------------------------------------------------
# Batch scanning
# ---------------------------------------------------------------------------

def scan_directory(
    directory: str,
    use_cloud: bool = False,
) -> List[ThreatVerdict]:
    """
    Scan all scannable files in a directory.
    Returns list of non-CLEAN / non-IGNORED verdicts only.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if not os.path.isdir(directory):
        return []

    files = []
    scanner = _get_scanner()
    if scanner is None:
        return []

    for root, _, filenames in os.walk(directory):
        for fname in filenames:
            fpath = os.path.join(root, fname)
            if scanner.should_scan_file(fpath):
                files.append(fpath)

    threats = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(scan_file, fp, use_cloud): fp for fp in files}
        for future in as_completed(futures):
            try:
                verdict = future.result()
                if verdict.verdict not in ("CLEAN", "IGNORED"):
                    threats.append(verdict)
            except Exception:
                pass

    return threats
