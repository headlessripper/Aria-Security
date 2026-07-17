# SentinelCompiler_v5.py
# Version: 5.0 (parallelized)

import yara
import os
import hashlib
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from winotify import Notification, audio
from pathlib import Path

from Main_Unit.find_items import find_items
from Main_Unit.Config.Sys_Config import (
    SYSTEM_ICON_PATH,
    APP_NAME,
    PE_EXTENSIONS,
    RULE_PATH,
    HASH_FILE_PATH,
    DETECTION_MODEL_PATH,
    HASH256_FILE_PATH,
)
from Main_Unit.Units.Engine_Unit_ML_v2 import model_scanner
from Main_Unit.Units.Engine_Unit_SG import sign_scanner
from Main_Unit.Service.write_to_log import write_to_log


def _llm_consult(file_path: str, reasons: list, details: dict) -> str | None:
    """
    LLM-assisted verdict for borderline files.
    Sentinel-R1 has been removed; AVBrain's LLM (Phi-3.5-mini) now handles
    system-wide threat intelligence. Scan verdicts rely solely on the ONNX
    ML engine + YARA + hash matching — no per-file LLM call needed.
    Returns None so the caller falls back to its existing ML-only verdict.
    """
    return None


class VirusScanner:
    def __init__(self, max_workers: int = 4):
        """Initialize scanner with all resources loaded."""
        self.sig_dir = find_items(RULE_PATH)
        self.hashes_file_md5 = find_items(HASH_FILE_PATH)

        write_to_log(f"Using signature directory: {self.sig_dir}")
        write_to_log(f"Using MD5 hashes file: {self.hashes_file_md5}")
        self.sha256_files = find_items(HASH256_FILE_PATH)
        write_to_log(f"Using SHA256 FILE: {self.sha256_files}")

        # Validate ALL paths before loading
        write_to_log(
            f"[DEBUG] sig_dir: '{self.sig_dir}' | md5: '{self.hashes_file_md5}' | sha256: {self.sha256_files}"
        )

        if not self.sig_dir or not os.path.exists(self.sig_dir):
            write_to_log(f"❌ CRITICAL: Signature directory invalid/missing: '{self.sig_dir}'")
            self.sig_dir = None  # Disable YARA

        if not self.hashes_file_md5 or not os.path.exists(self.hashes_file_md5):
            write_to_log(f"⚠️ MD5 hashes missing: '{self.hashes_file_md5}'")
            self.hashes_file_md5 = None

        if not self.sha256_files:
            write_to_log("⚠️ No SHA256 files found")

        self.known_virus_hashes_md5 = set()
        self.known_virus_hashes_sha256 = set()

        # In‑memory verdict cache: sha256 -> scan result dict
        self._verdict_cache = {}

        # Parallelism
        self.max_workers = max_workers

        self._load_resources()

    def _load_resources(self):
        """Load hashes, YARA rules, ML model, and signature scanner."""
        # Initialize signature scanner
        self.sign = sign_scanner()
        self.sign.init_windll(["wintrust"])

        # Load ML model
        write_to_log("Loading ML model...")
        self.ml_scanner = model_scanner()
        path_detection_model = find_items(DETECTION_MODEL_PATH)
        model_path = path_detection_model
        write_to_log(f"Model path: {model_path}")

        if self.ml_scanner.load_file(model_path):
            write_to_log(f"✅ Loaded model ({len(self.ml_scanner.models)})")
        else:
            write_to_log("❌ Model load failed")
            write_to_log(f"  Path exists: {os.path.exists(model_path)}")

        # Load virus hashes (MD5)
        write_to_log("Loading virus hash databases...")
        if self.hashes_file_md5 and os.path.exists(self.hashes_file_md5):
            with open(self.hashes_file_md5, 'r') as f:
                for line in f:
                    hash_val = line.strip()
                    if hash_val:
                        self.known_virus_hashes_md5.add(hash_val)
            write_to_log(f"Loaded {len(self.known_virus_hashes_md5)} MD5 virus hashes.")
        else:
            write_to_log(f"Warning: {self.hashes_file_md5} not found or invalid.")

        # Load SHA256 hashes (handles str or list from find_items)
        self.known_virus_hashes_sha256 = set()
        write_to_log(f"[DEBUG] Raw sha256_files: {self.sha256_files} (type: {type(self.sha256_files)})")

        # Normalize: str → [str], list → list
        if isinstance(self.sha256_files, str):
            sha256_files = [self.sha256_files]
        elif isinstance(self.sha256_files, list):
            sha256_files = [f for f in self.sha256_files if f and str(f).strip()]
        else:
            sha256_files = []

        write_to_log(f"[DEBUG] Normalized: {len(sha256_files)} files")

        loaded_count = 0
        for sha_file in sha256_files:
            if os.path.exists(sha_file):
                try:
                    with open(sha_file, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            hash_val = line.strip()
                            if (
                                len(hash_val) in (32, 64)
                                and all(c in '0123456789abcdefABCDEF' for c in hash_val)
                            ):
                                self.known_virus_hashes_sha256.add(hash_val.lower())
                                loaded_count += 1
                    write_to_log(f"✅ {os.path.basename(sha_file)}: {loaded_count} valid SHA256 hashes")
                except Exception as e:
                    write_to_log(f"❌ Error reading {sha_file}: {e}")
            else:
                write_to_log(f"❌ Missing: {sha_file}")

        write_to_log(f"🎯 Total SHA256 database: {len(self.known_virus_hashes_sha256)} hashes")

        # Load YARA rules
        if not self.sig_dir or not os.path.exists(self.sig_dir):
            raise ValueError(f"ERROR: {self.sig_dir} does not exist!")

        all_yara = []
        for root, dirs, files in os.walk(self.sig_dir):
            for file in files:
                if file.lower().endswith(('.yara', '.yar')):
                    all_yara.append(os.path.join(root, file))

        write_to_log(f"Found {len(all_yara)} .yara files across all subfolders.")
        if not all_yara:
            raise ValueError("No .yara files found!")

        filepaths = {os.path.splitext(os.path.basename(f))[0]: f for f in all_yara}
        self.rules = yara.compile(filepaths=filepaths)
        write_to_log(f"✅ Compiled {len(filepaths)} YARA rule namespaces.")

    def compute_hashes(self, file_path):
        """Compute MD5 and SHA256 hashes for a file."""
        file_hash_md5 = None
        file_hash_sha256 = None
        try:
            md5 = hashlib.md5()
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            file_hash_md5 = md5.hexdigest()
            file_hash_sha256 = sha256.hexdigest()
        except Exception:
            pass
        return file_hash_md5, file_hash_sha256

    def is_pe_file(self, file_path):
        """Verify if file is genuine PE (MZ + PE header)."""
        try:
            with open(file_path, 'rb') as f:
                # Check MZ signature (DOS header)
                if f.read(2) != b'MZ':
                    return False

                # Seek to PE offset (at offset 0x3C)
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]

                # Check PE signature
                f.seek(pe_offset)
                if f.read(4) != b'PE\x00\x00':
                    return False

                return True
        except Exception:
            return False

    def should_scan_file(self, file_path):
        """Check extension first, then verify PE structure for aggressive targeting."""
        file_ext = Path(file_path).suffix.lower()

        # Quick extension filter
        if file_ext not in PE_EXTENSIONS:
            return False

        # Verify actual PE structure (extensions can lie)
        return self.is_pe_file(file_path)

    # ----------------------------------------
    # Optional cheap pre-filter (size/entropy)
    # ----------------------------------------
    def is_suspicious_candidate(self, file_path):
        try:
            size = os.path.getsize(file_path)
            if size < 1024 or size > 100 * 1024 * 1024:  # <1KB or >100MB
                return False

            # Entropy over first 8KB
            import numpy as np
            with open(file_path, "rb") as f:
                data = f.read(8192)
            if not data:
                return False
            hist = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            hist = hist[hist > 0]
            hist = hist / hist.sum()
            entropy = -np.sum(hist * np.log2(hist))
            if entropy < 4.0:  # very low entropy → probably not packed malware
                return False
            return True
        except Exception:
            return True  # fail‑open to not miss threats

    # ----------------------------------------
    # Core single‑file scan (unchanged logic)
    # ----------------------------------------
    def scan_file(self, file_path):
        """
        Aggressively scan confirmed PE files with all 4 layers.
        Returns: {'verdict': str, 'reasons': list, 'details': dict}
        """
        # Only scan confirmed PE files
        if not self.should_scan_file(file_path):
            return {'verdict': 'IGNORED', 'reasons': ['Not PE file'], 'details': {}}

        # Whitelist check — skip entirely if the user trusts this file/path
        try:
            from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
            wl = get_whitelist()
            if wl.is_whitelisted_file(str(file_path)):
                return {'verdict': 'WHITELISTED', 'reasons': ['User-trusted path'], 'details': {}}
        except Exception:
            pass

        verdict = "CLEAN"
        reasons = []
        details = {}
        layer_hits = 0  # Confirmed malware hits

        print(f"🔍 PE Analysis: {file_path}")

        # Hash check (strongest single indicator)
        file_hash_md5, file_hash_sha256 = self.compute_hashes(file_path)
        details['md5'] = file_hash_md5
        details['sha256'] = file_hash_sha256

        # Whitelist hash check — trust known-clean hashes
        if file_hash_sha256:
            try:
                from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
                if get_whitelist().is_whitelisted_hash(file_hash_sha256):
                    return {'verdict': 'WHITELISTED', 'reasons': ['User-trusted hash'],
                            'details': {'sha256': file_hash_sha256, 'md5': file_hash_md5}}
            except Exception:
                pass

        # Cache hit
        if file_hash_sha256 and file_hash_sha256 in self._verdict_cache:
            cached = self._verdict_cache[file_hash_sha256]
            print(f"[CACHE HIT] {file_path}")
            return cached

        is_md5_hit = file_hash_md5 in self.known_virus_hashes_md5 if file_hash_md5 else False
        is_sha256_hit = file_hash_sha256 in self.known_virus_hashes_sha256 if file_hash_sha256 else False

        if is_md5_hit or is_sha256_hit:
            verdict = "MALWARE"
            reasons.append("Known virus hash match")
            layer_hits += 1

        # YARA check (behavioral patterns)
        matches = self.rules.match(file_path)
        details['yara_matches'] = [
            {'rule': m.rule, 'score': m.meta.get('score', 0)} for m in matches
        ]
        yara_high = any(m.meta.get('score', 0) >= 50 for m in matches)

        if yara_high:
            verdict = "MALWARE"
            reasons.append("High-risk YARA rule")
            layer_hits += 1
        elif any(30 <= m.meta.get('score', 0) < 50 for m in matches):
            reasons.append("Suspicious YARA rule")

        # ML check (PE-specific malware classifier)
        ml_malware = False
        if self.ml_scanner.models:
            ml_result = self.ml_scanner.model_scan(file_path)
            if (
                isinstance(ml_result, tuple)
                and ml_result[0] in self.ml_scanner.detect_set
                and isinstance(ml_result[1], int)
                and ml_result[1] >= self.ml_scanner.min_confidence
            ):
                details['ml_label'] = ml_result[0]
                details['ml_confidence'] = ml_result[1]

                # SPECIAL EXCEPTION: Pefile/General (100%) = INSTANT MALWARE
                if ml_result[0] == "Pefile/General" and ml_result[1] == 100:
                    verdict = "MALWARE"
                    reasons.append("CRITICAL ML HIT: Pefile/General (100%)")
                    layer_hits += 1
                    ml_malware = True
                    print(f"*** IMMEDIATE THREAT: Pefile/General (100%) DETECTED ***")
                elif "malware" in ml_result[0].lower():
                    ml_malware = True
                    layer_hits += 1
                    reasons.append(f"ML malware detection ({ml_result[1]}%)")
                else:
                    reasons.append(f"ML suspicious ({ml_result[0]} {ml_result[1]}%)")

        # Signature check (trust indicator)
        try:
            signed = self.sign.sign_verify(file_path)
            details['signed'] = signed
            if not signed:
                reasons.append("Unsigned PE / untrusted")
        except Exception as e:
            reasons.append(f"Signature check failed: {e}")

        # LLM tiebreaker — consulted only for borderline ML scores (60–90%)
        # so the heavy model isn't loaded on obvious clean or confirmed malware.
        ml_conf = details.get('ml_confidence', 0)
        if verdict != "MALWARE" and 60 <= ml_conf <= 90:
            try:
                llm_verdict = _llm_consult(file_path, reasons, details)
                if llm_verdict:
                    details['llm_verdict'] = llm_verdict
                    if llm_verdict.upper() == "MALWARE":
                        verdict = "MALWARE"
                        reasons.append(f"LLM escalated to MALWARE (ML borderline {ml_conf}%)")
                        layer_hits += 1
                    elif llm_verdict.upper() == "SUSPICIOUS":
                        reasons.append(f"LLM flagged as SUSPICIOUS (ML borderline {ml_conf}%)")
            except Exception as _llm_err:
                details['llm_error'] = str(_llm_err)

        # Cloud verification: VirusTotal hash check for files not yet confirmed malware.
        # Only fires when a VT API key is configured — no key, no request.
        if file_hash_sha256 and verdict != "MALWARE":
            try:
                from Main_Unit.Engine.Service.SentinelCloudAnalysis import get_vt_client
                vt = get_vt_client()
                if vt._is_configured():
                    cloud = vt.check_hash(file_hash_sha256)
                    details['vt_verdict'] = cloud.verdict_str
                    details['vt_malicious'] = cloud.malicious
                    details['vt_total'] = cloud.total_engines
                    if cloud.is_threat:
                        verdict = "MALWARE"
                        reasons.append(
                            f"VirusTotal: {cloud.malicious}/{cloud.total_engines} engines "
                            f"({', '.join(cloud.threat_names[:2])})" if cloud.threat_names
                            else f"VirusTotal: {cloud.malicious}/{cloud.total_engines} engines"
                        )
                        layer_hits += 1
                    elif cloud.found and cloud.suspicious > 0:
                        reasons.append(f"VirusTotal: {cloud.suspicious} suspicious detections")
            except Exception:
                pass

        # Final verdict logic
        if layer_hits >= 2:
            verdict = "MALWARE"
        elif layer_hits == 1 and verdict != "MALWARE":
            verdict = "SUSPICIOUS"
        details['layer_hits'] = layer_hits

        # Silent logging
        if verdict == "MALWARE":
            print(f"*** CONFIRMED PE MALWARE ({layer_hits}/4 layers) ***")
            file_name = os.path.basename(file_path)

            toast = Notification(
                app_id=APP_NAME,
                title="Confirmed Malware",
                msg=f"Threats Found: {file_name}",
                icon=find_items(SYSTEM_ICON_PATH),
                duration="short"
            )
            toast.set_audio(audio.Default, loop=True)
            toast.show()
        elif verdict == "SUSPICIOUS":
            print(f"Suspicious PE ({layer_hits}/4 layers)")
        else:
            print("Clean PE")

        # Details (silent)
        if details.get('md5'):
            print(f"MD5: {details['md5']}")
        if details.get('sha256'):
            print(f"SHA256: {details['sha256']}")
        for match in details.get('yara_matches', []):
            print(f"YARA: {match['rule']} | Score {match['score']}")
        if details.get('ml_label'):
            print(f"ML: {details['ml_label']} ({details['ml_confidence']}%)")
        if 'signed' in details:
            print(f"Signed: {details['signed']}")

        result = {
            'verdict': verdict,
            'reasons': reasons,
            'details': details
        }

        # Cache store
        if file_hash_sha256:
            self._verdict_cache[file_hash_sha256] = result

        # Persist to scan history (non-blocking, best-effort)
        if verdict not in ("IGNORED", "WHITELISTED"):
            try:
                from Main_Unit.Engine.Service.SentinelScanHistory import record
                record(str(file_path), result)
            except Exception:
                pass

        return result

    # ----------------------------------------
    # Helper for parallel directory scan
    # ----------------------------------------
    def _scan_single_file_task(self, file_path, executor, notify_confirmed_only):
        try:
            result = self.scan_file(file_path)
            if result['verdict'] == "MALWARE" and notify_confirmed_only and executor:
                task_id = executor.handle_threat(file_path)
                print(f"Task {task_id} added to queue for: {file_path}")
            return file_path, result
        except Exception as e:
            print(f"Error scanning PE {file_path}: {e}")
            return file_path, {
                'verdict': 'ERROR',
                'reasons': [str(e)],
                'details': {}
            }

    def scan_directory(self, target_dir, notify_confirmed_only=True,
                       executor=None, running_flag=None, cancel_flag=None):
        """
        Parallel scan of directory focusing on PE files only.
        Returns: (scan_count: int, detections: list[dict])
        """
        if not os.path.isdir(target_dir):
            raise ValueError(f"'{target_dir}' is not a directory")

        print(f"\n🛡️ PE-Focused Scan (parallel): {os.path.abspath(target_dir)}")
        detections = []
        confirmed_malware = []

        # Collect candidate files first
        file_candidates = []
        for root, dirs, files in os.walk(target_dir):
            if running_flag is not None and not running_flag[0]:
                print("⏹️ Scan cancelled by running_flag during walk")
                break

            for file in files:
                if cancel_flag is not None and cancel_flag[0]:
                    print("⏹️ Scan cancelled by cancel_flag during walk")
                    break
                if running_flag is not None and not running_flag[0]:
                    print("⏹️ Scan cancelled by running_flag during walk")
                    break

                file_path = os.path.join(root, file)
                if self.should_scan_file(file_path) and self.is_suspicious_candidate(file_path):
                    file_candidates.append(file_path)

        if not file_candidates:
            print("No PE candidates found for scanning.")
            return 0, []

        # Parallel execution
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = []
            for path in file_candidates:
                if cancel_flag is not None and cancel_flag[0]:
                    print("⏹️ Scan cancelled before submitting all tasks")
                    break
                futures.append(
                    pool.submit(
                        self._scan_single_file_task,
                        path,
                        executor,
                        notify_confirmed_only
                    )
                )

            for future in as_completed(futures):
                if cancel_flag is not None and cancel_flag[0]:
                    print("⏹️ Scan cancelled while collecting results")
                    break
                if running_flag is not None and not running_flag[0]:
                    print("⏹️ Scan cancelled while collecting results (running_flag)")
                    break

                file_path, result = future.result()
                if result['verdict'] != "CLEAN" and result['verdict'] != "IGNORED":
                    detections.append(result)
                    if result['verdict'] == "MALWARE" and notify_confirmed_only:
                        confirmed_malware.append(result)

        # Batch alert for confirmed PE malware only
        if notify_confirmed_only and confirmed_malware:
            reasons_summary = [
                f"{d['details'].get('layer_hits', 0)}/4 layers: {', '.join(d['reasons'][:2])}"
                for d in confirmed_malware
            ]

            toast = Notification(
                app_id=APP_NAME,
                title=f"🚨 {len(confirmed_malware)} Confirmed PE Malware",
                msg="\n".join(reasons_summary[:5]),
                icon=find_items(SYSTEM_ICON_PATH),
                duration="short"
            )
            toast.set_audio(audio.Default, loop=True)
            toast.show()

        print(
            f"✅ Analyzed {len(file_candidates)} PE files ({len(detections)} detections, "
            f"{len(confirmed_malware)} confirmed)."
        )
        return len(file_candidates), detections
