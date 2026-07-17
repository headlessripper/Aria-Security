# SentinelNetProtection.py

import argparse
import os
import sys
import time
import subprocess
import json
import re
import numpy as np
import pandas as pd
import joblib
from winotify import Notification, audio
from pathlib import Path
from collections import defaultdict, Counter, deque
from typing import List, Dict, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPRegressor
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
import pickle

from Main_Unit.Config.Sys_Config import IPS_FILE_PATH, WHITE_LIST_FILE_PATH, SYSTEM_ICON_PATH
from Main_Unit.Service.write_to_log import write_to_log
from Main_Unit.find_items import find_items as find_icon

def _get_brain():
    from Main_Unit.Engine.Service.SentinelBrain import get_brain, ThreatEvent, ThreatCategory, ThreatSeverity
    return get_brain(), ThreatEvent, ThreatCategory, ThreatSeverity

# Try to import Scapy for packet sensor
try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import pandas as pd
import joblib

MODEL_FILE = "nids_model.pkl"
SCALER_FILE = "nids_scaler.pkl"
LABEL_ENCODER_FILE = "nids_label_encoder.pkl"

# ---------- REBUILD FEATURE SPACE (MUST MATCH TRAINING) ----------

def load_sdn_dataset_for_cols(file_path: str):
    """
    Only used to reconstruct the union of feature columns (all_cols)
    exactly like in training.
    """
    df = pd.read_csv(file_path)
    cols = [
        "source_port",
        "destination_port",
        "protocol",
        "duration",
        "packet_count",
        "bytes_sent",
        "bytes_received",
        "bytes_per_packet",
        "label",
    ]
    df = df[cols]
    X = df.drop(columns=["label"])
    # (no one-hot in training for SDN)
    return X


def load_kaggle_dataset_for_cols(file_path: str):
    """
    Only used to reconstruct the union of feature columns (all_cols)
    exactly like in training.
    """
    df = pd.read_csv(file_path)

    label_col = "class"
    if label_col not in df.columns:
        raise ValueError("No 'class' column in Kaggle CSV; check file.")

    X = df.drop(columns=[label_col])

    cat_cols = X.select_dtypes(include=["object", "string"]).columns
    for col in cat_cols:
        X = pd.get_dummies(X, columns=[col], drop_first=True)

    return X


def build_all_cols():
    """
    Rebuild the same all_cols you used in train.py:
    union of SDN features and Kaggle features after encoding.
    IMPORTANT: use the same file names and paths as train.py.
    """
    # Use the same files as in training:
    X_sdn = load_sdn_dataset_for_cols("./models/Data_Files/network_traffic.csv")  # SDN file
    X_kag = load_kaggle_dataset_for_cols("./models/Data_Files/Train_data.csv")    # Kaggle TRAIN file

    all_cols = sorted(list(set(X_sdn.columns).union(set(X_kag.columns))))
    return all_cols


def align_features(X, all_columns):
    X_aligned = X.copy()
    for col in all_columns:
        if col not in X_aligned.columns:
            X_aligned[col] = 0
    X_aligned = X_aligned[all_columns]
    return X_aligned


def run_powershell_hidden(cmd: str, timeout: int = 12):
    """
    Run a PowerShell command with no visible window.
    Works for PyInstaller GUI builds too.
    """
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0

    return subprocess.run(
        ["powershell.exe", "-NoLogo", "-NonInteractive", "-Command", cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        startupinfo=si,
        creationflags=subprocess.CREATE_NO_WINDOW
    )

# ============================================================================
# GLOBAL STATE
# ============================================================================

BLACKLIST = set()
WHITELIST = set()  # trusted IPs never auto-blocked
BLOCKED_IPS = set()
IP_REPUTATION = defaultdict(lambda: {'score': 0.0, 'hits': 0, 'last_seen': 0})
CONNECTION_HISTORY = deque(maxlen=10_000_000)

LOCKS = {
    'blacklist': threading.Lock(),
    'blocked': threading.Lock(),
    'reputation': threading.Lock(),
    'history': threading.Lock()
}

SUSPICIOUS_PORTS = {21, 22, 23, 445, 1433, 3389, 5432, 5900}
N_WORKERS = 16
MAX_CONNS_PER_IP = 50  # raised from 20; browsers/CDNs open 30+ connections legitimately

# ---------------------------------------------------------------------------
# Trusted CDN / infrastructure IP ranges — NEVER auto-blocked.
# Covers Google, Cloudflare, Akamai, Microsoft Azure/Office, AWS, Meta, Apple.
# Checked as prefix strings for speed (full CIDR matching not needed here).
# ---------------------------------------------------------------------------
_TRUSTED_PREFIXES = (
    # Google (GFE, Workspace, YouTube, APIs)
    "172.217.", "172.253.", "216.58.", "216.239.",
    "64.233.", "66.102.", "66.249.", "74.125.",
    "209.85.", "142.250.", "142.251.", "108.177.",
    "173.194.", "34.64.", "34.80.", "34.96.", "34.104.",
    "34.120.", "34.128.", "35.186.", "35.190.", "35.191.",
    # Cloudflare
    "1.1.1.", "1.0.0.", "104.16.", "104.17.", "104.18.", "104.19.",
    "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
    "104.26.", "104.27.", "104.28.", "104.29.", "104.30.", "104.31.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
    "172.70.", "172.71.",
    "162.158.", "190.93.", "188.114.", "197.234.", "198.41.",
    # Microsoft / Azure / Office 365
    "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.",
    "13.70.", "13.71.", "13.72.", "13.73.", "13.74.", "13.75.",
    "13.76.", "13.77.", "13.78.", "13.79.", "13.80.", "13.81.",
    "13.82.", "13.83.", "13.84.", "13.85.", "13.86.", "13.87.",
    "13.88.", "13.89.", "13.90.", "13.91.", "13.92.", "13.93.",
    "13.94.", "13.95.", "20.36.", "20.37.", "20.38.", "20.39.",
    "20.40.", "20.41.", "20.42.", "20.43.", "20.44.", "20.45.",
    "20.46.", "20.47.", "20.48.", "20.49.", "20.50.", "20.51.",
    "20.52.", "20.53.", "20.54.", "20.55.", "20.56.", "20.57.",
    "20.58.", "20.59.", "20.60.", "20.61.", "40.64.", "40.65.",
    "40.66.", "40.67.", "40.68.", "40.69.", "40.70.", "40.71.",
    "40.72.", "40.73.", "40.74.", "40.75.", "40.76.", "40.77.",
    "40.78.", "40.79.", "40.80.", "40.81.", "40.82.", "40.83.",
    "40.84.", "40.85.", "40.86.", "40.87.", "40.88.", "40.89.",
    "40.90.", "52.136.", "52.137.", "52.138.", "52.139.",
    "52.140.", "52.141.", "52.142.", "52.143.", "52.144.",
    "52.145.", "52.146.", "52.147.", "52.148.", "52.149.",
    "52.150.", "52.151.", "52.152.", "52.153.", "52.154.",
    "52.155.", "52.156.", "52.157.", "52.158.", "52.159.",
    "52.160.", "52.161.", "52.162.", "52.163.", "52.164.",
    "52.165.", "52.166.", "52.167.", "52.168.", "52.169.",
    "52.170.", "52.171.", "52.172.", "52.173.", "52.174.",
    "52.175.", "52.176.", "52.177.", "52.178.", "52.179.",
    "52.180.", "52.181.", "52.182.", "52.183.", "52.184.",
    "52.185.", "52.186.", "52.187.", "52.188.", "52.189.",
    "52.190.", "52.191.",
    # AWS (common CDN / S3 / CloudFront)
    "54.160.", "54.161.", "54.162.", "54.163.", "54.164.",
    "54.165.", "54.166.", "54.167.", "54.168.", "54.169.",
    "54.170.", "54.171.", "54.172.", "54.173.", "54.174.",
    "54.175.", "54.176.", "54.177.", "54.178.", "54.179.",
    "54.180.", "54.181.", "54.182.", "54.183.",
    "52.0.", "52.1.", "52.2.", "52.3.", "52.4.", "52.5.",
    "52.6.", "52.7.", "52.8.", "52.9.", "52.10.", "52.11.",
    "52.12.", "52.13.", "52.14.", "52.15.",
    "15.197.", "13.33.", "13.32.", "13.35.", "13.224.",
    "13.225.", "13.226.", "13.227.", "13.228.", "13.229.",
    "13.230.", "13.231.", "13.232.", "13.233.", "13.234.",
    "13.235.",
    # Meta / Facebook
    "31.13.", "157.240.", "179.60.", "185.60.", "204.15.",
    "66.220.", "69.63.", "69.171.",
    # Apple
    "17.0.", "17.1.", "17.2.", "17.3.", "17.4.", "17.5.",
    "17.6.", "17.7.", "17.8.", "17.9.", "17.10.", "17.11.",
    "17.12.", "17.13.", "17.14.", "17.15.", "17.16.", "17.17.",
    "17.18.", "17.19.", "17.20.",
    # Akamai
    "23.0.", "23.1.", "23.2.", "23.3.", "23.4.", "23.5.",
    "23.6.", "23.7.", "23.8.", "23.9.", "23.10.", "23.11.",
    "23.12.", "23.13.", "23.14.", "23.15.",
    "96.6.", "96.7.", "184.24.", "184.25.", "184.26.", "184.27.",
    "184.28.", "184.29.", "184.50.", "184.51.", "184.84.", "184.85.",
    "184.86.", "184.87.",
    # GitHub
    "140.82.", "140.83.", "140.84.", "185.199.",
    "192.30.", "192.31.",
)

AI_MODEL = None
SCALER = None
NET_AUTOENCODER = None
NET_ISOFOREST = None
NET_SCALER = None
MALWARE_DETECTOR = None
PHISH_VECTOR = None
PHISH_DETECTOR = None

# columns autoencoder & network ISO were trained with (set on load)
NETWORK_FEATURE_COLUMNS: Optional[pd.Index] = None

MODELS_DIR = Path("./models")
MODELS_DIR.mkdir(exist_ok=True)

# NIDS (flow-based) model globals
NIDS_MODEL = None
NIDS_SCALER = None
NIDS_LABEL_ENCODER = None
NIDS_ALL_COLS = None

def load_whitelist(path: str = "whitelist_ips.txt"):
    global WHITELIST
    p = Path(path)
    if not p.exists():
        return
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            WHITELIST = {line.strip() for line in f if line.strip()}
    except Exception as e:
        write_to_log(f"⚠️ Whitelist load error: {e}", 'logs/NetPro.log')

# ============================================================================
# NETWORK HELPERS
# ============================================================================

def build_autoencoder_sklearn(input_dim: int) -> MLPRegressor:
    return MLPRegressor(
        hidden_layer_sizes=(128, 64, 32, 64, 128),
        activation='relu',
        solver='adam',
        max_iter=200,
        early_stopping=True,
        random_state=42
    )

def preprocess_network_data(df: pd.DataFrame):
    features = df[['bytes_sent', 'bytes_received', 'duration',
                   'port', 'protocol_type', 'service', 'flag']]
    categorical_cols = ['protocol_type', 'service', 'flag']
    features = pd.get_dummies(features, columns=categorical_cols)
    scaler = StandardScaler()
    numerical_cols = ['bytes_sent', 'bytes_received', 'duration', 'port']
    features[numerical_cols] = scaler.fit_transform(features[numerical_cols])
    return features, scaler

def detect_network_anomalies(autoencoder, iso_forest, X_test: pd.DataFrame):
    import numpy as _np

    predictions = autoencoder.predict(X_test)
    if predictions.shape != X_test.shape:
        predictions = predictions.reshape(X_test.shape)

    # Sanitize NaN and inf before MSE — badly-scaled inputs produce inf
    # predictions which propagate as inf through the entire score pipeline,
    # eventually causing OverflowError when C-level int() conversion is hit.
    if not _np.isfinite(predictions).all() or X_test.isna().any().any():
        predictions = _np.nan_to_num(predictions, nan=0.0, posinf=1e6, neginf=-1e6)
        X_test_clean = X_test.fillna(0)
    else:
        X_test_clean = X_test

    mse = _np.mean(_np.power(X_test_clean.values - predictions, 2), axis=1)
    mse = _np.clip(mse, 0.0, 1e12)   # cap at a finite ceiling; inf breaks scoring
    autoencoder_anomalies = mse > _np.percentile(mse, 99)
    iso_anomalies = iso_forest.predict(X_test) == -1
    combined_anomalies = autoencoder_anomalies | iso_anomalies
    return combined_anomalies, mse

def _safe_timestamp(ts: Any) -> float:
    if ts is None:
        return time.time()
    if isinstance(ts, (int, float)):
        return float(ts)
    try:
        return float(ts)
    except Exception:
        return time.time()

def _safe_int(val, default: int = 0) -> int:
    """Convert val to int, returning default on any failure (including infinity)."""
    try:
        return int(val)
    except (TypeError, ValueError, OverflowError):
        return default


def connections_raw_to_df(conns: List[Dict]) -> pd.DataFrame:
    if not conns:
        return pd.DataFrame(columns=[
            'bytes_sent', 'bytes_received', 'duration',
            'port', 'protocol_type', 'service', 'flag'
        ])

    rows = []
    now = time.time()
    for c in conns:
        ts = _safe_timestamp(c.get('timestamp', now))
        duration = float(now - ts)
        if not (0.0 <= duration <= 86400.0):   # clamp to 0–24 h; bad ts → 0
            duration = 0.0
        rows.append({
            'bytes_sent':     float(c.get('BytesSent', 0)),
            'bytes_received': float(c.get('BytesReceived', 0)),
            'duration':       duration,
            'port':           _safe_int(c.get('RemotePort', 0)),
            'protocol_type':  'tcp',
            'service':        'unknown',
            'flag':           c.get('State', 'SF'),
        })
    return pd.DataFrame(rows)

def connections_to_network_df(conns: List[Dict]) -> pd.DataFrame:
    """
    Full preprocessing for live connections:
    - build base DF
    - one-hot encode categoricals
    - reindex to training columns NETWORK_FEATURE_COLUMNS
    """
    global NETWORK_FEATURE_COLUMNS
    base_df = connections_raw_to_df(conns)
    if base_df.empty or NETWORK_FEATURE_COLUMNS is None:
        return pd.DataFrame(columns=NETWORK_FEATURE_COLUMNS if NETWORK_FEATURE_COLUMNS is not None else [])

    cat_cols = ['protocol_type', 'service', 'flag']
    for col in ['bytes_sent', 'bytes_received', 'duration', 'port'] + cat_cols:
        if col not in base_df.columns:
            base_df[col] = 0

    df = pd.get_dummies(base_df, columns=cat_cols)
    df = df.reindex(columns=NETWORK_FEATURE_COLUMNS, fill_value=0)
    return df

# ============================================================================
# MALWARE & PHISHING HELPERS
# ============================================================================

# ---------------------------------------------------------------------------
# AbuseIPDB integration — async reputation cache
# ---------------------------------------------------------------------------

_ABUSE_CACHE: Dict[str, Dict] = {}
_ABUSE_CACHE_TTL = 3600  # 1 hour
_ABUSE_LOCK = threading.Lock()


def _load_abuseipdb_key() -> str:
    try:
        from Main_Unit.find_items import find_items
        from Main_Unit.Config.Sys_Config import CONFIG_PATH
        cfg_path = find_items(CONFIG_PATH)
        if cfg_path and os.path.exists(cfg_path):
            import json as _json
            with open(cfg_path, 'r') as f:
                return _json.load(f).get("abuseipdb_api_key", "")
    except Exception:
        pass
    return ""


def _query_abuseipdb_async(ip: str, api_key: str) -> None:
    """Launch background AbuseIPDB lookup; result stored in cache and emitted to Brain."""
    with _ABUSE_LOCK:
        cached = _ABUSE_CACHE.get(ip)
        if cached and time.time() - cached.get('ts', 0) < _ABUSE_CACHE_TTL:
            return  # already cached

    def _do():
        try:
            from Main_Unit.Engine.Service.SentinelThreatIntelligence import lookup_ip_abuseipdb
            data = lookup_ip_abuseipdb(ip, api_key)
            if not data:
                return
            score = int(data.get("abuseConfidenceScore", 0))
            reports = int(data.get("totalReports", 0))
            with _ABUSE_LOCK:
                _ABUSE_CACHE[ip] = {"score": score, "reports": reports, "ts": time.time()}
            if score >= 50:
                try:
                    brain, ThreatEvent, ThreatCategory, ThreatSeverity = _get_brain()
                    sev = ThreatSeverity.HIGH if score >= 75 else ThreatSeverity.MEDIUM
                    brain.emit_event(ThreatEvent(
                        category=ThreatCategory.NETWORK,
                        severity=sev,
                        title=f"AbuseIPDB: {ip} — {score}% confidence",
                        detail=f"{reports} reports in last 30 days",
                        source_module="AbuseIPDB",
                        ip_address=ip,
                    ))
                except Exception:
                    pass
        except Exception:
            pass

    threading.Thread(target=_do, daemon=True).start()


def _get_abuseipdb_score(ip: str) -> Optional[int]:
    """Return cached AbuseIPDB score (0-100) or None if not yet known."""
    with _ABUSE_LOCK:
        cached = _ABUSE_CACHE.get(ip)
        if cached and time.time() - cached.get("ts", 0) < _ABUSE_CACHE_TTL:
            return cached.get("score")
    return None

# ============================================================================
# MAIN ENGINE
# ============================================================================

write_to_log(f"Path to ips file:{IPS_FILE_PATH}", 'logs/NetPro.log')

class AINetworkProtector:
    """AI-Powered Sentinel v4.0 - ML Anomaly + Behavioral + Integrated Models"""

    def __init__(self,
                 rules_file: str = IPS_FILE_PATH,
                 model_file: str = "Sentinel_ai.model",
                 whitelist_file: str = WHITE_LIST_FILE_PATH):
        self.rules_file = Path(rules_file)
        self.model_file = Path(model_file)
        load_whitelist(whitelist_file)
        self.load_blacklist()
        self.init_ai_models()

    # ---------- L0 ----------
    def load_blacklist(self):
        global BLACKLIST
        if not self.rules_file.exists():
            return
        try:
            with open(self.rules_file, 'r', encoding='utf-8', errors='ignore') as f:
                ips = re.findall(
                    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b',
                    f.read()
                )
            BLACKLIST = set(ips)
            try:
                write_to_log(f"L0: {len(BLACKLIST):,} signatures loaded", 'logs/NetPro.log')
            except Exception:
                pass
        except Exception as exc:
            try:
                write_to_log(f"L0 load error: {exc}", 'logs/NetPro.log')
            except Exception:
                pass

    # ---------- MODEL LOAD ----------
    def init_ai_models(self):
        global AI_MODEL, SCALER, NET_AUTOENCODER, NET_ISOFOREST, NET_SCALER
        global MALWARE_DETECTOR, PHISH_VECTOR, PHISH_DETECTOR, NETWORK_FEATURE_COLUMNS
        global NIDS_MODEL, NIDS_SCALER, NIDS_LABEL_ENCODER, NIDS_ALL_COLS

        # Legacy IsolationForest + scaler
        if self.model_file and Path(self.model_file).exists():
            try:
                with open(self.model_file, 'rb') as f:
                    AI_MODEL, SCALER = pickle.load(f)
                write_to_log("✅ L5: Legacy AI model loaded", 'logs/NetPro.log')
            except Exception as e:
                write_to_log(f"⚠️ L5: Cannot load legacy model: {e}", 'logs/NetPro.log')
                AI_MODEL = IsolationForest(contamination=0.1, random_state=42, n_estimators=50)
                SCALER = StandardScaler()
        else:
            AI_MODEL = IsolationForest(contamination=0.1, random_state=42, n_estimators=50)
            SCALER = StandardScaler()
            write_to_log("⚠️ L5: New IsolationForest (no legacy model file)", 'logs/NetPro.log')

        # Network models + feature columns
        try:
            net_auto_path = MODELS_DIR / "network_autoencoder.pkl"
            net_iso_path = MODELS_DIR / "network_isoforest.pkl"
            net_scaler_path = MODELS_DIR / "network_scaler.pkl"
            net_cols_path = MODELS_DIR / "network_columns.pkl"
            if net_auto_path.exists() and net_iso_path.exists() and net_scaler_path.exists():
                NET_AUTOENCODER = joblib.load(net_auto_path)
                NET_ISOFOREST = joblib.load(net_iso_path)
                NET_SCALER = joblib.load(net_scaler_path)
                if net_cols_path.exists():
                    with open(net_cols_path, "rb") as f:
                        NETWORK_FEATURE_COLUMNS = pickle.load(f)
                else:
                    NETWORK_FEATURE_COLUMNS = None
                write_to_log("✅ L5: Network autoencoder + IsolationForest loaded", 'logs/NetPro.log')
        except Exception as e:
            write_to_log(f"⚠️ L5 network models: {e}", 'logs/NetPro.log')

        # Malware model
        try:
            mal_path = MODELS_DIR / "malware_detector.pkl"
            if mal_path.exists():
                MALWARE_DETECTOR = joblib.load(mal_path)
                write_to_log("✅ Malware detector loaded", 'logs/NetPro.log')
        except Exception as e:
            write_to_log(f"⚠️ Malware model load: {e}", 'logs/NetPro.log')

        # Phishing model
        try:
            phv_path = MODELS_DIR / "phishing_vectorizer.pkl"
            phd_path = MODELS_DIR / "phishing_detector.pkl"
            if phv_path.exists() and phd_path.exists():
                PHISH_VECTOR = joblib.load(phv_path)
                PHISH_DETECTOR = joblib.load(phd_path)
                write_to_log("✅ Phishing detector loaded", 'logs/NetPro.log')
        except Exception as e:
            write_to_log(f"⚠️ Phishing model load: {e}", 'logs/NetPro.log')

        # NIDS flow-based model
        try:
            nids_model_path = MODELS_DIR / "./nids_model.pkl"
            nids_scaler_path = MODELS_DIR / "nids_scaler.pkl"
            nids_le_path = MODELS_DIR / "nids_label_encoder.pkl"

            if nids_model_path.exists() and nids_scaler_path.exists() and nids_le_path.exists():
                NIDS_MODEL = joblib.load(nids_model_path)
                NIDS_SCALER = joblib.load(nids_scaler_path)
                NIDS_LABEL_ENCODER = joblib.load(nids_le_path)

                NIDS_ALL_COLS = build_all_cols()

                write_to_log("✅ L5: NIDS flow model loaded", 'logs/NetPro.log')
            else:
                write_to_log("⚠️ NIDS model files not found (nids_model.pkl / nids_scaler.pkl / nids_label_encoder.pkl)", 'logs/NetPro.log')
        except Exception as e:
            write_to_log(f"⚠️ NIDS model load error: {e}", 'logs/NetPro.log')
            NIDS_MODEL = None
            NIDS_SCALER = None
            NIDS_LABEL_ENCODER = None
            NIDS_ALL_COLS = None

    # ---------- FEATURE EXTRACTION ----------
    def ai_extract_features(self, ip_conns: List[Dict]) -> np.ndarray:
        if not ip_conns:
            return np.zeros(12, dtype=np.float64)

        ports = [_safe_int(c.get('RemotePort', 0)) for c in ip_conns]
        procs = [c.get('ProcessName', 'Unknown') or 'Unknown' for c in ip_conns]
        states = [c.get('State', 'SF') or 'SF' for c in ip_conns]

        timestamps = [_safe_timestamp(c.get('timestamp', None)) for c in ip_conns]
        session_duration = float(time.time() - min(timestamps)) if timestamps else 0.0

        features = np.array([
            len(ip_conns),
            len(set(ports)),
            sum(1 for p in ports if p in SUSPICIOUS_PORTS),
            np.std(ports) if len(ports) > 1 else 0.0,
            len(set(procs)),
            len(set(states)),
            sum(1 for s in states if s == 'Established'),
            sum(1 for p in procs if p.lower() in {'svchost', 'lsass'}),
            max(ports) - min(ports) if ports else 0.0,
            len([p for p in ports if p < 1024]),
            len(set(c.get('LocalPort', 0) for c in ip_conns)),
            session_duration
        ], dtype=np.float64)
        # Guard against inf/nan from bad timestamps or port arithmetic
        return np.nan_to_num(features, nan=0.0, posinf=1e9, neginf=0.0)

    def ai_anomaly_score(self, features: np.ndarray) -> float:
        global AI_MODEL, SCALER
        if AI_MODEL is None or SCALER is None or len(features) == 0:
            return 0.0
        try:
            scaled = SCALER.transform(features.reshape(1, -1))
            score = AI_MODEL.decision_function(scaled)[0]
            return -score
        except Exception:
            return 0.0

    # ---------- NIDS (flow model) helpers ----------
    @staticmethod
    def _build_nsl_like_row_from_conns(ip_conns: List[Dict]) -> Dict:
        """
        Approximate an NSL-KDD-like feature row from Windows Get-NetTCPConnection data.
        Uses the same schema as Train_data.csv/Test_data.csv used by the NIDS model.
        """
        if not ip_conns:
            return {}

        c0 = ip_conns[0]
        duration = 0.0
        protocol_type = "tcp"
        service = "other"
        flag = c0.get('State', 'SF') or 'SF'

        src_bytes = 0
        dst_bytes = 0
        count = len(ip_conns)

        row = {
            "duration": duration,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "hot": 0,
            "num_failed_logins": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "root_shell": 0,
            "su_attempted": 0,
            "num_root": 0,
            "num_file_creations": 0,
            "num_shells": 0,
            "num_access_files": 0,
            "num_outbound_cmds": 0,
            "is_host_login": 0,
            "is_guest_login": 0,
            "count": count,
            "srv_count": count,
            "serror_rate": 0,
            "srv_serror_rate": 0,
            "rerror_rate": 0,
            "srv_rerror_rate": 0,
            "same_srv_rate": 0,
            "diff_srv_rate": 0,
            "srv_diff_host_rate": 0,
            "dst_host_count": 0,
            "dst_host_srv_count": 0,
            "dst_host_same_srv_rate": 0,
            "dst_host_diff_srv_rate": 0,
            "dst_host_same_src_port_rate": 0,
            "dst_host_srv_diff_host_rate": 0,
            "dst_host_serror_rate": 0,
            "dst_host_srv_serror_rate": 0,
            "dst_host_rerror_rate": 0,
            "dst_host_srv_rerror_rate": 0,
        }
        return row

    def _nids_score_ip(self, ip_conns: List[Dict]) -> Optional[Tuple[str, float]]:
        """
        Use the NIDS RandomForest model to classify one IP's aggregated connections
        as normal/anomaly. Returns (label_str, confidence) or None.
        """
        global NIDS_MODEL, NIDS_SCALER, NIDS_LABEL_ENCODER, NIDS_ALL_COLS
        if NIDS_MODEL is None or NIDS_SCALER is None or NIDS_LABEL_ENCODER is None or NIDS_ALL_COLS is None:
            return None

        row = self._build_nsl_like_row_from_conns(ip_conns)
        if not row:
            return None

        df = pd.DataFrame([row])

        cat_cols = df.select_dtypes(include=["object", "string"]).columns
        for col in cat_cols:
            df = pd.get_dummies(df, columns=[col], drop_first=True)

        X_test = align_features(df, NIDS_ALL_COLS)

        X_scaled = NIDS_SCALER.transform(X_test)
        y_pred_encoded = NIDS_MODEL.predict(X_scaled)
        y_pred_proba = NIDS_MODEL.predict_proba(X_scaled).max(axis=1)[0]

        y_pred_labels_str = NIDS_LABEL_ENCODER.inverse_transform(y_pred_encoded)
        label_map = {"0": "normal", "1": "anomaly"}
        label_str = label_map.get(y_pred_labels_str[0], y_pred_labels_str[0])

        return label_str, float(y_pred_proba)

    # ---------- REPUTATION / FIREWALL ----------
    @staticmethod
    def _is_trusted_cdn(ip: str) -> bool:
        """Return True if ip belongs to a known CDN / infrastructure range."""
        return any(ip.startswith(prefix) for prefix in _TRUSTED_PREFIXES)

    def update_reputation(self, ip: str, alerts: List[str], ai_score: float, conn_count: int):
        if self.is_whitelisted(ip):
            return
        if self._is_trusted_cdn(ip):
            return

        with LOCKS['reputation']:
            rep = IP_REPUTATION[ip]
            rep_raw = (len(alerts) * 10 + ai_score * 20 + conn_count * 0.2)
            rep['score'] = 0.8 * rep['score'] + 0.2 * rep_raw
            rep['hits'] += 1
            rep['last_seen'] = time.time()

            has_strong_alert = any(a.startswith("L1-") or a.startswith("L5-") for a in alerts)
            BLOCK_THRESHOLD = 400.0  # raised from 120; prevents blocking high-volume legitimate IPs

            if has_strong_alert and rep['score'] > BLOCK_THRESHOLD:
                self._firewall_block(ip)

    def _firewall_block(self, ip: str) -> bool:
        with LOCKS['blocked']:
            if ip in BLOCKED_IPS:
                return True

        if self._is_trusted_cdn(ip):
            write_to_log(f"⚠️ Block suppressed for trusted CDN IP: {ip}", 'logs/NetPro.log')
            return False

        try:
            ts = int(time.time())
            base_name = f"Sentinel_BLOCK_{ip}_{ts}"

            # Use netsh (sub-second) instead of New-NetFirewallRule (3-10s timeout risk)
            directions = [("IN", "in"), ("OUT", "out")]
            for suffix, dir_flag in directions:
                rule_name = f"{base_name}_{suffix.upper()}"
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
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                    )
                    if result.returncode != 0:
                        write_to_log(
                            f"❌ netsh block failed for {ip} {dir_flag}: {result.stdout.strip()}",
                            'logs/NetPro.log'
                        )
                except Exception as e_inner:
                    write_to_log(f"❌ netsh exception for {ip}: {e_inner}", 'logs/NetPro.log')

            with LOCKS['blocked']:
                BLOCKED_IPS.add(ip)

            toast = Notification(
                app_id="Aria Security",
                title="Network Protection",
                msg=f"AUTO-BLOCKED IP: {ip}",
                icon=find_icon(SYSTEM_ICON_PATH),
                duration="long"
            )
            toast.set_audio(audio.SMS, loop=False)
            toast.show()

            write_to_log(f"🔥 AUTO-BLOCK {ip}", 'logs/NetPro.log')
            try:
                brain, _ThreatEvent, _ThreatCategory, _ThreatSeverity = _get_brain()
                brain.emit_block(ip, "Reputation threshold exceeded — inbound and outbound traffic blocked")
            except Exception:
                pass
            return True

        except Exception as e:
            write_to_log(f"❌ Exception in _firewall_block for {ip}: {e}", 'logs/NetPro.log')
            return False

    def packet_alert(self, ip_src: str, reason: str, weight: float = 15.0):
        if not ip_src:
            return
        alerts = [reason]
        synthetic_ai_score = weight / 10.0
        synthetic_conn_count = 1
        self.update_reputation(ip_src, alerts, synthetic_ai_score, synthetic_conn_count)

    @staticmethod
    def firewall_cleanup():
        try:
            # Delete all Sentinel_BLOCK_* rules via netsh (no PowerShell dependency)
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            import re as _re
            rule_names = _re.findall(r'^Rule Name:\s+(Sentinel_BLOCK_.+)', result.stdout, _re.MULTILINE)
            for rule_name in rule_names:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name.strip()}"],
                    capture_output=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            with LOCKS['blocked']:
                BLOCKED_IPS.clear()
            write_to_log(f"🧹 Cleanup complete ({len(rule_names)} rules removed)", 'logs/NetPro.log')
        except Exception as e:
            write_to_log(f"⚠️ Cleanup error: {e}", 'logs/NetPro.log')

    # ---------- CONNECTIONS ----------
    @staticmethod
    def get_connections() -> List[Dict]:
        try:
            ps_cmd = r'''
            Get-NetTCPConnection |
              ?{$_.RemoteAddress -notmatch "^127\.|^::1|^0\.0\.0\.0|::1?" -and $_.State -in @("Established","Listen","TimeWait")} |
              Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,
                     @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).ProcessName}},
                     @{N='PID';E={$_.OwningProcess}},
                     @{N='timestamp';E={(Get-Date -UFormat %s)}} |
              Sort RemoteAddress,RemotePort |
              ConvertTo-Json -Compress
            '''
            result = run_powershell_hidden(ps_cmd, timeout=12)

            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for c in data:
                    c['timestamp'] = _safe_timestamp(c.get('timestamp', None))
                return [dict(c) for c in data]
            return []
        except Exception:
            return []

    # ---------- AI WORKER ----------
    def analyze_ip_ai(self, ip_conns: List[Dict], all_conns: List[Dict]) -> Optional[Tuple[str, List[str], int, float]]:
        remote_ip = ip_conns[0].get('RemoteAddress', '') if ip_conns else ''
        if not remote_ip or remote_ip == 'Unknown':
            return None

        if self.is_whitelisted(remote_ip):
            return None

        if self._is_trusted_cdn(remote_ip):
            return None

        with LOCKS['blocked']:
            if remote_ip in BLOCKED_IPS:
                return None

        alerts = []
        ai_score = 0.0

        if self.layer1_blacklist_check(remote_ip):
            alerts.append("L1-BLACKLIST")
            ai_score += 30
        if self.layer2_volume_check(all_conns, remote_ip):
            alerts.append("L2-FLOOD")
            ai_score += 25
        if self.layer3_port_scan_check(all_conns, remote_ip):
            alerts.append("L3-SCAN")
            ai_score += 20

        # L-ABUSE: AbuseIPDB reputation (non-blocking async cache)
        _abuseipdb_key = _load_abuseipdb_key()
        if _abuseipdb_key:
            abuse_score = _get_abuseipdb_score(remote_ip)
            if abuse_score is None:
                _query_abuseipdb_async(remote_ip, _abuseipdb_key)
            elif abuse_score >= 75:
                alerts.append(f"L-ABUSE({abuse_score}%)")
                ai_score += 40
            elif abuse_score >= 50:
                alerts.append(f"L-ABUSE({abuse_score}%)")
                ai_score += 20

        # L5: feature-based IsolationForest
        features = self.ai_extract_features(ip_conns)
        ml_anomaly = self.ai_anomaly_score(features)
        ai_score += ml_anomaly * 10
        if ml_anomaly > 0.5:
            alerts.append(f"L5-AI({ml_anomaly:.2f})")

        # L5-NIDS: flow-based RandomForest (normal/anomaly)
        nids_result = self._nids_score_ip(ip_conns)
        if nids_result is not None:
            nids_label, nids_conf = nids_result
            if nids_label == "anomaly" and nids_conf >= 0.6:
                alerts.append(f"L5-NIDS({nids_conf:.2f})")
                ai_score += nids_conf * 40.0

        # L5b: integrated autoencoder/IsolationForest if available
        global NET_AUTOENCODER, NET_ISOFOREST, NET_SCALER, NETWORK_FEATURE_COLUMNS
        if NET_AUTOENCODER is not None and NET_ISOFOREST is not None and NET_SCALER is not None and NETWORK_FEATURE_COLUMNS is not None:
            df = connections_to_network_df(ip_conns)
            if not df.empty:
                anomalies, mse = detect_network_anomalies(NET_AUTOENCODER, NET_ISOFOREST, df)
                if anomalies.any():
                    extra_score = float(np.mean(mse))
                    ai_score += extra_score * 5
                    alerts.append(f"L5-NET({extra_score:.2f})")

        self.update_reputation(remote_ip, alerts, ai_score, len(ip_conns))

        threat_score = ai_score + len(alerts) * 15
        if threat_score > 50:
            return (remote_ip, alerts, len(ip_conns), threat_score)
        return None

    # ---------- PIPELINE ----------
    def analyze_and_protect(self, raw_conns: List[Dict]) -> List[Tuple[str, List[str], int, float]]:
        with LOCKS['history']:
            CONNECTION_HISTORY.extend(raw_conns)

        ip_stats = defaultdict(list)
        for conn in raw_conns:
            ip = conn.get('RemoteAddress', '')
            if ip and ip != 'Unknown':
                ip_stats[ip].append(conn)

        threats = []
        with ThreadPoolExecutor(max_workers=N_WORKERS) as executor:
            futures = {
                executor.submit(self.analyze_ip_ai, list(conns), raw_conns): ip
                for ip, conns in ip_stats.items()
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    threats.append(result)

        return sorted(threats, key=lambda x: x[3], reverse=True)

    def get_status(self, conns: List[Dict], threats: List) -> str:
        bad_reps = sum(1 for rep in IP_REPUTATION.values() if rep['score'] > 75)
        return (
            f"{time.strftime('%H:%M:%S')} | "
            f"C:{len(conns)} I:{len(set(c.get('RemoteAddress') for c in conns))} | "
            f"{len(threats)} | {bad_reps} | {len(BLOCKED_IPS)}"
        )

    # ---------- CLASSIC LAYERS ----------
    @staticmethod
    def layer1_blacklist_check(ip: str) -> bool:
        with LOCKS['blacklist']:
            return ip in BLACKLIST

    @staticmethod
    def layer2_volume_check(conns: List[Dict], ip: str) -> bool:
        return sum(1 for c in conns if c.get('RemoteAddress') == ip) > MAX_CONNS_PER_IP

    @staticmethod
    def layer3_port_scan_check(conns: List[Dict], ip: str) -> bool:
        ports = [_safe_int(c.get('RemotePort', 0)) for c in conns if c.get('RemoteAddress') == ip]
        return len(set(ports)) > 10 or sum(p in SUSPICIOUS_PORTS for p in ports) > 2

    # ---------- TRAINING ----------
    def train_ai_model(self):
        global AI_MODEL, SCALER
        with LOCKS['history']:
            conns = list(CONNECTION_HISTORY)

        if not conns:
            write_to_log("⚠️ No history to train on.", 'logs/NetPro.log')
            return

        X = []
        for ip, group in self._group_by_ip(conns).items():
            feat = self.ai_extract_features(group)
            X.append(feat)
        X = np.array(X)
        if len(X) < 20:
            write_to_log(f"⚠️ Not enough samples to train: {len(X)}", 'logs/NetPro.log')
            return

        SCALER = StandardScaler()
        X_scaled = SCALER.fit_transform(X)
        AI_MODEL = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        AI_MODEL.fit(X_scaled)

        with open(self.model_file, 'wb') as f:
            pickle.dump((AI_MODEL, SCALER), f)

        write_to_log(f"Trained IsolationForest on {len(X)} IP behavior vectors.", 'logs/NetPro.log')

    @staticmethod
    def _group_by_ip(conns: List[Dict]) -> Dict[str, List[Dict]]:
        groups = defaultdict(list)
        for c in conns:
            ip = c.get('RemoteAddress', '')
            if ip:
                groups[ip].append(c)
        return groups

    @staticmethod
    def is_whitelisted(ip: str) -> bool:
        if ip in WHITELIST:
            return True
        try:
            from Main_Unit.Engine.Service.SentinelWhitelist import get_whitelist
            return get_whitelist().is_whitelisted_ip(ip)
        except Exception:
            return False

# ============================================================================
# SCAPY PACKET SENSOR
# ============================================================================

class ScapySensor(threading.Thread):
    """Background Scapy-based packet sensor feeding Sentinel reputation system."""
    def __init__(self, engine: AINetworkProtector,
                 iface: Optional[str] = None,
                 bpf_filter: Optional[str] = None):
        super().__init__(daemon=True)
        self.engine = engine
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.running = threading.Event()
        self.running.set()

        self.packet_sizes = []
        self.window = 200  # last N packets for pattern checks

    def stop(self):
        self.running.clear()

    def _packet_callback(self, packet):
        if not self.running.is_set():
            return

        if not packet.haslayer(IP):
            return

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        pkt_len = len(packet)

        self.packet_sizes.append(pkt_len)
        if len(self.packet_sizes) > self.window:
            self.packet_sizes.pop(0)

        if pkt_len > 1500:
            self.engine.packet_alert(ip_src, "L0-PACKET-LARGE", weight=25.0)

        if len(self.packet_sizes) >= 50:
            last_slice = self.packet_sizes[-50:]
            if len(set(last_slice)) <= 2:
                self.engine.packet_alert(ip_src, "L0-PACKET-FLOOD", weight=30.0)

    def run(self):
        if not SCAPY_AVAILABLE:
            write_to_log("Scapy not available, packet sensor disabled.", 'logs/NetPro.log')
            return

        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._packet_callback,
                store=0,
                stop_filter=lambda p: not self.running.is_set()
            )
        except Exception as e:
            write_to_log(f"Scapy sensor error: {e}", 'logs/NetPro.log')

# ============================================================================
# SentinelAgentService
# ============================================================================

class SentinelAgentService:
    """Non-blocking controller for SentinelNetProtection - for UI integration."""

    def __init__(self, interval: float = 1.5, rules_file: str = IPS_FILE_PATH,
                 whitelist_file: str = WHITE_LIST_FILE_PATH, enable_scapy: bool = True):
        self.interval = interval
        self.engine = AINetworkProtector(rules_file, whitelist_file=whitelist_file)
        self.running = False
        self.monitor_thread = None
        self.sensor = None
        self.enable_scapy = enable_scapy and SCAPY_AVAILABLE

    def start_monitoring(self):
        if self.running:
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        if self.enable_scapy:
            self.sensor = ScapySensor(self.engine)
            self.sensor.start()
            write_to_log("📡 Scapy sensor started", 'logs/NetPro.log')

        write_to_log("🚀 Sentinel NetPro Service ACTIVE", 'logs/NetPro.log')
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("NetProtection", True)
        except Exception:
            pass

    def stop_monitoring(self):
        self.running = False
        if self.sensor:
            self.sensor.stop()
            self.sensor = None

        AINetworkProtector.firewall_cleanup()
        write_to_log("🛑 Sentinel NetPro Service STOPPED", 'logs/NetPro.log')
        try:
            brain, _, _, _ = _get_brain()
            brain.set_module_running("NetProtection", False)
        except Exception:
            pass

    def _monitor_loop(self):
        import traceback as _tb
        while self.running:
            try:
                t0 = time.time()
                conns = self.engine.get_connections()
                threats = self.engine.analyze_and_protect(conns)

                status = self.engine.get_status(conns, threats)
                write_to_log(f"{status} | ⏱️{time.time()-t0:.2f}s", 'logs/NetPro.log')

                if threats:
                    write_to_log("🚨 AI THREATS:", 'logs/NetPro.log')
                    for ip, alerts, count, score in threats[:8]:
                        write_to_log(f"  {score:6.1f} ❌ {ip:<15} ({count}c) {','.join(alerts)}", 'logs/NetPro.log')

            except Exception as e:
                write_to_log(
                    f"⚠️ Monitor error: {e}\n{_tb.format_exc()}",
                    'logs/NetPro.log',
                )

            time.sleep(self.interval)

    def auto_collect_and_train(self, monitor_minutes: float, extra_collect_minutes: Optional[float] = 0):
        write_to_log(f"🚀 AUTO: Monitor {monitor_minutes}min + collect {extra_collect_minutes or 0}min → TRAIN", 'logs/NetPro.log')

        self.start_monitoring()
        write_to_log("✅ Monitoring started (building baseline history)...", 'logs/NetPro.log')

        time.sleep(monitor_minutes * 60)
        history_pre = len(CONNECTION_HISTORY)
        write_to_log(f"📊 Pre-training history: {history_pre} samples", 'logs/NetPro.log')

        if extra_collect_minutes > 0:
            write_to_log(f"📡 Extra collection: {extra_collect_minutes}min...", 'logs/NetPro.log')
            self._collect_and_train_blocking(extra_collect_minutes)

        self.stop_monitoring()
        write_to_log("🛑 Monitoring stopped", 'logs/NetPro.log')

        history_final = len(CONNECTION_HISTORY)
        write_to_log(f"🧠 Training {history_final} samples...", 'logs/NetPro.log')
        if history_final >= 20:
            self.engine.train_ai_model()
            write_to_log("✅ Model trained & saved! Ready for deployment.", 'logs/NetPro.log')
        else:
            write_to_log(f"⚠️ Low samples ({history_final}). Repeat with more traffic.", 'logs/NetPro.log')

    def train_model_async(self, collect_minutes: Optional[float] = None):
        def _worker():
            try:
                self.train_model(collect_minutes=collect_minutes)
            except Exception as e:
                write_to_log(f"⚠️ train_model_async error: {e}", 'logs/NetPro.log')

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return t

    def train_model(self, collect_minutes: Optional[float] = None):
        if collect_minutes is not None:
            self._collect_and_train_blocking(collect_minutes)
        else:
            history_count = len(CONNECTION_HISTORY)
            write_to_log(f"🧠 Training requested on existing history ({history_count} samples)...", 'logs/NetPro.log')
            if history_count >= 20:
                self.engine.train_ai_model()
                write_to_log("✅ Model trained & saved (Sentinel_ai.model)", 'logs/NetPro.log')
            else:
                write_to_log("⚠️ Insufficient history. Use collect_minutes or run monitoring longer.", 'logs/NetPro.log')

    def _collect_and_train_blocking(self, minutes: float):
        seconds = int(minutes * 60)
        write_to_log(f"📡 BLOCKING collection: {minutes:.1f}min before training...", 'logs/NetPro.log')

        if not self.running:
            self.start_monitoring()
            write_to_log("✅ Monitoring started (blocking collect)...", 'logs/NetPro.log')

        start_time = time.time()

        while time.time() - start_time < seconds:
            elapsed_min = (time.time() - start_time) / 60
            history_size = len(CONNECTION_HISTORY)
            write_to_log(
                f"[{elapsed_min:.1f}/{minutes:.1f}min] History: {history_size}",
                'logs/NetPro.log'
            )
            time.sleep(self.interval)

        self.stop_monitoring()
        write_to_log("🛑 Monitoring stopped (blocking collect finished)", 'logs/NetPro.log')

        history_count = len(CONNECTION_HISTORY)
        write_to_log(f"🧠 Training {history_count} samples from {minutes:.1f}min collection...", 'logs/NetPro.log')
        if history_count >= 20:
            self.engine.train_ai_model()
            write_to_log("✅ Model trained & saved (Sentinel_ai.model)", 'logs/NetPro.log')
        else:
            write_to_log(
                f"⚠️ STILL insufficient ({history_count}). Increase minutes or generate more traffic.",
                'logs/NetPro.log'
            )

    def get_status(self) -> dict:
        return {
            'running': self.running,
            'blocked_ips': len(BLOCKED_IPS),
            'bad_reps': sum(1 for rep in IP_REPUTATION.values() if rep['score'] > 75),
            'history_size': len(CONNECTION_HISTORY)
        }

# ============================================================================
# CLI
# ============================================================================

def cli_main():
    parser = argparse.ArgumentParser(description="Sentinel AI v4.0 - ML Network Guardian (Integrated)")
    parser.add_argument("-i", "--interval", type=float, default=1.5, help="Scan interval (s)")
    parser.add_argument("-r", "--rules", default=IPS_FILE_PATH)
    parser.add_argument("--train", action="true", help="Train AI model from history")
    parser.add_argument(
        "--collect-and-train",
        nargs="?",
        const=5.0,
        type=float,
        metavar="MINUTES",
        help="Collect traffic for N minutes (default 5) then train AI model"
    )
    parser.add_argument("--no-scapy", action="store_true", help="Disable Scapy packet sensor")
    parser.add_argument("--whitelist-file", default=WHITE_LIST_FILE_PATH, help="Path to IP whitelist file (one IP per line)")
    args = parser.parse_args()

    engine = AINetworkProtector(args.rules, whitelist_file=args.whitelist_file)

    write_to_log("Sentinel AI v4.0 ACTIVATED", 'logs/NetPro.log')
    write_to_log("ML Anomaly + Behavioral + 6-Layer Defense + Integrated Models", 'logs/NetPro.log')
    write_to_log("16x Parallel | Dynamic Reputation | Auto-Learn", 'logs/NetPro.log')

    sensor = None
    if not args.no_scapy and SCAPY_AVAILABLE:
        sensor = ScapySensor(engine)
        sensor.start()
        write_to_log("Scapy packet sensor enabled", 'logs/NetPro.log')

    if args.collect_and_train is not None:
        minutes = args.collect_and_train
        seconds = minutes * 60.0
        write_to_log(f"Collecting traffic for {minutes:.1f} minute(s) before training...", 'logs/NetPro.log')
        start = time.time()
        try:
            while time.time() - start < seconds:
                t0 = time.time()
                conns = engine.get_connections()
                threats = engine.analyze_and_protect(conns)
                write_to_log(f"{engine.get_status(conns, threats)} | {time.time()-t0:.2f}s", 'logs/NetPro.log')
                time.sleep(args.interval)
        except KeyboardInterrupt:
            write_to_log("\nCollection interrupted, training on collected history...", 'logs/NetPro.log')

        write_to_log("Training AI model from collected history...", 'logs/NetPro.log')
        engine.train_ai_model()
        if sensor is not None:
            sensor.stop()
        return

    if args.train:
        write_to_log("Training AI model from history...", 'logs/NetPro.log')
        engine.train_ai_model()
        return

    try:
        while True:
            t0 = time.time()
            conns = engine.get_connections()
            threats = engine.analyze_and_protect(conns)

            write_to_log(f"{engine.get_status(conns, threats)} | {time.time()-t0:.2f}s", 'logs/NetPro.log')

            if threats:
                write_to_log("AI THREATS:", 'logs/NetPro.log')
                for ip, alerts, count, score in threats[:8]:
                    write_to_log(f"  {score:6.1f} ❌ {ip:<15} ({count}c) {','.join(alerts)}", 'logs/NetPro.log')

            time.sleep(args.interval)
    except KeyboardInterrupt:
        write_to_log("\nShutdown.", 'logs/NetPro.log')
    finally:
        if sensor is not None:
            sensor.stop()
        AINetworkProtector.firewall_cleanup()

if __name__ == "__main__":
    cli_main()
