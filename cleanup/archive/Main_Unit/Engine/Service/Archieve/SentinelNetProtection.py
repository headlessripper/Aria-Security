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
# Try to import Scapy for packet sensor
try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    
import subprocess
import ctypes

def run_powershell_hidden(cmd: str, timeout: int = 12):
    """
    Run a PowerShell command with no visible window.
    Works for PyInstaller GUI builds too. [web:132]
    """
    # STARTF_USESHOWWINDOW = 0x00000001, SW_HIDE = 0
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
CONNECTION_HISTORY = deque(maxlen=10000000)

LOCKS = {
    'blacklist': threading.Lock(),
    'blocked': threading.Lock(),
    'reputation': threading.Lock(),
    'history': threading.Lock()
}

SUSPICIOUS_PORTS = {21, 22, 23, 445, 1433, 3389, 5432, 5900}
N_WORKERS = 16
MAX_CONNS_PER_IP = 20

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

def load_whitelist(path: str = "whitelist_ips.txt"):
    global WHITELIST
    p = Path(path)
    if not p.exists():
        return
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            # strip whitespace and ignore empty lines
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

    if _np.isnan(predictions).any() or X_test.isna().any().any():
        predictions = _np.nan_to_num(predictions)
        X_test_clean = X_test.fillna(0)
    else:
        X_test_clean = X_test

    mse = _np.mean(_np.power(X_test_clean - predictions, 2), axis=1)
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

def connections_raw_to_df(conns: List[Dict]) -> pd.DataFrame:
    if not conns:
        return pd.DataFrame(columns=[
            'bytes_sent', 'bytes_received', 'duration',
            'port', 'protocol_type', 'service', 'flag'
        ])

    rows = []
    now = time.time()
    for c in conns:
        rows.append({
            'bytes_sent': float(c.get('BytesSent', 0)),
            'bytes_received': float(c.get('BytesReceived', 0)),
            'duration': float(now - _safe_timestamp(c.get('timestamp', now))),
            'port': int(c.get('RemotePort', 0)),
            'protocol_type': 'tcp',
            'service': 'unknown',
            'flag': c.get('State', 'SF')
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

def extract_pe_features(file_path: str) -> Dict:
    np.random.seed(int(hash(file_path) % 2**32))
    features = {
        'filesize': np.random.randint(10000, 10000000),
        'num_sections': np.random.randint(1, 20),
        'num_imports': np.random.randint(10, 500),
        'num_exports': np.random.randint(0, 50),
        'contains_packer_sig': np.random.choice([0, 1], p=[0.7, 0.3]),
        'entry_point_entropy': np.random.uniform(0, 8),
        'avg_section_entropy': np.random.uniform(0, 8),
        'has_digital_signature': np.random.choice([0, 1], p=[0.6, 0.4]),
        'has_tls_callback': np.random.choice([0, 1], p=[0.9, 0.1]),
        'has_anti_debug': np.random.choice([0, 1], p=[0.8, 0.2]),
        'has_anti_vm': np.random.choice([0, 1], p=[0.8, 0.2])
    }
    return features

def extract_email_features(email_content: str) -> Dict:
    features = {
        'has_urgent_subject': bool(re.search(r'urgent|immediate|alert|critical', email_content, re.I)),
        'has_suspicious_links': bool(re.search(r'href=["\']https?://[^\/]*?(?:\d{1,3}\.){3}\d{1,3}', email_content)),
        'has_password_request': bool(re.search(r'password|credential|login|sign in', email_content, re.I)),
        'has_attachment_mention': bool(re.search(r'attach|download|open|file', email_content, re.I)),
        'has_financial_terms': bool(re.search(r'bank|account|money|transfer|paypal|credit|debit', email_content, re.I)),
        'has_misspellings': bool(re.search(r'verifcation|accaunt|securty|notifcation', email_content, re.I)),
        'email_length': len(email_content),
        'link_count': len(re.findall(r'href=["\']https?://', email_content)),
        'image_count': len(re.findall(r'<img', email_content))
    }
    return features

def preprocess_email_text(email_content: str) -> str:
    text = re.sub(r'<[^>]+>', ' ', email_content)
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'https?://\S+', '', text)
    return text

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
        if self.rules_file.exists():
            try:
                with open(self.rules_file, 'r', encoding='utf-8', errors='ignore') as f:
                    ips = re.findall(
                        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b',
                        f.read()
                    )
                BLACKLIST = set(ips)
                write_to_log(f"✅ L0: {len(BLACKLIST):,} signatures", 'logs/NetPro.log')
            except Exception as e:
                write_to_log(f"⚠️ L0 load: {e}", 'logs/NetPro.log')

    # ---------- MODEL LOAD ----------
    def init_ai_models(self):
        global AI_MODEL, SCALER, NET_AUTOENCODER, NET_ISOFOREST, NET_SCALER
        global MALWARE_DETECTOR, PHISH_VECTOR, PHISH_DETECTOR, NETWORK_FEATURE_COLUMNS

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

    # ---------- FEATURE EXTRACTION ----------
    def ai_extract_features(self, ip_conns: List[Dict]) -> np.ndarray:
        if not ip_conns:
            return np.zeros(12, dtype=np.float64)

        ports = [int(c.get('RemotePort', 0)) for c in ip_conns]
        procs = [c.get('ProcessName', 'Unknown') or 'Unknown' for c in ip_conns]  # Fix: None → 'Unknown'
        states = [c.get('State', 'SF') or 'SF' for c in ip_conns]  # Fix: None → 'SF'

        timestamps = [_safe_timestamp(c.get('timestamp', None)) for c in ip_conns]
        session_duration = float(time.time() - min(timestamps)) if timestamps else 0.0

        return np.array([
            len(ip_conns),
            len(set(ports)),
            sum(1 for p in ports if p in SUSPICIOUS_PORTS),
            np.std(ports) if len(ports) > 1 else 0.0,
            len(set(procs)),  # Safe now
            len(set(states)),  # Safe now
            sum(1 for s in states if s == 'Established'),
            sum(1 for p in procs if p.lower() in {'svchost', 'lsass'}),  # Safe now
            max(ports) - min(ports) if ports else 0.0,
            len([p for p in ports if p < 1024]),
            len(set(c.get('LocalPort', 0) for c in ip_conns)),
            session_duration
        ], dtype=np.float64)

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

    # ---------- REPUTATION / FIREWALL ----------
    def update_reputation(self, ip: str, alerts: List[str], ai_score: float, conn_count: int):
        # safeguard 1: never block whitelisted IPs
        if self.is_whitelisted(ip):
            return

        with LOCKS['reputation']:
            rep = IP_REPUTATION[ip]
            rep_raw = (len(alerts) * 10 + ai_score * 20 + conn_count * 0.2)  # toned-down weights
            rep['score'] = 0.8 * rep['score'] + 0.2 * rep_raw
            rep['hits'] += 1
            rep['last_seen'] = time.time()

            # safeguard 2: require at least one "strong" alert to ever block
            has_strong_alert = any(a.startswith("L1-") or a.startswith("L5-") for a in alerts)

            # higher block threshold to reduce false positives
            BLOCK_THRESHOLD = 120.0

            if has_strong_alert and rep['score'] > BLOCK_THRESHOLD:
                self._firewall_block(ip)

    def _firewall_block(self, ip: str) -> bool:
        with LOCKS['blocked']:
            if ip in BLOCKED_IPS:
                return True
        try:
            cmds = [
                f'New-NetFirewallRule -DisplayName "Sentinel_BLOCK_{ip}" -Direction Inbound -Action Block -RemoteAddress {ip}',
                f'New-NetFirewallRule -DisplayName "Sentinel_BLOCK_{ip}_OUT" -Direction Outbound -Action Block -RemoteAddress {ip}'
            ]
            for cmd in cmds:
                run_powershell_hidden(cmd, timeout=3)
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
            return True
        except Exception:
            return False

    def packet_alert(self, ip_src: str, reason: str, weight: float = 15.0):
        """Called by Scapy sensor: update reputation based on raw packet anomalies."""
        if not ip_src:
            return
        alerts = [reason]
        synthetic_ai_score = weight / 10.0
        synthetic_conn_count = 1
        self.update_reputation(ip_src, alerts, synthetic_ai_score, synthetic_conn_count)

    @staticmethod
    def firewall_cleanup():
        try:
            subprocess.run(
                ['powershell.exe', '-Command',
                 'Get-NetFirewallRule | ?{$_.DisplayName -like "Sentinel_BLOCK_*"} | Remove-NetFirewallRule -Force'],
                capture_output=True
            )
            with LOCKS['blocked']:
                BLOCKED_IPS.clear()
            write_to_log("🧹 Cleanup complete", 'logs/NetPro.log')
        except Exception:
            pass

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
        
        # skip analysis for whitelisted IPs
        if self.is_whitelisted(remote_ip):
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

        # L5: feature-based IsolationForest
        features = self.ai_extract_features(ip_conns)
        ml_anomaly = self.ai_anomaly_score(features)
        ai_score += ml_anomaly * 10
        if ml_anomaly > 0.5:
            alerts.append(f"L5-AI({ml_anomaly:.2f})")

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
        ports = [int(c.get('RemotePort', 0)) for c in conns if c.get('RemoteAddress') == ip]
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
    
        # ---------- CLASSIC LAYERS ----------
    @staticmethod
    def layer1_blacklist_check(ip: str) -> bool:
        with LOCKS['blacklist']:
            return ip in BLACKLIST

    @staticmethod
    def is_whitelisted(ip: str) -> bool:
        return ip in WHITELIST


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

        # Large packet
        if pkt_len > 1500:
            self.engine.packet_alert(ip_src, "L0-PACKET-LARGE", weight=25.0)

        # Repetitive size flood heuristic
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
            
# Add after class AINetworkProtector, before cli_main()

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
        """Start live monitoring in background thread."""
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
        
    def stop_monitoring(self):
        """Stop monitoring gracefully."""
        self.running = False
        if self.sensor:
            self.sensor.stop()
            self.sensor = None
            
        AINetworkProtector.firewall_cleanup()
        write_to_log("🛑 Sentinel NetPro Service STOPPED", 'logs/NetPro.log')
        
    def _monitor_loop(self):
        """Background monitoring loop."""
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
                write_to_log(f"⚠️ Monitor error: {e}", 'logs/NetPro.log')
                
            time.sleep(self.interval)
            
    def auto_collect_and_train(self, monitor_minutes: float, extra_collect_minutes: Optional[float] = 0):
        """
        COMPLETE FLOW: 
        1. Start monitoring for monitor_minutes
        2. [Optional] Extra silent collection
        3. Stop monitoring
        4. Train model
        """
        #total_minutes = monitor_minutes + (extra_collect_minutes or 0)
        write_to_log(f"🚀 AUTO: Monitor {monitor_minutes}min + collect {extra_collect_minutes or 0}min → TRAIN", 'logs/NetPro.log')
        
        # 1. START MONITORING
        self.start_monitoring()
        write_to_log("✅ Monitoring started (building baseline history)...", 'logs/NetPro.log')
        
        # 2. Monitor for specified time
        time.sleep(monitor_minutes * 60)
        history_pre = len(CONNECTION_HISTORY)
        write_to_log(f"📊 Pre-training history: {history_pre} samples", 'logs/NetPro.log')
        
        # 3. OPTIONAL extra collection (without monitor loop)
        if extra_collect_minutes > 0:
            write_to_log(f"📡 Extra collection: {extra_collect_minutes}min...", 'logs/NetPro.log')
            self._collect_and_train_blocking(extra_collect_minutes)  # Uses fixed blocking version
        
        # 4. STOP MONITORING
        self.stop_monitoring()
        write_to_log("🛑 Monitoring stopped", 'logs/NetPro.log')
        
        # 5. TRAIN
        history_final = len(CONNECTION_HISTORY)
        write_to_log(f"🧠 Training {history_final} samples...", 'logs/NetPro.log')
        if history_final >= 20:
            self.engine.train_ai_model()
            write_to_log("✅ Model trained & saved! Ready for deployment.", 'logs/NetPro.log')
        else:
            write_to_log(f"⚠️ Low samples ({history_final}). Repeat with more traffic.", 'logs/NetPro.log')
            
    def train_model_async(self, collect_minutes: Optional[float] = None):
        """
        Run train_model in a separate thread.
        This is safe for CLI callers that want non-blocking behavior
        and for any future integration (e.g. GUI) without freezing.
        """
        def _worker():
            try:
                self.train_model(collect_minutes=collect_minutes)
            except Exception as e:
                write_to_log(f"⚠️ train_model_async error: {e}", 'logs/NetPro.log')

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return t  # Return thread handle if caller wants to join/check

    def train_model(self, collect_minutes: Optional[float] = None):
        """
        Train AI model.
        - If collect_minutes is given: start monitoring, collect for that duration, stop, then train.
        - If collect_minutes is None: train on whatever history already exists.
        """
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
        """
        BLOCKING end‑to‑end:
        1) Start monitoring (if not running)
        2) Let monitor loop collect for N minutes
        3) Stop monitoring
        4) Train on collected CONNECTION_HISTORY
        """
        seconds = int(minutes * 60)
        write_to_log(f"📡 BLOCKING collection: {minutes:.1f}min before training...", 'logs/NetPro.log')

        # 1) Start monitoring if not already running
        if not self.running:
            self.start_monitoring()
            write_to_log("✅ Monitoring started (blocking collect)...", 'logs/NetPro.log')

        start_time = time.time()

        # 2) Let the existing _monitor_loop do the work; we just wait and log progress
        while time.time() - start_time < seconds:
            elapsed_min = (time.time() - start_time) / 60
            history_size = len(CONNECTION_HISTORY)
            write_to_log(
                f"[{elapsed_min:.1f}/{minutes:.1f}min] History: {history_size}",
                'logs/NetPro.log'
            )
            time.sleep(self.interval)

        # 3) Stop monitoring
        self.stop_monitoring()
        write_to_log("🛑 Monitoring stopped (blocking collect finished)", 'logs/NetPro.log')

        # 4) Train
        history_count = len(CONNECTION_HISTORY)
        write_to_log(f"🧠 Training {history_count} samples from {minutes:.1f}min collection...", 'logs/NetPro.log')
        if history_count >= 20:
            self.engine.train_ai_model()
            write_to_log("✅ Model trained & saved (Sentinel_ai.model)", 'logs/NetPro.log')
        else:
            write_to_log(
                f"⚠️ STILL insufficient ({history_count}). "
                f"Increase minutes or generate more traffic.",
                'logs/NetPro.log'
            )
        
    def get_status(self) -> dict:
        """Get current status for UI."""
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
    parser.add_argument("--train", action="store_true", help="Train AI model from history")
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
