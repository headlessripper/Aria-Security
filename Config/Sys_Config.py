# Sys_Config.py - FIXED

import os
import json
import socket 
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from PySide6.QtGui import QColor
from Interface.get_local_ip import get_local_ip

APP_NAME = "Aria Security"  # Updated to match your AV branding
COMPILER_VERSION = "SentinelCompiler_v5"
VERSION = "1.0.4"
DEVELOPER = "Samuel Ikenna Great"

RANSOM_BASE_DIR = Path.home() / ".AriaSecurity" / "RansomProtect"


# ----------------------------
# Find a free port
# ----------------------------
def find_free_port():
    """Find a free local port to use for the server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

COMMAND_PORT = find_free_port()

PAIR_PORT = 2255 #find_free_port()

MY_IP = get_local_ip()


# ------------------------
# Feature registry
# ------------------------
ALL_FEATURES = {
    "feature_advanced_tools",
    "feature_cloud_analysis",
    "feature_usb_control",
    "feature_firewall",
    "feature_ransomware_guard",
    "feature_behavioral_engine",
    "feature_threat_intel",
    "feature_sandbox",
    #"feature_copilot",          # future: LLM-assisted analysis
    #"feature_traceroute_analysis",
    #"feature_netmon",
    #"feature_task_manager"
}

user_profile = os.path.expanduser("~")
watch_dirs = [
    os.path.join(user_profile, "Documents", "TestRansom"),
    os.path.join(user_profile, "Desktop"),
    os.path.join(user_profile, "Downloads"),
    os.path.join(user_profile, "Pictures"),
    os.path.join(user_profile, "Music"),
    os.path.join(user_profile, "Videos"),
]

APP_DESCRIPTION = """ 
    Aria Security is an AI-powered antivirus and system defense platform built for real-time protection. \n
    It goes beyond traditional signature-based security by analyzing behavior, monitoring system activity, and responding instantly to threats. \n
    The platform actively safeguards processes, network connections, USB devices, and critical system areas, automatically blocking, isolating, and neutralizing suspicious activity before damage occurs. \n
    Designed to run efficiently in the background, Aria Security gives you powerful control through a modern, intuitive interface. \n
    Aria Security isn’t just antivirus software it’s an intelligent digital guardian for modern systems.

"""

BUILD_DATE = "2026-05-20"

DETECTION_MODEL_PATH = "Engine/Model/pe_detector.onnx"
FEATURES_META_PATH = "Engine/Model/features.json"
FUZZY_DB_PATH = "Engine/Signatures/fuzzy_bad.txt"
SYSTEM_ICON_PATH = "Interface/Icons/Icon-48.png"
SYSTEM_ICON_MID_PATH = "Interface/Icons/Icon-96.png"
SYSTEM_ICON_BIG_PATH = "Interface/Icons/Icon-100.png"
DANGER_ICON_PATH = "Interface/Icons/danger-48.png"
CONFIG_PATH = "Config/Config.json"
RULE_PATH = "Engine/Rules"
HASH_FILE_PATH = "Engine/Signatures/malware_hashes.txt"
HASH256_FILE_PATH = "Engine/Signatures/SHA256-Hashes.txt"
IPS_FILE_PATH = "Engine/Signatures/Sentinel_Rules_B1.ips"
WHITE_LIST_FILE_PATH = "Engine/Whitelist/whitelist_ips.txt"
NET_LOG_LOGGING_FILE = "logs/NetPro.log"
BEHAVIORAL_RULES_PATH = "Engine/Rules/behavioral_rules.json"
SANDBOX_LOG_PATH = "logs/Sandbox.log"
THREAT_INTEL_CACHE_DIR = str(Path.home() / ".AriaSecurity" / "ThreatIntel")

OWNER = 'headlessripper'
REPO = 'AriaSecurity'
CURRENT_VERSION = '1.0.4'

ENGINE_UNIT_CONTEXT = 8192
ENGINE_UNIT_THREADS = 6
ENGINE_UNIT_GPU_LAYERS = -1
ENGINE_UNIT_TEMPERATURE = 0.0

SCAN_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.sys', '.msi',
    '.bat', '.cmd', '.ps1',
    '.js', '.vbs', '.jar',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf', '.pdf',
    '.zip', '.rar', '.7z', '.iso', '.com', '.pdf.exe', '.docm', '.xlsm', '.pptm',
    '.hta', '.cpl', '.pif', '.lnk', '.gadget', '.xll', '.xla',
    '.xlam', '.wsf', '.lock', '.encrypted', '.crypto', '.cry', '.locked',
    '.ryk', '.conti', '.lockbit', '.wannacry', '.darkside'
}

PE_EXTENSIONS = {
    '.exe', '.dll', '.sys', '.scr', '.com',
    '.cpl', '.pif', '.gadget',
    '.xll', '.xla', '.xlam',
    '.msi', '.msp', '.mst',
    '.ocx', '.ax', '.drv',
    '.efi'
}

ORG_NAME = "AriaSecurity"
APP_NAME_WIDGET = "SentinelWidget"

ICON_SIZE = 24  # center icon 24x24

# Color scheme based on #3e3e3e and #000000
COLOR_BG_GLASS = QColor("#3e3e3e")
COLOR_BG_GLASS.setAlpha(210)
COLOR_BG_HALO = QColor("#000000")
COLOR_BG_HALO.setAlpha(120)
COLOR_ACCENT = QColor("#000000")
COLOR_BORDER = QColor("#000000")
COLOR_SLICE = QColor("#000000")
COLOR_SLICE.setAlpha(210)
COLOR_SLICE_HOVER = QColor("#3e3e3e")
COLOR_SLICE_HOVER.setAlpha(240)
COLOR_SLICE_ACTIVE = QColor("#000000")
COLOR_SLICE_ACTIVE.setAlpha(255)
COLOR_SLICE_BORDER = QColor("#3e3e3e")
COLOR_ICON = QColor("#ffffff")

def is_pe_file(path):
    with open(path, 'rb') as f:
        return f.read(2) == b'MZ'

def _get_default_user_paths() -> List[str]:
    paths = [
        os.path.expanduser('~/Desktop'),
        os.path.expanduser('~/Documents'),
        os.path.expanduser('~/Downloads'),
        os.path.expanduser('~/Pictures'),
        os.path.expanduser('~/Videos'),
        os.path.expanduser('~/Music'),
        str(Path.home() / 'Projects'),
        str(Path.home() / 'Code'),
        str(Path.home() / 'src')
    ]
    return [p.replace('/', os.sep) for p in paths if os.path.exists(p)]

_DEFAULT_IGNORE_PATTERNS = (
    '*~', '*.tmp', '*.temp', '*.bak', '*.swp', '*.swo',
    '*.db-journal', '*.lock', '*.lck', 'Thumbs.db', 'desktop.ini',
    'Network*', 'Local State', 'RGStats.*', 'cookies*', 'session*',
    '__pycache__', '.git', 'node_modules', '.vscode', '.idea',
    '$RECYCLE.BIN', 'System Volume Information'
)

def get_default_ignore_patterns() -> List[str]:
    return list(_DEFAULT_IGNORE_PATTERNS)

config_default = {
    "App_Name": APP_NAME,
    "Version": "1.0.0",
    "Suffix": [".com", ".dll", ".drv", ".exe", ".ocx", ".scr", ".sys", ".mui", ".cpl"],
    "Size": 256 * 1024 * 1024,  # 256MB max scan size
    "Sensitive": 95,             # ML confidence threshold %
    "Detection_Model_Path": DETECTION_MODEL_PATH,
    "virustotal_api_key": "1bdb6aec8a69dd996307bbb7b087393dcc1e3fd404062b1641ce04801815c1dd",    # VirusTotal API key (free tier at virustotal.com)
    "abuseipdb_api_key": "052579d2ae828eb078efcd8f49b56f59c6cb34f032dff0cbd7b3c2985a3d4f935193f501973fa319",     # AbuseIPDB API key (free tier at abuseipdb.com)
    "ransomware_protection": True,
    "usb_auto_scan": True,
    "behavioral_engine": True,
    "threat_intel_feeds": True,
    "sandbox_on_suspicious": True,
}

license_agreement = """
Aria Security AI Antivirus License Agreement
Last updated: 2026-1-21

This License Agreement (“Agreement”) is a legal agreement between you (an individual or a single entity) 
and the developer of Aria Security (“Developer”) for the software application Aria Security (“Software”).

BY INSTALLING, COPYING, OR USING THE SOFTWARE, YOU AGREE TO BE BOUND BY THE TERMS OF THIS AGREEMENT. 
IF YOU DO NOT AGREE, DO NOT INSTALL OR USE THE SOFTWARE.

1. License Grant
The Developer grants you a non-exclusive, non-transferable, revocable license to use Aria Security 
on your devices for personal or internal business purposes in accordance with this Agreement.

2. Restrictions
You may NOT:
  - Modify, adapt, or create derivative works based on the Software.
  - Reverse engineer, decompile, or disassemble the Software.
  - Rent, lease, or sublicense the Software.
  - Use the Software to distribute malware or perform any illegal activities.

3. Ownership
The Software is licensed, not sold. The Developer retains all rights, title, and interest in the Software, 
including all intellectual property rights.

4. Updates
The Developer may provide updates, patches, or new versions of the Software. You are not obligated to install updates, 
but doing so may be required for continued functionality.

5. Limitation of Liability
The Software is provided "as is" without warranty of any kind. The Developer shall not be liable for any damages 
arising from the use or inability to use the Software, including loss of data, profits, or other incidental or consequential damages.

6. Termination
This Agreement is effective until terminated. You may terminate it by uninstalling the Software. 
The Developer may terminate this Agreement if you fail to comply with any terms herein. 
Upon termination, you must cease all use of the Software and delete all copies.

7. Governing Law
This Agreement shall be governed by and construed in accordance with the laws of the jurisdiction in which the Developer resides.

By using Aria Security, you acknowledge that you have read, understood, and agree to be bound by the terms of this License Agreement.
"""


def save_config(file_path, config):
    """Save config to JSON, filtering UI-specific keys"""
    try:
        # Filter out widget-specific keys (safe even without self.widgets)
        filter_config = {}
        for k, v in config.items():
            if not (k.endswith("_button") and isinstance(v, bool)):
                filter_config[k] = v
        
        # Ensure directory exists
        path = os.path.dirname(file_path) or "."
        os.makedirs(path, exist_ok=True)
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(filter_config, f, indent=4, ensure_ascii=False)
        print(f"✅ Config saved: {file_path}")
    except Exception as e:
        print(f"❌ save_config error: {e}")

def read_config(file_path, default_value):
    """Load config with defaults fallback"""
    try:
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return default_value.copy()
    except Exception as e:
        print(f"❌ read_config error: {e}")
        return default_value.copy()

config = read_config(CONFIG_PATH, config_default)

def load_config():
    """Load config with version migration"""
    
    if not config:
        print("⚠️ Config.json is empty or invalid, loading defaults.")
        return config_default.copy()
    
    if config.get("Compiler_Version") != COMPILER_VERSION:
        config["Compiler_Version"] = COMPILER_VERSION
        save_config(CONFIG_PATH, config)
        print("🔄 Reset invalid config to defaults.")
        return config_default.copy()
    
    if config.get("DETECTION_MODEL_PATH") != DETECTION_MODEL_PATH:
        config["DETECTION_MODEL_PATH"] = DETECTION_MODEL_PATH
        save_config(CONFIG_PATH, config)
        print("🔄 Reset invalid config to defaults.")
        return config_default.copy()
    
    # Auto-upgrade config version
    if config.get("version") != VERSION:
        config["version"] = VERSION
        save_config(CONFIG_PATH, config)
        print(f"🔄 Config upgraded to v{VERSION}")
        
    if config.get("Suffix") is None:
        config["Suffix"] = config_default["Suffix"]
        save_config(CONFIG_PATH, config)
        print("🔄 Added missing 'Suffix' to config")

    if config.get("Size") is None:
        config["Size"] = config_default["Size"]
        save_config(CONFIG_PATH, config)
        print("🔄 Added missing 'Size' to config")
        
    if config.get("Sensitive") is None:
        config["Sensitive"] = config_default["Sensitive"]
        save_config(CONFIG_PATH, config)
        print("🔄 Added missing 'Sensitive' to config")    
    
    return config

# Global config loader (use this everywhere)
#CONFIG = load_config()
