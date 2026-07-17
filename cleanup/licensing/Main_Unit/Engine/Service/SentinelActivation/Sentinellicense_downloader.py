# Sentinellicense_downloader.py

import json
import os
import sys
from pathlib import Path
import requests

LICENSE_CONFIG_URL = "https://github.com/headlessripper/AriaSecurity/releases/download/License_Config/license_configuration.json"
CONFIG_DIR = Path.home() / ".AriaSecurity" / "config"
CONFIG_FILE = CONFIG_DIR / "license_configuration.json"


def ensure_license_config():
    """Download license_configuration.json to a hidden user dir if missing."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if CONFIG_FILE.exists():
        return  # already have it

    try:
        resp = requests.get(LICENSE_CONFIG_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()  # just to validate it’s valid JSON
        CONFIG_FILE.write_text(resp.text, encoding="utf-8")
    except Exception as e:
        print(f"Failed to download license config: {e}")
        return False

    return True
