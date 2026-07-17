# Main_Unit/Service/Sentinelactivation_check.py

import os
import sys
import json
from pathlib import Path

from Main_Unit.Engine.Service.SentinelActivation.activate_hwid import activate_hwid

ACTIVATED_FILE = Path("./activated_lock.json")


def ensure_activated_once():
    """
    If activated_lock.json is missing, run activate_hwid() to create hwid.lock,
    then create activated_lock.json. If present, do nothing.
    """
    if ACTIVATED_FILE.exists():
        return  # already activated on this machine

    # call function instead of subprocess
    activate_hwid()

    ACTIVATED_FILE.write_text(
        json.dumps({"activated": True}, indent=2),
        encoding="utf-8"
    )
