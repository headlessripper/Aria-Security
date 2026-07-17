# Main_Unit/Service/activate_hwid.py

from pathlib import Path
from Main_Unit.Engine.Service.SentinelActivation.Sentinelhwid_lock import compute_hwid, HWID_FILE
from Main_Unit.Service.write_to_log import write_to_log

def activate_hwid():
    """Generate hwid.lock for this machine."""
    HWID_FILE.parent.mkdir(parents=True, exist_ok=True)
    hwid = compute_hwid()
    HWID_FILE.write_text(hwid, encoding="utf-8")
    write_to_log(f"HWID lock created at: {HWID_FILE}")


if __name__ == "__main__":
    activate_hwid()

