# SentinelServiceAgent.py
# Service agent that will start multiple services if they are not already running.
# It checks if each service is already running before starting it to avoid multiple instances.

import os
import sys
import subprocess
from pathlib import Path

import psutil
from Main_Unit.Service.write_to_log import write_to_log


# Names of the executables to manage
EXE_NAMES = [
    "SentinelSenseService.exe",
    "SentinelTaskAgent.exe",
]

def find_exe(exe_name: str) -> str | None:
    """
    Find the path to the given executable based on the platform.
    Currently only Windows is supported.
    """
    script_dir = Path("./Plugin")

    if sys.platform.startswith("win"):
        possible_paths = [
            script_dir / exe_name,
            script_dir / "SentinelServices" / exe_name,
            (script_dir / os.pardir / exe_name).resolve(),
        ]
    else:
        raise Exception(f"Unsupported platform: {sys.platform}")

    for path in possible_paths:
        if path.exists():
            return str(path)

    return None


def is_running(proc_name: str) -> bool:
    """
    Check if a process with the given name is already running.
    """
    target = proc_name.lower()
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = (proc.info['name'] or "").lower()
            if name == target:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return False


def start_one(exe_name: str):
    """
    Start a single service executable if it is not already running.
    """
    exe_path = find_exe(exe_name)
    if not exe_path:
        write_to_log(f"{exe_name} not found in expected locations.")
        return

    if is_running(exe_name):
        write_to_log(f"{exe_name} is already running.")
        return

    try:
        if sys.platform.startswith("win"):
            os.startfile(exe_path)
        elif sys.platform.startswith("linux"):
            subprocess.Popen([exe_path])
        elif sys.platform.startswith("darwin"):
            subprocess.Popen(["open", exe_path])
        else:
            raise Exception(f"Unsupported platform: {sys.platform}")

        write_to_log(f"{exe_name} started successfully from: {exe_path}")
    except Exception as e:
        raise Exception(f"Failed to start {exe_name}: {e}") from e


def Start_Service():
    """
    Entry point: ensure all configured services are running.
    """
    for exe_name in EXE_NAMES:
        start_one(exe_name)


if __name__ == "__main__":
    Start_Service()
