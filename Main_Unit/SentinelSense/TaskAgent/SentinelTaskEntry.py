"""SentinelTaskEntry — Windows Task Scheduler registration helper.

Registers a logon-triggered Task Scheduler task so Aria Security starts
automatically at sign-in.  Returns True on success/already-exists, False on
failure, and always logs the outcome so callers are not left guessing.
"""
from __future__ import annotations

import os
import sys
import logging

FOLDER_PATH = r"\Aria"
TASK_NAME   = "AriaSecurityService"

# Resolve app path at import time: prefer the running exe, fall back to a
# conventional install location — never silently register a broken path.
def _default_app_path() -> str:
    if getattr(sys, "frozen", False):
        # Running as a PyInstaller bundle
        return sys.executable
    # Development / installed via pip editable — best-effort conventional path
    candidate = os.path.join(
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        "AriaSecurity",
        "AriaSecurity.exe",
    )
    return candidate


APP_PATH = _default_app_path()


def get_or_create_folder(service, folder_path: str):
    """Return the Task Scheduler folder, creating it if necessary."""
    try:
        return service.GetFolder(folder_path)
    except Exception:
        root = service.GetFolder("\\")
        name = folder_path.lstrip("\\")
        return root.CreateFolder(name)


def task_exists(folder, task_name: str) -> bool:
    try:
        return folder.GetTask(task_name) is not None
    except Exception:
        return False


def create_startup_task(
    folder_path: str = FOLDER_PATH,
    task_name:   str = TASK_NAME,
    app_path:    str = APP_PATH,
) -> bool:
    """Register a logon-trigger task in Windows Task Scheduler.

    Returns:
        True  — task was created, or already existed.
        False — creation failed (reason logged to the root logger).
    """
    if not app_path or not os.path.isfile(app_path):
        logging.warning(
            "[TaskEntry] app_path does not exist — task not registered: %s",
            app_path,
        )
        return False

    try:
        import win32com.client  # requires pywin32
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()

        folder = get_or_create_folder(scheduler, folder_path)

        if task_exists(folder, task_name):
            logging.debug("[TaskEntry] Task already exists: %s", task_name)
            return True

        task_def = scheduler.NewTask(0)

        settings = task_def.Settings
        settings.Enabled          = True
        settings.StartWhenAvailable = True
        settings.Hidden           = False

        reg_info = task_def.RegistrationInfo
        reg_info.Description = f"Aria Security — starts {app_path} on logon"
        reg_info.Author      = "AriaSecurity"

        trigger = task_def.Triggers.Create(9)   # TASK_TRIGGER_LOGON
        trigger.Enabled = True

        action = task_def.Actions.Create(0)     # TASK_ACTION_EXEC
        action.Path = app_path

        task_def.Principal.RunLevel = 1         # TASK_RUNLEVEL_HIGHEST

        # 6 = TASK_CREATE_OR_UPDATE, 3 = TASK_LOGON_INTERACTIVE_TOKEN
        folder.RegisterTaskDefinition(task_name, task_def, 6, None, None, 3)
        logging.info("[TaskEntry] Startup task registered: %s → %s", task_name, app_path)
        return True

    except ImportError:
        logging.warning("[TaskEntry] pywin32 not available — cannot register task.")
        return False
    except Exception as exc:
        logging.error("[TaskEntry] Failed to register startup task: %s", exc)
        return False


def remove_startup_task(
    folder_path: str = FOLDER_PATH,
    task_name:   str = TASK_NAME,
) -> bool:
    """Delete the startup task if it exists.  Returns True on success."""
    try:
        import win32com.client
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder = scheduler.GetFolder(folder_path)
        folder.DeleteTask(task_name, 0)
        logging.info("[TaskEntry] Startup task removed: %s", task_name)
        return True
    except ImportError:
        logging.warning("[TaskEntry] pywin32 not available.")
        return False
    except Exception as exc:
        logging.error("[TaskEntry] Failed to remove startup task: %s", exc)
        return False


if __name__ == "__main__":
    # CLI usage: python SentinelTaskEntry.py [task_name] [app_path]
    logging.basicConfig(level=logging.DEBUG)
    _name = sys.argv[1] if len(sys.argv) > 1 else TASK_NAME
    _path = sys.argv[2] if len(sys.argv) > 2 else APP_PATH
    ok = create_startup_task(FOLDER_PATH, _name, _path)
    sys.exit(0 if ok else 1)
