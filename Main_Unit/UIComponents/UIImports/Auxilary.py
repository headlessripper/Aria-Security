# main_ui.py (example)
import socket
from PySide6.QtWidgets import QPushButton
from PySide6.QtCore import Slot
from Main_Unit.Config.Sys_Config import COMMAND_PORT
# must match Execute_Action.py

def send_action_center_command(cmd: str):
    try:
        with socket.create_connection(("127.0.0.1", COMMAND_PORT), timeout=1.0) as s:
            s.sendall(cmd.encode("utf-8"))
    except OSError as e:
        print(f"Failed to send Action Center command: {e}")