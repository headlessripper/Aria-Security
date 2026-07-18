# Sentinelpsds.py
"""
PSDS – Production Port Scan Defense System
Kernel-level SYN blocking + behavioral detection
"""

import time
import json
import logging
import subprocess
import threading
from collections import defaultdict, deque, OrderedDict
from pathlib import Path
from Config.Sys_Config import SYSTEM_ICON_PATH
from Interface.write_to_log import write_to_log
from Interface.find_items import find_items as find_icon
from winotify import Notification, audio

import pydivert  # WinDivert
import psutil

import threading

_psds_thread = None
_psds_stop_flag = False

# =========================
# CONFIG
# =========================

SCAN_TIME_WINDOW = 5
PORT_THRESHOLD = 10
SYN_RATE_THRESHOLD = 50
IP_COOLDOWN = 60
MAX_TRACKED_IPS = 5000
MAX_BLOCKED_IPS = 1000
LOG_FILE = "logs/psds.log"

# =========================
# FIREWALL BLOCKING
# =========================

blocked_ips = set()


def _get_brain():
    """Lazy import so the brain singleton is resolved at call-time, not module load."""
    from Services.SentinelBrain import get_brain
    return get_brain()


def firewall_block(ip: str):
    if ip in blocked_ips or len(blocked_ips) >= MAX_BLOCKED_IPS:
        return

    for direction in ("in", "out"):
        subprocess.run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=PSDS_BLOCK_{ip}_{direction}",
                f"dir={direction}",
                "action=block",
                f"remoteip={ip}"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    blocked_ips.add(ip)
    toast = Notification(
        app_id="Aria Security",
        title="AntiPort Scan Agent",
        msg=f"HARD BLOCK applied to {ip}",
        icon=find_icon(SYSTEM_ICON_PATH),
        duration="short"
    )
    toast.set_audio(audio.SMS, loop=False)
    toast.show()
    write_to_log(f"🚫 HARD BLOCK applied to {ip}", 'logs/psds.log')
    try:
        _get_brain().emit_block(ip, "Port scan detected — hard block applied")
    except Exception:
        pass


# =========================
# IP TRACKING (LRU)
# =========================

class IPTracker:
    def __init__(self):
        self.activity = OrderedDict()
        self.last_alert = {}

    def record(self, ip, port, ts):
        if ip not in self.activity:
            self.activity[ip] = deque()
        self.activity[ip].append((port, ts))
        self.activity.move_to_end(ip)

        while self.activity[ip] and ts - self.activity[ip][0][1] > SCAN_TIME_WINDOW:
            self.activity[ip].popleft()

        while len(self.activity) > MAX_TRACKED_IPS:
            self.activity.popitem(last=False)

    def unique_ports(self, ip):
        return len({p for p, _ in self.activity.get(ip, [])})

    def cooldown_active(self, ip, now):
        return ip in self.last_alert and now - self.last_alert[ip] < IP_COOLDOWN

    def alert(self, ip, now):
        self.last_alert[ip] = now
        self.activity.pop(ip, None)


tracker = IPTracker()


# =========================
# SYN RATE TRACKING
# =========================

syn_counter = defaultdict(lambda: deque())

def syn_rate_exceeded(ip, ts):
    q = syn_counter[ip]
    q.append(ts)

    while q and ts - q[0] > 1:
        q.popleft()

    return len(q) >= SYN_RATE_THRESHOLD


# =========================
# WIN DIVERT THREAD
# =========================

def packet_defender():
    """
    Drops SYN packets BEFORE TCP stack responds.
    This is the critical protection layer.
    """
    write_to_log("🧬 WinDivert packet defender started", LOG_FILE)

    filter_rule = "tcp.Syn == 1 and tcp.Ack == 0"

    with pydivert.WinDivert(filter_rule) as w:
        for packet in w:
            ip = packet.src_addr
            ts = time.time()

            if ip in blocked_ips:
                continue  # DROP silently

            if syn_rate_exceeded(ip, ts):
                write_to_log(f"⚠️ SYN flood / scan detected from {ip}", 'logs/psds.log')
                firewall_block(ip)
                continue  # DROP

            tracker.record(ip, packet.dst_port, ts)

            if (
                tracker.unique_ports(ip) >= PORT_THRESHOLD
                and not tracker.cooldown_active(ip, ts)
            ):
                tracker.alert(ip, ts)
                write_to_log(f"⚠️ Port scan detected EARLY from {ip}", 'logs/psds.log')
                firewall_block(ip)
                continue  # DROP

            w.send(packet)  # SAFE packet


# =========================
# SECONDARY MONITOR (psutil)
# =========================

def post_detection_monitor():
    """
    Secondary visibility layer (logging, attribution)
    """
    write_to_log("📡 psutil monitor started", 'logs/psds.log')

    while True:
        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.raddr:
                    pass  # reserved for future analytics
            time.sleep(5)
        except Exception as e:
            write_to_log(f"psutil error: {e}", 'logs/psds.log')
            time.sleep(5)


# =========================
# MAIN
# =========================

def main():
    write_to_log("🛡️ PSDS PRODUCTION SYSTEM STARTED", 'logs/psds.log')

    t1 = threading.Thread(target=packet_defender, daemon=True)
    t2 = threading.Thread(target=post_detection_monitor, daemon=True)

    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        write_to_log("🛑 PSDS stopped by user", 'logs/psds.log')


def _run():
    main()  # your existing main() with while True loop

def start():
    global _psds_thread, _psds_stop_flag
    if _psds_thread and _psds_thread.is_alive():
        return
    _psds_stop_flag = False
    _psds_thread = threading.Thread(target=_run, daemon=True)
    _psds_thread.start()

def stop():
    global _psds_stop_flag
    _psds_stop_flag = True
    # in packet_defender/post_detection_monitor loops,
    # periodically check _psds_stop_flag and break
