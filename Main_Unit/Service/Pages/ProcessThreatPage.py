"""Process Threat Analyser Page — advanced heuristic threat scoring for all
running processes, with detail panel, kill/suspend actions, and auto-refresh."""
from __future__ import annotations

import csv
import os
import subprocess
import time
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSortFilterProxyModel
from PySide6.QtGui import QColor, QFont, QBrush
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QProgressBar, QSplitter, QScrollArea,
    QSizePolicy, QApplication, QMessageBox, QFileDialog,
    QGridLayout, QSpacerItem,
)

# ── Design tokens ─────────────────────────────────────────────────────────────
CARD    = "#161b22"
BORDER  = "#21262d"
SURFACE = "#0d1117"
ACCENT  = "#2f81f7"
GREEN   = "#3fb950"
RED     = "#f85149"
ORANGE  = "#d29922"
PURPLE  = "#bc8cff"
TEAL    = "#39d353"
TEXT       = "#e6edf3"
TEXT_DIM   = "#8b949e"
TEXT_MUTED = "#484f58"

# ── Threat level thresholds ───────────────────────────────────────────────────
def _threat_level(score: int) -> tuple[str, str]:
    """Return (label, color) for a threat score."""
    if score >= 71:
        return "HIGH", RED
    if score >= 41:
        return "MEDIUM", ORANGE
    if score >= 21:
        return "LOW", "#c9a227"
    return "SAFE", GREEN


# ── PE packing check (no external dependency) ─────────────────────────────────
_PACKER_SIGS = (b".upx", b".packed", b".themida", b"ASPack", b"PECompact")

def _check_packed(exe_path: str) -> bool:
    """Return True if the first 4 KB of the exe contains packer signatures."""
    try:
        with open(exe_path, "rb") as f:
            header = f.read(4096)
        lo = header.lower()
        return any(sig.lower() in lo for sig in _PACKER_SIGS)
    except Exception:
        return False


# ── Scoring engine ────────────────────────────────────────────────────────────
_SYSTEM_PROCS = frozenset({
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "wininit.exe", "services.exe",
})
_SUSPICIOUS_NAMES = frozenset({
    "svchost32", "svchost64", "lsass64", "lsass32", "csrss2",
    "winlogon32", "explorer32", "rundll64", "regsvr64", "taskhost32",
})
_SYSTEM32_PREFIXES = ("c:\\windows\\system32", "c:\\windows\\syswow64")
_BROWSER_PROCS = frozenset({
    "chrome.exe", "firefox.exe", "msedge.exe",
    "brave.exe", "opera.exe", "code.exe", "devenv.exe",
})
_OFFICE_PROCS = frozenset({
    "word.exe", "excel.exe", "outlook.exe",
    "winword.exe", "powerpnt.exe",
})
_SCRIPT_CHILDREN = frozenset({
    "cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe",
})
_SCRIPT_HOSTS = frozenset({"wscript.exe", "mshta.exe", "cscript.exe"})
_KNOWN_SERVICES = frozenset({
    "svchost.exe", "services.exe", "lsass.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "smss.exe", "system",
})


def _score_process(entry: dict, all_pids: set[int]) -> tuple[int, list[str]]:
    """Return (score 0-100, list_of_flag_strings) for a process entry dict."""
    score = 0
    flags: list[str] = []

    name    = (entry.get("name") or "").lower()
    exe     = (entry.get("exe") or "").lower().replace("/", "\\")
    ppid    = entry.get("ppid") or 0
    cmdline = " ".join(entry.get("cmdline") or []).lower()
    status  = (entry.get("status") or "").lower()
    username = (entry.get("username") or "").lower()
    num_threads = entry.get("num_threads") or 0
    mem_mb  = entry.get("mem_mb") or 0
    cpu     = entry.get("cpu_percent") or 0.0
    conns   = entry.get("connections") or 0
    create_time = entry.get("create_time") or 0.0
    parent_name = (entry.get("parent_name") or "").lower()

    # 1. Suspicious path (+25)
    suspicious_paths = (
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
        "\\downloads\\", "\\desktop\\", "\\public\\",
    )
    if exe and any(p in exe for p in suspicious_paths):
        score += 25
        flags.append("suspicious path")

    # 2. No exe path (+30)
    if not exe:
        score += 30
        flags.append("no exe path")

    # 3. System process impersonation (+40)
    if name in _SYSTEM_PROCS and exe:
        if not any(exe.startswith(pfx) for pfx in _SYSTEM32_PREFIXES):
            score += 40
            flags.append("system impersonation")

    # 4. Suspicious name (+35)
    if name.rstrip(".exe") in _SUSPICIOUS_NAMES or name in _SUSPICIOUS_NAMES:
        score += 35
        flags.append("suspicious name")

    # 5. Orphan process (+20): ppid not in existing pids AND ppid > 4
    if ppid and ppid > 4 and ppid not in all_pids:
        score += 20
        flags.append("orphan process")

    # 6. Encoded PowerShell command (+25)
    if "-enc" in cmdline or "-encodedcommand" in cmdline:
        score += 25
        flags.append("encoded PS command")

    # 7. PowerShell download cradle (+25)
    if any(kw in cmdline for kw in ("downloadstring", "downloadfile", "webclient")):
        score += 25
        flags.append("PS download cradle")

    # 8. PS execution policy bypass (+20)
    if "bypass" in cmdline and "executionpolicy" in cmdline:
        score += 20
        flags.append("execution policy bypass")

    # 9. URL in cmdline (+15)
    if "http://" in cmdline or "https://" in cmdline:
        score += 15
        flags.append("URL in cmdline")

    # 10. Script interpreter with args (+15)
    if name in _SCRIPT_HOSTS and cmdline.strip():
        score += 15
        flags.append("script interpreter")

    # 11. Suspicious parent-child relationship (+25)
    if parent_name in _OFFICE_PROCS and name in _SCRIPT_CHILDREN:
        score += 25
        flags.append("office→shell spawn")

    # 12. High CPU (+15)
    if cpu > 50:
        score += 15
        flags.append(f"high CPU {cpu:.0f}%")

    # 13. Excessive threads (+10)
    if num_threads > 100:
        score += 10
        flags.append(f"excess threads ({num_threads})")

    # 14. High private memory (+10) — excluding known heavy apps
    if mem_mb > 500 and name not in _BROWSER_PROCS:
        score += 10
        flags.append(f"high mem ({mem_mb} MB)")

    # 15. Many network connections (+15)
    if conns > 20:
        score += 15
        flags.append(f"many connections ({conns})")

    # 16. New process with network activity (+15)
    age_s = time.time() - create_time if create_time else 9999
    if age_s < 300 and conns > 2:
        score += 15
        flags.append("new proc+network")

    # 17. Hidden/unusual status (+10)
    if status == "stopped":
        score += 10
        flags.append("stopped status")

    # 18. PE packing indicator (+20)
    if exe and os.path.isfile(exe):
        try:
            if _check_packed(exe):
                score += 20
                flags.append("packed PE")
        except Exception:
            pass

    # 19. Unusual base module path (+20)
    maps = entry.get("maps") or []
    if maps:
        first = (maps[0] or "").lower().replace("/", "\\")
        if first and not any(first.startswith(pfx) for pfx in _SYSTEM32_PREFIXES):
            if "\\windows\\" not in first and first:
                score += 20
                flags.append("unusual base module")

    # 20. Running as SYSTEM but not a known service (+15)
    is_system = "system" in username or "nt authority\\system" in username
    if is_system and name not in _KNOWN_SERVICES:
        score += 15
        flags.append("SYSTEM non-service")

    return min(score, 100), flags


# ── Detail panel ──────────────────────────────────────────────────────────────
class _DetailPanel(QFrame):
    """Right-side detail panel for the selected process."""

    kill_requested    = Signal(int, str)   # pid, name
    suspend_requested = Signal(int, str)   # pid, name
    explore_requested = Signal(str)        # exe path

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(260)
        self.setMaximumWidth(400)
        self.setStyleSheet(
            f"QFrame{{background:{CARD};border:1px solid {BORDER};border-radius:10px;}}"
        )

        self._pid: int = -1
        self._name: str = ""
        self._exe: str = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 14, 14, 14)
        outer.setSpacing(10)

        # empty state
        self._empty_lbl = QLabel("Select a process to view details")
        self._empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_lbl.setStyleSheet(
            f"color:{TEXT_MUTED};font-size:12px;border:none;background:transparent;"
        )
        outer.addWidget(self._empty_lbl)

        # content widget (hidden when nothing selected)
        self._content = QWidget()
        self._content.setStyleSheet("background:transparent;border:none;")
        self._content.setVisible(False)
        content_layout = QVBoxLayout(self._content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)

        # process name + PID
        self._proc_name_lbl = QLabel("")
        self._proc_name_lbl.setStyleSheet(
            f"color:{TEXT};font-size:15px;font-weight:700;"
            f"background:transparent;border:none;"
        )
        self._proc_name_lbl.setWordWrap(True)
        content_layout.addWidget(self._proc_name_lbl)

        self._pid_lbl = QLabel("")
        self._pid_lbl.setStyleSheet(
            f"color:{TEXT_DIM};font-size:11px;background:transparent;border:none;"
        )
        content_layout.addWidget(self._pid_lbl)

        # threat badge
        self._threat_badge = QLabel("SAFE")
        self._threat_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._threat_badge.setFixedHeight(26)
        self._threat_badge.setStyleSheet(
            f"background:{GREEN}22;color:{GREEN};border:1px solid {GREEN}66;"
            f"border-radius:5px;font-size:12px;font-weight:700;padding:0 8px;"
        )
        content_layout.addWidget(self._threat_badge)

        # score bar
        score_row = QHBoxLayout()
        score_row.setSpacing(8)
        score_lbl = QLabel("Score:")
        score_lbl.setStyleSheet(
            f"color:{TEXT_DIM};font-size:11px;background:transparent;border:none;"
        )
        score_row.addWidget(score_lbl)
        self._score_bar = QProgressBar()
        self._score_bar.setRange(0, 100)
        self._score_bar.setValue(0)
        self._score_bar.setFixedHeight(10)
        self._score_bar.setTextVisible(False)
        self._score_bar.setStyleSheet(
            f"QProgressBar{{background:{SURFACE};border:1px solid {BORDER};border-radius:5px;}}"
            f"QProgressBar::chunk{{background:{GREEN};border-radius:4px;}}"
        )
        score_row.addWidget(self._score_bar, 1)
        self._score_num = QLabel("0")
        self._score_num.setStyleSheet(
            f"color:{TEXT};font-weight:700;font-size:12px;background:transparent;border:none;"
        )
        score_row.addWidget(self._score_num)
        content_layout.addLayout(score_row)

        # info grid
        self._grid_widget = QWidget()
        self._grid_widget.setStyleSheet("background:transparent;border:none;")
        self._grid = QGridLayout(self._grid_widget)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setSpacing(4)
        self._grid.setColumnStretch(1, 1)
        content_layout.addWidget(self._grid_widget)
        self._info_labels: dict[str, QLabel] = {}
        for row_idx, key in enumerate([
            "EXE", "Username", "PID", "PPID", "Threads",
            "Memory", "CPU", "Connections", "Started",
        ]):
            k_lbl = QLabel(key + ":")
            k_lbl.setStyleSheet(
                f"color:{TEXT_MUTED};font-size:10px;background:transparent;border:none;"
            )
            v_lbl = QLabel("—")
            v_lbl.setWordWrap(True)
            v_lbl.setStyleSheet(
                f"color:{TEXT};font-size:10px;background:transparent;border:none;"
            )
            self._grid.addWidget(k_lbl, row_idx, 0)
            self._grid.addWidget(v_lbl, row_idx, 1)
            self._info_labels[key] = v_lbl

        # flags section
        flags_title = QLabel("Flags:")
        flags_title.setStyleSheet(
            f"color:{TEXT_DIM};font-size:11px;font-weight:600;"
            f"background:transparent;border:none;"
        )
        content_layout.addWidget(flags_title)

        self._flags_container = QWidget()
        self._flags_container.setStyleSheet("background:transparent;border:none;")
        self._flags_layout = QHBoxLayout(self._flags_container)
        self._flags_layout.setContentsMargins(0, 0, 0, 0)
        self._flags_layout.setSpacing(4)
        self._flags_layout.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        # wrap with a scroll area so many flags don't overflow
        flags_scroll = QScrollArea()
        flags_scroll.setWidgetResizable(True)
        flags_scroll.setWidget(self._flags_container)
        flags_scroll.setFixedHeight(70)
        flags_scroll.setStyleSheet(
            f"QScrollArea{{background:transparent;border:1px solid {BORDER};border-radius:6px;}}"
            f"QScrollBar:horizontal{{height:6px;background:{SURFACE};}}"
            f"QScrollBar::handle:horizontal{{background:{BORDER};border-radius:3px;}}"
        )
        content_layout.addWidget(flags_scroll)

        # action buttons
        btn_style_base = (
            "QPushButton{border-radius:6px;padding:6px 10px;"
            "font-size:11px;font-weight:600;border:none;}"
            "QPushButton:hover{border:1px solid rgba(255,255,255,40);}"
            "QPushButton:disabled{background:#21262d;color:#484f58;}"
        )

        self._kill_btn = QPushButton("Kill Process")
        self._kill_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._kill_btn.setStyleSheet(
            f"QPushButton{{background:{RED};color:white;}}" + btn_style_base
        )
        self._kill_btn.clicked.connect(self._on_kill)

        self._suspend_btn = QPushButton("Suspend")
        self._suspend_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._suspend_btn.setStyleSheet(
            f"QPushButton{{background:{ORANGE};color:white;}}" + btn_style_base
        )
        self._suspend_btn.clicked.connect(self._on_suspend)

        self._copy_btn = QPushButton("Copy Info")
        self._copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy_btn.setStyleSheet(
            f"QPushButton{{background:{BORDER};color:{TEXT};}}" + btn_style_base
        )
        self._copy_btn.clicked.connect(self._on_copy)

        self._explore_btn = QPushButton("Open Folder")
        self._explore_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._explore_btn.setStyleSheet(
            f"QPushButton{{background:{BORDER};color:{TEXT};}}" + btn_style_base
        )
        self._explore_btn.clicked.connect(self._on_explore)

        btn_row1 = QHBoxLayout()
        btn_row1.setSpacing(6)
        btn_row1.addWidget(self._kill_btn)
        btn_row1.addWidget(self._suspend_btn)
        content_layout.addLayout(btn_row1)

        btn_row2 = QHBoxLayout()
        btn_row2.setSpacing(6)
        btn_row2.addWidget(self._copy_btn)
        btn_row2.addWidget(self._explore_btn)
        content_layout.addLayout(btn_row2)

        content_layout.addStretch()
        outer.addWidget(self._content)

        self._entry: dict = {}

    # ── public API ────────────────────────────────────────────────────────────
    def show_entry(self, entry: dict) -> None:
        self._entry = entry
        self._pid  = entry.get("pid", -1)
        self._name = entry.get("name", "")
        self._exe  = entry.get("exe", "")
        score      = entry.get("score", 0)
        flags      = entry.get("flags") or []
        level, color = _threat_level(score)

        self._empty_lbl.setVisible(False)
        self._content.setVisible(True)

        self._proc_name_lbl.setText(self._name)
        self._pid_lbl.setText(f"PID: {self._pid}")

        self._threat_badge.setText(level)
        self._threat_badge.setStyleSheet(
            f"background:{color}22;color:{color};border:1px solid {color}66;"
            f"border-radius:5px;font-size:12px;font-weight:700;padding:0 8px;"
            f"background:transparent;"
        )

        self._score_bar.setValue(score)
        self._score_bar.setStyleSheet(
            f"QProgressBar{{background:{SURFACE};border:1px solid {BORDER};border-radius:5px;}}"
            f"QProgressBar::chunk{{background:{color};border-radius:4px;}}"
        )
        self._score_num.setText(str(score))
        self._score_num.setStyleSheet(
            f"color:{color};font-weight:700;font-size:12px;"
            f"background:transparent;border:none;"
        )

        mem_mb = entry.get("mem_mb", 0)
        cpu    = entry.get("cpu_percent", 0.0)
        conns  = entry.get("connections", 0)
        ct     = entry.get("create_time", 0.0)
        started = datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S") if ct else "—"

        self._info_labels["EXE"].setText(self._exe or "—")
        self._info_labels["Username"].setText(entry.get("username") or "—")
        self._info_labels["PID"].setText(str(self._pid))
        self._info_labels["PPID"].setText(str(entry.get("ppid") or "—"))
        self._info_labels["Threads"].setText(str(entry.get("num_threads") or "—"))
        self._info_labels["Memory"].setText(f"{mem_mb} MB")
        self._info_labels["CPU"].setText(f"{cpu:.1f}%")
        self._info_labels["Connections"].setText(str(conns))
        self._info_labels["Started"].setText(started)

        # rebuild flags
        for i in reversed(range(self._flags_layout.count())):
            w = self._flags_layout.itemAt(i).widget()
            if w:
                w.deleteLater()

        if flags:
            for flag in flags:
                chip = QLabel(flag)
                chip.setStyleSheet(
                    f"background:{RED}22;color:{RED};border:1px solid {RED}55;"
                    f"border-radius:4px;font-size:9px;padding:2px 6px;"
                )
                self._flags_layout.addWidget(chip)
        else:
            no_flags = QLabel("No suspicious flags")
            no_flags.setStyleSheet(
                f"color:{TEXT_MUTED};font-size:10px;"
            )
            self._flags_layout.addWidget(no_flags)

        self._explore_btn.setEnabled(bool(self._exe and os.path.isfile(self._exe)))

    def clear(self) -> None:
        self._empty_lbl.setVisible(True)
        self._content.setVisible(False)
        self._entry = {}
        self._pid = -1

    # ── button handlers ───────────────────────────────────────────────────────
    def _on_kill(self) -> None:
        if self._pid >= 0:
            self.kill_requested.emit(self._pid, self._name)

    def _on_suspend(self) -> None:
        if self._pid >= 0:
            self.suspend_requested.emit(self._pid, self._name)

    def _on_copy(self) -> None:
        if not self._entry:
            return
        lines = [
            f"Process: {self._entry.get('name', '')}",
            f"PID: {self._entry.get('pid', '')}",
            f"EXE: {self._entry.get('exe', '')}",
            f"Score: {self._entry.get('score', 0)}",
            f"Flags: {', '.join(self._entry.get('flags') or [])}",
            f"Username: {self._entry.get('username', '')}",
            f"Memory: {self._entry.get('mem_mb', 0)} MB",
        ]
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText("\n".join(lines))

    def _on_explore(self) -> None:
        if self._exe:
            self.explore_requested.emit(self._exe)


# ── Scan worker ───────────────────────────────────────────────────────────────
class _ScanWorker(QThread):
    """Background thread: scans all processes, scores them, emits batches.

    IMPORTANT: signal is named 'scan_done' not 'finished' to avoid shadowing
    QThread.finished, which would prevent _on_finished from being called.
    """
    progress  = Signal(int, int, str)       # done, total, current_proc_name
    batch     = Signal(list)                # list of proc entry dicts
    scan_done = Signal(int, int, int, int)  # total, critical, high, medium

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        try:
            import psutil as ps
        except ImportError:
            try:
                self.scan_done.emit(0, 0, 0, 0)
            except Exception:
                pass
            return

        # collect all procs first
        try:
            all_procs = list(ps.process_iter([
                "pid", "name", "exe", "ppid", "cmdline",
                "status", "username", "num_threads",
                "memory_info", "create_time",
            ]))
        except Exception:
            self.scan_done.emit(0, 0, 0, 0)
            return

        total = len(all_procs)
        all_pids: set[int] = {p.pid for p in all_procs}

        # build pid→name map for parent lookup
        pid_to_name: dict[int, str] = {}
        for p in all_procs:
            try:
                pid_to_name[p.pid] = p.info.get("name") or ""
            except Exception:
                pass

        # prime CPU counters
        for p in all_procs:
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass

        self.msleep(800)  # wait for CPU measurement window

        batch: list[dict] = []
        critical_count = 0
        high_count = 0
        medium_count = 0

        for i, proc in enumerate(all_procs):
            if not self._running:
                break

            try:
                name = proc.info.get("name") or "Unknown"
                self.progress.emit(i + 1, total, name)

                exe     = proc.info.get("exe") or ""
                ppid    = proc.info.get("ppid") or 0
                cmdline = proc.info.get("cmdline") or []
                status  = proc.info.get("status") or ""
                username = proc.info.get("username") or ""
                num_threads = proc.info.get("num_threads") or 0
                create_time = proc.info.get("create_time") or 0.0

                mi = proc.info.get("memory_info")
                mem_mb = (mi.rss // (1024 * 1024)) if mi else 0

                cpu = 0.0
                try:
                    cpu = proc.cpu_percent(interval=None)
                except Exception:
                    pass

                conns = 0
                try:
                    conns = len(proc.connections())
                except Exception:
                    pass

                maps: list[str] = []
                try:
                    mm = proc.memory_maps()
                    if mm:
                        maps = [mm[0].path] if mm else []
                except Exception:
                    pass

                parent_name = pid_to_name.get(ppid, "")

                entry: dict = {
                    "pid":         proc.pid,
                    "name":        name,
                    "exe":         exe,
                    "ppid":        ppid,
                    "cmdline":     cmdline,
                    "status":      status,
                    "username":    username,
                    "num_threads": num_threads,
                    "mem_mb":      mem_mb,
                    "cpu_percent": cpu,
                    "connections": conns,
                    "create_time": create_time,
                    "parent_name": parent_name,
                    "maps":        maps,
                }

                score, flags = _score_process(entry, all_pids)
                entry["score"] = score
                entry["flags"] = flags
                level, _ = _threat_level(score)
                if level == "HIGH":
                    if score >= 71:
                        critical_count += 1
                    high_count += 1
                elif level == "MEDIUM":
                    medium_count += 1

                batch.append(entry)
                if len(batch) >= 25:
                    self.batch.emit(batch[:])
                    batch.clear()

            except Exception:
                pass

        try:
            if batch:
                self.batch.emit(batch)
            self.scan_done.emit(total, critical_count, high_count, medium_count)
        except Exception:
            pass


# ── Stat chip ─────────────────────────────────────────────────────────────────
class _StatChip(QFrame):
    def __init__(self, label: str, color: str, parent=None):
        super().__init__(parent)
        self.setFixedHeight(56)
        self.setStyleSheet(
            f"QFrame{{background:{CARD};border:1px solid {BORDER};border-radius:8px;}}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._val = QLabel("0")
        self._val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._val.setStyleSheet(
            f"color:{color};font-size:18px;font-weight:700;"
            f"border:none;background:transparent;"
        )
        layout.addWidget(self._val)

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            f"color:{TEXT_MUTED};font-size:10px;border:none;background:transparent;"
        )
        layout.addWidget(lbl)

    def set_value(self, n: int) -> None:
        self._val.setText(str(n))


# ── Main page ─────────────────────────────────────────────────────────────────
class ProcessThreatPage(QWidget):
    """Full process threat analyser with 20+ heuristics, detail panel, and actions."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self._worker: _ScanWorker | None = None
        self._all_entries: list[dict] = []
        self._auto_refresh: bool = False
        self._auto_timer: QTimer | None = None
        self._psutil_ok = False

        try:
            import psutil  # noqa: F401
            self._psutil_ok = True
        except ImportError:
            pass

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        self._build_header(root)
        self._build_chips(root)
        self._build_progress(root)
        self._build_splitter(root)

        # cleanup on app quit
        app = QApplication.instance()
        if app:
            app.aboutToQuit.connect(self._on_about_to_quit)

        if not self._psutil_ok:
            self._status_lbl.setText(
                "psutil is not installed — install it with: pip install psutil"
            )
            self._scan_btn.setEnabled(False)

    # ── layout builders ───────────────────────────────────────────────────────
    def _build_header(self, root: QVBoxLayout) -> None:
        hdr = QHBoxLayout()
        hdr.setSpacing(8)

        title = QLabel("Process Threat Analyser")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet(f"color:{TEXT};")
        hdr.addWidget(title)
        hdr.addStretch()

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by name / path…")
        self._search.setFixedWidth(200)
        self._search.setStyleSheet(
            f"QLineEdit{{background:{SURFACE};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:5px 10px;font-size:12px;}}"
        )
        self._search.textChanged.connect(self._apply_filter)
        hdr.addWidget(self._search)

        self._severity_combo = QComboBox()
        self._severity_combo.addItems(["All Levels", "HIGH", "MEDIUM", "LOW", "SAFE"])
        self._severity_combo.setFixedWidth(120)
        self._severity_combo.setStyleSheet(
            f"QComboBox{{background:{SURFACE};color:{TEXT};border:1px solid {BORDER};"
            f"border-radius:6px;padding:5px 10px;font-size:12px;}}"
            f"QComboBox::drop-down{{border:none;width:20px;}}"
            f"QComboBox QAbstractItemView{{background:{CARD};color:{TEXT};"
            f"border:1px solid {BORDER};selection-background-color:{ACCENT}22;}}"
        )
        self._severity_combo.currentTextChanged.connect(self._apply_filter)
        hdr.addWidget(self._severity_combo)

        self._scan_btn = QPushButton("Scan")
        self._scan_btn.setFixedHeight(34)
        self._scan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._scan_btn.setStyleSheet(
            f"QPushButton{{background:{ACCENT};color:white;border:none;"
            f"border-radius:6px;padding:6px 18px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#388bfd;}}"
            f"QPushButton:disabled{{background:{BORDER};color:{TEXT_MUTED};}}"
        )
        self._scan_btn.clicked.connect(self._start_scan)
        hdr.addWidget(self._scan_btn)

        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setFixedHeight(34)
        self._stop_btn.setEnabled(False)
        self._stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._stop_btn.setStyleSheet(
            f"QPushButton{{background:{RED};color:white;border:none;"
            f"border-radius:6px;padding:6px 14px;font-size:13px;font-weight:600;}}"
            f"QPushButton:hover{{background:#ff6b6b;}}"
            f"QPushButton:disabled{{background:{BORDER};color:{TEXT_MUTED};}}"
        )
        self._stop_btn.clicked.connect(self._stop_scan)
        hdr.addWidget(self._stop_btn)

        self._export_btn = QPushButton("Export CSV")
        self._export_btn.setFixedHeight(34)
        self._export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._export_btn.setStyleSheet(
            f"QPushButton{{background:{BORDER};color:{TEXT};border:none;"
            f"border-radius:6px;padding:6px 14px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{background:{SURFACE};}}"
        )
        self._export_btn.clicked.connect(self._export_csv)
        hdr.addWidget(self._export_btn)

        self._auto_btn = QPushButton("Auto-Refresh: OFF")
        self._auto_btn.setCheckable(True)
        self._auto_btn.setFixedHeight(34)
        self._auto_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._auto_btn.setStyleSheet(self._auto_style(False))
        self._auto_btn.clicked.connect(self._toggle_auto_refresh)
        hdr.addWidget(self._auto_btn)

        root.addLayout(hdr)

    def _build_chips(self, root: QVBoxLayout) -> None:
        row = QHBoxLayout()
        row.setSpacing(10)

        self._chip_high   = _StatChip("HIGH RISK",  RED)
        self._chip_medium = _StatChip("MEDIUM",     ORANGE)
        self._chip_low    = _StatChip("LOW",         "#c9a227")
        self._chip_safe   = _StatChip("SAFE",        GREEN)
        self._chip_total  = _StatChip("TOTAL",       TEXT_DIM)

        for chip in (
            self._chip_high, self._chip_medium, self._chip_low,
            self._chip_safe, self._chip_total,
        ):
            row.addWidget(chip, 1)

        root.addLayout(row)

    def _build_progress(self, root: QVBoxLayout) -> None:
        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setFixedHeight(6)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar{{background:{SURFACE};border:1px solid {BORDER};"
            f"border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{ACCENT};border-radius:3px;}}"
        )
        root.addWidget(self._progress)

        self._status_lbl = QLabel("Click 'Scan' to analyse running processes.")
        self._status_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        root.addWidget(self._status_lbl)

    def _build_splitter(self, root: QVBoxLayout) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{BORDER};width:2px;}}"
        )

        # ── left: table ───────────────────────────────────────────────────
        self._table = QTableWidget(0, 8)
        self._table.setHorizontalHeaderLabels([
            "Threat", "Score", "PID", "Process",
            "Memory", "CPU", "Connections", "Flags",
        ])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSortingEnabled(True)
        self._table.setStyleSheet(f"""
            QTableWidget{{
                background:{CARD};color:{TEXT};border:1px solid {BORDER};
                border-radius:8px;gridline-color:{BORDER};
            }}
            QHeaderView::section{{
                background:{CARD};color:{TEXT_DIM};font-size:11px;font-weight:600;
                border:none;border-bottom:1px solid {BORDER};padding:6px 8px;
            }}
            QTableWidget::item{{padding:5px 8px;border:none;}}
            QTableWidget::item:selected{{background:{ACCENT}22;color:{TEXT};}}
        """)
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        splitter.addWidget(self._table)

        # ── right: detail panel in scroll area ───────────────────────────
        self._detail = _DetailPanel()
        self._detail.kill_requested.connect(self._kill_process)
        self._detail.suspend_requested.connect(self._suspend_process)
        self._detail.explore_requested.connect(self._open_in_explorer)

        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setWidget(self._detail)
        detail_scroll.setMinimumWidth(260)
        detail_scroll.setMaximumWidth(400)
        detail_scroll.setStyleSheet(
            f"QScrollArea{{background:transparent;border:none;}}"
            f"QScrollBar:vertical{{background:{SURFACE};width:6px;border-radius:3px;}}"
            f"QScrollBar::handle:vertical{{background:{BORDER};border-radius:3px;}}"
        )
        splitter.addWidget(detail_scroll)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter, 1)

    # ── scan control ──────────────────────────────────────────────────────────
    def _start_scan(self) -> None:
        if self._worker and self._worker.isRunning():
            return

        self._all_entries.clear()
        self._table.setRowCount(0)
        self._detail.clear()
        self._progress.setValue(0)
        self._status_lbl.setText("Scanning processes…")
        self._scan_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)

        self._worker = _ScanWorker()
        self._worker.progress.connect(self._on_progress)
        self._worker.batch.connect(self._on_batch)
        self._worker.scan_done.connect(self._on_scan_done)
        self._worker.start()

    def _stop_scan(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.stop()
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("Stopping scan…")

    def _on_progress(self, done: int, total: int, name: str) -> None:
        pct = int(done / total * 100) if total else 0
        self._progress.setValue(pct)
        self._status_lbl.setText(f"Scanning {done}/{total}: {name}")

    def _on_batch(self, entries: list[dict]) -> None:
        self._table.setSortingEnabled(False)
        for entry in entries:
            self._all_entries.append(entry)
            self._add_row(entry)
        self._table.setSortingEnabled(True)
        self._apply_filter_silent()

    def _on_scan_done(self, total: int, critical: int, high: int, medium: int) -> None:
        self._worker = None  # FIRST — allow GC
        self._scan_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._progress.setValue(100)

        safe  = sum(1 for e in self._all_entries if e["score"] <= 20)
        low   = sum(1 for e in self._all_entries if 21 <= e["score"] <= 40)
        med   = sum(1 for e in self._all_entries if 41 <= e["score"] <= 70)
        h     = sum(1 for e in self._all_entries if e["score"] >= 71)
        tot   = len(self._all_entries)

        self._chip_high.set_value(h)
        self._chip_medium.set_value(med)
        self._chip_low.set_value(low)
        self._chip_safe.set_value(safe)
        self._chip_total.set_value(tot)

        self._status_lbl.setText(
            f"Scan complete — {tot} processes | "
            f"{h} HIGH | {med} MEDIUM | {low} LOW | {safe} SAFE"
        )

        # sort by score descending
        self._table.sortByColumn(1, Qt.SortOrder.DescendingOrder)

    def _apply_filter(self, *_) -> None:
        self._apply_filter_silent()

    def _apply_filter_silent(self) -> None:
        text  = self._search.text().lower()
        level = self._severity_combo.currentText()

        for r in range(self._table.rowCount()):
            name_item  = self._table.item(r, 3)
            flags_item = self._table.item(r, 7)
            level_item = self._table.item(r, 0)

            name_match = (
                not text or
                (name_item and text in name_item.text().lower()) or
                (flags_item and text in flags_item.text().lower())
            )
            level_match = (
                level == "All Levels" or
                (level_item and level_item.text() == level)
            )
            self._table.setRowHidden(r, not (name_match and level_match))

    def _add_row(self, entry: dict) -> None:
        score = entry["score"]
        flags = entry.get("flags") or []
        level, color = _threat_level(score)

        r = self._table.rowCount()
        self._table.insertRow(r)

        # tint row background slightly
        tint = QColor(color)
        tint.setAlpha(18)
        bg = QBrush(tint)

        def _item(text: str, align=Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft):
            it = QTableWidgetItem(text)
            it.setTextAlignment(align)
            it.setBackground(bg)
            return it

        # col 0: threat level chip-text
        threat_item = _item(level)
        threat_item.setForeground(QColor(color))
        threat_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        self._table.setItem(r, 0, threat_item)

        # col 1: score (numeric sort key stored in user role)
        score_item = QTableWidgetItem()
        score_item.setData(Qt.ItemDataRole.DisplayRole, score)
        score_item.setForeground(QColor(color))
        score_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        score_item.setBackground(bg)
        self._table.setItem(r, 1, score_item)

        # col 2: PID
        pid_item = QTableWidgetItem()
        pid_item.setData(Qt.ItemDataRole.DisplayRole, entry.get("pid", 0))
        pid_item.setBackground(bg)
        self._table.setItem(r, 2, pid_item)

        # col 3: name
        self._table.setItem(r, 3, _item(entry.get("name") or ""))

        # col 4: memory
        mem_item = QTableWidgetItem()
        mem_item.setData(Qt.ItemDataRole.DisplayRole, entry.get("mem_mb", 0))
        mem_item.setBackground(bg)
        self._table.setItem(r, 4, mem_item)

        # col 5: CPU
        cpu_item = QTableWidgetItem(f'{entry.get("cpu_percent", 0.0):.1f}%')
        cpu_item.setBackground(bg)
        self._table.setItem(r, 5, cpu_item)

        # col 6: connections
        conn_item = QTableWidgetItem()
        conn_item.setData(Qt.ItemDataRole.DisplayRole, entry.get("connections", 0))
        conn_item.setBackground(bg)
        self._table.setItem(r, 6, conn_item)

        # col 7: flags
        flags_text = ", ".join(flags) if flags else "clean"
        flags_item = _item(flags_text)
        flags_item.setForeground(QBrush(QColor(TEXT_DIM)))  # QTableWidgetItem has no setStyleSheet
        self._table.setItem(r, 7, flags_item)

        # store pid in row 0 user role for selection lookup
        self._table.item(r, 0).setData(Qt.ItemDataRole.UserRole, entry.get("pid", -1))

    # ── row selection → detail panel ──────────────────────────────────────────
    def _on_row_selected(self) -> None:
        rows = self._table.selectedItems()
        if not rows:
            self._detail.clear()
            return

        row = self._table.currentRow()
        pid_item = self._table.item(row, 0)
        if pid_item is None:
            return
        pid = pid_item.data(Qt.ItemDataRole.UserRole)
        if pid is None:
            return

        # find entry
        entry = next((e for e in self._all_entries if e.get("pid") == pid), None)
        if entry:
            self._detail.show_entry(entry)

    # ── process actions ───────────────────────────────────────────────────────
    def _kill_process(self, pid: int, name: str) -> None:
        reply = QMessageBox.question(
            self,
            "Kill Process",
            f"Kill process '{name}' (PID {pid})?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            import psutil
            psutil.Process(pid).kill()
            self._status_lbl.setText(f"Killed process {name} (PID {pid})")
        except Exception as exc:
            QMessageBox.warning(self, "Kill Failed", str(exc))

    def _suspend_process(self, pid: int, name: str) -> None:
        try:
            import psutil
            proc = psutil.Process(pid)
            if proc.status() == psutil.STATUS_STOPPED:
                proc.resume()
                self._status_lbl.setText(f"Resumed {name} (PID {pid})")
            else:
                proc.suspend()
                self._status_lbl.setText(f"Suspended {name} (PID {pid})")
        except Exception as exc:
            QMessageBox.warning(self, "Suspend Failed", str(exc))

    def _open_in_explorer(self, exe_path: str) -> None:
        try:
            subprocess.Popen(["explorer", "/select,", exe_path])
        except Exception as exc:
            QMessageBox.warning(self, "Open Failed", str(exc))

    # ── export CSV ────────────────────────────────────────────────────────────
    def _export_csv(self) -> None:
        if not self._all_entries:
            QMessageBox.information(self, "No Data", "Run a scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "process_threats.csv", "CSV files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Threat", "Score", "PID", "Process", "EXE",
                    "Memory (MB)", "CPU %", "Connections", "Flags",
                    "Username", "Threads", "Started",
                ])
                for e in self._all_entries:
                    level, _ = _threat_level(e["score"])
                    ct = e.get("create_time", 0.0)
                    started = datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S") if ct else ""
                    writer.writerow([
                        level,
                        e["score"],
                        e.get("pid", ""),
                        e.get("name", ""),
                        e.get("exe", ""),
                        e.get("mem_mb", 0),
                        f'{e.get("cpu_percent", 0.0):.1f}',
                        e.get("connections", 0),
                        "; ".join(e.get("flags") or []),
                        e.get("username", ""),
                        e.get("num_threads", 0),
                        started,
                    ])
            self._status_lbl.setText(f"Exported to {path}")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))

    # ── auto-refresh ──────────────────────────────────────────────────────────
    def _toggle_auto_refresh(self) -> None:
        self._auto_refresh = self._auto_btn.isChecked()
        self._auto_btn.setText(
            "Auto-Refresh: ON" if self._auto_refresh else "Auto-Refresh: OFF"
        )
        self._auto_btn.setStyleSheet(self._auto_style(self._auto_refresh))

        if self._auto_refresh:
            if self._auto_timer is None:
                self._auto_timer = QTimer(self)
                self._auto_timer.timeout.connect(self._auto_scan_tick)
            self._auto_timer.start(60000)  # re-scan every 60s
        else:
            if self._auto_timer:
                self._auto_timer.stop()

    def _auto_scan_tick(self) -> None:
        if self._auto_refresh and not (self._worker and self._worker.isRunning()):
            self._start_scan()

    # ── cleanup ───────────────────────────────────────────────────────────────
    def _on_about_to_quit(self) -> None:
        if self._auto_timer:
            self._auto_timer.stop()
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(5000)
        self._worker = None

    # ── style helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _auto_style(on: bool) -> str:
        color = TEAL if on else BORDER
        text  = SURFACE if on else TEXT_MUTED
        return (
            f"QPushButton{{background:{color};color:{text};border:none;"
            f"border-radius:6px;padding:6px 14px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{border:1px solid rgba(255,255,255,40);}}"
        )
