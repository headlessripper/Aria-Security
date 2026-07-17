"""Memory Cleaner Page — advanced RAM optimizer with live stats, arc gauge,
breakdown bars, three cleaning modes, per-process trim, and auto-clean."""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import math
import struct
import time
from datetime import datetime

from PySide6.QtCore import (
    Qt, QThread, Signal, QTimer, QRectF, QPointF,
)
from PySide6.QtGui import (
    QColor, QFont, QPainter, QPen, QBrush,
    QPainterPath, QLinearGradient,
)
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QSizePolicy, QApplication, QScrollArea,
    QSpacerItem,
)

# ── Design tokens ────────────────────────────────────────────────────────────
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

# ── Windows API setup ─────────────────────────────────────────────────────────
kernel32 = ctypes.windll.kernel32
ntdll    = ctypes.windll.ntdll
psapi    = ctypes.windll.psapi
advapi32 = ctypes.windll.advapi32

PROCESS_SET_QUOTA                  = 0x0100
PROCESS_QUERY_LIMITED_INFORMATION  = 0x1000
SIZE_T_MAX                         = ctypes.c_size_t(-1).value

TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY             = 0x0008
SE_PRIVILEGE_ENABLED    = 0x00000002


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb",                ctypes.c_uint),
        ("CommitTotal",       ctypes.c_size_t),
        ("CommitLimit",       ctypes.c_size_t),
        ("CommitPeak",        ctypes.c_size_t),
        ("PhysicalTotal",     ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache",       ctypes.c_size_t),
        ("KernelTotal",       ctypes.c_size_t),
        ("KernelPaged",       ctypes.c_size_t),
        ("KernelNonpaged",    ctypes.c_size_t),
        ("PageSize",          ctypes.c_size_t),
        ("HandleCount",       ctypes.c_uint),
        ("ProcessCount",      ctypes.c_uint),
        ("ThreadCount",       ctypes.c_uint),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", wt.LARGE_INTEGER), ("Attributes", wt.DWORD)]
    _fields_ = [
        ("PrivilegeCount", wt.DWORD),
        ("Privileges",     LUID_AND_ATTRIBUTES * 1),
    ]


class SYSTEM_MEMORY_LIST_INFORMATION(ctypes.Structure):
    """Returned by NtQuerySystemInformation(80, ...) — gives actual page-type counts."""
    _fields_ = [
        ("ZeroPageCount",             ctypes.c_size_t),
        ("FreePageCount",             ctypes.c_size_t),
        ("ModifiedPageCount",         ctypes.c_size_t),
        ("ModifiedNoWritePageCount",  ctypes.c_size_t),
        ("BadPageCount",              ctypes.c_size_t),
        ("PageCountByPriority",       ctypes.c_size_t * 8),   # standby at each priority
        ("RepurposedPagesByPriority", ctypes.c_size_t * 8),
        ("ModifiedPageCountPageFile", ctypes.c_size_t),
    ]


# ── Pure helper functions (no Qt) ─────────────────────────────────────────────
def _enable_privilege(name: str) -> bool:
    """Enable a Windows privilege on the current process token."""
    try:
        h_token = wt.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token),
        ):
            return False
        luid = wt.LARGE_INTEGER()
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            kernel32.CloseHandle(h_token)
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ok = advapi32.AdjustTokenPrivileges(
            h_token, False, ctypes.byref(tp),
            ctypes.sizeof(tp), None, None,
        )
        kernel32.CloseHandle(h_token)
        return bool(ok)
    except Exception:
        return False


def _get_perf_info() -> PERFORMANCE_INFORMATION | None:
    """Return a PERFORMANCE_INFORMATION struct, or None on failure."""
    pi = PERFORMANCE_INFORMATION()
    pi.cb = ctypes.sizeof(PERFORMANCE_INFORMATION)
    if psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        return pi
    return None


def _get_memory_list_info() -> SYSTEM_MEMORY_LIST_INFORMATION | None:
    """Return live page-type counts via NtQuerySystemInformation(80).

    Gives accurate Modified and Standby page counts identical to what
    Windows Task Manager shows in its memory breakdown panel.
    Requires no special privileges for a read-only query.
    """
    try:
        buf = SYSTEM_MEMORY_LIST_INFORMATION()
        # STATUS_SUCCESS = 0; any other value means unsupported / access denied
        status = ntdll.NtQuerySystemInformation(
            80,                      # SystemMemoryListInformation
            ctypes.byref(buf),
            ctypes.sizeof(buf),
            None,
        )
        if status == 0:
            return buf
    except Exception:
        pass
    return None


def _trim_process(pid: int) -> bool:
    """Trim a single process's working set. Returns True on success."""
    try:
        handle = kernel32.OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_QUERY_LIMITED_INFORMATION,
            False,
            pid,
        )
        if not handle:
            return False
        result = kernel32.SetProcessWorkingSetSize(
            handle,
            ctypes.c_size_t(SIZE_T_MAX),
            ctypes.c_size_t(SIZE_T_MAX),
        )
        kernel32.CloseHandle(handle)
        return bool(result)
    except Exception:
        return False


def _fmt_bytes(n: int) -> str:
    """Human-readable byte size string."""
    if n < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.2f} {unit}" if unit not in ("B", "KB") else f"{n:.0f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


# ── Custom arc gauge ──────────────────────────────────────────────────────────
class _RamGauge(QWidget):
    """Custom arc-based RAM usage gauge, painted with QPainter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._percent: float = 0.0
        self.setFixedSize(180, 180)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

    def set_percent(self, pct: float) -> None:
        self._percent = max(0.0, min(100.0, pct))
        self.update()

    def paintEvent(self, event):  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(16, 16, 148, 148)

        # ── background track arc ──────────────────────────────────────────
        track_pen = QPen(QColor(BORDER))
        track_pen.setWidth(14)
        track_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(track_pen)
        # Qt angles: 0° = 3 o'clock, positive = counter-clockwise
        # We want 220° start (bottom-left) going -260° (clockwise)
        p.drawArc(rect, 220 * 16, -260 * 16)

        # ── value arc ────────────────────────────────────────────────────
        pct = self._percent
        if pct < 60:
            arc_color = QColor(GREEN)
        elif pct < 80:
            arc_color = QColor(ORANGE)
        else:
            arc_color = QColor(RED)

        value_pen = QPen(arc_color)
        value_pen.setWidth(14)
        value_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(value_pen)
        span = int(-260 * 16 * pct / 100)
        p.drawArc(rect, 220 * 16, span)

        # ── center text ───────────────────────────────────────────────────
        p.setPen(QColor(TEXT))
        font_big = QFont("Segoe UI", 22, QFont.Weight.Bold)
        p.setFont(font_big)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{pct:.0f}%")

        label_rect = QRectF(16, 106, 148, 40)
        font_sub = QFont("Segoe UI", 9)
        p.setFont(font_sub)
        p.setPen(QColor(TEXT_DIM))
        p.drawText(label_rect, Qt.AlignmentFlag.AlignCenter, "RAM USAGE")

        p.end()


# ── Memory breakdown bar ──────────────────────────────────────────────────────
class _MemBar(QWidget):
    """Single labelled horizontal memory breakdown bar."""

    def __init__(self, label: str, color: str, parent=None):
        super().__init__(parent)
        self._color = color
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        lbl = QLabel(label)
        lbl.setFixedWidth(72)
        lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        layout.addWidget(lbl)

        self._bar = QProgressBar()
        self._bar.setRange(0, 1000)
        self._bar.setValue(0)
        self._bar.setFixedHeight(10)
        self._bar.setTextVisible(False)
        self._bar.setStyleSheet(
            f"QProgressBar{{background:{SURFACE};border:1px solid {BORDER};"
            f"border-radius:5px;}}"
            f"QProgressBar::chunk{{background:{color};border-radius:4px;}}"
        )
        layout.addWidget(self._bar, 1)

        self._val_lbl = QLabel("0.00 GB")
        self._val_lbl.setFixedWidth(68)
        self._val_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self._val_lbl.setStyleSheet(f"color:{TEXT};font-size:11px;font-weight:600;")
        layout.addWidget(self._val_lbl)

    def set_value(self, value_bytes: int, total_bytes: int) -> None:
        if total_bytes > 0:
            ratio = max(0.0, min(1.0, value_bytes / total_bytes))
        else:
            ratio = 0.0
        self._bar.setValue(int(ratio * 1000))
        self._val_lbl.setText(f"{value_bytes / (1024**3):.2f} GB")


# ── Stat chip ─────────────────────────────────────────────────────────────────
class _StatChip(QFrame):
    """Small stat chip: large bold value + small label."""

    def __init__(self, label: str, color: str = TEXT, parent=None):
        super().__init__(parent)
        self._color = color
        self.setFixedHeight(60)
        self.setStyleSheet(
            f"QFrame{{background:{CARD};border:1px solid {BORDER};"
            f"border-radius:8px;}}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._val = QLabel("—")
        self._val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._val.setStyleSheet(
            f"color:{color};font-size:15px;font-weight:700;"
            f"border:none;background:transparent;"
        )
        layout.addWidget(self._val)

        lbl = QLabel(label)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl.setStyleSheet(
            f"color:{TEXT_MUTED};font-size:10px;border:none;background:transparent;"
        )
        layout.addWidget(lbl)

    def set_value(self, text: str) -> None:
        self._val.setText(text)


# ── Action card ───────────────────────────────────────────────────────────────
class _ActionCard(QFrame):
    """Cleaning action card with icon, name, description, last-freed info, and button."""

    clicked = Signal()

    def __init__(self, icon: str, name: str, desc: str, btn_color: str = ACCENT, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            f"QFrame{{background:{CARD};border:1px solid {BORDER};border-radius:10px;}}"
        )
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(140)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        # icon + name row
        top_row = QHBoxLayout()
        top_row.setSpacing(8)
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size:22px;background:transparent;border:none;")
        top_row.addWidget(icon_lbl)
        name_lbl = QLabel(name)
        name_lbl.setStyleSheet(
            f"color:{TEXT};font-size:13px;font-weight:700;"
            f"background:transparent;border:none;"
        )
        top_row.addWidget(name_lbl)
        top_row.addStretch()
        layout.addLayout(top_row)

        desc_lbl = QLabel(desc)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet(
            f"color:{TEXT_DIM};font-size:11px;background:transparent;border:none;"
        )
        layout.addWidget(desc_lbl)

        self._freed_lbl = QLabel("Last freed: —")
        self._freed_lbl.setStyleSheet(
            f"color:{TEXT_MUTED};font-size:10px;background:transparent;border:none;"
        )
        layout.addWidget(self._freed_lbl)

        layout.addStretch()

        self._btn = QPushButton("Run")
        self._btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn.setStyleSheet(
            f"QPushButton{{background:{btn_color};color:white;border:none;"
            f"border-radius:6px;padding:6px 18px;font-size:12px;font-weight:600;}}"
            f"QPushButton:hover{{border:1px solid rgba(255,255,255,40);}}"
            f"QPushButton:disabled{{background:{BORDER};color:{TEXT_MUTED};}}"
        )
        self._btn.clicked.connect(self.clicked)
        layout.addWidget(self._btn)

    def set_freed(self, n_bytes: int) -> None:
        self._freed_lbl.setText(f"Last freed: {_fmt_bytes(n_bytes)}")

    def set_running(self, running: bool) -> None:
        self._btn.setEnabled(not running)
        self._btn.setText("Running…" if running else "Run")

    def set_button_text(self, text: str) -> None:
        self._btn.setText(text)


# ── Cleaning worker ───────────────────────────────────────────────────────────
class _CleanWorker(QThread):
    """Background thread that performs memory cleaning operations."""
    progress  = Signal(str)   # status message
    done      = Signal(int)   # bytes_freed (approximate)
    failed    = Signal(str)   # error message

    def __init__(self, mode: str = "quick", parent=None):
        super().__init__(parent)
        self._mode = mode
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        try:
            self._do_clean()
        except Exception as exc:
            try:
                self.failed.emit(str(exc))
            except Exception:
                pass
        except BaseException:
            pass  # prevent any unhandled exception from reaching Qt's C++ run() wrapper

    def _do_clean(self) -> None:
        try:
            import psutil
            HAS_PSUTIL = True
        except ImportError:
            HAS_PSUTIL = False

        # ── measure free RAM before ───────────────────────────────────────
        vm_before = None
        if HAS_PSUTIL:
            import psutil as ps
            vm_before = ps.virtual_memory()

        trimmed = 0
        mode = self._mode

        # ── step 1: working set trim (all modes) ──────────────────────────
        self.progress.emit("Trimming process working sets…")
        if HAS_PSUTIL:
            import psutil as ps
            pids = [p.pid for p in ps.process_iter(["pid"])]
        else:
            pids = []  # psutil unavailable — skip working-set trim

        if HAS_PSUTIL:
            for pid in pids:
                if not self._running:
                    break
                if _trim_process(pid):
                    trimmed += 1
            self.progress.emit(f"Trimmed {trimmed} processes.")

        if not self._running:
            self.done.emit(0)
            return

        if mode in ("deep", "smart"):
            # ── step 2: enable privilege ──────────────────────────────────
            self.progress.emit("Enabling memory privileges…")
            _enable_privilege("SeProfileSingleProcessPrivilege")
            _enable_privilege("SeIncreaseQuotaPrivilege")

            # ── step 3: flush modified page list (cmd=0) ──────────────────
            self.progress.emit("Flushing modified page list…")
            cmd = ctypes.c_uint(0)
            ret = ntdll.NtSetSystemInformation(80, ctypes.byref(cmd), 4)
            if ret != 0:
                self.progress.emit(f"Flush modified: status 0x{ret & 0xFFFFFFFF:08X} (may need elevation)")

            if not self._running:
                self.done.emit(0)
                return

            # ── step 4: purge standby list (cmd=2) ────────────────────────
            self.progress.emit("Purging standby list…")
            cmd = ctypes.c_uint(2)
            ret = ntdll.NtSetSystemInformation(80, ctypes.byref(cmd), 4)
            if ret != 0:
                self.progress.emit(f"Purge standby: status 0x{ret & 0xFFFFFFFF:08X} (needs elevation)")

        if mode == "smart" and self._running:
            # ── step 5: compact file system cache ─────────────────────────
            self.progress.emit("Compacting file system cache…")
            FILE_CACHE_MIN_HARD_ENABLE = 0x1
            FILE_CACHE_MAX_HARD_ENABLE = 0x2
            kernel32.SetSystemFileCacheSize(
                ctypes.c_size_t(0),
                ctypes.c_size_t(0),
                ctypes.c_ulong(FILE_CACHE_MIN_HARD_ENABLE | FILE_CACHE_MAX_HARD_ENABLE),
            )

        # ── measure freed RAM ─────────────────────────────────────────────
        freed_bytes = 0
        if HAS_PSUTIL and vm_before is not None:
            import psutil as ps
            self.msleep(800)
            vm_after = ps.virtual_memory()
            freed_bytes = max(0, vm_after.available - vm_before.available)

        self.done.emit(freed_bytes)


# ── Stats worker ──────────────────────────────────────────────────────────────
class _StatsWorker(QThread):
    """Background thread that polls memory stats every 2 seconds."""
    updated = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True

    def stop(self) -> None:
        self._running = False

    def run(self) -> None:
        try:
            import psutil as ps
        except ImportError:
            return

        while self._running:
            try:
                vm = ps.virtual_memory()
                pi = _get_perf_info()

                page_size = pi.PageSize if pi else 4096
                sys_cache_bytes = (pi.SystemCache * page_size) if pi else 0

                top_procs: list[dict] = []
                for proc in sorted(
                    ps.process_iter(["pid", "name", "memory_info"]),
                    key=lambda p: (p.info.get("memory_info") or type("_", (), {"rss": 0})()).rss,
                    reverse=True,
                )[:25]:
                    try:
                        mi = proc.info.get("memory_info")
                        if mi is None:
                            continue
                        rss = mi.rss
                        private = getattr(mi, "private", 0) or 0
                        top_procs.append({
                            "pid":     proc.pid,
                            "name":    proc.info.get("name") or "Unknown",
                            "rss":     rss,
                            "private": private,
                            "pct":     rss / vm.total * 100 if vm.total else 0,
                        })
                    except Exception:
                        pass

                # Query accurate page-type counts for modified/standby bars
                ml = _get_memory_list_info()
                page = pi.PageSize if pi else 4096
                if ml:
                    modified_bytes = ml.ModifiedPageCount * page
                    standby_bytes  = sum(ml.PageCountByPriority) * page
                else:
                    modified_bytes = 0
                    standby_bytes  = sys_cache_bytes   # best fallback

                self.updated.emit({
                    "total":          vm.total,
                    "used":           vm.used,
                    "available":      vm.available,
                    "percent":        vm.percent,
                    "cached":         getattr(vm, "cached", 0),
                    "sys_cache":      sys_cache_bytes,
                    "modified_bytes": modified_bytes,
                    "standby_bytes":  standby_bytes,
                    "pi":             pi,
                    "top_procs":      top_procs,
                })
            except Exception:
                pass
            except BaseException:
                break   # unrecoverable; exit cleanly instead of propagating to C++
            self.msleep(2000)


# ── Main page ─────────────────────────────────────────────────────────────────
class MemoryCleanerPage(QWidget):
    """Advanced RAM optimizer page."""

    def __init__(self, parent=None):
        super().__init__(parent)

        self._auto_clean_armed: bool = False
        self._auto_timer: QTimer | None = None
        self._clean_worker: _CleanWorker | None = None
        self._stats_worker: _StatsWorker | None = None
        self._last_vm: dict = {}
        self._psutil_ok: bool = False

        # Check psutil availability
        try:
            import psutil  # noqa: F401
            self._psutil_ok = True
        except ImportError:
            pass

        # ── Outer layout hosts only the scroll area (no content margins) ──
        _outer = QVBoxLayout(self)
        _outer.setContentsMargins(0, 0, 0, 0)
        _outer.setSpacing(0)

        _scroll = QScrollArea()
        _scroll.setWidgetResizable(True)
        _scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        _scroll.setStyleSheet(
            "QScrollArea{border:none;background:transparent;}"
            f"QScrollBar:vertical{{background:{SURFACE};width:8px;border-radius:4px;}}"
            f"QScrollBar::handle:vertical{{background:{BORDER};border-radius:4px;}}"
            "QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0px;}"
        )
        _outer.addWidget(_scroll)

        _content = QWidget()
        _scroll.setWidget(_content)

        # All builders write into this inner layout — same API, no change needed
        root = QVBoxLayout(_content)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)

        self._build_header(root)
        self._build_stats_row(root)
        self._build_chips_row(root)
        self._build_actions_row(root)
        if self._psutil_ok:
            self._build_process_table(root)
        else:
            warn = QLabel("psutil is not installed — process list unavailable.")
            warn.setStyleSheet(f"color:{ORANGE};font-size:11px;")
            root.addWidget(warn)
        self._build_status_bar(root)
        root.addStretch()  # push all widgets to the top; prevents vertical stretching

        # ── wire app quit ─────────────────────────────────────────────────
        app = QApplication.instance()
        if app:
            app.aboutToQuit.connect(self._on_about_to_quit)

        # ── start stats worker ────────────────────────────────────────────
        if self._psutil_ok:
            self._stats_worker = _StatsWorker()
            self._stats_worker.updated.connect(self._on_stats)
            self._stats_worker.start()

    # ── layout builders ───────────────────────────────────────────────────────
    def _build_header(self, root: QVBoxLayout) -> None:
        hdr = QHBoxLayout()
        hdr.setSpacing(12)

        title = QLabel("Memory Optimizer")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setStyleSheet(f"color:{TEXT};")
        hdr.addWidget(title)
        hdr.addStretch()

        self._last_cleaned_lbl = QLabel("Last cleaned: Never")
        self._last_cleaned_lbl.setStyleSheet(f"color:{TEXT_DIM};font-size:11px;")
        hdr.addWidget(self._last_cleaned_lbl)

        # Auto-clean toggle button
        self._auto_btn = QPushButton("Auto-Clean: OFF")
        self._auto_btn.setCheckable(True)
        self._auto_btn.setFixedHeight(32)
        self._auto_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._auto_btn.setStyleSheet(self._auto_btn_style(False))
        self._auto_btn.clicked.connect(self._toggle_auto_clean)
        hdr.addWidget(self._auto_btn)

        root.addLayout(hdr)

    def _build_stats_row(self, root: QVBoxLayout) -> None:
        row = QHBoxLayout()
        row.setSpacing(16)

        # Gauge
        gauge_frame = QFrame()
        gauge_frame.setStyleSheet(
            f"QFrame{{background:{CARD};border:1px solid {BORDER};border-radius:10px;}}"
        )
        gauge_layout = QVBoxLayout(gauge_frame)
        gauge_layout.setContentsMargins(10, 10, 10, 10)
        gauge_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._gauge = _RamGauge()
        gauge_layout.addWidget(self._gauge, 0, Qt.AlignmentFlag.AlignCenter)
        gauge_frame.setFixedWidth(200)
        row.addWidget(gauge_frame)

        # Breakdown bars
        bars_frame = QFrame()
        bars_frame.setStyleSheet(
            f"QFrame{{background:{CARD};border:1px solid {BORDER};border-radius:10px;}}"
        )
        bars_layout = QVBoxLayout(bars_frame)
        bars_layout.setContentsMargins(16, 14, 16, 14)
        bars_layout.setSpacing(10)

        breakdown_title = QLabel("Memory Breakdown")
        breakdown_title.setStyleSheet(
            f"color:{TEXT};font-size:12px;font-weight:700;background:transparent;border:none;"
        )
        bars_layout.addWidget(breakdown_title)

        self._bar_inuse    = _MemBar("In Use",    "#c0392b")
        self._bar_modified = _MemBar("Modified",  ORANGE)
        self._bar_standby  = _MemBar("Standby",   ACCENT)
        self._bar_free     = _MemBar("Free",      GREEN)
        self._bar_cache    = _MemBar("File Cache", TEAL)

        for bar in (
            self._bar_inuse, self._bar_modified,
            self._bar_standby, self._bar_free, self._bar_cache,
        ):
            bars_layout.addWidget(bar)

        row.addWidget(bars_frame, 1)
        root.addLayout(row)

    def _build_chips_row(self, root: QVBoxLayout) -> None:
        row = QHBoxLayout()
        row.setSpacing(10)

        self._chip_total  = _StatChip("Total",  TEXT)
        self._chip_used   = _StatChip("Used",   RED)
        self._chip_free   = _StatChip("Free",   GREEN)
        self._chip_cached = _StatChip("Cached", TEAL)

        for chip in (
            self._chip_total, self._chip_used,
            self._chip_free, self._chip_cached,
        ):
            row.addWidget(chip, 1)

        root.addLayout(row)

    def _build_actions_row(self, root: QVBoxLayout) -> None:
        lbl = QLabel("Cleaning Actions")
        lbl.setStyleSheet(f"color:{TEXT};font-size:13px;font-weight:700;")
        root.addWidget(lbl)

        row = QHBoxLayout()
        row.setSpacing(12)

        self._card_quick = _ActionCard(
            "⚡", "Quick Clean",
            "Trims working sets for all accessible processes. "
            "No elevation required. Fast and safe.",
            btn_color=GREEN,
        )
        self._card_deep = _ActionCard(
            "🔥", "Deep Clean",
            "Quick Clean + flush modified page list + purge standby list. "
            "Requires elevation for full effect.",
            btn_color=ORANGE,
        )
        self._card_smart = _ActionCard(
            "🧠", "Smart Optimize",
            "Deep Clean + compact file system cache. "
            "Maximum memory recovery. Run as Administrator.",
            btn_color=ACCENT,
        )

        self._card_quick.clicked.connect(lambda: self._start_clean("quick"))
        self._card_deep.clicked.connect(lambda: self._start_clean("deep"))
        self._card_smart.clicked.connect(lambda: self._start_clean("smart"))

        row.addWidget(self._card_quick)
        row.addWidget(self._card_deep)
        row.addWidget(self._card_smart)
        root.addLayout(row)

    def _build_process_table(self, root: QVBoxLayout) -> None:
        tbl_lbl = QLabel("Top Memory Consumers")
        tbl_lbl.setStyleSheet(f"color:{TEXT};font-size:13px;font-weight:700;")
        root.addWidget(tbl_lbl)

        self._proc_table = QTableWidget(0, 6)
        self._proc_table.setHorizontalHeaderLabels(
            ["Process", "PID", "Working Set", "Private", "% RAM", "Trim"]
        )
        self._proc_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        self._proc_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self._proc_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self._proc_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self._proc_table.horizontalHeader().setSectionResizeMode(
            4, QHeaderView.ResizeMode.ResizeToContents
        )
        self._proc_table.horizontalHeader().setSectionResizeMode(
            5, QHeaderView.ResizeMode.ResizeToContents
        )
        self._proc_table.verticalHeader().setVisible(False)
        self._proc_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._proc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._proc_table.setFixedHeight(220)
        self._proc_table.setStyleSheet(f"""
            QTableWidget{{
                background:{CARD};color:{TEXT};border:1px solid {BORDER};
                border-radius:8px;gridline-color:{BORDER};
            }}
            QHeaderView::section{{
                background:{CARD};color:{TEXT_DIM};font-size:11px;font-weight:600;
                border:none;border-bottom:1px solid {BORDER};padding:5px 8px;
            }}
            QTableWidget::item{{padding:4px 8px;border:none;}}
            QTableWidget::item:selected{{background:{ACCENT}22;color:{TEXT};}}
        """)
        root.addWidget(self._proc_table)

    def _build_status_bar(self, root: QVBoxLayout) -> None:
        self._status_bar = QLabel("Ready")
        self._status_bar.setStyleSheet(
            f"color:{TEXT_DIM};font-size:11px;"
            f"background:{SURFACE};border-top:1px solid {BORDER};"
            f"padding:4px 8px;border-radius:4px;"
        )
        root.addWidget(self._status_bar)

    # ── slots ─────────────────────────────────────────────────────────────────
    def _on_stats(self, data: dict) -> None:
        self._last_vm = data
        total    = data["total"]
        used     = data["used"]
        avail    = data["available"]
        cached   = data["cached"]
        percent  = data["percent"]
        pi       = data.get("pi")

        self._gauge.set_percent(percent)

        # chips
        self._chip_total.set_value(f"{total / (1024**3):.1f} GB")
        self._chip_used.set_value(f"{used / (1024**3):.1f} GB")
        self._chip_free.set_value(f"{avail / (1024**3):.1f} GB")
        self._chip_cached.set_value(f"{cached / (1024**3):.1f} GB")

        # breakdown bars — use the accurate page-type counts from NtQuerySystemInformation
        modified_bytes = data.get("modified_bytes", 0)
        standby_bytes  = data.get("standby_bytes",  0)
        inuse          = max(0, used - data.get("sys_cache", 0))
        free           = avail
        sys_cache      = data.get("sys_cache", 0)

        self._bar_inuse.set_value(inuse,          total)
        self._bar_modified.set_value(modified_bytes, total)
        self._bar_standby.set_value(standby_bytes,   total)
        self._bar_free.set_value(free,             total)
        self._bar_cache.set_value(sys_cache,       total)

        # process table
        top = data.get("top_procs", [])
        if hasattr(self, "_proc_table"):
            self._proc_table.setRowCount(0)
            self._proc_table.setSortingEnabled(False)
            for entry in top:
                r = self._proc_table.rowCount()
                self._proc_table.insertRow(r)

                name_item = QTableWidgetItem(entry["name"])
                pid_item  = QTableWidgetItem(str(entry["pid"]))
                rss_item  = QTableWidgetItem(_fmt_bytes(entry["rss"]))
                priv_item = QTableWidgetItem(_fmt_bytes(entry["private"]))
                pct_item  = QTableWidgetItem(f'{entry["pct"]:.2f}%')

                for col, item in enumerate(
                    [name_item, pid_item, rss_item, priv_item, pct_item]
                ):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
                    self._proc_table.setItem(r, col, item)

                # Trim button
                trim_btn = QPushButton("Trim")
                trim_btn.setFixedSize(52, 22)
                trim_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                trim_btn.setStyleSheet(
                    f"QPushButton{{background:{SURFACE};color:{TEXT_DIM};border:1px solid {BORDER};"
                    f"border-radius:4px;font-size:10px;padding:0px;}}"
                    f"QPushButton:hover{{background:{ACCENT};color:white;border-color:{ACCENT};}}"
                )
                pid_val = entry["pid"]
                trim_btn.clicked.connect(lambda checked=False, p=pid_val: self._trim_single(p))
                self._proc_table.setCellWidget(r, 5, trim_btn)

            self._proc_table.setSortingEnabled(True)

        # auto-clean check
        if self._auto_clean_armed:
            free_pct = (avail / total * 100) if total else 100
            if free_pct < 20:
                self._start_clean("quick")

    def _trim_single(self, pid: int) -> None:
        ok = _trim_process(pid)
        if ok:
            self._set_status(f"Trimmed process PID {pid}")
        else:
            self._set_status(f"Could not trim PID {pid} (access denied?)")

    def _start_clean(self, mode: str) -> None:
        if self._clean_worker and self._clean_worker.isRunning():
            return

        for card in (self._card_quick, self._card_deep, self._card_smart):
            card.set_running(True)

        self._set_status(f"Starting {mode} clean…")

        self._clean_worker = _CleanWorker(mode=mode)
        self._clean_worker.progress.connect(self._set_status)
        self._clean_worker.done.connect(lambda b, m=mode: self._on_clean_done(b, m))
        self._clean_worker.failed.connect(self._on_clean_failed)
        self._clean_worker.start()

    def _on_clean_done(self, freed_bytes: int, mode: str) -> None:
        self._clean_worker = None
        for card in (self._card_quick, self._card_deep, self._card_smart):
            card.set_running(False)

        now = datetime.now().strftime("%H:%M:%S")
        self._last_cleaned_lbl.setText(f"Last cleaned: {now} — freed {_fmt_bytes(freed_bytes)}")

        card_map = {"quick": self._card_quick, "deep": self._card_deep, "smart": self._card_smart}
        if mode in card_map:
            card_map[mode].set_freed(freed_bytes)

        self._set_status(f"Done — freed {_fmt_bytes(freed_bytes)}")

    def _on_clean_failed(self, msg: str) -> None:
        self._clean_worker = None
        for card in (self._card_quick, self._card_deep, self._card_smart):
            card.set_running(False)
        self._set_status(f"Error: {msg}")

    def _toggle_auto_clean(self) -> None:
        self._auto_clean_armed = self._auto_btn.isChecked()
        self._auto_btn.setText(
            "Auto-Clean: ARMED" if self._auto_clean_armed else "Auto-Clean: OFF"
        )
        self._auto_btn.setStyleSheet(self._auto_btn_style(self._auto_clean_armed))

    def _set_status(self, msg: str) -> None:
        self._status_bar.setText(msg)

    def _on_about_to_quit(self) -> None:
        if self._stats_worker:
            self._stats_worker.stop()
            self._stats_worker.wait(3000)
        if self._clean_worker:
            self._clean_worker.stop()
            self._clean_worker.wait(3000)

    # ── style helpers ─────────────────────────────────────────────────────────
    @staticmethod
    def _auto_btn_style(armed: bool) -> str:
        color = ORANGE if armed else BORDER
        text  = TEXT if armed else TEXT_MUTED
        return (
            f"QPushButton{{background:{color};color:{text};border:none;"
            f"border-radius:6px;padding:4px 12px;font-size:11px;font-weight:600;}}"
            f"QPushButton:hover{{border:1px solid rgba(255,255,255,40);}}"
        )
