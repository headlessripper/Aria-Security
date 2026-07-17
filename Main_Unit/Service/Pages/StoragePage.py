from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QProgressBar, QListWidget, QListWidgetItem,
    QDialog, QGraphicsOpacityEffect
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QRectF, QTimer, QEasingCurve, QPropertyAnimation
)
from PySide6.QtGui import QPainter, QColor
import psutil
import os
import sys
import ctypes
from pathlib import Path
import hashlib

from Main_Unit.Service.Pages.Style_Qss.qss import qss

# optional WMI import for drive metadata (Windows only)
try:
    import wmi  # pip install wmi
    HAS_WMI = True
except Exception:
    HAS_WMI = False


# ===================== Custom storage visualizer =====================

class StorageVisualizerBar(QWidget):
    """
    Multi-segment bar:
    user (red), apps (orange), system (blue), recycle (green),
    other (light gray), free (dark gray).
    Styled as a pill for a dark dashboard.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(32)
        self.setMaximumHeight(36)
        self._total = 0
        self._user = 0
        self._app = 0
        self._system = 0
        self._recycle = 0
        self._other = 0
        self._free = 0

    def set_segments(self, *, total, user_b, app_b, sys_b, rec_b, other_b, free_b):
        self._total = max(int(total), 1)
        self._user = max(int(user_b), 0)
        self._app = max(int(app_b), 0)
        self._system = max(int(sys_b), 0)
        self._recycle = max(int(rec_b), 0)
        self._other = max(int(other_b), 0)
        self._free = max(int(free_b), 0)
        self.update()

    def paintEvent(self, event):
        if self._total <= 0:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)

        rect = self.rect().adjusted(2, 2, -2, -2)
        radius = rect.height() / 2

        # dark pill background
        painter.setBrush(QColor(20, 22, 30))
        painter.setPen(QColor(35, 40, 55))
        painter.drawRoundedRect(rect, radius, radius)

        inner = rect.adjusted(3, 3, -3, -3)
        total_width = inner.width()

        def draw_segment(x_offset, bytes_size, color: QColor):
            if bytes_size <= 0:
                return x_offset
            w = total_width * (bytes_size / self._total)
            if w < 1:
                return x_offset
            seg_rect = QRectF(inner.x() + x_offset, inner.y(), w, inner.height())
            painter.setBrush(color)
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(
                seg_rect,
                inner.height() / 2,
                inner.height() / 2
            )
            return x_offset + w

        x = 0.0
        x = draw_segment(x, self._user, QColor("#f97373"))      # user
        x = draw_segment(x, self._app, QColor("#fb923c"))       # apps
        x = draw_segment(x, self._system, QColor("#3b82f6"))    # system
        x = draw_segment(x, self._recycle, QColor("#22c55e"))   # recycle
        x = draw_segment(x, self._other, QColor("#9ca3af"))     # other
        x = draw_segment(x, self._free, QColor("#4b5563"))      # free


# ===================== Helpers =====================

def _make_card(obj_name: str = "SideCard") -> QWidget:
    card = QWidget()
    card.setObjectName(obj_name)
    v = QVBoxLayout(card)
    v.setContentsMargins(18, 16, 18, 16)
    v.setSpacing(8)
    return card


def _get_recycle_bin_size_for_c() -> int:
    """
    Compute total size of files in C: recycle bin.
    """
    if not sys.platform.startswith("win"):
        return 0
    size = 0
    candidates = [
        Path(os.environ.get("SystemDrive", "C:")) / "$Recycle.Bin",
        Path("C:/$Recycle.Bin"),
    ]
    for base in candidates:
        if not base.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                try:
                    size += fpath.stat().st_size
                except Exception:
                    pass
    return size


def _get_drive_metadata_c():
    """
    Returns (label, model, media_type_str) for C: using WMI when possible.
    media_type_str is 'SSD', 'HDD', or 'Unknown'.
    """
    label = "Local Disk (C:)"
    model = "Generic Disk"
    media = "Unknown"

    if not (sys.platform.startswith("win") and HAS_WMI):
        return label, model, media

    try:
        c = wmi.WMI()

        # logical disk label
        for ld in c.Win32_LogicalDisk(DeviceID="C:"):
            vol = getattr(ld, "VolumeName", None)
            if vol:
                label = f"{vol} (C:)"

        # map logical C: to partition and physical disk
        logical_to_partition = {}
        for assoc in c.Win32_LogicalDiskToPartition():
            ld = assoc.Dependent
            part = assoc.Antecedent
            logical_to_partition[ld.DeviceID] = part.DeviceID

        partition_to_diskindex = {}
        for part in c.Win32_DiskPartition():
            partition_to_diskindex[part.DeviceID] = part.DiskIndex

        disk_index = None
        part_id = logical_to_partition.get("C:")
        if part_id in partition_to_diskindex:
            disk_index = partition_to_diskindex[part_id]

        if disk_index is not None:
            for disk in c.Win32_DiskDrive():
                if getattr(disk, "Index", None) == disk_index:
                    m = getattr(disk, "Model", "") or ""
                    if m.strip():
                        model = m.strip()

                    # MediaType and Model may hint HDD vs SSD
                    mtype = getattr(disk, "MediaType", "") or ""
                    full = f"{mtype} {model}".lower()
                    if "ssd" in full:
                        media = "SSD"
                    elif "fixed" in full or "hard" in full or "hdd" in full:
                        media = "HDD"
                    else:
                        bus = getattr(disk, "InterfaceType", "") or ""
                        if "nvme" in bus.lower():
                            media = "SSD"
                        elif "scsi" in bus.lower() or "sata" in bus.lower():
                            media = "HDD"
                    break
    except Exception:
        pass

    return label, model, media


# ===================== Quick scan worker (fast, approximate) =====================

class QuickScanWorker(QThread):
    """
    Very fast scan to get initial segments:
    uses psutil.disk_usage and recycle-bin size, no file walk.
    """
    quick_finished = Signal(dict)

    def __init__(self, drive_root: str = "C:\\", parent=None):
        super().__init__(parent)
        self.drive_root = drive_root

    def run(self):
        usage = psutil.disk_usage(self.drive_root)
        total = usage.total
        used = usage.used
        free = usage.free

        recycle_bytes = _get_recycle_bin_size_for_c()

        # treat recycle as part of used
        used_minus_recycle = max(used - recycle_bytes, 0)

        user_b = int(used_minus_recycle * 0.40)
        app_b = int(used_minus_recycle * 0.25)
        sys_b = int(used_minus_recycle * 0.25)
        other_b = used_minus_recycle - (user_b + app_b + sys_b)

        summary = {
            "total_bytes": total,
            "user_bytes": user_b,
            "app_bytes": app_b,
            "system_bytes": sys_b,
            "recycle_bytes": recycle_bytes,
            "other_bytes": other_b,
            "free_bytes": free,
        }
        self.quick_finished.emit(summary)


# ===================== Deep clean + classify worker =====================

class DeepCleanWorker(QThread):
    """
    Deep scan that only traverses user directories and classifies bytes into:
    user / recycle / other, estimates junk, and finds duplicate groups by full hash.
    System directories (Windows, Program Files, drivers, etc.) are not scanned.
    """
    scan_finished = Signal(dict)
    progress_updated = Signal(int, str)

    # tuning knobs for performance
    MAX_ESTIMATED_FILES = 400_000      # used to scale progress
    MAX_TOTAL_FILES = 800_000          # hard cap to avoid insane scans
    MIN_DUP_SIZE = 1 * 1024 * 1024     # only consider duplicates >= 1 MB
    MAX_BUCKET_FILES = 200             # max files per same-size bucket to hash

    # conservative junk extension set; system/installer types explicitly excluded
    JUNK_EXTENSIONS = {
        ".tmp", ".temp", ".log", ".old", ".bak", ".dmp",
        ".chk", ".gid", ".~mp", ".~tmp", ".cache"
    }
    # directories whose content is typically junk (under user profile)
    JUNK_DIR_KEYWORDS = {
        "temp", "tmp", "cache", "caches", "logs", "log", "__pycache__"
    }
    # system/installer/library extensions that should NEVER be treated as junk
    PROTECTED_EXTENSIONS = {
        # core executable / script / library
        ".exe", ".dll", ".sys", ".drv", ".ocx",
        ".bat", ".cmd", ".com", ".scr",
        ".js", ".py"

        # installers / packages / drivers / firmware
        ".msi", ".efi",

        # data / assets / configs / models
        ".dat", ".bin", ".pak", ".pma", ".json",
        ".wasm", ".onnx",

        # web / image assets that may be required
        ".svg", ".gif",

        # catch-all: files with no extension at all (important configs/binaries)
        ""
    }

    def __init__(self, drive_root: str = "C:\\", parent=None):
        super().__init__(parent)
        self.drive_root = drive_root
        self._running = True

        # define user-root(s) we will scan; by default the current user's home only
        self.user_roots = [Path(os.path.expanduser("~"))]

    def stop(self):
        self._running = False

    def _is_under_user_root(self, path: Path) -> bool:
        for root in self.user_roots:
            try:
                if path.is_relative_to(root):
                    return True
            except Exception:
                continue
        return False

    def _is_junk_file(self, fpath: Path) -> bool:
        """
        Decide whether a file is considered junk, using:
        - directory names (temp/cache/log, etc.)
        - file extension (tmp, bak, log, etc.)
        Protected extensions always return False.
        """
        suffix = fpath.suffix.lower()
        if suffix in self.PROTECTED_EXTENSIONS:
            return False

        # directory-based junk: any ancestor directory containing typical junk keywords
        for part in (p.lower() for p in fpath.parts):
            if part in self.JUNK_DIR_KEYWORDS:
                # still do not mark explicitly protected extensions as junk
                return suffix in self.JUNK_EXTENSIONS or suffix == ""
        # extension-based junk
        return suffix in self.JUNK_EXTENSIONS

    def run(self):
        total_bytes = 0
        user_bytes = 0
        app_bytes = 0
        system_bytes = 0
        other_bytes = 0
        junk_bytes = 0

        size_buckets: dict[int, list[Path]] = {}

        scanned = 0

        # walk only inside each user root, never full C:\
        for user_root in self.user_roots:
            root = user_root
            if not root.exists():
                continue

            for dirpath, dirnames, filenames in os.walk(root):
                if not self._running:
                    break

                path_obj = Path(dirpath)

                # skip any .git or similar heavy VCS metadata folders if you want
                # (you can add '.git', '.hg', '.svn', etc. here)
                # quick example:
                dirnames[:] = [d for d in dirnames if d.lower() not in {".git", ".hg", ".svn", ".idea"}]

                for fname in filenames:
                    if not self._running:
                        break

                    fpath = path_obj / fname
                    try:
                        st = fpath.stat()
                        size = st.st_size
                    except Exception:
                        continue

                    total_bytes += size
                    scanned += 1

                    # classification: everything we scan here is under user root
                    user_bytes += size

                    # junk detection (directory + extension based, with protected list)
                    try:
                        if self._is_junk_file(fpath):
                            junk_bytes += size
                    except Exception:
                        pass

                    # duplicates: only track files big enough
                    if size >= self.MIN_DUP_SIZE:
                        bucket = size_buckets.setdefault(size, [])
                        if len(bucket) < self.MAX_BUCKET_FILES:
                            bucket.append(fpath)

                    if scanned % 5000 == 0:
                        pct = int(min(70, scanned / self.MAX_ESTIMATED_FILES * 100))
                        self.progress_updated.emit(
                            pct,
                            f"Scanning user files… {scanned:,} files"
                        )

                    if scanned >= self.MAX_TOTAL_FILES:
                        self.progress_updated.emit(
                            72,
                            f"Reached scan limit at {scanned:,} files, stopping early"
                        )
                        self._running = False
                        break

                if not self._running:
                    break

        # we are not walking system folders at all, so app_bytes/system_bytes/other_bytes stay 0
        recycle_bytes = _get_recycle_bin_size_for_c()
        total_bytes += recycle_bytes

        # duplicate computation with its own progress slice (from 70 to 95)
        dup_bytes, dup_groups = self._compute_duplicates(size_buckets, start_pct=70, end_pct=95)

        summary = {
            "total_bytes": total_bytes,
            "user_bytes": user_bytes,
            "app_bytes": app_bytes,
            "system_bytes": system_bytes,
            "recycle_bytes": recycle_bytes,
            "other_bytes": other_bytes,
            "junk_bytes": junk_bytes,
            "dup_bytes": dup_bytes,
            "dup_groups": dup_groups,
        }
        self.progress_updated.emit(100, "Scan complete")
        self.scan_finished.emit(summary)

    def _compute_duplicates(self, size_buckets: dict[int, list[Path]], start_pct: int = 70, end_pct: int = 95):
        dup_bytes = 0
        groups: list[list[str]] = []

        bucket_sizes = [len(v) for v in size_buckets.values() if len(v) > 1]
        total_to_hash = sum(bucket_sizes) or 1
        hashed_count = 0

        for size, paths in size_buckets.items():
            if len(paths) < 2:
                continue

            if not self._running:
                break

            by_hash: dict[str, list[Path]] = {}
            for p in paths:
                if not self._running:
                    break
                try:
                    h = self._hash_file(p)
                except Exception:
                    continue
                bucket = by_hash.setdefault(h, [])
                bucket.append(p)

                hashed_count += 1
                if hashed_count % 50 == 0:
                    frac = hashed_count / total_to_hash
                    pct = start_pct + int(frac * (end_pct - start_pct))
                    self.progress_updated.emit(
                        pct,
                        f"Analyzing duplicates… {hashed_count:,} candidate files"
                    )

            for h, dups in by_hash.items():
                if len(dups) > 1:
                    dup_bytes += size * (len(dups) - 1)
                    groups.append([str(p) for p in dups])

        return dup_bytes, groups

    @staticmethod
    def _hash_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
        sha = hashlib.sha1()
        with path.open("rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                sha.update(data)
        return sha.hexdigest()


# ===================== Storage page =====================

class StoragePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setStyleSheet(qss)

        self.worker: DeepCleanWorker | None = None
        self.quick_worker: QuickScanWorker | None = None
        self._last_summary: dict | None = None
        self._overlay_timer: QTimer | None = None
        self._overlay_dot_state = 0
        self._scan_popup: QDialog | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        # Header
        title = QLabel("C: Storage")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        subtitle = QLabel("Usage overview, breakdown, and deep clean tools.")
        subtitle.setObjectName("PageHint")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # ===== Overview card (legend + visualizer + total) =====
        self.overview_card = _make_card("SideCard")
        ov = self.overview_card.layout()

        overview_header_row = QHBoxLayout()
        ov_title = QLabel("Overview")
        ov_title.setObjectName("SectionTitle")
        overview_header_row.addWidget(ov_title)

        c_drive = Path("C:/")
        usage = psutil.disk_usage(str(c_drive))
        total_gb = usage.total / (1024**3)

        total_label = QLabel(f"Total: {total_gb:.1f} GB")
        total_label.setObjectName("PageHint")
        overview_header_row.addStretch()
        overview_header_row.addWidget(total_label)
        ov.addLayout(overview_header_row)

        legend_row = QHBoxLayout()
        legend_row.setSpacing(12)

        def legend_item(color_hex: str, text: str) -> QWidget:
            w = QWidget()
            h = QHBoxLayout(w)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(4)
            color_box = QLabel()
            color_box.setFixedSize(10, 10)
            color_box.setStyleSheet(
                f"QLabel {{ background-color: {color_hex}; border-radius: 2px; }}"
            )
            label = QLabel(text)
            label.setObjectName("PageHint")
            h.addWidget(color_box)
            h.addWidget(label)
            return w

        legend_row.addWidget(legend_item("#f97373", "User files"))
        legend_row.addWidget(legend_item("#fb923c", "Apps"))
        legend_row.addWidget(legend_item("#3b82f6", "System"))
        legend_row.addWidget(legend_item("#22c55e", "Recycle Bin"))
        legend_row.addWidget(legend_item("#9ca3af", "Other"))
        legend_row.addWidget(legend_item("#4b5563", "Free"))
        legend_row.addStretch()
        ov.addLayout(legend_row)

        self.viz_bar = StorageVisualizerBar()
        self.viz_bar.setObjectName("StorageVisualizerBar")
        ov.addWidget(self.viz_bar)

        used_gb = usage.used / (1024**3)
        free_gb = usage.free / (1024**3)
        percent = usage.percent
        dev_lbl = QLabel(
            f"Used {used_gb:.1f} GB · Free {free_gb:.1f} GB ({percent:.1f} %)"
        )
        dev_lbl.setObjectName("PageHint")
        dev_lbl.setWordWrap(True)
        ov.addWidget(dev_lbl)

        layout.addWidget(self.overview_card)

        self._scanning_label = QLabel("Scanning")
        self._scanning_label.setObjectName("OverviewScanningLabel")
        self._scanning_label.setAlignment(Qt.AlignCenter)
        self._scanning_label.hide()
        ov.addWidget(self._scanning_label)

        # ===== Breakdown card =====
        breakdown_card = _make_card("SideCard")
        b_lay = breakdown_card.layout()

        b_title = QLabel("Breakdown")
        b_title.setObjectName("SectionTitle")
        b_lay.addWidget(b_title)

        label, model, media = _get_drive_metadata_c()
        drive_meta = QLabel(
            f"Drive: {label} · Model: {model} · Type: {media}"
        )
        drive_meta.setObjectName("PageHint")
        drive_meta.setWordWrap(True)
        b_lay.addWidget(drive_meta)

        self.lbl_breakdown = QLabel(
            "User files: —      "
            "Apps: —      "
            "System: —      "
            "Recycle Bin: —      "
            "Other: —      "
            "Free: —"
        )
        self.lbl_breakdown.setObjectName("PageHint")
        self.lbl_breakdown.setWordWrap(True)
        b_lay.addWidget(self.lbl_breakdown)

        layout.addWidget(breakdown_card)

        # ===== Deep clean + duplicates card =====
        clean_card = _make_card("SideCard")
        c_lay = clean_card.layout()

        top_row = QHBoxLayout()
        title_lbl = QLabel("Deep clean & duplicates")
        title_lbl.setObjectName("SectionTitle")
        top_row.addWidget(title_lbl)
        top_row.addStretch()

        self.btn_scan = QPushButton("Scan")
        self.btn_scan.setObjectName("SmallButton")
        self.btn_clean = QPushButton("Empty recycle bin")
        self.btn_clean.setObjectName("SmallButton")
        self.btn_clean.setEnabled(False)

        top_row.addWidget(self.btn_scan)
        top_row.addWidget(self.btn_clean)
        c_lay.addLayout(top_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        c_lay.addWidget(self.progress_bar)

        dup_label = QLabel("Duplicate groups (user directories only)")
        dup_label.setObjectName("PageHint")
        c_lay.addWidget(dup_label)

        self.list_duplicates = QListWidget()
        self.list_duplicates.setObjectName("StorageDupList")
        c_lay.addWidget(self.list_duplicates)

        layout.addWidget(clean_card)
        layout.addStretch()

        # Wire
        self.btn_scan.clicked.connect(self._start_deep_scan)
        self.btn_clean.clicked.connect(self._confirm_and_clean)

        # Start quick scan immediately (whole C:, for overview only)
        self._start_quick_scan()

    # ---------- quick scan flow ----------

    def _start_quick_scan(self):
        if self.quick_worker and self.quick_worker.isRunning():
            return
        self.quick_worker = QuickScanWorker(drive_root="C:\\", parent=self)
        self.quick_worker.quick_finished.connect(self._on_quick_finished)
        self.quick_worker.start()

    def _on_quick_finished(self, summary: dict):
        total = summary["total_bytes"]
        user_b = summary["user_bytes"]
        app_b = summary["app_bytes"]
        sys_b = summary["system_bytes"]
        rec_b = summary["recycle_bytes"]
        other_b = summary["other_bytes"]
        free_b = summary["free_bytes"]

        self.viz_bar.set_segments(
            total=total,
            user_b=user_b,
            app_b=app_b,
            sys_b=sys_b,
            rec_b=rec_b,
            other_b=other_b,
            free_b=free_b,
        )

        def fmt_gb(x):
            return f"{x / (1024**3):.2f} GB"

        self.lbl_breakdown.setText(
            f"User files: {fmt_gb(user_b)}      "
            f"Apps: {fmt_gb(app_b)}      "
            f"System: {fmt_gb(sys_b)}      "
            f"Recycle Bin: {fmt_gb(rec_b)}      "
            f"Other: {fmt_gb(other_b)}      "
            f"Free: {fmt_gb(free_b)}"
        )

    # ---------- deep clean flow ----------

    def _start_deep_scan(self):
        if self.worker and self.worker.isRunning():
            return
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Starting deep scan of user files…")
        self.btn_scan.setEnabled(False)
        self.btn_clean.setEnabled(False)
        self._last_summary = None
        self.list_duplicates.clear()

        self._show_overview_scanning_overlay()

        self.worker = DeepCleanWorker(drive_root="C:\\", parent=self)
        self.worker.progress_updated.connect(self._on_scan_progress)
        self.worker.scan_finished.connect(self._on_scan_finished)
        self.worker.start()

    def _on_scan_progress(self, percent: int, label: str):
        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(label)

    def _on_scan_finished(self, summary: dict):
        self._last_summary = summary
        self.btn_scan.setEnabled(True)
        self.btn_clean.setEnabled(True)

        self._hide_overview_scanning_overlay()
        self._hide_scan_popup()

        usage = psutil.disk_usage("C:\\")
        total_disk_bytes = usage.total

        user_b = summary.get("user_bytes", 0)
        app_b = summary.get("app_bytes", 0)
        sys_b = summary.get("system_bytes", 0)
        rec_b = summary.get("recycle_bytes", 0)
        other_b = summary.get("other_bytes", 0)
        free_b = usage.free

        def fmt_gb(x):
            return f"{x / (1024**3):.2f} GB"

        self.lbl_breakdown.setText(
            f"User files: {fmt_gb(user_b)}      "
            f"Apps: {fmt_gb(app_b)}      "
            f"System: {fmt_gb(sys_b)}      "
            f"Recycle Bin: {fmt_gb(rec_b)}      "
            f"Other: {fmt_gb(other_b)}      "
            f"Free: {fmt_gb(free_b)}"
        )

        reclaimable = summary.get("junk_bytes", 0) + summary.get("dup_bytes", 0) + rec_b
        self.progress_bar.setFormat(
            f"Scan done. Potential reclaim (user + recycle): {fmt_gb(reclaimable)}"
        )

        self.viz_bar.set_segments(
            total=total_disk_bytes,
            user_b=user_b,
            app_b=app_b,
            sys_b=sys_b,
            rec_b=rec_b,
            other_b=other_b,
            free_b=free_b,
        )

        self.list_duplicates.clear()
        dup_groups = summary.get("dup_groups", [])
        for group in dup_groups:
            if len(group) < 2:
                continue
            header = QListWidgetItem(f"Group ({len(group)} files)")
            header.setFlags(Qt.ItemIsEnabled)
            self.list_duplicates.addItem(header)
            for path_str in group:
                item = QListWidgetItem("  " + path_str)
                item.setFlags(Qt.ItemIsEnabled)
                self.list_duplicates.addItem(item)

    # ---------- scanning overlay + popup ----------

    def _show_overview_scanning_overlay(self):
        self._scanning_label.show()
        self._overlay_dot_state = 0
        if self._overlay_timer is None:
            self._overlay_timer = QTimer(self)
            self._overlay_timer.timeout.connect(self._update_overlay_text)
        self._overlay_timer.start(350)

    def _hide_overview_scanning_overlay(self):
        if self._overlay_timer:
            self._overlay_timer.stop()
        self._scanning_label.hide()

    def _update_overlay_text(self):
        self._overlay_dot_state = (self._overlay_dot_state + 1) % 4
        dots = "." * self._overlay_dot_state
        self._scanning_label.setText(f"Scanning{dots}")

    def _hide_scan_popup(self):
        if getattr(self, "_scan_popup", None) is not None:
            self._scan_popup.close()
            self._scan_popup.deleteLater()
            self._scan_popup = None

    # ---------- clean ----------

    def _confirm_and_clean(self):
        if not self._last_summary:
            return
        self._empty_recycle_bin()
        self.btn_clean.setEnabled(False)
        self.progress_bar.setFormat(
            "Recycle bin emptied. Junk/duplicate deletion is manual."
        )

    def _empty_recycle_bin(self):
        if not sys.platform.startswith("win"):
            return
        try:
            shell32 = ctypes.windll.shell32
            shell32.SHEmptyRecycleBinW(None, None, 0x0007)
        except Exception:
            pass

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
        super().closeEvent(event)

#if __name__ == "__main__":
##    from PySide6.QtWidgets import QApplication
#   import sys  
#    app = QApplication(sys.argv)
#    window = StoragePage()
#    window.show()
#    sys.exit(app.exec())
    