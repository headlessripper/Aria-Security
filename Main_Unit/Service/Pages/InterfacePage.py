# InterfacePage.py

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QFrame, QApplication, QPushButton
)
from PySide6.QtCore import QEvent, QThread, Signal, QTimer, QDateTime, Qt
from PySide6.QtWebEngineWidgets import QWebEngineView
from Main_Unit.Service.Pages.Style_Qss.qss import qss
from PySide6.QtGui import QPainterPath, QRegion, QIcon

import sys
import folium
import io
import ipinfo
import json
import psutil
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from collections import Counter
from Main_Unit.Service.find_menu import find_menu

# ===================== Config =====================

IPINFO_TOKEN = "65eef18ec4f102"  # DO NOT use in normal run once cache is filled
CACHE_DIR = Path.home() / ".AriaSecurity" / "TraceRoute"
CACHE_PATH = CACHE_DIR / "ipinfo_cache.json"
CACHE_PUBLIC_IP_KEY = "__public_ip__"

# Time in ms between allowed map HTML reloads (throttling)
MAP_UPDATE_MIN_INTERVAL_MS = 20000  # 20 seconds

CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ===================== Simple JSON cache =====================

def load_ip_cache() -> Dict[str, Dict]:
    if not CACHE_PATH.exists():
        return {}
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_ip_cache(cache: Dict[str, Dict]):
    try:
        with CACHE_PATH.open("w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


_ip_cache: Dict[str, Dict] = load_ip_cache()
_handler: Optional[ipinfo.Handler] = None


def _ipinfo_get(details, field: str, default="") -> str:
    """Safely read a field from ipinfo Details — not all fields are always present."""
    try:
        val = getattr(details, field, None)
        if val is None:
            val = details.all.get(field, default)
        return val or default
    except Exception:
        return default


def _get_handler() -> ipinfo.Handler:
    global _handler
    if _handler is None:
        _handler = ipinfo.getHandler(IPINFO_TOKEN)
    return _handler


# ===================== Geolocation helpers (with caching) =====================

def geolocate_ip_cached(ip: str) -> Optional[Dict]:
    """
    - If ip in _ip_cache: return it (no network).
    - If not in cache: call ipinfo once, store result in cache, return it.
    """
    if ip in _ip_cache:
        return _ip_cache[ip]

    try:
        handler = _get_handler()
        details = handler.getDetails(ip)
    except Exception:
        return None

    try:
        loc_str = details.loc or ""
        lat, lon = None, None
        if loc_str and "," in loc_str:
            lat_str, lon_str = loc_str.split(",")
            lat = float(lat_str)
            lon = float(lon_str)

        info = {
            "ip":       _ipinfo_get(details, "ip"),
            "city":     _ipinfo_get(details, "city"),
            "region":   _ipinfo_get(details, "region"),
            "country":  _ipinfo_get(details, "country"),
            "lat":      lat,
            "lon":      lon,
            "org":      _ipinfo_get(details, "org"),
            "hostname": _ipinfo_get(details, "hostname"),
        }
        _ip_cache[ip] = info
        save_ip_cache(_ip_cache)
        return info
    except Exception:
        return None


def get_or_fetch_public_ip_details() -> Optional[Dict]:
    """
    Current public IP geodata, with caching:
    - If CACHE_PUBLIC_IP_KEY points to an IP in cache, use it.
    - Else call ipinfo.getDetails() once, cache it, and mark it as primary.
    """
    key = _ip_cache.get(CACHE_PUBLIC_IP_KEY)
    if isinstance(key, str) and key in _ip_cache:
        return _ip_cache.get(key)

    # Not yet known: discover once
    try:
        handler = _get_handler()
        details = handler.getDetails()  # current IP
    except Exception:
        return None

    ip = details.ip
    if ip in _ip_cache:
        info = _ip_cache[ip]
    else:
        loc_str = details.loc or ""
        lat, lon = None, None
        if loc_str and "," in loc_str:
            lat_str, lon_str = loc_str.split(",")
            lat = float(lat_str)
            lon = float(lon_str)

        info = {
            "ip":       _ipinfo_get(details, "ip"),
            "city":     _ipinfo_get(details, "city"),
            "region":   _ipinfo_get(details, "region"),
            "country":  _ipinfo_get(details, "country"),
            "lat":      lat,
            "lon":      lon,
            "org":      _ipinfo_get(details, "org"),
            "hostname": _ipinfo_get(details, "hostname"),
        }
        _ip_cache[ip] = info

    _ip_cache[CACHE_PUBLIC_IP_KEY] = ip
    save_ip_cache(_ip_cache)
    return info


# ===================== Active connections helper =====================

def get_active_remote_ips(limit: int = 20) -> List[str]:
    """
    Get unique remote IPs from current inet connections, most frequent first.
    Done in worker thread.
    """
    conns = psutil.net_connections(kind="inet")
    ips = []
    for c in conns:
        if c.raddr and c.status == psutil.CONN_ESTABLISHED:
            if hasattr(c.raddr, "ip"):
                ip = c.raddr.ip
            else:
                ip = c.raddr[0]
            ips.append(ip)

    counts = Counter(ips)
    ordered = [ip for ip, _ in counts.most_common(limit)]
    return ordered


# ===================== Worker for connections + map HTML =====================

class ConnectionsGeoWorker(QThread):
    """
    Worker:
      - Gets current public IP (self) with cache.
      - Gets active remote IPs.
      - Geolocates via ipinfo with caching.
      - Builds folium map HTML string off-UI.
    Emits dict:
      { 'self': info_or_None, 'peers': [info, ...], 'html': str }
    """
    data_ready = Signal(dict)

    def __init__(self, parent=None, limit=20, center: Tuple[float, float] = (0, 0), zoom: int = 1):
        super().__init__(parent)
        self.limit = limit
        self.center = center
        self.zoom = zoom

    def run(self):
        self_info = get_or_fetch_public_ip_details()
        peers_infos: List[Dict] = []

        try:
            ips = get_active_remote_ips(limit=self.limit)
        except Exception:
            ips = []

        for ip in ips:
            info = geolocate_ip_cached(ip)
            if info and info.get("lat") is not None and info.get("lon") is not None:
                peers_infos.append(info)

        html = self._build_map_html(self_info=self_info, peers=peers_infos, center=self.center, zoom=self.zoom)
        self.data_ready.emit({"self": self_info, "peers": peers_infos, "html": html})

    @staticmethod
    def _build_map_html(self_info: Optional[Dict], peers: List[Dict],
                        center: Tuple[float, float], zoom: int) -> str:
        # Use provided view as starting point
        center_lat, center_lon = center
        zoom_start = zoom if zoom > 0 else 1

        fmap = folium.Map(
            location=[center_lat, center_lon],
            zoom_start=zoom_start,
            tiles="CartoDB dark_matter",
        )

        # Plot self (current public IP)
        if self_info and self_info.get("lat") is not None:
            popup_text = ConnectionsGeoWorker._format_isp_label(self_info)
            folium.CircleMarker(
                location=(self_info["lat"], self_info["lon"]),
                radius=8,
                color="#22c55e",
                fill=True,
                fill_color="#22c55e",
                fill_opacity=0.95,
                opacity=0.95,
                tooltip="This machine (exit IP)",
                popup=popup_text,
            ).add_to(fmap)

        # Plot peers + straight-line routes
        for idx, p in enumerate(peers, start=1):
            plat = p.get("lat")
            plon = p.get("lon")
            if plat is None or plon is None:
                continue

            city = p.get("city") or ""
            country = p.get("country") or ""
            org = p.get("org") or ""
            ip = p.get("ip") or ""

            popup_text = f"Peer {idx}\n{city}, {country}\n{org}\nIP: {ip}"

            folium.CircleMarker(
                location=(plat, plon),
                radius=6,
                color="#38bdf8",
                fill=True,
                fill_color="#38bdf8",
                fill_opacity=0.9,
                opacity=0.9,
                tooltip=f"Peer {idx}",
                popup=popup_text,
            ).add_to(fmap)

            if self_info and self_info.get("lat") is not None:
                fmap.add_child(
                    folium.PolyLine(
                        locations=[
                            (self_info["lat"], self_info["lon"]),
                            (plat, plon),
                        ],
                        color="#f97316",
                        weight=2,
                        opacity=0.7,
                    )
                )

        data = io.BytesIO()
        fmap.save(data, close_file=False)
        html = data.getvalue().decode("utf-8")
        return html

    @staticmethod
    def _format_isp_label(info: Dict) -> str:
        city = info.get("city") or ""
        country = info.get("country") or ""
        org = info.get("org") or ""
        ip = info.get("ip") or ""
        parts = []
        if org:
            parts.append(org)
        if city or country:
            parts.append(", ".join(p for p in [city, country] if p))
        if ip:
            parts.append(f"IP: {ip}")
        return "Network: " + " · ".join(parts) if parts else "Network: unknown"


# ===================== Traceroute/Connections Page =====================

class InterfacesListPage(QWidget):
    """
    Traceroute/Connections page:
    - Uses worker to fetch connections + geodata + build HTML.
    - Throttles map reloads and skips if endpoints unchanged to reduce flicker.
    - Keeps last known center/zoom as the starting view for each new map.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.current_ipinfo: Optional[Dict] = None
        self.conn_worker: Optional[ConnectionsGeoWorker] = None

        self.setStyleSheet(qss)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        traceroute_card = QWidget()
        traceroute_card.setObjectName("TracerouteCard")
        layout = QVBoxLayout(traceroute_card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        tr_title = QLabel("Live Connections Map")
        tr_title.setObjectName("PageTitle")
        layout.addWidget(tr_title)

        self.isp_label = QLabel("Network: resolving…")
        self.isp_label.setObjectName("PageHint")
        layout.addWidget(self.isp_label)

        tr_sub = QLabel("Routes from this machine to active remote IPs")
        tr_sub.setObjectName("PageHint")
        layout.addWidget(tr_sub)

        map_frame = QFrame()
        map_frame.setObjectName("TracerouteMap")
        map_layout = QVBoxLayout(map_frame)
        map_layout.setContentsMargins(0, 0, 0, 0)
        map_layout.setSpacing(0)

        self.map_view = QWebEngineView()
        self.map_view.setObjectName("TracerouteWebView")
        map_layout.addWidget(self.map_view)

        layout.addWidget(map_frame, 1)
        root.addWidget(traceroute_card, 1)

        self.map_view.installEventFilter(self)

        # For throttling and diffing
        self._last_html_fingerprint: Optional[str] = None
        self._last_map_update_ms: int = 0

        # Approximate view state we pass into worker
        self._last_center = (0.0, 0.0)
        self._last_zoom = 2

        # Kick off first fetch
        self._start_connections_worker()

        # Periodic refresh for "real time" updates (worker side)
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._start_connections_worker)
        self._refresh_timer.start(15000)  # worker every 15 seconds
        
        icon_path_close = find_menu("menu/close.png")
        close_btn = QPushButton()
        close_btn.setIcon(QIcon(icon_path_close))
        close_btn.setFixedSize(30, 30)
        close_btn.clicked.connect(self._close_main)
        close_btn.setObjectName("closeButton")

        #layout.addWidget(notif)
        layout.addWidget(close_btn, alignment=Qt.AlignRight)

    # ---------- Worker orchestration ----------

    def _start_connections_worker(self):
        # Avoid overlapping workers
        if self.conn_worker is not None and self.conn_worker.isRunning():
            return

        self.conn_worker = ConnectionsGeoWorker(
            parent=self,
            limit=30,
            center=self._last_center,
            zoom=self._last_zoom,
        )
        self.conn_worker.data_ready.connect(self._on_connections_geo_ready)
        self.conn_worker.start()

    def _on_connections_geo_ready(self, data: Dict):
        self.current_ipinfo = data.get("self")

        # update ISP label (cheap, every cycle)
        if self.current_ipinfo:
            self.isp_label.setText(ConnectionsGeoWorker._format_isp_label(self.current_ipinfo))
        else:
            self.isp_label.setText("Network: unknown (no cached geodata)")

        html = data.get("html") or ""
        peers = data.get("peers", [])
        self._maybe_update_map(html, peers)

    # ---------- Map update throttling & diff ----------

    def _maybe_update_map(self, html: str, peers: List[Dict]):
        if not html:
            return

        self_ip = (self.current_ipinfo or {}).get("ip")
        peer_ips = sorted([p.get("ip") for p in peers if p.get("ip")])
        fingerprint_obj = {"self": self_ip, "peers": peer_ips}
        fingerprint = json.dumps(fingerprint_obj, sort_keys=True)

        now_ms = int(QDateTime.currentMSecsSinceEpoch())
        elapsed = now_ms - self._last_map_update_ms

        # If endpoints haven't changed and last update was recent, skip
        if fingerprint == self._last_html_fingerprint and elapsed < MAP_UPDATE_MIN_INTERVAL_MS:
            return

        # Throttle absolute update rate too
        if elapsed < MAP_UPDATE_MIN_INTERVAL_MS and self._last_html_fingerprint is not None:
            return

        # Commit update (keep last center/zoom; worker used them already)
        self._last_html_fingerprint = fingerprint
        self._last_map_update_ms = now_ms
        self.map_view.setHtml(html)

    # ---------- Rounded mask ----------

    def eventFilter(self, obj, event):
        if obj is self.map_view and event.type() == QEvent.Type.Resize:
            self._update_map_mask()
        return super().eventFilter(obj, event)

    def _update_map_mask(self):
        r = self.map_view.rect()
        if r.isNull():
            return
        path = QPainterPath()
        path.addRoundedRect(r, 16, 16)
        region = QRegion(path.toFillPolygon().toPolygon())
        self.map_view.setMask(region)
        
    def _close_main(self):
        win = self.window()
        if isinstance(win, QWidget):
            win.close()


# ===================== main =====================

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = InterfacesListPage()
    w.resize(1000, 600)
    w.show()
    sys.exit(app.exec())
