"""Headless dev runner for the Aria Security Flask UI.

Starts the SPA on 127.0.0.1:<port> without elevation or the pywebview window,
so the in-app browser preview / a normal browser can load it during UI work.
Not part of the shipped app — a developer convenience only.

    python run_dev.py [port]
"""
import importlib.util
import os
import sys

# Parse the optional port before we rewrite sys.argv for the app.
_port = 8765
for _a in sys.argv[1:]:
    if _a.isdigit():
        _port = int(_a)
        break

os.environ.setdefault("SENTINEL_NO_ELEVATE", "1")
sys.argv = [sys.argv[0], "--no-elevate"]

_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(_ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

spec = importlib.util.spec_from_file_location(
    "sentinel_app", os.path.join(_ROOT, "SentinelUI_Flask.py")
)
_m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(_m)

try:
    _m._PORT = _port
except Exception:
    pass

print(f"[run_dev] serving Aria Security on http://127.0.0.1:{_port}", flush=True)
_m._start_flask()
