"""
run_dev.py — development/preview launcher for the Flask UI.

Runs the Flask + Socket.IO server WITHOUT the UAC elevation relaunch and
WITHOUT the pywebview window, so it can be opened in a normal browser for
testing. Admin-only features (firewall/netsh, USB registry) will error
gracefully unless this is started from an elevated shell.

Usage:  python run_dev.py [port]   (default port 8765)
"""
import os
import sys

os.environ["SENTINEL_NO_ELEVATE"] = "1"

import SentinelUI_Flask as app_mod

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    print(f"[run_dev] Flask UI on http://127.0.0.1:{port}/  (no elevation, no pywebview)")
    app_mod.socketio.run(
        app_mod.app,
        host="127.0.0.1",
        port=port,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
