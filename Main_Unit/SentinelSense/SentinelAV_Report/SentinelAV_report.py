#!/usr/bin/env python3
import ctypes
import psutil
import webbrowser
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List
import sys
import os


def hide_console():
    """Hide console window on Windows."""
    if os.name == 'nt':  # Windows
        try:
            ctypes.windll.user32.ShowWindow(
                ctypes.windll.kernel32.GetConsoleWindow(),
                0  # SW_HIDE
            )
        except:
            pass


# Your log paths (match service)
LOG_PATHS = [
    Path(r"C:\Program Files\AriaSecurity\logs\NetPro.log"),
    Path(r"C:\Program Files\AriaSecurity\logs\psds.log"),
    Path(r"C:\Program Files\AriaSecurity\logs\Sense.log"),
    Path(r"C:\Program Files\AriaSecurity\logs\sys.log"),
    Path(r"C:\Program Files\AriaSecurity\logs\RansomPro.log"),
    Path(r"C:\Program Files\AriaSecurity\Sentinel.log"),
    Path(r"C:\Program Files\AriaSecurity\zashiron_exploit_log.txt"),
    Path.home() / ".AriaSecurity" / ".SentinelSense" / "sense_core.log",
]


REPORT_DIR = Path.home() / ".AriaSecurity" / ".SentinelReports"
REPORT_FILE = REPORT_DIR / "AriaSecurity_Report.html"


def tail_lines(path: Path, n: int = 50) -> List[str]:
    """Get last N lines from log file."""
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return [line.rstrip("\n") for line in f.readlines()[-n:]]
    except Exception:
        return []


def generate_crash_report(output_path: Path):
    """Generate crash report from recent logs."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    
    events = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"[{timestamp}] Generating crash report...")
    scanned_logs = 0
    
    for log_path in LOG_PATHS:
        lines = tail_lines(log_path, 50)
        if lines:
            scanned_logs += 1
            for line in lines:
                # Crash/error keywords
                if any(kw in line.lower() for kw in [
                    "error", "exception", "crash", "failed", "fault", 
                    "traceback", "segfault", "access violation"
                ]):
                    events.append({
                        "timestamp": timestamp,
                        "log": log_path.name,
                        "event": line.strip()
                    })
    
    # Generate HTML report
    html = f"""<!DOCTYPE html>
<html><head><title>AriaSecurity Crash Report</title>
<style>
body {{font-family:Arial,sans-serif;margin:20px;background:#f9f9f9;}}
h1 {{color:#e74c3c;}}
h2 {{color:#c0392b;}}
table {{border-collapse:collapse;width:100%;margin:20px 0;}}
th,td {{border:1px solid #ddd;padding:12px;text-align:left;}}
th {{background:#e74c3c;color:white;font-weight:bold;}}
tr:nth-child(even) {{background:#f2f2f2;}}
.crash {{background:#ffebee !important;}}
.empty {{color:#999;font-style:italic;padding:40px;text-align:center;}}
.status {{padding:10px;margin:10px 0;border-radius:5px;}}
</style>
</head>
<body>
<h1>🚨 AriaSecurity Crash Report</h1>
<h2>Generated: {timestamp}</h2>
<div class='status'>Process crashed/stopped - Auto-generated report</div>
"""
    
    if events:
        html += f"<p><strong>{len(events)} critical errors</strong> found in recent logs:</p>"
        html += "<table><tr><th>Log File</th><th>Error Details</th></tr>"
        for e in events:
            safe_event = e['event'].encode('ascii', 'replace').decode('ascii')
            html += f"<tr class='crash'><td>{e['log']}</td><td>{safe_event}</td></tr>"
        html += "</table>"
    else:
        html += "<div class='empty'>No recent errors found. Check full logs manually.</div>"
    
    html += f"""
    <p><small>Scanned: {scanned_logs}/{len(LOG_PATHS)} logs | Last 50 lines each</small></p>
    <script>console.log('AriaSecurity crash report loaded');</script>
    </body></html>"""
    
    try:
        output_path.write_text(html, encoding='utf-8')
        print(f"✅ Crash report: {output_path.absolute()}")
        return True
    except Exception:
        return False


def is_zashiron_running() -> bool:
    """Check if AriaSecurity process is running."""
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if 'AriaSecurity' in proc.info['name']:
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return False


def open_report_browser():
    """Open crash report in default browser."""
    try:
        if REPORT_FILE.exists():
            webbrowser.open(f'file://{REPORT_FILE.absolute()}')
            print("✅ Crash report opened in browser")
        else:
            print("❌ Report file not found")
    except Exception as e:
        print(f"❌ Browser error: {e}")


def main():
    """Crash monitoring loop."""
    # Hide console immediately
    hide_console()
    
    print("🚀 AriaSecurity Crash Monitor started...")
    print("Monitoring process: AriaSecurity")
    print("Press Ctrl+C to stop\n")
    
    was_running = False
    
    try:
        while True:
            is_running = is_zashiron_running()
            
            # Detect crash (was running, now stopped)
            if was_running and not is_running:
                print("🚨 AriaSecurity CRASHED!")
                if generate_crash_report(REPORT_FILE):
                    open_report_browser()
                else:
                    print("❌ Failed to generate report")
            
            was_running = is_running
            time.sleep(2)  # Check every 2 seconds
            
    except KeyboardInterrupt:
        print("\n🛑 Crash monitor stopped by user")
    except Exception as e:
        print(f"❌ Monitor error: {e}")


if __name__ == "__main__":
    # Ensure psutil is available
    try:
        import psutil
    except ImportError:
        print("❌ psutil required: pip install psutil")
        sys.exit(1)
    
    main()
