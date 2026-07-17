"""
PluginInstaller.py

Npcap has been removed — AriaSecurity uses WinDivert (pydivert) for
packet interception, which does not require Npcap or scapy.

The ensure_all_installed() entry-point is kept so existing call-sites
in start_app() do not need to be changed.
"""


def ensure_all_installed() -> bool:
    """No-op — all required drivers are handled by their own installers."""
    return True
