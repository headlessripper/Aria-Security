import threading, time

class ThreatIntelStore:
    """Thread-safe shared IOC + reputation store (producer: ThreatIntelligence, consumer: NetworkProtection)."""
    def __init__(self):
        self._lock = threading.RLock()
        self._bad_ips = set()
        self._bad_hashes = set()
        self._reputation = {}   # ip -> (score, expires_ts)
        self._sources = {}

    def add_bad_ips(self, ips, source="unknown"):
        with self._lock:
            new = {str(i).strip() for i in ips if i and str(i).strip()}
            self._bad_ips |= new
            self._sources[source] = len(new)

    def add_bad_hashes(self, hashes, source="unknown"):
        with self._lock:
            self._bad_hashes |= {str(h).strip().lower() for h in hashes if h and str(h).strip()}

    def is_bad_ip(self, ip):
        with self._lock:
            return ip in self._bad_ips

    def is_bad_hash(self, sha256):
        with self._lock:
            return (sha256 or "").lower() in self._bad_hashes

    def set_reputation(self, ip, score, ttl_s=3600):
        with self._lock:
            self._reputation[ip] = (int(score), time.time() + ttl_s)

    def ip_reputation(self, ip):
        with self._lock:
            entry = self._reputation.get(ip)
            if not entry:
                return None
            score, exp = entry
            if time.time() > exp:
                del self._reputation[ip]
                return None
            return score

    def stats(self):
        with self._lock:
            return {"bad_ips": len(self._bad_ips), "bad_hashes": len(self._bad_hashes),
                    "reputation_cached": len(self._reputation), "sources": dict(self._sources)}

_STORE = None
def get_intel_store():
    global _STORE
    if _STORE is None:
        _STORE = ThreatIntelStore()
    return _STORE
