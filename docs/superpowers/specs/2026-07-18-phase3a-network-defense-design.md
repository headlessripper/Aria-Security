# Phase 3A — Network Defense — Design

**Date:** 2026-07-18
**Status:** Design (awaiting user review) → implementation plan.
**Context:** Second sub-project of Phase 3 (order 3B done → **3A (this)** → 3C → 3D). Full clean-slate rewrite on the `BaseService` framework (built in 3B). Master spec: `2026-07-17-zashiron-rebuild-design.md`.

---

## 1. Scope

Rewrite the network defense cluster as **reputation + IOC-feed + heuristic + packet-level** defense — no flow-ML (user-approved). Retire the stale `.pkl` zoo entirely.

**Services (all → `BaseService` subclasses):**
1. **ThreatIntelligence** — live IOC feed ingestion → a shared `ThreatIntelStore`.
2. **NetworkProtection** — connection monitor: IOC/reputation/heuristic → firewall block (rewrite of the 1,337-line `AINetworkProtector`, dropping all ML/CSV logic).
3. **PSDS** — WinDivert SYN-flood / port-scan packet defense.

**Retire → `cleanup/phase3a-network-pkl/`:** `models/*.pkl` (nids/anomaly/`malware_detector`/phishing — all loaded ONLY by the old NetProtectionNG2) + `models/Data_Files/*.csv`. The old runtime CSV feature-column building is deleted, not moved.

**Out of scope:** flow-ML NIDS (explicitly declined); the kernel minifilter driver (final phase). File-malware/phishing detection is NOT the network service's job (PE engine owns file malware).

---

## 2. Architecture

```
ThreatIntelligence(BaseService)  --populates-->  ThreatIntelStore  <--queries--  NetworkProtection(BaseService)
   (Feodo/CINS/URLhaus/                          (bad_ips, bad_hashes,              (psutil conns -> classify
    MalwareBazaar/AbuseIPDB)                       reputation cache; query API)       -> netsh firewall block)
PSDS(BaseService) -- WinDivert SYN/scan drop + firewall block (independent)
```

### 2.1 `ThreatIntelStore` (`Services/Protection/threat_intel_store.py`) — new
Shared, thread-safe IOC/reputation store both services use (decouples producer from consumer; injectable for tests).
```
class ThreatIntelStore:
    def add_bad_ips(self, ips: set[str], source: str) -> None
    def add_bad_hashes(self, hashes: set[str], source: str) -> None
    def is_bad_ip(self, ip: str) -> bool
    def is_bad_hash(self, sha256: str) -> bool
    def set_reputation(self, ip: str, score: int, ttl_s: float = 3600) -> None
    def ip_reputation(self, ip: str) -> int | None      # cached AbuseIPDB score 0-100 or None
    def stats(self) -> dict                              # counts for UI/health
def get_intel_store() -> ThreatIntelStore                # module singleton
```

---

## 3. Service Rewrites

### 3.1 ThreatIntelligence (`Services/SentinelThreatIntelligence.py`)
`BaseService`, `name="ThreatIntelligence"`. Keeps the existing real feed sources; drops the raw `threading.Thread`.
- **Pure feed parsers (test-pinned):** `parse_ip_list(text) -> set[str]`, `parse_urlhaus_hashes(bytes) -> tuple[set,set]` — extract IOCs from feed payloads, ignoring comments/blanks/malformed lines.
- `_run`: on start load persisted blocklists into the store; loop with interruptible `_sleep(check_interval)`; when a feed is due (`UPDATE_INTERVAL_HOURS`, default 4), fetch it (guarded), parse, `store.add_bad_ips/add_bad_hashes`, persist to `IPS_FILE_PATH`, and `emit_threat(SYSTEM, INFO, "feed updated", …)`. HTTP fetches are exception-isolated (a dead feed logs + is skipped, never crashes the service).
- `lookup_ip_abuseipdb(ip, api_key)` retained as a helper; on-demand reputation lookups populate `store.set_reputation`.

### 3.2 NetworkProtection (`Services/Protection/SentinelNetProtectionNG2.py`)
`BaseService`, `name="NetProtection"`. Rewrite — **no `.pkl`, no CSV, no pandas ML.**
- **Pure classifier (test-pinned):** `classify_connection(conn: dict, intel: ThreatIntelStore, cfg: dict) -> (action: str, reason: str, severity)` where `conn={raddr_ip, raddr_port, laddr_port, pid, status}` and `action ∈ {"clean","alert","block"}`. Order: whitelist/private/loopback IP → `clean`; `intel.is_bad_ip(ip)` → `block`/HIGH; `intel.ip_reputation(ip) >= rep_block_threshold` (default 80) → `block`/HIGH; `>= rep_alert_threshold` (default 50) → `alert`/MEDIUM; heuristic (destination port in `suspicious_ports`, or connection-velocity to new IPs over `velocity_threshold`/window) → `alert`/MEDIUM; else `clean`.
- `_run`: poll `psutil.net_connections(kind="inet")` (guarded — AccessDenied under non-admin logs once + degrades) every `poll_interval`; dedupe by remote IP; run `classify_connection`; on `block` → `_firewall_block(ip)` (netsh, both directions — kept from the current code) + `emit_threat(NETWORK, HIGH, …, ip_address=ip)`; on `alert` → emit only. On-demand AbuseIPDB reputation lookups (async, cached in the store) for unknown IPs.
- Whitelist: private ranges (10/8, 172.16/12, 192.168/16, 127/8) + user allowlist from config; never block those.

### 3.3 PSDS (`Services/Protection/Sentinelpsds.py`)
`BaseService`, `name="PSDS"`. WinDivert SYN-flood / port-scan defense.
- **Pure logic (test-pinned):** `class SynRateTracker` — `record(ip, ts)` and `exceeded(ip, now) -> bool` (≥ `syn_rate_threshold` SYNs within `window`).
- `_run`: if `pydivert` importable AND admin, open a WinDivert handle on the SYN filter and drop SYNs from IPs whose rate is exceeded (+ `_firewall_block`, emit `NETWORK`/HIGH). **Graceful degradation:** if `pydivert`/WinDivert/admin is unavailable, log ONCE, set health note, and idle (service stays "running" but inert) — never crash. `_teardown` closes the handle.

---

## 4. Orchestration + retirement
- Replace the `_NetThread`/`_PsdsThread`/`_IntelThread` `_ModuleThread` wrappers in `Services/SentinelService_v2.py` with `_ServiceHolder` wrapping the new `BaseService` instances (same pattern 3B used). Construct ThreatIntelligence first so its store is populated before NetworkProtection queries it; NetworkProtection gets the store via `get_intel_store()`. Other clusters' wrappers stay.
- `git mv` the 9 `.pkl` + the `Data_Files/*.csv` to `cleanup/phase3a-network-pkl/`. Confirm no live import references them (only the old NetProtectionNG2 did).

## 5. Data flow & error handling
**Flow:** feeds → ThreatIntelligence → `ThreatIntelStore`; connections → NetworkProtection → classify (querying the store) → netsh block + `emit_threat(NETWORK, …)`; SYN packets → PSDS → WinDivert drop + block. **Errors:** every feed fetch, connection poll, and packet-loop iteration is exception-isolated; missing `pydivert`/admin degrades gracefully; a dead feed is skipped. All three inherit `BaseService`'s crash isolation.

## 6. Testing (synthetic — no real feeds/attacks/network)
- **ThreatIntelStore:** add/query bad IPs & hashes; reputation set/get + TTL expiry; `is_bad_ip` false on unknown.
- **ThreatIntelligence:** `parse_ip_list` / `parse_urlhaus_hashes` on sample payloads (with comments/garbage) → correct IOC sets; a feed-refresh cycle with the HTTP fetch monkeypatched → store populated, no network call.
- **NetworkProtection:** `classify_connection` with a fake store — bad IP → `block`; high reputation → `block`; mid reputation → `alert`; suspicious port → `alert`; whitelisted/private IP → `clean`; benign public IP, clean store → `clean`. `_firewall_block` monkeypatched (never runs `netsh` in tests).
- **PSDS:** `SynRateTracker.exceeded` threshold/window logic; `_run` with `pydivert` absent → service degrades (health note set) without raising.
- All services: `BaseService` lifecycle (start/stop) with a fake brain.

## 7. Dependencies
`pydivert` (WinDivert; may need install — PSDS degrades gracefully without it). Already present: `psutil`, `requests`/`urllib`.

## 8. Deferred / future
3C (device/discovery) and 3D (support) clusters; the kernel minifilter driver (final phase). No ML-NIDS (declined). AbuseIPDB/API keys remain in `Config.json` (untouched per user).
