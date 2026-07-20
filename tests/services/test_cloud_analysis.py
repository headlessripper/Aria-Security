"""
Tests for Services.SentinelCloudAnalysis — pure RateLimiter, request
timeouts, and graceful no-API-key handling.

Adaptations from the brief:
- The real lookup method is ``check_hash`` (not ``lookup_hash``).
- The real "no key" verdict field is ``status`` with value ``"unavailable"``
  (added to ``CloudVerdict`` by this task; it did not exist before).
- ``VirusTotalClient(api_key="")`` (explicit empty string) forces a keyless
  client without touching the on-disk config, which for real dev machines in
  this repo *does* have a live ``virustotal_api_key`` in Config/Config.json.
  Omitting the ``api_key`` kwarg entirely still loads from config (legacy
  default behavior, preserved for other call sites).
- No test exercises real network I/O; the HTTP-path robustness test
  monkeypatches ``requests.Session.get`` to raise, verifying the client
  degrades to a non-raising "error" verdict rather than depending on a
  live VirusTotal connection.
"""
import Services.SentinelCloudAnalysis as ca
from Services.SentinelCloudAnalysis import RateLimiter, VirusTotalClient, CloudVerdict


def test_rate_limiter():
    rl = RateLimiter(max_calls=4, per_seconds=60)
    assert all(rl.allow(now=0) for _ in range(4))
    assert rl.allow(now=0) is False           # 5th within the window blocked
    assert rl.allow(now=61) is True            # window elapsed


def test_no_api_key_returns_unavailable():
    c = VirusTotalClient(api_key="")          # explicitly no key
    assert c._is_configured() is False
    v = c.check_hash("a" * 64)
    assert v is not None
    assert v.status == "unavailable"
    assert v.found is False


def test_no_api_key_check_url_also_unavailable():
    c = VirusTotalClient(api_key="")
    v = c.check_url("http://example.com")
    assert v is not None
    assert v.status == "unavailable"


def test_no_api_key_never_makes_http_call(monkeypatch):
    """The no-key path must short-circuit before any requests call."""
    c = VirusTotalClient(api_key="")

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP call made despite missing API key")

    monkeypatch.setattr(c._session, "get", _boom)
    monkeypatch.setattr(c._session, "post", _boom)

    v = c.check_hash("b" * 64)
    assert v.status == "unavailable"


def test_http_error_degrades_to_error_verdict_never_raises(monkeypatch):
    """Any HTTP/JSON failure must return a verdict, never propagate."""
    c = VirusTotalClient(api_key="fake-key-for-test")

    def _raise_timeout(*args, **kwargs):
        raise ca.requests.exceptions.Timeout("simulated timeout")

    monkeypatch.setattr(c._session, "get", _raise_timeout)

    v = c.check_hash("c" * 64)
    assert v is not None
    assert v.status == "error"
    assert v.found is False


def test_check_hash_passes_a_timeout_to_requests(monkeypatch):
    """Every requests call in the module must pass an explicit timeout."""
    c = VirusTotalClient(api_key="fake-key-for-test")
    captured = {}

    class _FakeResp:
        status_code = 404

    def _fake_get(url, headers=None, timeout=None):
        captured["timeout"] = timeout
        return _FakeResp()

    monkeypatch.setattr(c._session, "get", _fake_get)
    c.check_hash("d" * 64)
    assert captured["timeout"] is not None
