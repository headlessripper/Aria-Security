ML_HIGH = 0.90
ML_MED = 0.50
TLSH_NEAR = 40           # informational; FuzzyHasher already applies it
TRUST_CONF_RELIEF = 20   # confidence reduction when a valid trusted signature is present

def _verdict(v, conf, reasons, details):
    return {"verdict": v, "confidence": int(conf), "reasons": reasons, "details": details}

def fuse(results):
    details = dict(results)
    if results.get("whitelisted"):
        return _verdict("CLEAN", 100, ["Whitelisted"], details)
    if results.get("hash_exact"):
        return _verdict("MALWARE", 100, ["Known-bad hash"], details)
    fz = results.get("fuzzy") or {}
    if fz.get("matched"):
        return _verdict("MALWARE", 90, [f"Fuzzy match ({fz.get('source')})"], details)
    yara_hits = results.get("yara") or []
    if yara_hits:
        return _verdict("MALWARE", 90, ["YARA: " + ", ".join(yara_hits[:3])], details)
    cert = results.get("cert") or {}
    if cert.get("abused"):
        return _verdict("MALWARE", 95, ["Signed by known-abused certificate"], details)
    p = results.get("ml_prob")
    if p is not None:
        trusted = bool(cert.get("trusted"))
        if p >= ML_HIGH:
            conf = 85 - (TRUST_CONF_RELIEF if trusted else 0)
            verdict = "SUSPICIOUS" if trusted else "MALWARE"
            reason = f"ML p={p:.2f}" + (" (trusted-signed → downgraded)" if trusted else "")
            return _verdict(verdict, max(conf, 60), [reason], details)
        if p >= ML_MED:
            return _verdict("SUSPICIOUS", int(p * 100), [f"ML p={p:.2f}"], details)
    return _verdict("CLEAN", 0, ["No layer fired"], details)
