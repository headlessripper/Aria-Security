from Engine.Detection.Engine_Unit_SG import sign_scanner

class CertReputation:
    """Signature trust via Windows WinVerifyTrust, plus an abused-signer list.
    Full Authenticode signer-name extraction (PKCS#7) is deferred; `signer` is
    best-effort None for now, so `abused` only fires when a signer is provided."""
    def __init__(self, abused_signers=None):
        self.sign = sign_scanner()
        try:
            self.sign.init_windll(["wintrust"])
        except Exception:
            pass
        self.abused = {s.lower() for s in (abused_signers or [])}

    def evaluate(self, file_path):
        # Fast path: embedded Authenticode (WTD_CHOICE_FILE).
        try:
            trusted = bool(self.sign.sign_verify(file_path))
        except Exception:
            trusted = False
        signature_type = "embedded" if trusted else None

        # Slow path: most modern Windows system binaries are catalog-signed (the
        # signature lives in a system .cat, not the PE), so the embedded check reads
        # them as untrusted. Fall back to catalog verification to avoid false positives.
        if not trusted:
            try:
                if bool(self.sign.catalog_verify(file_path)):
                    trusted = True
                    signature_type = "catalog"
            except Exception:
                pass

        signer = self._signer_name(file_path)
        return {
            "signed": trusted,          # WinVerifyTrust trusts only valid signatures
            "trusted": trusted,
            "revoked": False,           # best-effort; full revocation check deferred
            "abused": bool(signer and signer.lower() in self.abused),
            "signer": signer,
            "signature_type": signature_type,   # "embedded" | "catalog" | None
        }

    def _signer_name(self, file_path):
        # Best-effort placeholder: proper PKCS#7 subject extraction is deferred to
        # the post-dataset phase (needs signtool/cryptography parsing). Returns None.
        return None
