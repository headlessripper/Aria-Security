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
        try:
            trusted = bool(self.sign.sign_verify(file_path))
        except Exception:
            trusted = False
        signer = self._signer_name(file_path)
        return {
            "signed": trusted,          # WinVerifyTrust trusts only valid signatures
            "trusted": trusted,
            "revoked": False,           # best-effort; full revocation check deferred
            "abused": bool(signer and signer.lower() in self.abused),
            "signer": signer,
        }

    def _signer_name(self, file_path):
        # Best-effort placeholder: proper PKCS#7 subject extraction is deferred to
        # the post-dataset phase (needs signtool/cryptography parsing). Returns None.
        return None
