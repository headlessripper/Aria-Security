import os
from pathlib import Path
try:
    import tlsh as _tlsh
    _HAS_TLSH = True
except Exception:
    _HAS_TLSH = False
import pefile

class FuzzyHasher:
    def __init__(self, db_path=None, tlsh_near: int = 40):
        self.tlsh_near = tlsh_near
        self.bad_imphashes = set()
        self.bad_tlsh = []
        if db_path and os.path.exists(db_path):
            self._load_db(db_path)

    def _load_db(self, db_path):
        for line in Path(db_path).read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("imphash:"):
                self.bad_imphashes.add(line[8:].lower())
            elif line.startswith("tlsh:"):
                self.bad_tlsh.append(line[5:])

    def imphash(self, file_path):
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            h = pe.get_imphash()
            return h.lower() if h else None
        except Exception:
            return None

    def tlsh(self, bytez):
        if not _HAS_TLSH or not bytez or len(bytez) < 256:
            return None
        try:
            h = _tlsh.hash(bytez)
            return h if h and h != "TNULL" else None
        except Exception:
            return None

    def match(self, file_path):
        result = {"matched": False, "best_distance": None, "source": None}
        imp = self.imphash(file_path)
        if imp and imp in self.bad_imphashes:
            return {"matched": True, "best_distance": 0, "source": f"imphash:{imp}"}
        try:
            with open(file_path, "rb") as f:
                bytez = f.read()
        except Exception:
            return result
        th = self.tlsh(bytez)
        if th and self.bad_tlsh:
            dists = []
            for b in self.bad_tlsh:
                try:
                    dists.append(_tlsh.diff(th, b))
                except Exception:
                    pass
            if dists:
                best = min(dists)
                result["best_distance"] = best
                if best <= self.tlsh_near:
                    result.update(matched=True, source=f"tlsh:{best}")
        return result
