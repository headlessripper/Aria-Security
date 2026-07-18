import json, os
from pathlib import Path
import numpy as np
import onnxruntime as ort
from Engine.Detection.pe_features import PEFeatureExtractor

class MLScanner:
    def __init__(self, threshold: float = 0.5):
        self.session = None
        self.input_name = None
        self.threshold = threshold
        self.extractor = PEFeatureExtractor(print_feature_warning=False)
        self.feature_version = None

    def load_file(self, onnx_path, features_json=None):
        if not onnx_path or not os.path.exists(onnx_path):
            return False
        try:
            self.session = ort.InferenceSession(onnx_path, providers=["CPUExecutionProvider"])
            self.input_name = self.session.get_inputs()[0].name
        except Exception as e:
            print(f"[MLScanner] load error: {e}")
            self.session = None
            return False
        meta_path = features_json or str(Path(onnx_path).with_name("features.json"))
        try:
            meta = json.loads(Path(meta_path).read_text())
            self.feature_version = meta.get("feature_version")
            if self.feature_version != self.extractor.version:
                print(f"[MLScanner] feature_version mismatch: model={self.feature_version} "
                      f"extractor={self.extractor.version}")
        except Exception:
            pass
        return True

    def score(self, file_path):
        if self.session is None:
            return None
        try:
            with open(file_path, "rb") as f:
                bytez = f.read()
            vec = self.extractor.feature_vector(bytez).reshape(1, -1).astype(np.float32)
            out = self.session.run(None, {self.input_name: vec})
            return float(self._extract_prob(out))
        except Exception as e:
            print(f"[MLScanner] score error: {e}")
            return None

    @staticmethod
    def _extract_prob(out):
        # onnxmltools LightGBM export: out[0]=label, out[1]=probabilities.
        # ZipMap on -> list[dict{0:p0,1:p1}]; off -> array [n,2].
        try:
            probs = out[1]
            row = probs[0]
            if isinstance(row, dict):
                return row.get(1, row.get(True, 0.0))
            return float(np.ravel(row)[-1])
        except Exception:
            return float(np.ravel(out[0])[0])

    def model_scan(self, file_path, full_output=False):
        p = self.score(file_path)
        if p is None:
            return (False, False)
        if p >= self.threshold:
            return ("Malware", int(round(p * 100)))
        return (False, False)
