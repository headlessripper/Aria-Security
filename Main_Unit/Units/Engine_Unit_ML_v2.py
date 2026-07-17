# Engine_Unit_ML_v2.py

import os
import base64
import numpy as np
import onnxruntime as ort
from PIL import Image
from io import BytesIO


class model_scanner:
    def __init__(self):
        # Loaded ONNX models
        self.models = []

        # Model labels (must match training order)
        self.labels = ["Pefile/White", "Pefile/General"]

        # What we consider malicious
        self.detect_set = {"Pefile/General"}

        # Image preprocessing
        self.resize = (224, 224)

        # Confidence threshold (percent)
        self.min_confidence = 85

        # PE file extensions (fast gate)
        self.pe_extensions = (".exe", ".dll", ".sys", ".scr", ".ocx")

    # --------------------------------------------------
    # MODEL LOADING
    # --------------------------------------------------
    def load_path(self, path, callback=None):
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                if callback:
                    callback(full_path)
                self.load_file(full_path)

    def load_file(self, file):
        if not file.lower().endswith(".onnx"):
            return False
        try:
            # If GPU available and provider installed, you can switch to:
            # providers=["CUDAExecutionProvider", "CPUExecutionProvider"]
            session = ort.InferenceSession(file, providers=["CPUExecutionProvider"])
            self.models.append(session)
            return True
        except Exception as e:
            print(f"[ONNX LOAD ERROR] {file}: {e}")
            return False

    # --------------------------------------------------
    # FILE VALIDATION
    # --------------------------------------------------
    def is_pe_file(self, data: bytes) -> bool:
        # Windows PE files start with "MZ"
        return len(data) > 2 and data[:2] == b"MZ"

    def is_pe_candidate(self, file_path: str) -> bool:
        return file_path.lower().endswith(self.pe_extensions)

    # --------------------------------------------------
    # MAIN SCAN FUNCTION (single file)
    # --------------------------------------------------
    def model_scan(self, file_path, full_output=False):
        if not self.models:
            return (False, False)

        # Fast extension gate
        if not self.is_pe_candidate(file_path):
            return (False, False)

        data = self.get_data(file_path)
        if not data:
            return (False, False)

        # Hard PE header gate
        if not self.is_pe_file(data):
            return (False, False)

        image = self.preprocess_image(data, self.resize)
        if image is None:
            return (False, False)

        arr = np.asarray(image).astype("float32") / 255.0
        arr = np.expand_dims(arr, axis=0)

        if arr.ndim == 3:
            arr = np.expand_dims(arr, axis=-1)

        best_malicious = None
        results = []

        for model in self.models:
            try:
                input_meta = model.get_inputs()[0]
                input_name = input_meta.name
                input_shape = input_meta.shape

                curr_arr = arr.copy()

                # Handle NCHW vs NHWC
                if len(input_shape) == 4:
                    if input_shape[1] in (1, 3) and input_shape[3] not in (1, 3):
                        curr_arr = curr_arr.transpose(0, 3, 1, 2)

                probs = model.run(None, {input_name: curr_arr})[0]
                pred = probs[0]

                idx = int(np.argmax(pred))
                conf = float(pred[idx]) * 100.0

                if not np.isfinite(conf):
                    continue

                label = self.labels[idx] if idx < len(self.labels) else f"Class_{idx}"
                conf = round(conf, 2)

                if full_output:
                    results.append(
                        ("Whole File", label, conf, self.pil_to_base64(image))
                    )

                if label in self.detect_set and conf >= self.min_confidence:
                    if best_malicious is None or conf > best_malicious[1]:
                        best_malicious = (label, int(conf))

            except Exception as e:
                print(f"[INFERENCE ERROR] {e}")
                continue

        if full_output:
            results.sort(key=lambda x: (x[1] not in self.detect_set, -x[2]))
            malicious_count = sum(1 for _, lbl, _, _ in results if lbl in self.detect_set)
            return results, str(file_path), f"{malicious_count}/{len(results)}"

        return best_malicious if best_malicious else (False, False)

    # --------------------------------------------------
    # OPTIONAL: BATCH SCAN (for future integration)
    # --------------------------------------------------
    def batch_model_scan(self, file_paths):
        """
        Batch inference for multiple files.
        Returns: dict[file_path] -> (label, confidence) for malicious detections.
        """
        if not self.models:
            return {}

        batch = []
        for path in file_paths:
            if not self.is_pe_candidate(path):
                continue
            data = self.get_data(path)
            if not data or not self.is_pe_file(data):
                continue
            image = self.preprocess_image(data, self.resize)
            if image is None:
                continue
            arr = np.asarray(image).astype("float32") / 255.0
            arr = np.expand_dims(arr, axis=0)
            if arr.ndim == 3:
                arr = np.expand_dims(arr, axis=-1)
            batch.append((path, arr))

        if not batch:
            return {}

        # Stack into one batch
        batch_arr = np.concatenate([arr for _, arr in batch], axis=0)

        results = {}
        for model in self.models:
            try:
                input_meta = model.get_inputs()[0]
                input_name = input_meta.name
                input_shape = input_meta.shape

                curr_arr = batch_arr.copy()
                if len(input_shape) == 4 and input_shape[1] in (1, 3) and input_shape[3] not in (1, 3):
                    curr_arr = curr_arr.transpose(0, 3, 1, 2)

                probs = model.run(None, {input_name: curr_arr})[0]
                for i, (path, _) in enumerate(batch):
                    pred = probs[i]
                    idx = int(np.argmax(pred))
                    conf = float(pred[idx]) * 100.0
                    if not np.isfinite(conf):
                        continue
                    label = self.labels[idx] if idx < len(self.labels) else f"Class_{idx}"
                    conf = round(conf, 2)
                    if label in self.detect_set and conf >= self.min_confidence:
                        prev = results.get(path)
                        if prev is None or conf > prev[1]:
                            results[path] = (label, int(conf))
            except Exception as e:
                print(f"[INFERENCE ERROR] {e}")

        return results

    # --------------------------------------------------
    # HELPERS
    # --------------------------------------------------
    def pil_to_base64(self, img):
        buf = BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()

    def preprocess_image(self, data, size, channels=1):
        try:
            width, height = size
            side = int(np.ceil(np.sqrt(len(data) / channels)))

            raw = np.frombuffer(data, dtype=np.uint8)
            buf = np.zeros(side * side * channels, dtype=np.uint8)
            buf[: len(raw)] = raw

            image = Image.fromarray(buf.reshape((side, side)), "L")
            return image.resize((width, height), Image.Resampling.NEAREST)
        except Exception:
            return None

    def get_data(self, file_path):
        try:
            with open(file_path, "rb") as f:
                return f.read()
        except Exception:
            return None
