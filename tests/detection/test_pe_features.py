import numpy as np
from Engine.Detection.pe_features import PEFeatureExtractor


def test_dim_and_version():
    ext = PEFeatureExtractor()
    assert ext.version == 2
    assert ext.dim == 2381


def test_vector_shape_and_dtype(benign_pe_bytes):
    ext = PEFeatureExtractor()
    v = ext.feature_vector(benign_pe_bytes)
    assert isinstance(v, np.ndarray)
    assert v.shape == (2381,)
    assert v.dtype == np.float32
    assert np.isfinite(v).all()


def test_deterministic(benign_pe_bytes):
    ext = PEFeatureExtractor()
    a = ext.feature_vector(benign_pe_bytes)
    b = ext.feature_vector(benign_pe_bytes)
    assert np.array_equal(a, b)


def test_garbage_input_does_not_raise():
    ext = PEFeatureExtractor()
    v = ext.feature_vector(b"not a pe file")
    assert v.shape == (2381,)
