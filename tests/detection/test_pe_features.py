import numpy as np
from Engine.Detection.pe_features import PEFeatureExtractor


def test_dim_and_version():
    ext = PEFeatureExtractor(print_feature_warning=False)
    assert ext.version == 2
    assert ext.dim == 2381


def test_vector_shape_and_dtype(benign_pe_bytes):
    ext = PEFeatureExtractor(print_feature_warning=False)
    v = ext.feature_vector(benign_pe_bytes)
    assert isinstance(v, np.ndarray)
    assert v.shape == (2381,)
    assert v.dtype == np.float32
    assert np.isfinite(v).all()


def test_deterministic(benign_pe_bytes):
    ext = PEFeatureExtractor(print_feature_warning=False)
    a = ext.feature_vector(benign_pe_bytes)
    b = ext.feature_vector(benign_pe_bytes)
    assert np.array_equal(a, b)


def test_garbage_input_does_not_raise():
    ext = PEFeatureExtractor(print_feature_warning=False)
    v = ext.feature_vector(b"not a pe file")
    assert v.shape == (2381,)


def test_real_pe_has_nontrivial_signal(benign_pe_bytes):
    ext = PEFeatureExtractor(print_feature_warning=False)
    v = ext.feature_vector(benign_pe_bytes)
    # a real PE must populate many features; all-zeros (a broken extractor) fails here
    assert int((v != 0).sum()) > 100
    # parsing must actually happen: garbage input differs from a real PE
    g = ext.feature_vector(b"not a pe file")
    assert not np.array_equal(v, g)
