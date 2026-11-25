import math

import numpy as np
import pytest

from dtds.ml.private_fl import (MOD, PrivacyConfig, SecAggClient, clip, decode, encode,
                                flatten, gaussian_epsilon, secure_sum, train_private, unflatten)
from tests.test_ml import synthetic


def test_fixed_point_roundtrip_and_negatives():
    x = np.array([0.0, 1.5, -2.25, 1e-5, -123.456])
    np.testing.assert_allclose(decode(encode(x)), x, atol=1 / (1 << 16))
    with pytest.raises(OverflowError):
        encode(np.array([1e6]))


def test_masks_cancel_exactly():
    rng = np.random.default_rng(0)
    clients = [SecAggClient(i) for i in range(6)]
    pubs = {c.index: c.public_key for c in clients}
    updates = [rng.normal(0, 0.5, 1000) for _ in clients]
    masked = [c.mask(u, pubs, round_no=3) for c, u in zip(clients, updates)]
    # Integer sums mod 2^32 match the sum of the encoded updates bit for bit.
    enc_sum = sum(encode(u) for u in updates) % MOD
    assert np.array_equal(sum(masked) % MOD, enc_sum)
    np.testing.assert_allclose(secure_sum(masked), np.sum(updates, axis=0), atol=6 / (1 << 16))


def test_single_masked_update_reveals_nothing_useful():
    rng = np.random.default_rng(1)
    clients = [SecAggClient(i) for i in range(3)]
    pubs = {c.index: c.public_key for c in clients}
    u = rng.normal(0, 0.5, 5000)
    m = decode(clients[0].mask(u, pubs, round_no=1))
    assert abs(np.corrcoef(m, u)[0, 1]) < 0.05
    # Masks change every round, so the same update is masked differently.
    assert not np.array_equal(clients[0].mask(u, pubs, 1), clients[0].mask(u, pubs, 2))


def test_pairwise_secrets_agree():
    a, b = SecAggClient(0), SecAggClient(1)
    assert np.array_equal(a._mask(b.public_key, 7, 64), b._mask(a.public_key, 7, 64))


def test_clip():
    v = np.array([3.0, 4.0])
    c, was = clip(v, 1.0)
    assert was and math.isclose(np.linalg.norm(c), 1.0)
    c2, was2 = clip(v, 10.0)
    assert not was2 and np.array_equal(c2, v)


def test_epsilon_accountant():
    assert gaussian_epsilon(0.0, 10) == math.inf
    # Stronger noise and fewer rounds both mean a smaller epsilon (better privacy).
    assert gaussian_epsilon(6, 30) < gaussian_epsilon(3, 30) < gaussian_epsilon(1, 30)
    assert gaussian_epsilon(3, 10) < gaussian_epsilon(3, 30)
    # Known closed form check: one round, minimised over alpha, sigma large:
    # eps ~ 1/(2 s^2) + sqrt(2 log(1/delta)) / s for large s.
    s = 50.0
    approx = 1 / (2 * s ** 2) + math.sqrt(2 * math.log(1e5)) / s
    assert gaussian_epsilon(s, 1) == pytest.approx(approx, rel=0.05)


def test_flatten_roundtrip():
    like = ([np.ones((3, 2)), np.ones((2, 4))], [np.zeros(2), np.zeros(4)])
    v = np.arange(3 * 2 + 2 * 4 + 2 + 4, dtype=float)
    c, i = unflatten(v, like)
    np.testing.assert_array_equal(flatten((c, i)), v)


def test_secure_aggregation_matches_plain_fedavg():
    """With no DP noise, masking must not change the trained model at all
    (beyond fixed-point rounding)."""
    from dtds.ml.federated import FederatedPreprocessor
    ds = synthetic(600)
    parts = np.array_split(np.arange(len(ds.X_train)), 3)
    prep = FederatedPreprocessor(ds.categorical, ds.numeric).fit(ds.X_train)
    data = [(prep.transform(ds.X_train.iloc[p]), ds.y_train.iloc[p].to_numpy()) for p in parts]
    n = data[0][0].shape[1]
    m1, _, _ = train_private(data, ds.classes, n, 3, PrivacyConfig(clip_norm=1e6, secure_aggregation=True))
    m2, _, _ = train_private(data, ds.classes, n, 3, PrivacyConfig(clip_norm=1e6, secure_aggregation=False))
    np.testing.assert_allclose(flatten((m1.coefs_, m1.intercepts_)), flatten((m2.coefs_, m2.intercepts_)),
                               atol=1e-3)
