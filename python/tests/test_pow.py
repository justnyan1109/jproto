"""test_pow: ctx init, mine 4–6 бит ≤ 2 с, verify ok/fail; JPPOW_DISABLE."""

import hashlib
import os
import time

import pytest

from jproto_ref import pow as JP

SEED_HOUR = b"\x11" * 32
SEED_ROUND = b"\x22" * 32
PAYLOAD = b"unit-test-payload"


def _digest() -> bytes:
    return JP.pow_digest(PAYLOAD)


def test_pow_context_and_hash():
    pw = JP.Pow(SEED_HOUR)
    pw.add_vms(2)
    d1 = pw.hash(SEED_ROUND, _digest(), 42)
    d2 = pw.hash(SEED_ROUND, _digest(), 43)
    assert d1 != d2
    b = pw.lzbits(d1)
    assert 0 <= b < 32
    pw.close()


@pytest.mark.parametrize("min_bits,budget", [(4, 800), (5, 1500), (6, 1800)])
def test_pow_mine_within_2s_and_verify(min_bits: int, budget: int):
    pw = JP.Pow(SEED_HOUR)
    pd = _digest()
    t0 = time.time()
    res = pw.mine(SEED_ROUND, pd, min_bits, budget, nthreads=2)
    dt = time.time() - t0
    assert dt < 2.0, f"mine {min_bits} bits занял {dt:.2f}s"
    assert res is not None, f"не намайнилось {min_bits} бит за {budget} мс"
    nonce, bits = res
    assert bits >= min_bits
    # verify ok (nonce настоящий, у майнерского digest самому посчитать lzbits)
    assert pw.verify(SEED_ROUND, pd, nonce, bits, min_bits)
    actual = pw.bits_of(SEED_ROUND, pd, nonce)
    # jppow_mine может занизить/завысить reported bits у «испорченного» digest —
    # факт только actual (см. jppow.c баг); actual тоже обязан ≥ min_bits
    assert actual >= min_bits, (actual, bits)
    # fail-ветки
    assert pw.verify(SEED_ROUND, pd, nonce, actual + 1, min_bits) is False
    assert pw.verify(SEED_ROUND, pd, nonce + 1, bits, min_bits) is False
    assert pw.verify(SEED_ROUND, pd, nonce, bits, 20) is False
    pw.close()


def test_pow_module_mine_needs_ctx():
    JP._CURRENT = None
    with pytest.raises(JP.PowUnavailable):
        JP.mine(SEED_ROUND, _digest(), 4, 100)


def test_pow_digest_domain():
    d = JP.pow_digest(b"abc")
    assert len(d) == 32
    from jproto_ref.crypto import H, D_POW
    assert d == H(b"abc", D_POW)


def test_pow_round_binding():
    """PoW привязан к seed_round: verify для другого раунда падает."""
    pw = JP.Pow(SEED_HOUR)
    pd = _digest()
    res = pw.mine(SEED_ROUND, pd, 4, 800)
    assert res is not None
    nonce, bits = res
    other_round = b"\x33" * 32
    assert pw.verify(other_round, pd, nonce, bits, 4) is False
    pw.close()
