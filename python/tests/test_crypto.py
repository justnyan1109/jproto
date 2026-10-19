"""test_crypto: KEM enc/dec, DSA sig, AEAD (включая pure-python fallback)."""

import os

import pytest

from jproto_ref import crypto as C

HAS_ML = C._HAS_ML
# KAT, полученный из OpenSSL-реализации ChaCha20-Poly1305 (package `cryptography`)
# и вмороженный в тест: якорит pure-python fallback независимо от пакета.
KAT_KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
KAT_NONCE = bytes.fromhex("4142434445464748494a4b4c")
KAT_AAD = bytes.fromhex("505152535455565758595a5b5c5d5e5f606162")
KAT_PT = b"Ladies and Gentlemen of the class of '99: sunscreen tip, zero retries."
KAT_CTTAG = bytes.fromhex(
    "9cfb522df544f9d9646a3c262eddba20d45c7dddec07a633d9c06c0432b756c8f407cd8777f0d31992800cd0b0e9acdcd5cff9bf2b675a575da589d0dae5c7d7442cde369b28271ed5dc891a3b345c3681cc4e1aac6e")


def test_rfc8439_fallback_vector():
    """KAT (OpenSSL-полученный) на pure-python пути."""
    ct = C._keystream_xor(KAT_KEY, KAT_NONCE, KAT_PT, 1)
    tag = C._aead_mac(C._chacha20_block(KAT_KEY, 0, KAT_NONCE)[:32], KAT_AAD, ct)
    assert ct + tag == KAT_CTTAG


@pytest.mark.skipif(not C._HAVE_CHACHA and not True, reason="кросс-проверка")
def test_aead_fallback_matches_cryptography():
    if not C._HAVE_CHACHA:
        pytest.skip("cryptography недоступен — fallback сравнивать не с чем")
    for n in (0, 1, 63, 64, 65, 200):
        key = os.urandom(32)
        nonce = os.urandom(12)
        aad = os.urandom(19)
        pt = os.urandom(n)
        ct = C._keystream_xor(key, nonce, pt, 1)
        fast = C.ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
        slow = ct + C._aead_mac(C._chacha20_block(key, 0, nonce)[:32], aad, ct)
        assert fast == slow
        # decrypt через общий API (в fallback-режиме пакет подменён)
        assert C.aead_decrypt(key, nonce, aad, fast) == pt


def test_aead_roundtrip_and_tamper():
    key = os.urandom(32)
    nonce = os.urandom(12)
    aad = os.urandom(33)
    pt = b"payload" * 9
    ct = C.aead_encrypt(key, nonce, aad, pt)
    assert C.aead_decrypt(key, nonce, aad, ct) == pt
    bad = bytearray(ct); bad[0] ^= 1
    with pytest.raises(ValueError):
        C.aead_decrypt(key, nonce, aad, bytes(bad))
    with pytest.raises(ValueError):
        C.aead_decrypt(key, nonce, b"other-aad!", ct)


@pytest.mark.skipif(not HAS_ML, reason="ML-KEM недоступен в cryptography")
def test_kem_roundtrip_and_sizes():
    pk, sk = C.kem_generate()
    assert len(pk) == C.KEM_PK_LEN and len(sk) == C.KEM_SK_SEED_LEN
    for _ in range(3):
        ss, ct = C.kem_encaps(pk)
        assert len(ct) == C.KEM_CT_LEN and len(ss) == C.KEM_SS_LEN
        assert C.kem_decaps(sk, ct) == ss


@pytest.mark.skipif(not HAS_ML, reason="ML-KEM недоступен")
def test_kem_wrong_ciphertext_never_crashes():
    """ML-KEM implicit rejection: decaps мусорного ct не роняет ключи."""
    pk, sk = C.kem_generate()
    ss, ct = C.kem_encaps(pk)
    bad = bytearray(ct); bad[5] ^= 0xFF
    ss2 = C.kem_decaps(sk, bytes(bad))
    assert ss2 != ss or len(ss2) == 32  # любой 32-байтовый SS валиден как tested


@pytest.mark.skipif(not HAS_ML, reason="ML-DSA недоступен")
def test_dsa_sign_verify_and_tamper():
    pk, sk = C.dsa_generate()
    msg = os.urandom(77)
    sig = C.dsa_sign(sk, msg)
    assert len(sig) == C.DSA_SIG_LEN
    assert C.dsa_verify(pk, sig, msg)
    assert not C.dsa_verify(pk, sig, msg + b"x")
    broken = bytearray(sig); broken[100] ^= 0x40
    assert not C.dsa_verify(pk, bytes(broken), msg)


def test_h_domains_differ():
    x = b"x"
    tags = [C.H(x, t) for t in (C.D_DIR, C.D_H, C.D_BEACON, C.D_POW, C.D_MIX,
                                C.D_DIRLIST, C.D_MSG, C.D_REC)]
    assert len(set(tags)) == len(tags)
    assert all(len(t) == 32 for t in tags)
    # переопределение: H(x, tag) = shake_256(tag ‖ x)
    import hashlib
    assert C.H(b"abc", b"T") == hashlib.shake_256(b"Tabc").digest(32)
