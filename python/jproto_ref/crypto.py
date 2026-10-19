"""Крипто-примитивы jproto (docs/protocol.md §0).

Все хэши = SHAKE256(tag ‖ x, 32 B); домены — ASCII-теги из protocol.md §0.
ML-KEM-768 / ML-DSA-44 через пакет `cryptography` (модули mlkem/mldsa, ≥46).
AEAD ChaCha20-Poly1305 (RFC 8439): основной путь — cryptography, fallback —
compact pure-python (KAT и кросс-проверка в tests/test_crypto.py).

Важные детали API пакета `cryptography`:
- MLKEM768PublicKey.encapsulate() возвращает (shared_secret, ciphertext);
- приватные ключи сериализуются как seed (ML-KEM 64 B = d‖z, ML-DSA 32 B),
  восстановление from_seed_bytes(); expanded-ключ (2400 B) наружу не отдаём.
"""

from __future__ import annotations

import hashlib
import struct

# --- домены H(tag, x) -------------------------------------------------------

D_DIR = b"jproto.dir.1"        # адрес узла/клиента
D_H = b"jproto.h.1"            # cell index
D_BEACON = b"jproto.beacon.1"  # seed/commit
D_POW = b"jproto.pow.1"        # payload digest для PoW
D_AAD = b"jproto.aad.1"        # AAD AEAD
D_MIX = b"jproto.mix.1"        # onion-слои (route_digest)
D_DIRLIST = b"jproto.dirlist.1"
D_MSG = b"jproto.msg.1"        # AAD payload сообщения (зарезервирован)
D_REC = b"jproto.rec.1"        # digest записи BS (новый домен — DESIGN_NOTES)


def H(x: bytes, tag: bytes = b"") -> bytes:
    """H(x, tag) = SHAKE256(tag ‖ x).digest(32)."""
    return hashlib.shake_256(tag + bytes(x)).digest(32)


def h_dir(x: bytes) -> bytes:      return H(x, D_DIR)
def h_cell(x: bytes) -> bytes:     return H(x, D_H)
def h_beacon(x: bytes) -> bytes:   return H(x, D_BEACON)
def h_pow(x: bytes) -> bytes:      return H(x, D_POW)
def h_mix(x: bytes) -> bytes:      return H(x, D_MIX)
def h_dirlist(x: bytes) -> bytes:  return H(x, D_DIRLIST)
def h_rec(x: bytes) -> bytes:      return H(x, D_REC)


# Genesis seed(-1): детерминированная константа для вычисления seed(boot-раунда)
# (пробел спеки — см. DESIGN_NOTES §beacon).
GENESIS_SEED = h_beacon(b"jproto-genesis-1")

# Dev-константа ключа RandomX cache, пока узел не владеет вычисленным seed
# часового раунда. Привязка PoW к раунду сохраняется через seed_round во входе.
import os as _os
_dev_hour = _os.environ.get("JPROTO_DEV_HOUR_SEED") or "jproto-dev-hour-seed"
DEV_SEED_HOUR = h_beacon(_dev_hour.encode())

# --- размерности ------------------------------------------------------------

KEM_PK_LEN = 1184
KEM_CT_LEN = 1088
KEM_SS_LEN = 32
KEM_SK_SEED_LEN = 64   # seed (d‖z); expanded-ключ = 2400 B (не используем)
DSA_PK_LEN = 1312
DSA_SIG_LEN = 2420
DSA_SK_SEED_LEN = 32

AEAD_KEY_LEN = 32
AEAD_NONCE_LEN = 12
AEAD_TAG_LEN = 16

try:
    from cryptography.hazmat.primitives.asymmetric.mlkem import (
        MLKEM768PrivateKey, MLKEM768PublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA44PrivateKey, MLDSA44PublicKey,
    )
    _HAS_ML = True
except Exception:  # pragma: no cover
    _HAS_ML = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    _HAVE_CHACHA = True
except Exception:  # pragma: no cover
    _HAVE_CHACHA = False


# --- ML-KEM-768 -------------------------------------------------------------

def kem_generate() -> tuple[bytes, bytes]:
    """(pk 1184 B, sk_seed 64 B)."""
    if not _HAS_ML:
        raise ImportError("cryptography с ML-KEM недоступен")
    k = MLKEM768PrivateKey.generate()
    pk = k.public_key().public_bytes_raw()
    sk = k.private_bytes_raw()
    assert len(pk) == KEM_PK_LEN and len(sk) == KEM_SK_SEED_LEN
    return pk, sk


def kem_encaps(pk: bytes) -> tuple[bytes, bytes]:
    """Encaps: (shared_secret 32 B, ciphertext 1088 B)."""
    assert len(pk) == KEM_PK_LEN
    ss, ct = MLKEM768PublicKey.from_public_bytes(bytes(pk)).encapsulate()
    assert len(ss) == KEM_SS_LEN and len(ct) == KEM_CT_LEN
    return ss, ct


def kem_decaps(sk_seed: bytes, ct: bytes) -> bytes:
    """Decaps. ML-KEM возвращает SS и для «мусорного» ct (implicit rejection) —
    ошибки вскрываются на этапе AEAD."""
    assert len(ct) == KEM_CT_LEN
    ss = MLKEM768PrivateKey.from_seed_bytes(bytes(sk_seed)).decapsulate(bytes(ct))
    assert len(ss) == KEM_SS_LEN
    return ss


# --- ML-DSA-44 --------------------------------------------------------------

def dsa_generate() -> tuple[bytes, bytes]:
    """(pk 1312 B, sk_seed 32 B)."""
    if not _HAS_ML:
        raise ImportError("cryptography с ML-DSA недоступен")
    d = MLDSA44PrivateKey.generate()
    pk = d.public_key().public_bytes_raw()
    sk = d.private_bytes_raw()
    assert len(pk) == DSA_PK_LEN and len(sk) == DSA_SK_SEED_LEN
    return pk, sk


def dsa_sign(sk_seed: bytes, msg: bytes) -> bytes:
    d = MLDSA44PrivateKey.from_seed_bytes(bytes(sk_seed))
    sig = d.sign(bytes(msg))
    assert len(sig) == DSA_SIG_LEN
    return sig


def dsa_verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        MLDSA44PublicKey.from_public_bytes(bytes(pk)).verify(bytes(sig), bytes(msg))
        return True
    except Exception:
        return False


# --- ChaCha20-Poly1305, pure-python (RFC 8439) fallback ----------------------

def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _quarter(x: list[int], a: int, b: int, c: int, d: int) -> None:
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl32(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl32(x[b] ^ x[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter & 0xFFFFFFFF]
    state += list(struct.unpack("<3I", nonce))
    x = state[:]
    for _ in range(10):
        _quarter(x, 0, 4, 8, 12);  _quarter(x, 1, 5, 9, 13)
        _quarter(x, 2, 6, 10, 14); _quarter(x, 3, 7, 11, 15)
        _quarter(x, 0, 5, 10, 15); _quarter(x, 1, 6, 11, 12)
        _quarter(x, 2, 7, 8, 13);  _quarter(x, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(x, state)])


def _poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF  # clamp (RFC 8439 §2.5.1)
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        blk = msg[i:i + 16]
        n = int.from_bytes(blk, "little") + (1 << (8 * len(blk)))
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _keystream_xor(key: bytes, nonce: bytes, data: bytes, counter_from: int = 1) -> bytes:
    out = bytearray()
    c = counter_from
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, c, nonce)
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        c += 1
    return bytes(out)


def _aead_mac(poly_key: bytes, aad: bytes, ct: bytes) -> bytes:
    msg = _pad16(aad) + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return _poly1305(poly_key, msg)


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * ((-len(data)) % 16)


# --- публичный AEAD API ------------------------------------------------------

def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes) -> bytes:
    """ChaCha20-Poly1305: nonce 12 B → ct ‖ tag(16)."""
    key, nonce, aad, pt = bytes(key), bytes(nonce), bytes(aad), bytes(pt)
    assert len(key) == AEAD_KEY_LEN and len(nonce) == AEAD_NONCE_LEN
    if _HAVE_CHACHA:
        return ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    ct = _keystream_xor(key, nonce, pt, 1)
    tag = _aead_mac(poly_key, aad, ct)
    return ct + tag


def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ct_tag: bytes) -> bytes:
    """AEAD decrypt; при провале тега — ValueError."""
    key, nonce, aad = bytes(key), bytes(nonce), bytes(aad)
    ct_tag = bytes(ct_tag)
    assert len(key) == AEAD_KEY_LEN and len(nonce) == AEAD_NONCE_LEN
    if _HAVE_CHACHA:
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, ct_tag, aad)
        except Exception as e:
            raise ValueError("AEAD tag mismatch") from e
    if len(ct_tag) < AEAD_TAG_LEN:
        raise ValueError("ct too short")
    ct, tag = ct_tag[:-AEAD_TAG_LEN], ct_tag[-AEAD_TAG_LEN:]
    poly_key = _chacha20_block(key, 0, nonce)[:32]
    if _aead_mac(poly_key, aad, ct) != tag:
        raise ValueError("AEAD tag mismatch")
    return _keystream_xor(key, nonce, ct, 1)
