"""PoW bindings для build/libjppow.so (ctypes), src/jppow.c / include/jproto/jppow.h.

Функция PoW (protocol.md §3):
  key    = seed_hour (32 B)         # ключ RandomX cache
  input  = seed_round(32) ‖ payload_digest(32) ‖ nonce(u64 LE)
  digest = RandomX_H(key, input)

Отличия приложения от заголовка C:
- payload_digest считается вне: pow_digest(payload) = SHAKE256(pow.1, payload).
- jppow_mine() вернёт «лучший» digest, но в текущей сборке digest_best портится
  багом в jppow.c (out[i] <<= 1 при подсчёте ведущих нулей затирает данные) —
  поэтому Python НИКОГДА не доверяет out_digest из mine(): verification пересчитывает
  digest по nonce (jppow_verify) — это и по спеке, и обходит баг.

Env:
  JPPOW_LIB    путь к .so (по умолчанию <repo>/build/libjppow.so)
  JPPOW_NVM    число RandomX VM (default 2)
  JPPOW_DISABLE=1  отключить PoW (unit-тесты без .so); mine/verify кидают
                   PowUnavailable; полный интеграционный тест требует рабочий .so.
"""

from __future__ import annotations

import ctypes
import os
import threading
import time
import hashlib
from typing import Optional

# путь по умолчанию: <repo>/build/libjppow.so
_DEFAULT_LIB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "build", "libjppow.so")

from .crypto import h_pow


def pow_digest(payload: bytes) -> bytes:
    """payload_digest = SHAKE256(tag=jproto.pow.1, payload) — 32 B."""
    return h_pow(payload)


class PowUnavailable(Exception):
    pass


class Pow:
    """Контекст RandomX (cache построен по seed_hour через randomx_alloc_cache)."""

    def __init__(self, seed_hour: bytes, nvm: int | None = None, lib: "ctypes.CDLL | None" = None):
        self.lib = lib if lib is not None else load_lib()
        self.seed_hour = bytes(seed_hour)
        assert len(self.seed_hour) == 32
        nvm = nvm if nvm is not None else max(1, int(os.environ.get("JPPOW_NVM", "2")))
        self.nvm = nvm
        self.lock = threading.RLock()
        self._closed = False
        if self.lib is None:  # JPPOW_DISABLE / нет .so
            self.ctx = None
            self._add_vms = None
            return
        init = self.lib.jppow_init
        init.restype = ctypes.c_void_p
        init.argtypes = [ctypes.c_char_p, ]
        self.ctx = ctypes.c_void_p(init(self.seed_hour))
        if not self.ctx:
            raise PowUnavailable(f"jppow_init failed for seed_hour={self.seed_hour.hex()}")
        add = self.lib.jppow_add_vms
        add.restype = ctypes.c_int
        add.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self._add_vms = add
        self.add_vms(self.nvm)

    @property
    def disabled(self) -> bool:
        return self.lib is None

    def _ensure_open(self) -> None:
        if self._closed or self.lib is None:
            raise PowUnavailable("pow ctx closed / disabled")

    def add_vms(self, nvm: int) -> int:
        self._ensure_open()
        return self._add_vms(self.ctx, int(nvm))

    def hash(self, seed_round: bytes, payload_digest: bytes, nonce: int, thread: int = 0) -> bytes:
        self._ensure_open()
        seed_round = bytes(seed_round); payload_digest = bytes(payload_digest)
        assert len(seed_round) == 32 and len(payload_digest) == 32
        out = ctypes.create_string_buffer(32)
        with self.lock:
            rc = self.lib.jppow_hash(self.ctx, int(thread), seed_round, payload_digest, ctypes.c_uint64(nonce), out)
        if rc != 0:
            raise PowUnavailable(f"jppow_hash rc={rc}")
        return out.raw

    def lzbits(self, digest: bytes) -> int:
        """Ведущие нулевые биты digest."""
        d = bytes(digest)
        bits = 0
        for byte in d:
            if byte == 0:
                bits += 8
                continue
            for b in range(7, -1, -1):
                if byte & (1 << b):
                    return bits
                bits += 1
        return bits

    def mine(self, seed_round: bytes, payload_digest: bytes, min_bits: int, budget_ms: int,
             nthreads: int | None = None) -> tuple[int, int] | None:
        """Возвращает (nonce, bits) при bits >= min_bits; None — бюджет исчерпан.
        digest НЕ доверяем (баг в C) — верификация только по jppow_verify."""
        self._ensure_open()
        seed_round = bytes(seed_round); payload_digest = bytes(payload_digest)
        with self.lock:
            avail = self.nvm
            nthreads = avail if nthreads is None else min(avail, int(nthreads))
            if nthreads < 1:
                return None
            out_nonce = ctypes.c_uint64(0)
            out_bits = ctypes.c_int(0)
            digest_buf = ctypes.create_string_buffer(32)  # вложенный буфер — C портит
            rc = self.lib.jppow_mine(self.ctx, seed_round, payload_digest, int(min_bits),
                                     int(budget_ms), int(nthreads),
                                     ctypes.byref(out_nonce), digest_buf, ctypes.byref(out_bits))
        if rc == 0:
            bits = int(out_bits.value)
            if bits < min_bits:
                return None
            return int(out_nonce.value), bits
        return None

    def verify(self, seed_round: bytes, payload_digest: bytes, nonce: int,
               claimed_bits: int, required_bits: int) -> bool:
        """verify по nonce (пересчёт RandomX) — как jppow_verify; проще читается."""
        self._ensure_open()
        seed_round = bytes(seed_round); payload_digest = bytes(payload_digest)
        with self.lock:
            rc = self.lib.jppow_verify(self.ctx, seed_round, payload_digest,
                                       ctypes.c_uint64(nonce), int(claimed_bits), int(required_bits))
        return rc == 0

    def bits_of(self, seed_round: bytes, payload_digest: bytes, nonce: int) -> int:
        """Фактические ведущие нулевые биты по digest(nonce) — самопроверка."""
        return self.lzbits(self.hash(seed_round, payload_digest, nonce))

    def close(self) -> None:
        with self.lock:
            if self._closed:
                return
            self._closed = True
            if self.lib is not None and self.ctx:
                self.lib.jppow_free(self.ctx)
                self.ctx = ctypes.c_void_p(None)


# --- module-level --------------------------------------------------------------

_lib_cache: Optional[ctypes.CDLL] = None
_lib_warned = False
_CURRENT: Optional[Pow] = None
_CTXS: dict[bytes, Pow] = {}
_CTX_ORDER: list[bytes] = []
_CTX_MAX = 4


def _disabled() -> bool:
    return os.environ.get("JPPOW_DISABLE", "") == "1"


def load_lib() -> Optional[ctypes.CDLL]:
    """Загрузка libjppow.so; при отсутствии/AILS возвращает None с предупреждением."""
    global _lib_cache, _lib_warned
    if _disabled():
        return None
    if _lib_cache is not None:
        return _lib_cache
    path = os.environ.get("JPPOW_LIB", _DEFAULT_LIB)
    try:
        lib = ctypes.CDLL(path)
    except OSError as e:
        if not _lib_warned:
            _lib_warned = True
            import sys
            print(f"jproto_ref.pow: JPPOW lib недоступен ({path}): {e} — PoW отключён;", file=sys.stderr)
            print("  (для unit-тестов без .so: JPPOW_DISABLE=1; интеграционный тест требует .so)", file=sys.stderr)
        _lib_cache = None
        return None
    # сигнатуры из jppow.h
    lib.jppow_init.restype = ctypes.c_void_p
    lib.jppow_init.argtypes = [ctypes.c_char_p]
    lib.jppow_free.restype = None
    lib.jppow_free.argtypes = [ctypes.c_void_p]
    lib.jppow_add_vms.restype = ctypes.c_int
    lib.jppow_add_vms.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.jppow_hash.restype = ctypes.c_int
    lib.jppow_hash.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_uint64, ctypes.c_char_p]
    lib.jppow_leading_zero_bits.restype = ctypes.c_int
    lib.jppow_leading_zero_bits.argtypes = [ctypes.c_char_p]
    lib.jppow_mine.restype = ctypes.c_int
    lib.jppow_mine.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int,
                               ctypes.POINTER(ctypes.c_uint64), ctypes.c_char_p,
                               ctypes.POINTER(ctypes.c_int)]
    lib.jppow_verify.restype = ctypes.c_int
    lib.jppow_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_uint64, ctypes.c_int, ctypes.c_int]
    _lib_cache = lib
    return lib


def pow_ctx(seed_hour: bytes, register: bool = True) -> Pow:
    """Контекст с LRU-кэшем по seed_hour (кэш RandomX дорог: ~330 мс)."""
    global _CURRENT
    key = bytes(seed_hour)
    pw = _CTXS.get(key)
    if pw is None:
        pw = Pow(key)
        _CTXS[key] = pw
        _CTX_ORDER.append(key)
        if len(_CTX_ORDER) > _CTX_MAX:
            old = _CTX_ORDER.pop(0)
            gone = _CTXS.pop(old, None)
            if gone is not None:
                gone.close()
    if register:
        _CURRENT = pw
    return pw


def mine(seed_round: bytes, payload_digest: bytes, min_bits: int, budget_ms: int,
         nthreads: int | None = None, ctx: Optional[Pow] = None) -> tuple[int, int] | None:
    """Функция-модуль; контекст берётся из последнего pow_ctx() либо явно ctx=.
    Возвращает (nonce, bits) или None при исчерпании бюджета (best < min)."""
    pw = ctx or _CURRENT
    if pw is None:
        raise PowUnavailable("no pow ctx: вызовите pow_ctx(seed_hour) ранее")
    return pw.mine(seed_round, payload_digest, min_bits, budget_ms, nthreads)


def verify(ctx: Optional[Pow], seed_round: bytes, payload_digest: bytes, nonce: int,
           claimed_bits: int, required_bits: int) -> bool:
    """bool по контракту; ctx может быть None → False (нет PoW)."""
    if ctx is None:
        return False
    return ctx.verify(seed_round, payload_digest, nonce, claimed_bits, required_bits)


def close_all() -> None:
    global _CURRENT
    for pw in _CTXS.values():
        pw.close()
    _CTXS.clear()
    _CTX_ORDER.clear()
    _CURRENT = None
