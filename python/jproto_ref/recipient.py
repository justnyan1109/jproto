"""Recipient-payload (wire.md §5): общий формат клиента и ноды.

Inner PT последнего слоя onion:
    header 14 B: magic 'JP' u16 ‖ ver u8 ‖ itype u8 ‖ session u32 ‖ seq u32 ‖ body_len u16
    body (body_len): ky_ct(1088) ‖ nonce12 ‖ msg_ct            (для I_ONLINE)
                     cell_idx(32) ‖ ky_ct ‖ nonce12 ‖ msg_ct   (для store-типов —
                     [ I_STORE_LOCAL / I_STORE_GLOBAL / I_OFFER / I_REPLY ]: честный
                     cell index должен доехать до home-ноды; пробел спеки, решение
                     в DESIGN_NOTES)
    + CSPRNG padding до полного слоя (в конструируемом PT последний слой = PT_L
    вплоть до 1268 B AEAD plaintext; см. DESIGN_NOTES §onion).

msg_ct = AEAD(ss_msg, nonce12, aad = sess(4LE)‖seq(4LE)‖reply_to(4LE), pt = app_bytes)
ss_msg = Encaps(pk_recipient).fresh на каждое сообщение (per-message KEM).
reply_to=0, когда получатель отрицает/reply не требуется.

Число параметров seq/qrstuvwxyz — удерживается klanten-ом (счётчики) и предан
читающей стороне явно.
"""

from __future__ import annotations

import os
import struct

from . import wire as W
from .crypto import (AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, KEM_CT_LEN,
                     kem_encaps, kem_decaps, aead_encrypt, aead_decrypt,
                     h_cell, h_mix, DEV_SEED_HOUR)

# Размер PT (AEAD plaintext) самого последнего слоя в dev-структуре onion.
# В wire.md константа 1280 относится к блобу слоя (nonce 12 + ct 1268);
# PT последнего слоя = 1268 - 32(addr_next) - 2(ct_len) = 1234 B.
PT_L_SIZE = 1268
RECIPIENT_PT_MAX = PT_L_SIZE - 32 - 2           # 1234
MSG_CT_MAX = RECIPIENT_PT_MAX - W.RECIPIENT_HDR_LEN - KEM_CT_LEN - AEAD_NONCE_LEN


def cell_index(seed_hour: bytes, pk_recipient: bytes, salt: bytes, session: int) -> bytes:
    """cell_index = H(h.1, seed_hour ‖ pk_B ‖ salt ‖ sess) (protocol.md §7).

    Первое сообщение пары: salt = 0^64, sess = 0 (protocol.md §7; README говорит
    «без них» — выигрывает protocol.md как контракт: конкатенация НУЛЕВЫХ полей).
    """
    assert len(seed_hour) == 32
    return h_cell(bytes(seed_hour) + bytes(pk_recipient) + bytes(salt) + W.u32(session))


def msg_aad(session: int, seq: int, reply_to: int) -> bytes:
    """AAD AEAD сообщения: (sess u32, seq u32, reply_to u32=0) — 3 элемента fix-shot."""
    return W.u32(session) + W.u32(seq) + W.u32(reply_to)


def encaps_msg(pk: bytes, app_pt: bytes, session: int, seq: int, reply_to: int) -> tuple[bytes, bytes, bytes]:
    """(ky_ct, nonce12, msg_ct): fresh ML-KEM encaps + AEAD."""
    ss, kyct = kem_encaps(pk)
    nonce = os.urandom(AEAD_NONCE_LEN)
    ct = aead_encrypt(ss, nonce, msg_aad(session, seq, reply_to), app_pt)
    return kyct, nonce, ct


def decaps_msg(sk_seed: bytes, kyct: bytes, nonce: bytes, msg_ct: bytes,
               session: int, seq: int, reply_to: int) -> bytes:
    ss = kem_decaps(sk_seed, kyct)
    return aead_decrypt(ss, nonce, msg_aad(session, seq, reply_to), msg_ct)


def build_recipient(itype: int, session: int, seq: int, body: bytes,
                    pt_total: int = RECIPIENT_PT_MAX, rng=None) -> bytes:
    """Полный recipient-payload (внутр. plaintext PT последнего слоя) = header+body
    + CSPRNG padding до pt_total (без addr/ctlen wrapper — их добавляет onion)."""
    if len(body) > RECIPIENT_PT_MAX - W.RECIPIENT_HDR_LEN:
        raise ValueError(f"recipient body too big: {len(body)}")
    hdr = W.enc_recipient_header(itype, session, seq, len(body))
    data = hdr + body
    rng = rng or os.urandom
    pad = rng(pt_total - len(data))
    return data + pad


def parse_recipient(rec: bytes) -> dict:
    """header + body + padding; возвращает itype/session/seq/body/body_len."""
    meta = W.recipient_header(rec)
    body = rec[W.RECIPIENT_HDR_LEN:W.RECIPIENT_HDR_LEN + meta["body_len"]]
    if len(body) != meta["body_len"]:
        raise ValueError("recipient body short")
    meta["body"] = body
    return meta


def store_body(cell_idx: bytes, kyct: bytes, nonce: bytes, msg_ct: bytes) -> bytes:
    """body store-типа: cell_idx(32) ‖ ky ‖ nonce ‖ ct (см. DESIGN_NOTES)."""
    assert len(cell_idx) == 32
    return cell_idx + kyct + nonce + msg_ct


def online_body(kyct: bytes, nonce: bytes, msg_ct: bytes) -> bytes:
    return kyct + nonce + msg_ct


def parse_store_body(b: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """→ (cell_idx, kyct, nonce12, msg_ct)."""
    cell, rest = b[:32], b[32:]
    if len(rest) < KEM_CT_LEN + AEAD_NONCE_LEN:
        raise ValueError("store body short")
    return cell, rest[:KEM_CT_LEN], rest[KEM_CT_LEN:KEM_CT_LEN + AEAD_NONCE_LEN], rest[KEM_CT_LEN + AEAD_NONCE_LEN:]


# --- маршрут / route_digest (protocol.md §5) ---------------------------------

def route_digest(route_addrs: list[bytes], round_num: int) -> bytes:
    """route_digest = H(mix.1, r1.addr ‖ … ‖ rL.addr ‖ u64(round)) (protocol.md §5)."""
    assert route_addrs, "route пуст"
    return h_mix(b"".join(bytes(a) for a in route_addrs) + W.u64(round_num))


def hour_seed(seeds: dict[int, bytes], round_num: int, blocks: int = 360) -> bytes:
    """seed_hour = seed(round − round mod blocks); если не вычислен — DEV_SEED_HOUR
    (dev-fallback; привязка PoW к раунду живёт в seed_round во входе — DESIGN_NOTES)."""
    anchor = round_num - (round_num % blocks)
    s = seeds.get(anchor)
    return s if s is not None else DEV_SEED_HOUR
