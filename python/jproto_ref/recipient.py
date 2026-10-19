"""Recipient-payload (wire.md §5): общий формат клиента и ноды.

PT последнего слоя onion (о финале сигнализирует magic 'JP' в начале PT — см.
DESIGN_NOTES §onion: поля addr_next==0 в финальном слое нет, чтобы выиграть
ёмкость для app-payload):

    header 50 B: magic 'JP' u16 ‖ ver u8 ‖ itype u8 ‖ dest(32) ‖ session u32 ‖
                 seq u32 ‖ reply_to u32 ‖ body_len u16
    body (body_len):
        store-типы (I_STORE_LOCAL/I_STORE_GLOBAL/I_OFFER/I_REPLY):
            cell_idx(32) ‖ ky_ct(1088) ‖ nonce12 ‖ msg_ct
        I_ONLINE:            ky_ct(1088) ‖ nonce12 ‖ msg_ct
    + CSPRNG padding до целевого размера PT (PT_TARGET).

msg_ct = AEAD(ss_msg, nonce12, aad = sess(4LE)‖seq(4LE)‖reply_to(4LE), pt=app_bytes)
ss_msg = ML-KEM Encaps(pk_recipient), FRESH на каждое сообщение.
dest/التsession/seq/reply_to читает финальная нода (маршрутизация ONLINE и
логирование); НЕКОТОРЫЕ поля тела — только получатель (msg AAD = header-поля).

Ёмкости: MNEM TARGET ниже подобраны так, чтобы blob-размеры слоёв уложились
в u16, а OFFER/REPLY TLV-набор (~220 B) влез в app- plaintext (DESIGN_NOTES).
"""

from __future__ import annotations

import os

from . import wire as W
from .crypto import (AEAD_NONCE_LEN, KEM_CT_LEN, aead_decrypt, aead_encrypt,
                     h_cell, h_mix, kem_decaps, kem_encaps, DEV_SEED_HOUR)

# Целевые размеры PT (AEAD plaintext) последнего слоя.
PT_TARGET = {
    W.I_ONLINE: 1400,
    W.I_STORE_LOCAL: 1800,
    W.I_STORE_GLOBAL: 1800,
    W.I_OFFER: 1800,
    W.I_REPLY: 1800,
}

PT_L_MAX = 1252   # ceiling по upstream фиксированному blob 1280 — справочно
MSG_CT_MAX = max(PT_TARGET.values()) - W.RECIPIENT_HDR_LEN - KEM_CT_LEN - AEAD_NONCE_LEN


def pt_target(itype: int) -> int:
    return PT_TARGET.get(itype, max(PT_TARGET.values()))


def cell_index(seed_hour: bytes, pk_recipient: bytes, salt: bytes, session: int) -> bytes:
    """cell_index = H(h.1, seed_hour ‖ pk_B ‖ salt ‖ sess) (protocol.md §7).

    Первое сообщение пары: salt = 0^64, sess = 0 (protocol.md §7 wins; README
    предлагает omit — DESIGN_NOTES: конкатенация НУЛЕВЫХ полей).
    """
    assert len(seed_hour) == 32 and len(pk_recipient) == 1184 and len(salt) == 64
    return h_cell(bytes(seed_hour) + bytes(pk_recipient) + bytes(salt) + W.u32(session))


def msg_aad(session: int, seq: int, reply_to: int) -> bytes:
    return W.u32(session) + W.u32(seq) + W.u32(reply_to)


def first_salt() -> bytes:
    """salt первого контакта (protocol.md §7): нулевой 64 B."""
    return bytes(64)


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


def build_recipient(itype: int, dest: bytes, session: int, seq: int,
                    reply_to: int, body: bytes, pt_total: int = 0, rng=None) -> bytes:
    """Полный recipient-payload = header + body + CSPRNG padding до pt_total."""
    target = pt_total or pt_target(itype)
    hdr = W.enc_recipient_header(itype, dest, session, seq, reply_to, len(body))
    data = hdr + body
    if len(data) > target:
        raise ValueError(f"recipient payload too big: {len(data)} > {target}")
    rng = rng or os.urandom
    return data + rng(target - len(data))


def parse_recipient(rec: bytes) -> dict:
    """header + body (+padding игнорируется); вернёт itype/dest/session/seq/reply_to/body."""
    meta = W.recipient_header(rec)
    body = rec[W.RECIPIENT_HDR_LEN:W.RECIPIENT_HDR_LEN + meta["body_len"]]
    if len(body) != meta["body_len"]:
        raise ValueError("recipient body short")
    meta["body"] = body
    return meta


def store_body(kyct: bytes, nonce: bytes, msg_ct: bytes, cell_idx: bytes) -> bytes:
    """body store-типа: cell_idx(32) ‖ ky ‖ nonce ‖ ct (DESIGN_NOTES)."""
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
    """route_digest = H(mix.1, r1.addr ‖ … ‖ rL.addr ‖ u64(round))."""
    assert route_addrs, "route пуст"
    return h_mix(b"".join(bytes(a) for a in route_addrs) + W.u64(round_num))


def hour_seed(seeds: dict[int, bytes], round_num: int, blocks: int = 360,
              fallback: bytes | None = None) -> bytes:
    """seed_hour = seed(round − round mod blocks); если не вычислен — fallback
    (dev-константа; привязка PoW к раунду живёт в seed_round во входе)."""
    anchor = round_num - (round_num % blocks)
    s = seeds.get(anchor)
    if s is not None:
        return s
    return fallback if fallback is not None else DEV_SEED_HOUR
