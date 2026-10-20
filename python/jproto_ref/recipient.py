"""Recipient-payload (R) + onion build/peel — wire.md §5 v2, байт-в-байт с src/onion.c.

R (фикс 7028 B):
    hdr 24 B: magic 'JP' u16 ‖ ver u8=1 ‖ itype u8 ‖ session u32 ‖ seq u32 ‖
              pow_nonce u64 LE ‖ pow_bits u8 ‖ pow_prof u8 ‖ body_len u16
    body:     ky_ct(1088) ‖ aead_nonce(12) ‖ msg_ct(msg+tag16)
    tail:     CSPRNG padding до 7028 (в body_len не входит)
msg_ct = AEAD(ss_msg, nonce12, aad = itype‖session‖seq (9 B), pt = msg);
ss_msg = ML-KEM-768 Encaps(pk_recipient), свежий на каждое сообщение.

Onion (v2): packet = kem_ct_i(1088) ‖ blob_i;
    blob_i = nonce12 ‖ AEAD(ss_i, AD = ONION_AD, PT_i);
    PT_i   = next_addr(32) ‖ u16 ctl ‖ [ct_{i+1}(1088) при ctl=1088] ‖ blob_{i+1};
    финальный слой: addr = 0^32, ctl = 0, remainder = R (ровно 7028 B).
Длины детерминированы: blob(d) = 7090 + (d−1)*1150; packet(3) = 10478,
packet(4) = 11628.
"""

from __future__ import annotations

import os
import struct

from . import crypto as C
from . import wire as W

RPL_LEN_FIXED   = W.RPL_LEN_FIXED          # 7028
RPL_HDR_LEN     = W.RECIPIENT_HDR_LEN      # 56 (core 24 + dest 32)T_HDR_LEN      # 24
MSG_PAYLOAD_MAX = W.MSG_PAYLOAD_MAX        # 5888
BLOB_BASE       = W.BLOB_BASE              # 7090
LAYER_ADD       = W.ONION_LAYER_ADD        # 1150
ONION_AD        = W.ONION_AD               # b"jproto.onion.1"

KEM_CT = C.KEM_CT_LEN
NONCE_LEN = C.AEAD_NONCE_LEN
TAG_LEN = C.AEAD_TAG_LEN


def msg_aad(itype: int, session: int, seq: int) -> bytes:
    """9 B: itype u8 ‖ session u32 LE ‖ seq u32 LE."""
    return struct.pack("<BII", itype, session, seq)


def blob_len(depth_remaining: int) -> int:
    """|blob| для depth слоёв ниже (depth=1 — финальный слой)."""
    if not 1 <= depth_remaining <= 4:
        raise ValueError("depth 1..4")
    return BLOB_BASE + (depth_remaining - 1) * LAYER_ADD


def packet_len(total_layers: int) -> int:
    """|packet| = kem_ct(1088) ‖ blob(L)."""
    return KEM_CT + blob_len(total_layers)


def onion_layer_count(itype: int) -> int:
    """I_ONLINE → 3; store/offere/reply (BL-записи) → 4."""
    return 3 if itype == W.I_ONLINE else 4


def wrap_layer(pt: bytes, pk: bytes) -> tuple[bytes, bytes]:
    """Encaps(pk) → (ct, blob = nonce12 ‖ AEAD(PT)). Возвращает (kem_ct, blob)."""
    ss, ct = C.kem_encaps(pk)
    nonce = os.urandom(NONCE_LEN)
    blob = nonce + C.aead_encrypt(ss, nonce, ONION_AD, bytes(pt))
    return ct, blob


def peel(kem_sk_seed: bytes, packet: bytes) -> dict:
    """Peel одного слоя. Возвращает dict:
       final=True  → "rpl": R (7028 B), "next": None
       final=False → "next": ct_next ‖ blob_next, "next_addr": addr32
    Ошибка ключа/тэга/размеров → ValueError."""
    pkt = bytes(packet)
    if len(pkt) < KEM_CT + BLOB_BASE:
        raise ValueError(f"packet too short {len(pkt)}")
    ss = C.kem_decaps(kem_sk_seed, pkt[:KEM_CT])
    blob = pkt[KEM_CT:]
    try:
        pt = C.aead_decrypt(ss, blob[:NONCE_LEN], ONION_AD, blob[NONCE_LEN:])
    except Exception as e:
        raise ValueError("bad aead tag") from e
    addr = pt[:W.ADDR_LEN]
    ctl = pt[W.ADDR_LEN] | (pt[W.ADDR_LEN + 1] << 8)
    if ctl == 0:
        rpl = pt[W.ADDR_LEN + 2:]
        if len(rpl) != RPL_LEN_FIXED:
            raise ValueError(f"final R len {len(rpl)} != {RPL_LEN_FIXED}")
        return {"final": True, "rpl": rpl, "next": None, "next_addr": None}
    if ctl != KEM_CT:
        raise ValueError(f"bad ctl {ctl}")
    ct_next = pt[W.ADDR_LEN + 2: W.ADDR_LEN + 2 + KEM_CT]
    blob_next = pt[W.ADDR_LEN + 2 + KEM_CT:]
    if len(ct_next) != KEM_CT or len(blob_next) < blob_len(1):
        raise ValueError("bad next layer sizes")
    return {"final": False, "next": ct_next + blob_next, "next_addr": addr, "rpl": None}


def build_onion(rpl: bytes, route: list[tuple[bytes, bytes]]) -> bytes:
    """R → полный packet по маршруту [(addr32, kem_pk1184), …] от n1 к nL."""
    rpl = bytes(rpl)
    if len(rpl) != RPL_LEN_FIXED:
        raise ValueError(f"rpl len {len(rpl)} != {RPL_LEN_FIXED}")
    if not 1 <= len(route) <= 4:
        raise ValueError("route 1..4 хопов")
    blob = None
    ct = None
    for i in range(len(route) - 1, -1, -1):
        addr, pk = route[i]
        pt = bytearray()
        if i == len(route) - 1:
            pt += bytes(32)
            pt += struct.pack("<H", 0)
            pt += rpl
        else:
            pt += route[i + 1][0]          # addr узла i+1 (читает его узел i)
            pt += struct.pack("<H", KEM_CT)
            pt += ct
            pt += blob
        ct, blob = wrap_layer(bytes(pt), pk)
    return ct + blob


# --- R: encode / parse ----------------------------------------------------------

def encode(itype: int, session: int, seq: int, pow_nonce: int,
           pow_bits: int, pow_prof: int, pk_recip: bytes, msg: bytes,
           dest: bytes | None = None) -> bytes:
    """msg → полный R (7028 B): encaps + AEAD + CSPRNG-паддинг. dest —
    32 B cell-индекс для BS-ноды (R v2.1); None → 0^32 (cell от payload)."""
    msg = bytes(msg)
    if not 1 <= len(msg) <= MSG_PAYLOAD_MAX:
        raise ValueError(f"msg len {len(msg)} не в 1..{MSG_PAYLOAD_MAX}")
    ss, ky = C.kem_encaps(pk_recip)
    nonce = os.urandom(NONCE_LEN)
    msg_ct = C.aead_encrypt(ss, nonce, msg_aad(itype, session, seq), msg)
    return assemble(itype, session, seq, pow_nonce, pow_bits, pow_prof,
                    ky, nonce, msg_ct, dest=dest)


def assemble(itype: int, session: int, seq: int, pow_nonce: int,
             pow_bits: int, pow_prof: int, ky_ct: bytes, aead_nonce: bytes,
             msg_ct: bytes, dest: bytes | None = None) -> bytes:
    """Из готовых компонентов → R (заполнение CSPRNG до 7028)."""
    body = bytes(ky_ct) + bytes(aead_nonce) + bytes(msg_ct)
    if len(body) != KEM_CT + NONCE_LEN + len(msg_ct):
        raise ValueError("body components mismatch")
    if not TAG_LEN <= len(msg_ct) <= MSG_PAYLOAD_MAX + TAG_LEN:
        raise ValueError("msg_ct out of range")
    hdr = W.enc_recipient_header(itype, session, seq, pow_nonce, pow_bits,
                                 pow_prof, len(body), dest=dest)
    pad = len(hdr) + len(body)
    if pad > RPL_LEN_FIXED:
        raise ValueError("R overflow")
    out = hdr + body + os.urandom(RPL_LEN_FIXED - pad)
    assert len(out) == RPL_LEN_FIXED
    return out


def parse(r: bytes) -> dict:
    """R → meta + body-слайсы. body_off = полный заголовок 56 (core+dest)."""
    r = bytes(r)
    if len(r) != RPL_LEN_FIXED:
        raise ValueError(f"R len {len(r)} != {RPL_LEN_FIXED}")
    meta = W.recipient_header(r)
    body_off = W.RECIPIENT_HDR_LEN
    body = r[body_off: body_off + meta["body_len"]]
    return {**meta,
            "ky_ct": body[:KEM_CT],
            "aead_nonce": body[KEM_CT: KEM_CT + NONCE_LEN],
            "msg_ct": body[KEM_CT + NONCE_LEN:],
            "rpl": r}


def value_of(rpl_dict: dict) -> bytes:
    """value BS-записи (и gossip-дайджеста): ky ‖ nonce ‖ msg_ct."""
    return rpl_dict["ky_ct"] + rpl_dict["aead_nonce"] + rpl_dict["msg_ct"]


def cell_of(rpl_dict: dict) -> bytes:
    """Ячейка BS-ноды: dest из заголовка (R v2.1); 0^32 → h_cell(value)
    (совместимость с R v2.0)."""
    d = rpl_dict.get("dest") or b"\x00" * 32
    if d != b"\x00" * 32:
        return bytes(d)
    return C.h_cell(value_of(rpl_dict))


def pow_digest_rpl(rpl: bytes) -> bytes:
    """NODE-PoW digest КАНОНИЧНО: H(pow.1, R с обнулённым полем pow_nonce).
    Нонс попадать в свой digest не может (chicken-egg): клиент майнит по
    zero-nonce R, нода верифицирует так же (обнуляя поле перед хэшем)."""
    b = bytearray(bytes(rpl))
    if len(b) != W.RPL_LEN_FIXED:
        raise ValueError("R len")
    b[12:20] = b"\x00" * 8
    return C.h_pow(bytes(b))


def decaps_msg(kem_sk_seed: bytes, parsed: dict, itype: int,
               session: int, seq: int) -> bytes:
    """Вскрывает принятое сообщение: Decaps(sk_B) + AEAD open msg."""
    ss = C.kem_decaps(kem_sk_seed, parsed["ky_ct"])
    return C.aead_decrypt(ss, parsed["aead_nonce"],
                          msg_aad(itype, session, seq), parsed["msg_ct"])
