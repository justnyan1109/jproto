"""Wire-кодек jproto v1 (docs/wire.md).

Все целые little-endian.
- varint = LEB128 от u64.
- Frame: varint(total) ‖ u16 type ‖ u16 flags ‖ body; total = len(type+flags+body), varint НЕ учитывается.
- TLV: u16 ttype ‖ u32 tlen ‖ value(tlen). ttype 0 = reserved (запрещён).
- Неизвестные ttype получатель обязан игнорировать; TLV ищутся по ttype, не по позиции.

Константы F_* (frame types), T_* (TLV types), I_* (inner message types),
FLAG_* — точно из docs/wire.md §2–§5.
"""

from __future__ import annotations

import struct
from typing import Iterable, NamedTuple, Sequence

# --- frame types (f-типы) ---------------------------------------------------
F_HELLO            = 0x0001
F_HELLO_OK         = 0x0002
F_SEED_REQ         = 0x0010
F_SEED             = 0x0011
F_DIR_REQ          = 0x0020
F_DIR              = 0x0021
F_MIX_ONION        = 0x0030
F_MIX_ACK          = 0x0031
F_BS_STORE         = 0x0040
F_BS_READ          = 0x0041
F_BS_READ_RESP     = 0x0042
F_ONLINE_DELIVER   = 0x0050
F_ONLINE_ACK       = 0x0051
F_BEACON_COMMIT    = 0x0060
F_BEACON_REVEAL    = 0x0061
F_BEACON_SEED      = 0x0062
F_GOSSIP_PUSH      = 0x0070
F_GOSSIP_FETCH     = 0x0071
F_GOSSIP_DATA      = 0x0072
F_PING             = 0x0080
F_PONG             = 0x0081

FLAG_NEEDS_ACK     = 0x0001

# --- TLV types (t-типы) -----------------------------------------------------
T_PAYLOAD          = 0x0001   # binary: основная полезная нагрузка (onion-слой)
T_SEED             = 0x0002   # 32 B seed
T_ROUND            = 0x0003   # u64 round N
T_PK_KEM           = 0x0004   # 1184 B ML-KEM-768 pk
T_PK_DSA           = 0x0005   # 1312 B ML-DSA-44 pk
T_SIG              = 0x0006   # 2420 B ML-DSA-44 sig
T_ADDR             = 0x0007   # 32 B address (digest pk)
T_NONCE            = 0x0008   # 8..32 B nonce/salt
T_TRANSPORT        = 0x0009   # (host cstring, port u16, tls u8)
T_TIMESTAMP        = 0x000A   # u64 unix_ts мс
T_CELL_IDX         = 0x000B   # 32 B cell index
T_CELL_REC         = 0x000C   # ky_ct(1088) ‖ nonce12 ‖ ct_msg ‖ score(u32) ‖ ts(u64)
T_POW              = 0x000D   # cert: nonce(u64) ‖ bits(u8) ‖ profile(u8) ‖ reserved(6)
T_POW_PAR          = 0x000E   # profile(u8) ‖ bits(u8) ‖ budget_hint(u32) ‖ mode(u8)
T_ERR              = 0x000F   # код ошибки u16 + строка (опц.)
T_KYBER_CT         = 0x0010   # 1088 B ML-KEM ct
T_AEAD_NONC        = 0x0011   # 12 B nonce AEAD
T_MSG_CT           = 0x0012   # AEAD ct сообщения
T_SALT             = 0x0013   # 64 B salt (handshake)
T_SESSION          = 0x0014   # u32 session number
T_SEQ              = 0x0015   # u32 seq внутри сессии
T_NODE_LIST        = 0x0016   # N × T_NODE_ENTRY (конкатенация вложенных TLV)
T_NODE_ENTRY       = 0x0017   # T_ADDR ‖ T_PK_KEM ‖ T_PK_DSA ‖ T_TRANSPORT
T_ROUTE            = 0x0018   # 3 адреса маршрута по 32 B (исп. также как список addr)
T_VER              = 0x0019   # u16 версия
T_CAPS             = 0x001A   # u32 capabilities bitmap
T_COMMIT           = 0x001B   # 32 B commit beacon-участника
T_DIR_DIGEST       = 0x001C   # 32 B digest директории
T_REC_DIGEST       = 0x001E   # 32 B H(rec) записи BS
T_PAD              = 0x001F   # padding (CSPRNG)

# --- PoW профили -------------------------------------------------------------
POW_TRANSPORT      = 1
POW_NODE           = 2
POW_READ           = 3

# --- inner message types (I_*) ----------------------------------------------
I_ONLINE           = 1
I_STORE_LOCAL      = 2
I_STORE_GLOBAL     = 3
I_OFFER            = 4
I_REPLY            = 5

# --- константы формата -------------------------------------------------------
VERSION            = 1        # T_VER
INNER_PACKET_SIZE  = 1280     # wire.md §5 (см. DESIGN_NOTES — Evaluation: BLOB ПОСЛЕДНЕГО
                              #  СЛОЯ ПЕРЕМЕННЫЙ; 1280 было бы PT=1252 → app-payload ≤ 100 B)
RECIPIENT_HDR_LEN  = 50       # magic(2) ver(1) itype(1) dest(32) session(4) seq(4) reply_to(4) body_len(2)
RECIPIENT_MAGIC    = 0x4A50   # 'JP'
MAX_MSG_PAYLOAD    = 8192     # из protocol.md §12 (в onion не помещается целиком — DESIGN_NOTES)
KEM_CT_LEN         = 1088     # ML-KEM-768 ct (например внутри T_KYBER_CT)
AEAD_NONCE_LEN     = 12

CAPS_MIX           = 1 << 0
CAPS_BS            = 1 << 1
CAPS_BEACON        = 1 << 2
CAPS_GOSSIP        = 1 << 3


class Frame(NamedTuple):
    """Кадр: type, flags, список TLV (пары (ttype, bytes)); порядок сохраняется."""
    type: int
    flags: int
    tvs: tuple[tuple[int, bytes], ...]


# --- varint (LEB128) ---------------------------------------------------------

def encode_varint(v: int) -> bytes:
    if v < 0:
        raise ValueError("varint < 0")
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_varint(data: bytes | memoryview, offset: int = 0) -> tuple[int, int]:
    """Возвращает (value, количество прочитанных байт)."""
    result = 0
    shift = 0
    n = len(data)
    i = offset
    while True:
        if i >= n:
            raise ValueError("varint truncated")
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, i - offset
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


# --- TLV ---------------------------------------------------------------------

def tlv(ttype: int, value: bytes) -> tuple[int, bytes]:
    if not 1 <= ttype <= 0xFFFF:
        raise ValueError("ttype out of range (0 = reserved)")
    return ttype, bytes(value)


def append_tlv_into(out: bytearray, ttype: int, value: bytes) -> None:
    out += struct.pack("<HI", ttype, len(value))
    out += value


def parse_tvs(body: bytes) -> tuple[tuple[int, bytes], ...]:
    tvs: list[tuple[int, bytes]] = []
    i = 0
    n = len(body)
    while i < n:
        if i + 6 > n:
            raise ValueError("tlv header truncated")
        ttype, tlen = struct.unpack_from("<HI", body, i)
        i += 6
        if i + tlen > n:
            raise ValueError("tlv value truncated")
        tvs.append((ttype, bytes(body[i:i + tlen])))
        i += tlen
    return tuple(tvs)


def build_tlv_bytes(ttype: int, value: bytes) -> bytes:
    out = bytearray()
    append_tlv_into(out, ttype, value)
    return bytes(out)


# --- frame -------------------------------------------------------------------

def frame_payload(ftype: int, flags: int, tvs: Iterable[tuple[int, bytes]]) -> bytes:
    if not 0 < ftype <= 0xFFFF:
        raise ValueError("ftype out of range")
    out = bytearray(struct.pack("<HH", ftype, flags))
    for ttype, value in tvs:
        append_tlv_into(out, ttype, value)
    return bytes(out)


def build_frame(ftype: int, flags: int = 0, tvs: Iterable[tuple[int, bytes]] = ()) -> bytes:
    payload = frame_payload(ftype, flags, tvs)
    return encode_varint(len(payload)) + payload


def decode_frame(buf: bytes | memoryview) -> Frame:
    """Ожидает ПОЛНЫЙ кадр: varint(total) ‖ payload(total)."""
    buf = bytes(buf)
    total, hdr = decode_varint(buf)
    if len(buf) - hdr < total:
        raise ValueError(f"frame truncated: have {len(buf) - hdr}, need {total}")
    body = buf[hdr:hdr + total]
    ftype, flags = struct.unpack_from("<HH", body, 0)
    tvs = parse_tvs(body[4:])
    return Frame(ftype, flags, tvs)


# --- helpers над tvs ---------------------------------------------------------

def get(tvs: Sequence[tuple[int, bytes]], ttype: int) -> bytes | None:
    """Первый TLV данного типа или None."""
    for t, v in tvs:
        if t == ttype:
            return v
    return None


def get_all(tvs: Sequence[tuple[int, bytes]], ttype: int) -> list[bytes]:
    return [v for t, v in tvs if t == ttype]


def has(tvs: Sequence[tuple[int, bytes]], ttype: int) -> bool:
    return any(t == ttype for t, _ in tvs)


# ---little-endian скаляры -----------------------------------------------------

def u16(v: int) -> bytes:  return struct.pack("<H", v)
def u32(v: int) -> bytes:  return struct.pack("<I", v)
def u64(v: int) -> bytes:  return struct.pack("<Q", v)


def as_u16(v: bytes | None) -> int | None:
    return None if v is None else struct.unpack("<H", v)[0]


def as_u32(v: bytes | None) -> int | None:
    return None if v is None else struct.unpack("<I", v)[0]


def as_u64(v: bytes | None) -> int | None:
    return None if v is None else struct.unpack("<Q", v)[0]


# --- T_TRANSPORT: (host cstring, port u16, tls u8) ---------------------------

def enc_transport(host: str, port: int, tls: bool = False) -> bytes:
    return host.encode("utf-8") + b"\x00" + struct.pack("<HB", port, 1 if tls else 0)


def dec_transport(v: bytes) -> tuple[str, int, bool]:
    i = v.find(b"\x00")
    if i < 0:
        raise ValueError("transport: no nul")
    host = v[:i].decode("utf-8")
    port, tls = struct.unpack_from("<HB", v, i + 1)
    return host, port, bool(tls)


# --- recipient-payload helpers (wire.md §5, внутренний plaintext слоя L) ------
# header 50 B: magic u16 'JP' ‖ ver u8 ‖ itype u8 ‖ dest(32) ‖ session u32 ‖
#              seq u32 ‖ reply_to u32 ‖ body_len u16
# body: store-типы (I_STORE_LOCAL/I_STORE_GLOBAL/I_OFFER/I_REPLY):
#           cell_idx(32) ‖ kyber_ct(1088) ‖ nonce(12) ‖ msg_ct     [DESIGN_NOTES]
#       I_ONLINE:          kyber_ct(1088) ‖ nonce(12) ‖ msg_ct
# далее CSPRNG padding до целевого размера PT (см. jproto_ref.recipient).
# dest нужен финальной ноде для адресации ONLINE-доставки (клиент зарегистрирован
# T_ADDR в HELLO); session/seq/reply_to идут открыто — клиент берёт их для AAD;
# integrity обеспечивает AEAD. Поле dest — пробел спеки (DESIGN_NOTES §recipient).

def enc_recipient_header(itype: int, dest: bytes, session: int, seq: int,
                         reply_to: int, body_len: int) -> bytes:
    if not 1 <= itype <= 5 or len(dest) != 32:
        raise ValueError("itype 1..5 / dest 32B required")
    return struct.pack("<HBB", RECIPIENT_MAGIC, VERSION, itype) + bytes(dest) + \
        struct.pack("<IIIH", session, seq, reply_to, body_len)


def recipient_header(value: bytes) -> dict:
    """Разбор заголовка recipient-payload (PT последнего слоя)."""
    if len(value) < RECIPIENT_HDR_LEN:
        raise ValueError("recipient header truncated")
    magic, ver, itype = struct.unpack_from("<HBB", value, 0)
    if magic != RECIPIENT_MAGIC:
        raise ValueError("bad magic")
    if ver != VERSION:
        raise ValueError("bad version")
    if not 1 <= itype <= 5:
        raise ValueError("bad itype")
    dest = value[4:36]
    session, seq, reply_to, body_len = struct.unpack_from("<IIIH", value, 36)
    if body_len < KEM_CT_LEN + AEAD_NONCE_LEN:
        raise ValueError("recipient body_len too small")
    return {"itype": itype, "dest": dest, "session": session, "seq": seq,
            "reply_to": reply_to, "body_len": body_len}


def recipient_clean(value: bytes) -> tuple[dict, bytes]:
    """header + body без padding; возвращает (meta, header‖body)."""
    meta = recipient_header(value)
    return meta, bytes(value[:RECIPIENT_HDR_LEN + meta["body_len"]])


# --- PoW cert (wire.md §6) ----------------------------------------------------

def enc_pow_cert(nonce: int, bits: int, profile: int) -> bytes:
    b = bytearray(struct.pack("<QBB", nonce, bits, profile))
    b += b"\x00" * 6
    return bytes(b)


def dec_pow_cert(v: bytes) -> tuple[int, int, int]:
    if len(v) != 16:
        raise ValueError("pow cert size")
    nonce, bits, profile = struct.unpack_from("<QBB", v, 0)
    return nonce, bits, profile


def enc_pow_par(profile: int, bits: int, budget_hint: int, mode: int = 0) -> bytes:
    return struct.pack("<BBIB", profile, bits, budget_hint, mode)


def dec_pow_par(v: bytes) -> tuple[int, int, int, int]:
    profile, bits, budget, mode = struct.unpack_from("<BBIB", v, 0)
    return profile, bits, budget, mode


def enc_err(code: int, msg: str = "") -> bytes:
    return struct.pack("<H", code) + (msg.encode("utf-8") if msg else b"")


def dec_err(v: bytes) -> tuple[int, str]:
    if len(v) < 2:
        return 0, ""
    code = struct.unpack_from("<H", v, 0)[0]
    return code, v[2:].decode("utf-8", "replace")


# --- self-test (round-trip) ---------------------------------------------------

def selftest() -> None:
    """Round-trip: varint, TLV, frame, скаляры, transport,_pow cert, header."""
    for v in (0, 1, 127, 128, 0x3FFF, 0x4000, 12345678901234567890):
        raw = encode_varint(v)
        got, n = decode_varint(raw)
        assert got == v and n == len(raw), (v, got, n)

    body = build_tlv_bytes(T_PAYLOAD, b"AB") + build_tlv_bytes(T_ROUND, u64(7))
    fr = build_frame(F_MIX_ONION, FLAG_NEEDS_ACK, [(T_PAYLOAD, b"AB"), (T_ROUND, u64(7))])
    fr2 = decode_frame(fr)
    assert fr2.type == F_MIX_ONION and fr2.flags == FLAG_NEEDS_ACK
    assert get(fr2.tvs, T_PAYLOAD) == b"AB"
    assert as_u64(get(fr2.tvs, T_ROUND)) == 7
    assert parse_tvs(body) == ((T_PAYLOAD, b"AB"), (T_ROUND, u64(7)))

    assert as_u32(u32(0xDEADBEEF)) == 0xDEADBEEF
    assert dec_transport(enc_transport("127.0.0.1", 9100, True)) == ("127.0.0.1", 9100, True)

    cert = enc_pow_cert(2**40 + 5, 6, POW_TRANSPORT)
    assert dec_pow_cert(cert) == (2**40 + 5, 6, POW_TRANSPORT)

    hdr = enc_recipient_header(I_OFFER, b"\x11" * 32, 11, 22, 33, 1100)
    meta = recipient_header(hdr)
    assert meta["itype"] == I_OFFER and meta["session"] == 11 and meta["seq"] == 22
    assert meta["reply_to"] == 33 and meta["body_len"] == 1100 and meta["dest"] == b"\x11" * 32

    _e = enc_err(7, "boom")
    assert dec_err(_e) == (7, "boom")

    base = frame_payload(F_PING, 0, [(T_PAYLOAD, b"qqq")])
    assert parse_tvs(base[4:]) == ((T_PAYLOAD, b"qqq"),)
    # varint u32 total + 4B заголовок кадра входит в total


if __name__ == "__main__":
    selftest()
    print("wire selftest OK")
