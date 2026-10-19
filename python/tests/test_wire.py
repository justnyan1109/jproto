"""Round-trip кодека: wire.py + recipient-payload (wire.md)."""

import os

import pytest

from jproto_ref import wire as W
from jproto_ref import recipient as R
from jproto_ref.crypto import KEM_CT_LEN, AEAD_NONCE_LEN


def test_varint_roundtrip():
    for v in (0, 1, 127, 128, 255, 16383, 16384, 2**32 - 1, 2**53, 2**63, 2**64 - 1):
        raw = W.encode_varint(v)
        got, used = W.decode_varint(raw)
        assert got == v and used == len(raw)
    # канонические байты LEB128
    assert W.encode_varint(300) == b"\xac\x02"


def test_frame_roundtrip_flags_tlv_order():
    tvs = [(W.T_VER, W.u16(1)), (W.T_ROUND, W.u64(123456)), (W.T_PAYLOAD, os.urandom(50))]
    raw = W.build_frame(W.F_HELLO, W.FLAG_NEEDS_ACK, tvs)
    total, hdr = W.decode_varint(raw)
    assert hdr + total == len(raw)
    fr = W.decode_frame(raw)
    assert fr.type == W.F_HELLO and fr.flags == W.FLAG_NEEDS_ACK
    assert tuple(fr.tvs) == tuple(tvs)  # порядок продюсера обязателен


def test_get_get_all_ignore_unknown():
    fr = W.decode_frame(W.build_frame(W.F_PING, 0, [
        (W.T_PAYLOAD, b"x"), (0x7FFF, b"unknown"), (W.T_PAYLOAD, b"y"),
    ]))
    assert W.get(fr.tvs, W.T_PAYLOAD) == b"x"
    assert W.get_all(fr.tvs, W.T_PAYLOAD) == [b"x", b"y"]
    assert W.get(fr.tvs, 0x7FFF) == b"unknown"
    assert W.get(fr.tvs, W.T_SEED) is None


def test_frame_unknown_types_forward_compat():
    unknown = W.build_frame(0xFFFF, 0x8000, [(0x7FFF, b"??"), (W.T_PAD, os.urandom(10))])
    fr = W.decode_frame(unknown)
    assert fr.type == 0xFFFF and fr.flags & 0x8000
    assert len(fr.tvs) == 2


def test_scalars_transport_pow_err():
    assert W.as_u32(W.u32(0x01020304)) == 0x01020304
    assert W.as_u64(W.u64(2**64 - 2)) == 2**64 - 2
    host, port, tls = W.dec_transport(W.enc_transport("fed1.example", 9103, False))
    assert (host, port, tls) == ("fed1.example", 9103, False)
    nonce, bits, profile = W.dec_pow_cert(W.enc_pow_cert(11, 6, W.POW_NODE))
    assert (nonce, bits, profile) == (11, 6, W.POW_NODE)
    par = W.dec_pow_par(W.enc_pow_par(W.POW_TRANSPORT, 6, 1500, 0))
    assert par == (1, 6, 1500, 0)
    assert W.dec_err(W.enc_err(3, "nopow")) == (3, "nopow")


def test_recipient_payload_roundtrip_online():
    pk, _sk = __import__("jproto_ref.crypto", fromlist=["kem_generate"]).kem_generate()
    dest = os.urandom(32)
    kyct, nonce, msg_ct = R.encaps_msg(pk, b"hello-B", session=1, seq=1, reply_to=0)
    body = R.online_body(kyct, nonce, msg_ct)
    rec = R.build_recipient(W.I_ONLINE, dest, 1, 1, 0, body)
    assert len(rec) == R.PT_TARGET[W.I_ONLINE]     # padding до целевого PT
    meta = R.parse_recipient(rec)
    assert meta["itype"] == W.I_ONLINE and meta["session"] == 1 and meta["seq"] == 1
    assert meta["dest"] == dest and meta["reply_to"] == 0
    assert len(meta["body"]) == len(body)
    # header-поля совпадают с AAD
    assert W.recipient_header(rec[:W.RECIPIENT_HDR_LEN])["body_len"] == len(body)


def test_recipient_payload_store_body_and_aad():
    pk, sk = __import__("jproto_ref.crypto", fromlist=["kem_generate"]).kem_generate()
    dest = os.urandom(32)
    cell = R.cell_index(os.urandom(32), pk, bytes(64), 0)
    kyct, nonce, msg_ct = R.encaps_msg(pk, b"pl", session=0, seq=1, reply_to=0)
    body = R.store_body(kyct, nonce, msg_ct, cell)
    assert body[:32] == cell
    c2, k2, n2, m2 = R.parse_store_body(body)
    assert (c2, k2, n2, m2) == (cell, kyct, nonce, msg_ct)
    parse = R.parse_recipient(R.build_recipient(W.I_STORE_LOCAL, dest, 0, 1, 0, body))
    assert parse["itype"] == W.I_STORE_LOCAL and parse["session"] == 0

    aad = R.msg_aad(0, 1, 0)
    assert aad == W.u32(0) + W.u32(1) + W.u32(0)
    pt = R.decaps_msg(sk, kyct, nonce, msg_ct, 0, 1, 0)
    assert pt == b"pl"
    with pytest.raises(ValueError):
        R.decaps_msg(sk, kyct, nonce, msg_ct, 0, 1, 7)  # чужой reply_to в AAD


def test_recipient_capacity_fits_offer_tlvs():
    """OFFER-набор TLV обязан влезать в app-plaintext (DESIGN_NOTES §onion)."""
    body_app = (W.build_tlv_bytes(W.T_SALT, bytes(64)) + W.build_tlv_bytes(W.T_SESSION, W.u32(1))
                + W.build_tlv_bytes(W.T_ADDR, bytes(32))
                + W.build_tlv_bytes(W.T_ROUTE, bytes(32) * 3))
    assert len(body_app) <= R.MSG_CT_MAX, len(body_app)
    pk, _sk = __import__("jproto_ref.crypto", fromlist=["kem_generate"]).kem_generate()
    kyct, nonce, msg_ct = R.encaps_msg(pk, body_app, 0, 1, 0)
    body = R.store_body(kyct, nonce, msg_ct, os.urandom(32))
    rec = R.build_recipient(W.I_OFFER, os.urandom(32), 0, 1, 0, body)
    assert len(rec) == R.PT_TARGET[W.I_OFFER]
    blob = len(rec) + 16 + 12           # blob последнего слоя
    assert blob + 16 < 65536            # и у укладки слоёв u16 не переполнится


def test_wire_selftest():
    W.selftest()
