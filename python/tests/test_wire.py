"""Round-trip кодека: wire.py + recipient-payload (wire.md)."""

import os

import pytest

from jproto_ref import wire as W
from jproto_ref import recipient as R
from jproto_ref import crypto as C


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


# --- v2 (wire.md §5) -------------------------------------------------------------

def test_onion_v2_lengths():
    assert R.RPL_LEN_FIXED == 7028
    assert R.blob_len(1) == 7090
    assert R.blob_len(2) == 7090 + 1150
    assert R.packet_len(3) == 10478
    assert R.packet_len(4) == 11628
    assert R.onion_layer_count(W.I_ONLINE) == 3
    assert R.onion_layer_count(W.I_STORE_GLOBAL) == 4
    assert R.msg_aad(2, 0x11223344, 7) == bytes([2]) + W.u32(0x11223344) + W.u32(7)


def test_recipient_v2_roundtrip():
    pk, sk = C.kem_generate()
    msg = os.urandom(1337)
    rpl = R.encode(W.I_STORE_GLOBAL, 0x11223344, 7, 0x99, 6, W.POW_NODE, pk, msg)
    assert len(rpl) == R.RPL_LEN_FIXED
    p = R.parse(rpl)
    assert p["itype"] == W.I_STORE_GLOBAL and p["session"] == 0x11223344
    assert p["seq"] == 7 and p["pow_nonce"] == 0x99 and p["pow_bits"] == 6
    assert p["pow_prof"] == W.POW_NODE
    assert R.decaps_msg(sk, p, W.I_STORE_GLOBAL, 0x11223344, 7) == msg
    # value/cell выводимы нодой без расшифровки; паддинг CSPRNG на cell не влияет
    assert len(R.value_of(p)) == 1088 + 12 + 1337 + 16
    p2 = R.parse(R.assemble(W.I_STORE_GLOBAL, 0x11223344, 7, 0x99, 6, W.POW_NODE,
                            p["ky_ct"], p["aead_nonce"], p["msg_ct"]))
    assert R.cell_of(p2) == R.cell_of(p)


def test_onion_build_peel_chain():
    keys = [C.kem_generate() for _ in range(4)]  # n1..n3 + получатель B
    route = [(os.urandom(32), keys[i][0]) for i in range(3)]
    msg = b"onion-v2-roundtrip"
    rpl = R.encode(W.I_ONLINE, 7, 3, 5, 4, W.POW_NODE, keys[3][0], msg)
    pkt = R.build_onion(rpl, route)
    assert len(pkt) == R.packet_len(3)
    d1 = R.peel(keys[0][1], pkt)
    assert not d1["final"] and d1["next_addr"] == route[1][0]
    assert len(d1["next"]) == R.packet_len(2)
    d2 = R.peel(keys[1][1], d1["next"])
    assert not d2["final"] and d2["next_addr"] == route[2][0]
    assert len(d2["next"]) == R.packet_len(1)
    d3 = R.peel(keys[2][1], d2["next"])
    assert d3["final"] and d3["rpl"] == rpl and d3["next"] is None
    m = R.parse(d3["rpl"])
    assert R.decaps_msg(keys[3][1], m, W.I_ONLINE, 7, 3) == msg
    # tamper → reject; чужой sk → reject
    bad = bytearray(pkt)
    bad[1200] ^= 1
    with pytest.raises(ValueError):
        R.peel(keys[0][1], bytes(bad))
    with pytest.raises(ValueError):
        R.peel(keys[3][1], pkt)


def test_recipient_capacity_fits_offer_tlvs():
    """OFFER-набор TLV обязан влезать в msg-plaintext (v2)."""
    body_app = (W.build_tlv_bytes(W.T_SALT, bytes(64)) + W.build_tlv_bytes(W.T_SESSION, W.u32(1))
                + W.build_tlv_bytes(W.T_ADDR, bytes(32))
                + W.build_tlv_bytes(W.T_ROUTE, bytes(32) * 3))
    assert len(body_app) <= R.MSG_PAYLOAD_MAX
    pk, _sk = C.kem_generate()
    rec = R.encode(W.I_OFFER, 0, 1, 0, 6, W.POW_NODE, pk, body_app)
    assert len(rec) == R.RPL_LEN_FIXED


def test_wire_selftest():
    W.selftest()
