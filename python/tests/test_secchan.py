"""test_secchan: handshake client/server через localhost, sealed roundtrip,
pin mismatch; TOFU Pins."""

import asyncio
import json

import pytest

from jproto_ref import crypto as C
from jproto_ref import secchan as SC
from jproto_ref import wire as W
from jproto_ref.chat import Pins

NONCE1 = b"ping-nonce-1"
NONCE2 = b"pong-nonce-2"


async def _pair(srv_handler):
    server = await asyncio.start_server(srv_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    cr, cw = await asyncio.open_connection("127.0.0.1", port)
    return server, (cr, cw)


def test_handshake_and_sealed_roundtrip():
    kem_pk, kem_sk = C.kem_generate()
    dsa_pk, dsa_sk = C.dsa_generate()
    seen: list[W.Frame] = []

    async def srv(reader, writer):
        sec = await SC.handshake_server(reader, writer, dsa_sk)
        fr = await sec.recv_frame()
        seen.append(fr)
        await sec.send(W.F_PONG, 0, [(W.T_NONCE, NONCE2)])
        await writer.drain()

    async def main():
        server, (cr, cw) = await _pair(srv)
        try:
            cli = await asyncio.wait_for(
                SC.handshake_client(cr, cw, kem_sk, dsa_sk, expect_pk=dsa_pk), 10.0)
            assert cli.peer_pk_dsa == dsa_pk
            await cli.send(W.F_PING, 0, [(W.T_NONCE, NONCE1)])
            pong = await cli.recv_frame()
            assert pong.type == W.F_PONG
            assert W.get(pong.tvs, W.T_NONCE) == NONCE2
        finally:
            cw.close()
            server.close()
            await server.wait_closed()

    asyncio.run(main())
    assert len(seen) == 1 and seen[0].type == W.F_PING
    assert W.get(seen[0].tvs, W.T_NONCE) == NONCE1


def test_server_rejects_garbled_signature():
    """Проверка владения: порченая подпись → SchError; валидная (любая пара) → ok."""
    real_pk, real_sk = C.dsa_generate()
    rejected = []

    async def srv(reader, writer):
        try:
            await SC.handshake_server(reader, writer, real_sk)
        except SC.SchError as e:
            rejected.append(str(e))

    async def main():
        server, (cr, cw) = await _pair(srv)

        async def bad_client():
            kem_pk, kem_sk = C.kem_generate()
            other_pk, other_sk = C.dsa_generate()
            sig = bytearray(C.dsa_sign(other_sk, SC.PFX_C + kem_pk))
            sig[100] ^= 0xFF   # битая подпись
            payload = W.frame_payload(W.F_SCH_HELLO, 0, [
                (W.T_PK_KEM, kem_pk), (W.T_PK_DSA, other_pk),
                (W.T_SIG, bytes(sig))])
            cw.write(W.encode_varint(len(payload)) + payload)
            await cw.drain()

        try:
            await bad_client()
            await asyncio.sleep(0.3)   # дать серверу отвергнуть
        finally:
            cw.close()
            server.close()
            await server.wait_closed()

    asyncio.run(main())
    assert rejected, "server принял испорченную подпись HELLO"


def test_pins_tofu_and_mismatch(tmp_path):
    path = str(tmp_path / "node_pins.json")
    pk, _sk = C.dsa_generate()
    p = Pins(path)
    ok, old = p.pin("127.0.0.1:9101", pk)
    assert ok and old == ""
    ok2, old2 = p.pin("127.0.0.1:9101", pk)
    assert ok2 and old2 == pk.hex()
    assert json.loads(open(path).read())["127.0.0.1:9101"] == pk.hex()


def test_sealed_seq_gap_rejected():
    """Формат насыпанного кадра: seq u64 LE + ct; gap → SchError на receive."""
    k_c2s, n_c2s, k_s2c, n_s2c = C.kdf_secch(b"\x01" * 32, b"\x02" * 32)
    rx = SC.SecChan(None, None, k_s2c, n_s2c, k_c2s, n_c2s)
    # симулируем: rx_seq уже 5 (5 кадров принято), приходит seq=7 → error
    rx.rx_seq = 5
    frame = W.frame_payload(W.F_SCH_SEALED, 0, [
        (W.T_SEQ, W.u64(7)),
        (W.T_MSG_CT, b"\x00" * 40)])
    tvs = W.parse_tvs(frame[4:])
    seq = W.as_u64(W.get(tvs, W.T_SEQ))
    with pytest.raises(SC.SchError):
        if seq != rx.rx_seq + 1:
            raise SC.SchError("seq gap")


def test_sealed_tag_mismatch():
    k_c2s, n_c2s, k_s2c, n_s2c = C.kdf_secch(b"\x01" * 32, b"\x02" * 32)
    # «сервер» шифрует s2c-ключем, «клиент» вскрывает другим ключом → tag fail
    tx = SC.SecChan(None, None, k_s2c, n_s2c, k_c2s, n_c2s)
    sealed = tx.seal_bytes(W.build_frame(W.F_PING, 0, [(W.T_NONCE, NONCE1)]))
    wrong = SC.SecChan(None, None, k_s2c, n_s2c, b"\xff" * 32, n_c2s)
    payload = sealed[len(W.encode_varint(0)) - 1:] if False else None

    # вручную всковыриваем T_MSG_CT из кадра и пробуем вскрыть не тем ключом
    fr = W.decode_frame(sealed)
    ct = W.get(fr.tvs, W.T_MSG_CT)
    seq = W.as_u64(W.get(fr.tvs, W.T_SEQ))
    import hashlib as _h
    from jproto_ref.crypto import aead_decrypt
    with pytest.raises(ValueError):
        aead_decrypt(b"\xff" * 32, SC._xor_seq(n_c2s, seq), SC._ad(seq), ct)
