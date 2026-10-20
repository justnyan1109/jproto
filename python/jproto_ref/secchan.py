"""secchan — шифрованный канал (wire.md §7, src/secchan.c байт-в-байт).

Рукопожатие (plaintext-кадры):
  C→S  F_SCH_HELLO:     (T_PK_KEM kem_pk_c)(T_PK_DSA dsa_pk_c)(T_SIG sig_c)
                        sig_c = ML-DSA-44(sk_c, "JPCS1" ‖ kem_pk_c)
  S→C  F_SCH_HELLO_OK:  (T_KYBER_CT ct_s)(T_PK_DSA pk_dsa_s)(T_SIG sig_s)
                        ct_s = Encaps(kem_pk_c); sig_s = sign("JPCS2" ‖ kem_pk_c ‖ ct_s)
  th = SHAKE256(secch.1, kem_pk_c ‖ ct_s)   (32 B)
  K  = SHAKE256(secch.1, ss ‖ th) → 88 B:
       c2s.key(32) ‖ c2s.nonce(12) ‖ s2c.key(32) ‖ s2c.nonce(12)
Клиент шлёт c2s, сервер s2c.

Насыпанный кадр F_SCH_SEALED: (T_SEQ u64 LE)(T_MSG_CT ct), T_SEQ идёт первым.
plaintext ct = ПОЛНЫЕ байты wire-кадра (varint(total) ‖ u16 type ‖ u16 flags ‖ body).
nonce = base; nonce[4:12] ^= seq(u64 LE); AD = b"JPSFR" ‖ seq(u64 LE);
seq строго +1, начиная с 1 (внутренние счётчики с нуля).
Сервер проверяет подпись клиента (владение sk); pin сервера делает клиент —
см. `python -m jproto_ref.chat` (TOFU-pinfile по pk_dsa).
"""

from __future__ import annotations

import asyncio
import struct

from . import crypto as C
from . import wire as W

PFX_C = b"JPCS1"
PFX_S = b"JPCS2"
AD_PFX = b"JPSFR"

MAX_FRAME_TOTAL = 65536


class SchError(ValueError):
    """Протокольная ошибка secchan (handshake/seq/tag)."""


# --- async frame I/O (read_frame из node.py вынесен сюда для общего пользования) --

async def read_frame(reader) -> W.Frame | None:
    """varint(total) + payload; None — EOF; ValueError — мусор."""
    total = 0
    shift = 0
    first = True
    while True:
        chunk = await reader.readexactly(1)
        b = chunk[0]
        if first:
            first = False
        total |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    if first or total < 4 or total > MAX_FRAME_TOTAL:
        raise ValueError(f"bad frame total {total}")
    payload = await reader.readexactly(total)
    ftype, flags = payload[0] | (payload[1] << 8), payload[2] | (payload[3] << 8)
    tvs = W.parse_tvs(payload[4:])
    return W.Frame(ftype, flags, tvs)


def _xor_seq(base: bytes, seq: int) -> bytes:
    n = bytearray(base)
    for i in range(8):
        n[4 + i] ^= (seq >> (8 * i)) & 0xFF
    return bytes(n)


def _ad(seq: int) -> bytes:
    return AD_PFX + struct.pack("<Q", seq)


def _keys(ss: bytes, th: bytes, is_client: bool) -> tuple[bytes, bytes, bytes, bytes]:
    k_c2s, n_c2s, k_s2c, n_s2c = C.kdf_secch(ss, th)
    if is_client:
        return k_c2s, n_c2s, k_s2c, n_s2c
    return k_s2c, n_s2c, k_c2s, n_c2s


class SecChan:
    """Насыпанные кадры поверх готовых TCP-стримов (одна сторона канала)."""

    __slots__ = ["reader", "writer", "key_tx", "ntx", "key_rx", "nrx",
                 "tx_seq", "rx_seq", "peer_pk_dsa"]

    def __init__(self, reader, writer, key_tx: bytes, nonce_tx: bytes,
                 key_rx: bytes, nonce_rx: bytes, peer_pk_dsa: bytes | None = None):
        self.reader = reader
        self.writer = writer
        self.key_tx, self.ntx = key_tx, nonce_tx
        self.key_rx, self.nrx = key_rx, nonce_rx
        self.tx_seq = 0
        self.rx_seq = 0
        self.peer_pk_dsa = peer_pk_dsa   # pk, предъявленный peer'ом в handshake

    # --- отправка ------------------------------------------------------------

    def seal_bytes(self, frame: bytes) -> bytes:
        """Полные байты кадра → полный байтовый F_SCH_SEALED-кадр."""
        self.tx_seq += 1
        nonce = _xor_seq(self.ntx, self.tx_seq)
        ct = C.aead_encrypt(self.key_tx, nonce, _ad(self.tx_seq), bytes(frame))
        payload = W.frame_payload(W.F_SCH_SEALED, 0, [
            (W.T_SEQ, W.u64(self.tx_seq)),
            (W.T_MSG_CT, ct),
        ])
        return W.encode_varint(len(payload)) + payload

    async def send_frame_bytes(self, frame: bytes) -> None:
        self.writer.write(self.seal_bytes(frame))
        try:
            await self.writer.drain()
        except (ConnectionError, RuntimeError) as e:
            raise ConnectionError(f"secchan send: {e}") from e

    async def send(self, ftype: int, flags: int = 0, tvs=()) -> None:
        await self.send_frame_bytes(W.build_frame(ftype, flags, tvs))

    # --- приём ----------------------------------------------------------------

    async def recv_frame(self) -> W.Frame:
        fr = await read_frame(self.reader)
        if fr is None:
            raise ConnectionError("secchan: EOF")
        if fr.type != W.F_SCH_SEALED:
            raise SchError(f"secchan: ожидался F_SCH_SEALED, got {hex(fr.type)}")
        seq = W.as_u64(W.get(fr.tvs, W.T_SEQ))
        ct = W.get(fr.tvs, W.T_MSG_CT)
        if seq is None or not ct or len(ct) < C.AEAD_TAG_LEN + 1:
            raise SchError("secchan: bad sealed frame")
        if seq != self.rx_seq + 1:
            raise SchError(f"secchan: seq {seq} != {self.rx_seq + 1} (replay/gap)")
        try:
            pt = C.aead_decrypt(self.key_rx, _xor_seq(self.nrx, seq), _ad(seq), ct)
        except ValueError as e:
            raise SchError(f"secchan: AEAD tag mismatch (seq {seq})") from e
        self.rx_seq = seq
        return W.decode_frame(pt)


# --- рукопожатия -----------------------------------------------------------------

async def handshake_client(reader, writer, kem_sk_seed: bytes, dsa_sk_seed: bytes,
                           expect_pk: bytes | None = None) -> SecChan:
    """Клиентская сторона: pin-check pk сервера (expect_pk) перед encaps."""
    kem_pk = C.kem_pk_from_sk_seed(kem_sk_seed)
    dsa_pk = C.dsa_pk_from_sk_seed(dsa_sk_seed)
    sig = C.dsa_sign(dsa_sk_seed, PFX_C + kem_pk)
    payload = W.frame_payload(W.F_SCH_HELLO, 0, [
        (W.T_PK_KEM, kem_pk), (W.T_PK_DSA, dsa_pk), (W.T_SIG, sig)])
    writer.write(W.encode_varint(len(payload)) + payload)
    await writer.drain()

    fr = await read_frame(reader)
    if fr is None:
        raise ConnectionError("server closed during handshake")
    if fr.type != W.F_SCH_HELLO_OK:
        raise SchError(f"ожидался F_SCH_HELLO_OK, got {hex(fr.type)}")
    ct = W.get(fr.tvs, W.T_KYBER_CT)
    pk_dsa_s = W.get(fr.tvs, W.T_PK_DSA)
    sig_s = W.get(fr.tvs, W.T_SIG)
    if (not ct or len(ct) != C.KEM_CT_LEN or not pk_dsa_s or len(pk_dsa_s) != C.DSA_PK_LEN
            or not sig_s or len(sig_s) != C.DSA_SIG_LEN):
        raise SchError("bad HELLO_OK TLV")
    if not C.dsa_verify(pk_dsa_s, sig_s, PFX_S + kem_pk + ct):
        raise SchError("bad server signature")
    if expect_pk is not None and pk_dsa_s != expect_pk:
        raise SchError("server pk_dsa != pin (MITM?)")

    ss = C.kem_decaps(kem_sk_seed, ct)
    th = C.H(kem_pk + ct, C.D_SECCH)
    return SecChan(reader, writer, *_keys(ss, th, is_client=True),
                   peer_pk_dsa=pk_dsa_s)


async def handshake_server(reader, writer, dsa_sk_seed: bytes,
                           first_frame: W.Frame | None = None) -> SecChan:
    """Серверная сторона; first_frame — уже прочитанный F_SCH_HELLO (сниффер ноды)."""
    fr = first_frame if first_frame is not None else await read_frame(reader)
    if fr is None or fr.type != W.F_SCH_HELLO:
        raise SchError(f"ожидался F_SCH_HELLO, got {hex(fr and fr.type)}")
    tkm = W.get(fr.tvs, W.T_PK_KEM)
    tdc = W.get(fr.tvs, W.T_PK_DSA)
    tsg = W.get(fr.tvs, W.T_SIG)
    if (not tkm or len(tkm) != C.KEM_PK_LEN or not tdc or len(tdc) != C.DSA_PK_LEN
            or not tsg or len(tsg) != C.DSA_SIG_LEN):
        raise SchError("bad HELLO TLV")
    if not C.dsa_verify(tdc, tsg, PFX_C + tkm):
        raise SchError("bad client signature")

    ss, ct = C.kem_encaps(tkm)
    my_dsa_pk = C.dsa_pk_from_sk_seed(dsa_sk_seed)
    sig = C.dsa_sign(dsa_sk_seed, PFX_S + tkm + ct)
    payload = W.frame_payload(W.F_SCH_HELLO_OK, 0, [
        (W.T_KYBER_CT, ct), (W.T_PK_DSA, my_dsa_pk), (W.T_SIG, sig)])
    writer.write(W.encode_varint(len(payload)) + payload)
    await writer.drain()

    th = C.H(tkm + ct, C.D_SECCH)
    return SecChan(reader, writer, *_keys(ss, th, is_client=False),
                   peer_pk_dsa=tdc)


if __name__ == "__main__":  # smoke: loopback через реальный TCP-сокет
    import secrets

    async def _smoke() -> None:
        k_c2s, n_c2s, k_s2c, n_s2c = C.kdf_secch(b"\x01" * 32, b"\x02" * 32)

        async def _srv(reader, writer):
            srv = SecChan(reader, writer, k_s2c, n_s2c, k_c2s, n_c2s)
            fr = await srv.recv_frame()
            assert fr.type == W.F_PING and W.get(fr.tvs, W.T_NONCE) == b"nonce1"
            await srv.send(W.F_PONG, 0, [(W.T_NONCE, b"nonce2")])
            writer.close()

        server = await asyncio.start_server(_srv, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        cli = SecChan(r, w, k_c2s, n_c2s, k_s2c, n_s2c)
        await cli.send(W.F_PING, 0, [(W.T_NONCE, b"nonce1")])
        fr = await cli.recv_frame()
        assert fr.type == W.F_PONG and W.get(fr.tvs, W.T_NONCE) == b"nonce2"
        w.close()
        server.close()
        await server.wait_closed()
        secrets.token_bytes(1)  # noqa: B311 — silence import lint

    asyncio.run(_smoke())
    print("secchan selfcheck OK")
