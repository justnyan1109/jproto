"""jchat — базовый cmd-клиент мессенджера jproto (wire.md §5/§7, DESIGN_NOTES).

Канал клиент→нода - secchan (ML-KEM-768 handshake + ChaCha20-Poly1305, TFU-pin).
Сервис:
  * ONLINE-чат: 3-hop onion до 'home' ноды получателя + TRANSPORT-PoW
    (digest = h_pow(packet), майнится клиентом по seed'у раунда);
  * offline-доска (direct BS): F_BS_STORE/F_BS_READ в 'почтовую' ячейку
    часа cell = h_cell("board"‖hour‖addr), value = ky‖nonce‖msg_ct{AD =
    msg_aad(I_STORE_LOCAL, 0, 0)} — расшифровка только владельцем sk.
  Команды run-режима: /help /me /nodes /seed /to /msg /post /fetch /quit.

CLI:
  python -m jproto_ref.chat keygen <file.json>
  python -m jproto_ref.chat run --node HOST:PORT --me <file.json> [--pin-dir D]
  python -m jproto_ref.chat oneshot --node HOST:PORT --me f --to ADDR
        [--home IDX|HOST:PORT] --msg TEXT [--expect SUBSTR] [--wait S]  (e2e/scripts)
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import secrets
import struct
import sys
import time
from dataclasses import dataclass

from . import crypto as C
from . import pow as JP
from . import recipient as R
from . import secchan as SC
from . import wire as W

# --- параметры клиента --------------------------------------------------------

MINE_BUDGET_MS = {                    # profile → бюджет майнинга (мс)
    W.POW_TRANSPORT: 2500,
    W.POW_NODE: 2500,
    W.POW_READ: 400,
}
MSG_PAYLOAD_MAX = R.MSG_PAYLOAD_MAX


# --- идентичность ---------------------------------------------------------------

@dataclass
class Identity:
    pk_kem: bytes
    sk_kem: bytes          # seed 64 B (см. crypto.py docstring)
    pk_dsa: bytes
    sk_dsa: bytes          # seed 32 B

    @property
    def addr(self) -> bytes:
        return C.h_dir(self.pk_kem)

    @classmethod
    def generate(cls) -> "Identity":
        pk_kem, sk_kem = C.kem_generate()
        pk_dsa, sk_dsa = C.dsa_generate()
        return cls(pk_kem, sk_kem, pk_dsa, sk_dsa)

    def save(self, path: str) -> None:
        d = {"pk_kem": self.pk_kem.hex(), "sk_kem": self.sk_kem.hex(),
             "pk_dsa": self.pk_dsa.hex(), "sk_dsa": self.sk_dsa.hex(),
             "addr": self.addr.hex()}
        with open(path, "w") as f:
            json.dump(d, f, indent=1)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: str) -> "Identity":
        with open(path) as f:
            d = json.load(f)
        me = cls(bytes.fromhex(d["pk_kem"]), bytes.fromhex(d["sk_kem"]),
                 bytes.fromhex(d["pk_dsa"]), bytes.fromhex(d["sk_dsa"]))
        if me.pk_kem != C.kem_pk_from_sk_seed(me.sk_kem) or \
                me.pk_dsa != C.dsa_pk_from_sk_seed(me.sk_dsa):
            raise ValueError(f"{path}: pk не соответствует sk (файл битый)")
        return me


# --- TOFU-pin pk ноды -------------------------------------------------------------

class Pins:
    """pin-файл {node_key: pk_dsa_hex}. Первый коннект — pin + warn; дальше —
    жёсткая проверка (иначе MITM)."""

    def __init__(self, path: str | None):
        self.path = path
        self.data: dict[str, str] = {}
        if path and os.path.exists(path):
            try:
                with open(path) as f:
                    self.data = json.load(f)
            except Exception:
                self.data = {}

    def pin(self, node_key: str, pk: bytes) -> tuple[bool, str]:
        """→ (ok, prior_pk_hex|''). mismatch → False."""
        h = pk.hex()
        old = self.data.get(node_key)
        if old is None:
            self.data[node_key] = h
            self._flush()
            return True, ""
        return old == h, old

    def _flush(self) -> None:
        if not self.path:
            return
        tmp = self.path + ".tmp"
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=1)
        os.replace(tmp, self.path)


# --- parse dir entry (локальная копия node._parse_entry: без импорта ноды) -------

def _parse_entry(val: bytes) -> dict | None:
    try:
        tvs = W.parse_tvs(val)
        pk_kem = W.get(tvs, W.T_PK_KEM)
        pk_dsa = W.get(tvs, W.T_PK_DSA)
        tr = W.get(tvs, W.T_TRANSPORT)
        if not pk_kem or not pk_dsa or not tr:
            return None
        host, port, tls = W.dec_transport(tr)
        return {"pk_kem": pk_kem, "pk_dsa": pk_dsa, "host": host,
                "port": int(port), "tls": tls,
                "addr": C.h_dir(pk_kem)}
    except Exception:
        return None


def _resolve_recipient(spec: str) -> tuple[bytes, bytes]:
    """PK получателя: 2368-hex (pk_kem) либо путь к файлу идентичности
    (полной) или карточке (только pk_kem/pk_dsa/addr — см. `jchat card`).
    Возвращает (pk, addr). NOTE: 64-hex addr необратим — отправителю нужен pk."""
    spec = spec.strip()
    if os.path.isfile(spec):
        with open(spec) as f:
            d = json.load(f)
        pk = bytes.fromhex(d["pk_kem"])
        addr = bytes.fromhex(d["addr"]) if d.get("addr") else C.h_dir(pk)
        if len(pk) != C.KEM_PK_LEN:
            raise ValueError(f"{spec}: bad pk")
        return pk, addr
    raw = bytes.fromhex(spec)
    if len(raw) == C.KEM_PK_LEN:
        return raw, C.h_dir(raw)
    raise ValueError("recipient: 2368-hex pk_kem либо файл идентичности/карточка")


def board_cell(addr: bytes, hour: int) -> bytes:
    """«Почтовая» ячейка прямой BS-доставки: выводится без ноды."""
    return C.h_cell(b"board" + W.u64(hour) + addr)


def _now_hhmmss() -> str:
    return time.strftime("%H:%M:%S")


# --- клиент ------------------------------------------------------------------------

class Chat:
    def __init__(self, ident: Identity, host: str, port: int,
                 pin_dir: str | None = None, out=print):
        self.ident = ident
        self.host, self.port = host, port
        self.out = out

        node_key = f"{host}:{port}"
        self.pins = Pins(os.path.join(pin_dir, "node_pins.json")
                         if pin_dir else None)
        self.pin_key = node_key

        self.sec: SC.SecChan | None = None
        self.node_addr: bytes | None = None
        self.pow_par: dict[int, tuple[int, int]] = {}   # profile → (bits, budget)
        self.stor_par: dict | None = None               # T_STOR_PAR ноды (§6a)
        self.seeds: dict[int, bytes] = {}
        self.round: int | None = None
        self.nodes: dict[bytes, dict] = {}

        self.session: int = secrets.randbits(32)
        self.seq: int = 0
        self.alive = False
        self.last_incoming: str = ""
        self._bs_fut: asyncio.Future | None = None

        # PoW
        self.pow_ok = JP.load_lib() is not None
        self._pow: JP.Pow | None = None

    # --- соединение -------------------------------------------------------------

    async def connect(self) -> None:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), 10.0)
        sec = await asyncio.wait_for(
            SC.handshake_client(reader, writer, self.ident.sk_kem,
                                self.ident.sk_dsa), 10.0)
        # TOFU-pin: сверяем pk, предъявленный сервером в handshake — первый раз
        # запоминаем, дальше несовпадение = MITM → отказ.
        ok_old, old = self.pins.pin(self.pin_key, sec.peer_pk_dsa)
        if not ok_old:
            await writer.drain()
            writer.close()
            raise SC.SchError(
                f"pin mismatch {self.pin_key}: pinned {old[:16]}…, got "
                f"{sec.peer_pk_dsa.hex()[:16]}… (MITM?)")
        self.sec = sec
        self.alive = True
        await self.sec.send(W.F_HELLO, 0, [
            (W.T_VER, W.u16(W.VERSION)),
            (W.T_CAPS, W.u32(W.CAPS_MIX | W.CAPS_BS)),
            (W.T_ADDR, self.ident.addr)])
        ok = await self.sec.recv_frame()
        if ok is None or ok.type != W.F_HELLO_OK:
            raise ConnectionError(f"bad HELLO_OK ({ok and hex(ok.type)})")
        self.node_addr = W.get(ok.tvs, W.T_ADDR)
        for v in W.get_all(ok.tvs, W.T_POW_PAR):
            prof, bits, budget, _mode = W.dec_pow_par(v)
            self.pow_par[prof] = (bits, budget)
        v = W.get(ok.tvs, W.T_STOR_PAR)
        if v:
            self._take_stor_par(v)

        # dir (нужен для маршрута), потом seeds с ретраем (beacon финализируется
        # к t0+0.6R — свежую ноду подождём)
        await self._refresh_dir()
        await self._refresh_seeds_retry()

    async def _refresh_dir(self) -> None:
        await self.sec.send(W.F_DIR_REQ)
        fr = await self.sec.recv_frame()
        if fr is None or fr.type != W.F_DIR:
            raise ConnectionError("no DIR answer")
        body = W.get(fr.tvs, W.T_NODE_LIST) or b""
        pairs = W.parse_tvs(body)
        for i in range(0, len(pairs) - 1, 2):
            if pairs[i][0] != W.T_NODE_ENTRY or pairs[i + 1][0] != W.T_SIG:
                continue
            ent = _parse_entry(pairs[i][1])
            if not ent or not C.dsa_verify(ent["pk_dsa"], pairs[i + 1][1],
                                           C.h_dirlist(pairs[i][1])):
                continue
            self.nodes[ent["addr"]] = ent
        v = W.get(fr.tvs, W.T_STOR_PAR)     # свежая стат ноды (§6a)
        if v:
            self._take_stor_par(v)

    def _take_stor_par(self, v: bytes) -> None:
        try:
            keys = ("slots_lbs", "slots_gbs", "lam_day", "window_h", "bits_min",
                    "tau_h", "retention_h", "n_active")
            self.stor_par = dict(zip(keys, W.dec_stor_par(v)))
        except ValueError:
            pass

    async def _refresh_seeds_retry(self, tries: int = 10, pause: float = 1.0) -> None:
        await self.sec.send(W.F_SEED_REQ)
        fr = await self.sec.recv_frame()
        if fr is None or fr.type != W.F_SEED:
            raise ConnectionError("no SEED answer")
        err = W.get(fr.tvs, W.T_ERR)
        if err:
            if tries <= 0:
                raise ConnectionError("SEED 503: beacon ещё не финализировал раунд")
            await asyncio.sleep(pause)
            return await self._refresh_seeds_retry(tries - 1, pause)
        tvs = fr.tvs
        for i in range(0, len(tvs) - 1, 2):
            if tvs[i][0] == W.T_ROUND and tvs[i + 1][0] == W.T_SEED:
                self.seeds[W.as_u64(tvs[i][1])] = tvs[i + 1][1]
        if self.seeds:
            self.round = max(self.seeds)

    # --- внутренности PoW --------------------------------------------------------

    def _pow_ctx(self) -> JP.Pow | None:
        if not self.pow_ok:
            return None
        if self._pow is None:
            seed_hour = C.DEV_SEED_HOUR    # dev: совпадает с cfg ноды по умолчанию
            self._pow = JP.pow_ctx(seed_hour)
        return self._pow

    def mine_cert(self, payload: bytes, profile: int,
                  bits_min: int | None = None) -> tuple[int, int]:
        """cert по payload (digest = pow_digest(payload)). Страховка от бага
        jppow_mine (out_bits может завышаться): фактические ведущие биты
        пересчитываем jppow_hash+лз уже на client-side — иначе нода (честно
        пересчитывая digest) откажет cert. bits_min — форс требуемых бит
        (удержание ≥ published retention). При сдохшем .so — zero-cert."""
        bits_req, budget = self.pow_par.get(
            profile, (6 if profile == W.POW_TRANSPORT else 4, 2000))
        if bits_min is not None:
            bits_req = max(bits_req, int(bits_min))
        if not self.pow_ok:
            self.out("!! JPPOW недоступен: шлю zero-cert (нода skip_pow?")
            return 0, 0
        if not self.seeds:
            raise RuntimeError("нет seed раунда — refresh не сделан")
        seed = self.seeds[max(self.seeds)]
        pd = JP.pow_digest(payload)
        pw = self._pow_ctx()
        t_end = time.time() + max(0.5, (int(budget) / 1000) * 3)
        for _ in range(6):
            res = JP.mine(seed, pd, bits_req, budget, ctx=pw)
            if res is None:
                break
            nonce = res[0]
            actual = pw.lzbits(pw.hash(seed, pd, nonce))   # честный digest… по nonce
            if actual >= bits_req:
                return nonce, actual
            if time.time() > t_end:
                break
        raise RuntimeError(
            f"PoW {profile}: не добыто ≥{bits_req} бит (факт-верификация)")

    # --- отправка ONLINE -----------------------------------------------------------

    def _route_online(self, home: dict | None) -> list[dict]:
        """I_ONLINE: 3 слоя [наш(отправка), случайный, home]. Наша нода обязана
        быть route[0] (мы шлём кадр ей); home = home получателя (Dir Index)."""
        us = self.nodes.get(self.node_addr)
        if us is None:
            raise RuntimeError("наша нода не в dir")
        target = home or us
        others = [e for a, e in sorted(self.nodes.items())
                  if a not in (us["addr"], target["addr"])]
        mid = random.choice(others) if others else us
        return [us, mid, target]

    async def send_online(self, text: str, recip_pk: bytes,
                          home: dict | None = None) -> int:
        pt = text.encode("utf-8")
        if not 1 <= len(pt) <= MSG_PAYLOAD_MAX:
            raise ValueError(f"длина msg 1..{MSG_PAYLOAD_MAX}")
        self.seq += 1
        rpl = R.encode(W.I_ONLINE, self.session, self.seq, 0, 0, 0,
                       recip_pk, pt)
        route = self._route_online(home)
        packet = R.build_onion(rpl, [(e["addr"], e["pk_kem"]) for e in route])
        nonce, bits = self.mine_cert(packet, W.POW_TRANSPORT)
        cert = W.enc_pow_cert(nonce, bits, W.POW_TRANSPORT)
        await self.sec.send(W.F_MIX_ONION, 0, [
            (W.T_PAYLOAD, packet), (W.T_POW, cert)])
        return self.seq

    # --- direct-BS: пост/чтение доски часа ------------------------------------------

    def _hour(self) -> int:
        """час = номер раунда // hour_blocks (360 @10s, как в beacon ноды)."""
        if self.round is None:
            return int(time.time() // 3600)
        return self.round // 360

    def retention_bits(self, keep_h: int | None = None) -> int:
        """Сколько бит майнить под запись: bits_min ноды; если keep_h выше
        published retention — +⌈(keep − retain)/τ⌉ («+1 бит ≈ +1 неделя»)."""
        sp = self.stor_par or {}
        bits_min = int(sp.get("bits_min") or 6)
        if not keep_h:
            return bits_min
        tau = int(sp.get("tau_h") or 168)
        ret = int(sp.get("retention_h") or 0)
        over = max(0, int(keep_h) - ret)
        return min(32, bits_min + -(-over // tau))

    async def post(self, text: str, keep_h: int | None = None) -> int:
        pt = text.encode("utf-8")
        if not 1 <= len(pt) <= MSG_PAYLOAD_MAX:
            raise ValueError(f"длина msg 1..{MSG_PAYLOAD_MAX}")
        ss, ky = C.kem_encaps(self.ident.pk_kem)
        nonce = secrets.token_bytes(C.AEAD_NONCE_LEN)
        msg_ct = C.aead_encrypt(ss, nonce, R.msg_aad(W.I_STORE_LOCAL, 0, 0), pt)
        value = ky + nonce + msg_ct
        hour = self._hour()
        idx = board_cell(self.ident.addr, hour)
        rec = value + W.u32(0) + W.u64(0)          # хвост (score/ts) у ноды заново
        bits_keep = self.retention_bits(keep_h)
        nonce_p, bits = self.mine_cert(idx + rec, W.POW_TRANSPORT,
                                       bits_min=bits_keep)
        cert = W.enc_pow_cert(nonce_p, bits, W.POW_TRANSPORT)
        await self.sec.send(W.F_BS_STORE, 0, [
            (W.T_CELL_IDX, idx), (W.T_CELL_REC, rec), (W.T_POW, cert)])
        return hour

    async def fetch(self, back_hours: int = 0) -> list[str]:
        hour = self._hour() - max(0, int(back_hours))
        idx = board_cell(self.ident.addr, hour)
        nonce, bits = self.mine_cert(idx, W.POW_READ)
        cert = W.enc_pow_cert(nonce, bits, W.POW_READ)
        await self.sec.send(W.F_BS_READ, 0, [
            (W.T_CELL_IDX, idx), (W.T_POW, cert)])
        # читает фоновый read_loop (double-read = RuntimeError readexactly)
        fut = asyncio.get_running_loop().create_future()
        self._bs_fut = fut
        try:
            fr = await asyncio.wait_for(fut, 10.0)
        except TimeoutError:
            raise ConnectionError("нет ответа на READ (таймаут)")
        finally:
            self._bs_fut = None
        if fr is None or fr.type != W.F_BS_READ_RESP:
            raise ConnectionError("нет ответа на READ")
        out: list[str] = []
        for v in W.get_all(fr.tvs, W.T_CELL_REC):
            value, meta = v[:len(v) - 12], v[len(v) - 12:]
            ts = struct.unpack_from("<Q", meta, 4)[0]
            try:
                txt = C.aead_decrypt(
                    C.kem_decaps(self.ident.sk_kem, value[:C.KEM_CT_LEN]),
                    value[C.KEM_CT_LEN:C.KEM_CT_LEN + C.AEAD_NONCE_LEN],
                    R.msg_aad(W.I_STORE_LOCAL, 0, 0),
                    value[C.KEM_CT_LEN + C.AEAD_NONCE_LEN:])
                out.append(f"[{time.strftime('%d.%m %H:%M', time.localtime(ts))}] "
                           f"{txt.decode('utf-8', 'replace')}")
            except Exception:
                pass   # не наша запись — implicit rejection
        return out

    # --- приём ----------------------------------------------------------------------

    def try_open(self, rpl: bytes) -> str | None:
        """R → открытый текст (implicit rejection). None = не наше."""
        try:
            meta = W.recipient_header(rpl)
            parsed = R.parse(rpl)
            pt = R.decaps_msg(self.ident.sk_kem, parsed, meta["itype"],
                              meta["session"], meta["seq"])
            return pt.decode("utf-8", "replace")
        except Exception:
            return None

    async def read_loop(self) -> None:
        while self.alive and self.sec is not None:
            try:
                fr = await self.sec.recv_frame()
            except (SC.SchError, ConnectionError, asyncio.IncompleteReadError):
                self.alive = False
                break
            if fr.type == W.F_ONLINE_DELIVER:
                rpl = W.get(fr.tvs, W.T_PAYLOAD)
                if rpl:
                    txt = self.try_open(rpl)
                    if txt is not None:
                        self.last_incoming = txt
                        meta = W.recipient_header(rpl)
                        self.out(f"  ← [{_now_hhmmss()} sess={meta['session'] & 0xFFFF:04x}] {txt}")
            elif fr.type == W.F_BS_READ_RESP:
                # ответ доски: ждущий /fetch забирает через _bs_fut
                # (читатель потока один — иначе RuntimeError readexactly)
                f = self._bs_fut
                if f is not None and not f.done():
                    f.set_result(fr)
            elif fr.type in (W.F_ONLINE_ACK, W.F_BEACON_SEED, W.F_GOSSIP_DATA,
                             W.F_BEACON_COMMIT, W.F_BEACON_REVEAL, W.F_MIX_ACK):
                if fr.type == W.F_BEACON_SEED:
                    n = W.as_u64(W.get(fr.tvs, W.T_ROUND))
                    seed = W.get(fr.tvs, W.T_SEED)
                    if n is not None and seed:
                        self.seeds[n] = seed
                        self.round = max(self.seeds)
                # прочее — dev-фоновый шум, молчим
            else:
                self.out(f"  · кадр {hex(fr.type)} (игнор)")


# --- интерактивный cmd-режим ------------------------------------------------------

HELP_TXT = """команды:
  /help            — эта справка
  /me              — мой адрес + подключение
  /nodes           — dir-ноды [индекс] host:port addr…
  /seed            — текущий раунд/seed
  /to CARD[@HOME]  — получатель: КОМПАКТ-карта = карточка (без sk) ИЛИ файл
                     идентичности ИЛИ pk (2368 hex); HOME = индекс его ноды
                     (см. /nodes) или host:port; без HOME — наша нода
  /msg ТЕКСТ       — послать ТЕКСТ получателю (onion 3 hop + PoW ≈1 с)
  ТЕКСТ            — шорткат /msg (после /to)
  /post ТЕКСТ      — direct-BS в мою почтовую ячейку часа (offline-заметка себе)
  /fetch [N]       — прочитать доску текущего часа (N — N часов назад)
  /quit            — выход"""


def _parse_home(spec: str, entries: list[dict]) -> dict | None:
    """Индекс (1-base по sort(addr)) из /nodes либо host:port."""
    spec = spec.strip()
    if not spec:
        return None
    if spec.isdigit():
        i = int(spec)
        if not 1 <= i <= len(entries):
            raise ValueError(f"нет ноды №{i} (всего {len(entries)})")
        return entries[i - 1][1]
    host, sep, port = spec.rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"HOME: ожидалось N|host:port, получено {spec!r}")
    for _, e in entries:
        if e["host"] == host and e["port"] == int(port):
            return e
    raise ValueError(f"нет ноды {spec} в dir")


class ChatApp:
    def __init__(self, chat: Chat, out=print, keep_h: int | None = None):
        self.c = chat
        self.out = out
        self.keep_h = keep_h          # --keep ЧАСЫ (деф.: min-сложность ноды)
        self.peer: tuple[bytes, dict | None] | None = None
        self.running = True

    def _entries(self) -> list[tuple[bytes, dict]]:
        return sorted(self.c.nodes.items(), key=lambda kv: kv[0])

    def _short(self, b: bytes, n: int = 12) -> str:
        return b.hex()[:n]

    async def handle(self, line: str) -> None:
        line = line.rstrip("\n")
        cmd, _, rest = line.strip().partition(" ")
        rest = rest.strip()
        if not cmd:
            return
        c = cmd.lower()
        if not c.startswith("/"):
            if self.peer:
                await self._msg(line)
            else:
                self.out("  нет /to ADDR — см. /help")
            return

        if c in ("/quit", "/exit", "/q"):
            self.running = False
        elif c == "/help":
            self.out(HELP_TXT)
        elif c == "/me":
            self.out(f"  addr  {self.c.ident.addr.hex()}")
            self.out(f"  node  {self.c.pin_key} secured, round={self.c.round - W.GENESIS_RND} "
                     f"(unix={int(self.c.round * 10) + W.GENESIS_TS})")
            sp = self.c.stor_par
            if sp:
                self.out(f"  stor  seff={sp['slots_lbs']} gbs={sp['slots_gbs']} "
                         f"bits_min={sp['bits_min']} τ={sp['tau_h']}ч "
                         f"retain≈{sp['retention_h']}ч λ={sp['lam_day']}/д "
                         f"n_active={sp['n_active']}")
        elif c == "/nodes":
            for i, (a, e) in enumerate(self._entries(), 1):
                mark = "*" if e["addr"] == self.c.node_addr else " "
                self.out(f"  {i:2}{mark} {e['host']}:{e['port']:<5} {self._short(a)}")
        elif c == "/seed":
            self.out(f"  round={self.c.round - W.GENESIS_RND} "
                     f"(unix={int(self.c.round * 10) + W.GENESIS_TS}) "
                     f"seeds={[(l - W.GENESIS_RND, int(l * 10) + W.GENESIS_TS) for l in self.c.seeds]}")
        elif c == "/to":
            spec, sep, home_s = rest.partition("@")
            pk, addr = _resolve_recipient(spec)
            home = _parse_home(home_s, self._entries()) if home_s.strip() else None
            where = "наша нода" if home is None else f"{home['host']}:{home['port']}"
            mode = "файл" if os.path.isfile(spec.strip()) else "pk"
            self.peer = (pk, home)
            self.out(f"  → получатель addr={addr.hex()[:16]} ({mode}), home={where}")
        elif c == "/msg":
            await self._msg(rest)
        elif c == "/post":
            if not rest:
                raise ValueError("post: пустой текст")
            t0 = time.time()
            hour = await self.c.post(rest, keep_h=self.keep_h)
            bits = self.c.retention_bits(self.keep_h)
            self.out(f"  ✓ post → доска часа {hour}, bits={bits} "
                     f"(удержание ≈{self.keep_h or 'min'} ч, PoW {time.time() - t0:.2f}s)")
        elif c == "/fetch":
            for line_ in await self.c.fetch(int(rest or 0)):
                self.out(f"  📌 {line_}")
            self.out("  (fetch — конец доски)")
        elif c == "/reply":
            await self._msg(rest)
        else:
            self.out(f" неизвестная команда {cmd} — /help")

    async def _msg(self, text: str) -> None:
        if not self.peer:
            raise ValueError("получатель не задан (/to ADDR[@HOME])")
        recip, home = self.peer
        t0 = time.time()
        seq = await self.c.send_online(text, recip, home)
        self.out(f"  → seq={seq} (onion 3 hop, PoW {time.time() - t0:.2f}s, "
                 f"нода {self.c.pin_key})")

    async def run(self) -> None:
        reader_task = asyncio.create_task(self.c.read_loop())
        self.out("jchat v0.1 (secchan+onion). /help — справка, /quit — выход.")
        try:
            while self.running and self.c.alive:
                try:
                    line = await asyncio.to_thread(input, "chat> ")
                except EOFError:
                    break
                try:
                    await self.handle(line)
                except Exception as e:
                    self.out(f"  ! {e!r}")
        finally:
            self.running = False
            self.c.alive = False
            if not reader_task.done():
                reader_task.cancel()
            try:
                await reader_task
            except (asyncio.CancelledError, Exception):
                pass
            self.out("  (отключились)")


# --- CLI --------------------------------------------------------------------------

def _cli() -> int:
    import argparse
    p = argparse.ArgumentParser(prog="jchat", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("keygen", help="создать файл идентичности")
    pk.add_argument("file")

    pc = sub.add_parser("card", help="публичная карточка (stdout; без sk) — то,\n"
                                     "что передаётся собеседнику в /to")
    pc.add_argument("file")

    pr = sub.add_parser("run", help="интерактивный чат")
    pr.add_argument("--node", required=True, metavar="HOST:PORT")
    pr.add_argument("--me", required=True, metavar="IDFILE")
    pr.add_argument("--pin-dir", default=None, help="каталог pin-файла (default ~/.jproto)")
    pr.add_argument("--keep", type=int, default=None, metavar="HOURS",
                    help="удержание /post (часы); деф. — min-сложность ноды")
    po = sub.add_parser("oneshot", help="скриптовый: послать и/или ждать")
    po.add_argument("--node", required=True, metavar="HOST:PORT")
    po.add_argument("--me", required=True, metavar="IDFILE")
    po.add_argument("--to", help="карта получателя: файл идентичности или pk 2368-hex")
    po.add_argument("--home", help="HOME ноды получателя: индекс/NODE host:port")
    po.add_argument("--msg")
    po.add_argument("--reply")   # автоответ на пришедшее (e2e)
    po.add_argument("--expect")  # ждать сообщение с подстрокой → exit 0
    po.add_argument("--wait", type=float, default=20.0)
    po.add_argument("--keep", type=int, default=None, metavar="HOURS",
                    help="удержание /post (часы); деф. — min-сложность ноды")
    po.add_argument("--pin-dir", default=None)

    a = p.parse_args()
    if a.cmd == "keygen":
        ident = Identity.generate()
        ident.save(a.file)
        print(f"identity → {a.file}  addr={ident.addr.hex()}")
        return 0
    if a.cmd == "card":
        ident = Identity.load(a.file)
        json.dump({"pk_kem": ident.pk_kem.hex(), "pk_dsa": ident.pk_dsa.hex(),
                   "addr": ident.addr.hex()}, sys.stdout, indent=1)
        print()
        return 0

    pin_dir = a.pin_dir or os.path.expanduser("~/.jproto")
    ident = Identity.load(a.me)
    host, _, port = a.node.rpartition(":")
    if not host or not port.isdigit():
        print("--node HOST:PORT", file=sys.stderr)
        return 2

    async def _main() -> int:
        chat = Chat(ident, host, int(port), pin_dir=pin_dir)
        try:
            await chat.connect()
        except Exception as e:
            print(f"подключение: {e!r}", file=sys.stderr)
            return 1
        if a.cmd == "run":
            await ChatApp(chat, keep_h=a.keep).run()
            return 0

        # oneshot: sender-режим (--msg TO) и/или wait-режим (--expect/--reply)
        got: asyncio.Queue[str] = asyncio.Queue()

        def _out(s: str) -> None:
            print(s, flush=True)
            if "← [" in s:
                got.put_nowait(s)

        chat.out = _out
        to = None
        to_card = a.to
        if to_card:
            to, _to_addr = _resolve_recipient(to_card)
        app = ChatApp(chat)
        home = _parse_home(a.home, app._entries()) if a.home else None
        if a.msg:
            if not to:
                print("--msg требует --to (файл идентичности | pk 2368-hex)", file=sys.stderr)
                return 2
            seq = await chat.send_online(a.msg, to, home)
            print(f"oneshot: sent seq={seq} → {to[:16].hex()}", flush=True)
            if not a.expect:
                return 0
        reader = asyncio.create_task(chat.read_loop())
        try:
            return await asyncio.wait_for(
                _oneshot_wait(chat, got, a, reply_to=to_card if a.reply else None),
                timeout=a.wait)
        except asyncio.TimeoutError:
            print("oneshot: таймаут ожидания", file=sys.stderr)
            return 3
        finally:
            chat.alive = False
            if not reader.done():
                reader.cancel()

    async def _oneshot_wait(chat: Chat, got: asyncio.Queue, a, reply_to: str | None) -> int:
        """exit 0 когда: пришло сообщение (без --expect); либо пришло сообщение
        содержащее --expect (тогда опционально --reply TO → послать ответ)."""
        while True:
            _ = await got.get()
            if a.expect:
                incoming = chat.last_incoming or ""
                if a.expect in incoming:
                    print("expect OK", flush=True)
                    if a.reply and reply_to:
                        rp, _addr = _resolve_recipient(reply_to)
                        await chat.send_online(a.reply, rp)
                    return 0
                continue
            return 0

    try:
        return asyncio.run(_main())
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(_cli())