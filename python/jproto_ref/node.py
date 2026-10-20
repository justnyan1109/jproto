"""Ссылочная нода jproto (Python): TCP-сервер + beacon(v2) + mix(v2) + BS + gossip.

Соответствие контракту: docs/protocol.md (§2 beacon hbdrand v2, §3 PoW, §5 onion,
§7 handshake/BS, §9/§10 BS/gossip) и docs/wire.md. Отступы от буквального wire.md
собраны в python/DESIGN_NOTES.md (online-доставка всем registered, cell = h_cell,
sk-как-seed и т.д.).

Сервисы ноды:
  * beacon hbdrand v2: commit → reveal → finalize (+публикация F_BEACON_SEED);
  * mix v2: entry верифицирует TRANSPORT-PoW (digest = h_pow(packet)), peel,
    форвард ct_next‖blob_next дальше (без per-hop майнинга); финальный слой —
    R: ONLINE → доставка клиенту; store → NODE-PoW из заголовка R и вставка в BS
    по cell = h_cell(value);
  * BS: Local (256 dev-ячеек) для I_STORE_LOCAL/I_OFFER/I_REPLY/I_STORE_GLOBAL?;
    Global (1024) для I_STORE_GLOBAL; прямые пути F_BS_STORE (TRANSPORT PoW) и
    F_BS_READ (READ PoW); eviction score = bits − age_s//3600 внутри ячейки;
  * gossip: PUSH/FETCH/DATA для Global BS (digest = h_rec(value));
  * ONLINE-доставка зарегистрированным клиентам (HELLO c T_ADDR);
  * HTTP-обёртка: POST /jp (кадры в один ход) и GET /status;
  * JSON-lines логи в stderr;
  * rate limit 5 msg/s/IP на «тарифицируемые» типы кадров;
  * снимок BS в data_dir (bs_snapshot.json) при остановке и по таймеру.

Ключ PoW (seed_hour) — статичный cfg['pow_seed_hour'] (default DEV_SEED_HOUR);
привязка PoW к раунду живёт в seed_round во входе jppow. secchan — TODO (beacon
и gossip пока в открытом wire-виде; см. wire.md §7 и src/secchan.c в C).
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import secrets
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import crypto as C
from . import pow as JP
from . import recipient as R
from . import wire as W

# --- defaults конфига (переопределяются в cfg; tests/set особо) ---------------

DEFAULTS = {
    "name": None,
    "host": "0.0.0.0",          # bind (docker: все интерфейсы)
    "publish_host": "127.0.0.1",  # адрес, публикуемый в dir-entry (внутри jpnet — имя сервиса)
    "port": 9100,
    "http_port": 9200,          # 0 = HTTP off
    "http_host": "0.0.0.0",     # bind HTTP (совпадает с hostname по умолчанию)
    "data_dir": None,           # каталог снимка BS
    "peers": [],                # [(host, port), ...] bootstrap-контакты

    "round_len": 10.0,          # s; протокол = 10
    "commit_frac": 0.3,         # доля раунда на окно commit
    "reveal_frac": 0.6,         # t0+6s при 10s
    "hour_blocks": 360,         # раундов в часе (10 s → 360)
    "pow_seed_hour": None,      # bytes|None → DEV_SEED_HOUR

    "mix_delay": (1.0, 3.0),    # s, случайная задержка перед форвард (protocol.md §5)
    "gossip_interval": 60.0,    # s
    "gossip_bucket": 64,        # записей в PUSH / DATA за раз

    "transport_bits": 6,        # PoW профилей (protocol.md §12)
    "node_bits": 4,
    "read_bits": 2,
    "pow_budget_ms": 150,       # PoW_node бюджет, ×2³ ретрая (~150→400 ms)
    "skip_pow": False,          # dev-knob: не просить PoW вовсе

    "rate_limit": 5.0,          # msg/s/IP (протокол: 5)
    "max_local_cells": 256,
    "max_global_cells": 1024,
    "cell_size": 50,
    "bs_save_s": 60.0,
}

# Тарифицируемые типы кадров (rate limit applies; beacon/gossip/ping свободны).
RT_LIMITED = {W.F_MIX_ONION, W.F_BS_STORE, W.F_BS_READ, W.F_SEED_REQ, W.F_DIR_REQ}
MAX_FRAME_TOTAL = 60000    # guard: varint(total) больше — соединение рвём


def log_json(node_name: str, lvl: str, ev: str, **kw) -> None:
    """JSON-lines в stderr (все события ноды/клиента)."""
    rec = {"ts": round(time.time(), 6), "lvl": lvl, "node": node_name, "ev": ev}
    rec.update({k: (v.hex() if isinstance(v, (bytes, bytearray)) and len(v) > 20
                    else v) for k, v in kw.items()})
    print(json.dumps(rec, ensure_ascii=False, default=str), file=sys.stderr, flush=True)


# --- session ------------------------------------------------------------------

class Sess:
    __slots__ = ["reader", "writer", "ip", "port", "kind", "addr", "closed", "id"]

    def __init__(self, reader, writer, ip: str, port: int, kind: str = "?"):
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.port = port
        self.kind = kind          # 'client' | 'node' | 'http' | '?'
        self.addr: bytes | None = None
        self.closed = False
        self.id = id(self)

    async def send(self, frame: bytes) -> None:
        if self.closed:
            return
        self.writer.write(frame)
        try:
            await self.writer.drain()
        except (ConnectionError, RuntimeError):
            self.closed = True

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.writer.close()
            except Exception:
                pass


async def read_frame(reader) -> W.Frame | None:
    """Читает varint(total) + payload; None — EOF; ValueError — мусор."""
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


def frame_bytes(payload: bytes) -> bytes:
    return W.encode_varint(len(payload)) + payload


def reply(ftype: int, flags: int = 0, tvs=()) -> bytes:
    return frame_bytes(W.frame_payload(ftype, flags, tvs))


# --- round state ----------------------------------------------------------------

class RoundState:
    __slots__ = ["n", "v", "r", "commit", "commit_sent", "reveal_sent", "finalized",
                 "commits", "reveals", "excluded"]

    def __init__(self, n: int, prev_seed: bytes, pk: bytes):
        self.n = n
        self.v = secrets.token_bytes(32)
        self.r = secrets.token_bytes(16)
        # C_i = SHAKE256(beacon.1, seed(N−1) ‖ N ‖ pk_i ‖ v_i ‖ r_i)
        self.commit = C.h_beacon(prev_seed + W.u64(n) + pk + self.v + self.r)
        self.commit_sent = False
        self.reveal_sent = False
        self.finalized = False
        self.commits: dict[bytes, tuple[bytes, bytes]] = {}     # pk → (C, sig)
        self.reveals: dict[bytes, tuple[bytes, bytes, bytes]] = {}  # pk → (v, r, sig)
        self.excluded: set[bytes] = set()


# --- Node ------------------------------------------------------------------------

class Node:
    def __init__(self, cfg: dict | None = None, **over):
        self.cfg = dict(DEFAULTS)
        self.cfg.update(over)
        if cfg:
            self.cfg.update(cfg)
        self.name = self.cfg["name"] or f"jp-node:{self.cfg['port']}"

        self.pk_kem, self.sk_kem = C.kem_generate()
        self.pk_dsa, self.sk_dsa = C.dsa_generate()
        self.addr = C.h_dir(self.pk_kem)

        self.dir_own = self._self_entry()
        self.dir: dict[bytes, dict] = {self.addr: self.dir_own}

        self.pow_hour_seed = bytes(self.cfg["pow_seed_hour"]) if self.cfg["pow_seed_hour"] else C.DEV_SEED_HOUR
        self._pow_ctxs: dict[bytes, JP.Pow] = {}

        self.sessions: dict[int, Sess] = {}
        self.online: dict[bytes, list[Sess]] = {}
        self.peer_conns: dict[tuple[str, int], Sess] = {}

        self.seeds: dict[int, bytes] = {}
        self.round_states: dict[int, RoundState] = {}

        self.local_bs: dict[bytes, list[dict]] = {}
        self.global_bs: dict[bytes, list[dict]] = {}

        self.counters = {"mix_in": 0, "mix_fwd": 0, "mix_online": 0,
                         "mix_store_local": 0, "mix_store_global": 0,
                         "pow_fail": 0, "rate_drop": 0, "bs_store": 0,
                         "bs_read": 0, "beacon_seed_pub": 0, "gossip_push": 0}
        self._buckets: dict[str, dict] = {}      # ip → {tokens, last}
        self._bucket_lock = threading.Lock()

        self.ex = ThreadPoolExecutor(max_workers=2, thread_name_prefix=f"{self.name}-pow")
        self.loop: asyncio.AbstractEventLoop | None = None
        self._stop_evt: asyncio.Event | None = None
        self._tasks: list[asyncio.Task] = []
        self._server: asyncio.Server | None = None
        self._http = None
        self._ready = asyncio.Event()
        self.started_at = time.time()

    # --- boot / run -------------------------------------------------------------

    def _self_entry(self) -> dict:
        """Собственная запись директории: T_NODE_ENTRY-значение (+сиг, чтобы нода
        могла распространять dir другим узлам/клиентам)."""
        host = self.cfg["publish_host"] or self.cfg["host"]
        tr = W.enc_transport(host, self.cfg["port"], False)
        val = b"".join([W.build_tlv_bytes(W.T_PK_KEM, self.pk_kem),
                        W.build_tlv_bytes(W.T_PK_DSA, self.pk_dsa),
                        W.build_tlv_bytes(W.T_TRANSPORT, tr)])
        return {"pk_kem": self.pk_kem, "pk_dsa": self.pk_dsa,
                "host": host, "port": self.cfg["port"], "tls": False,
                "entry_val": val, "sig": C.dsa_sign(self.sk_dsa, C.h_dirlist(val)),
                "addr": self.addr}

    async def wait_ready(self, timeout: float = 10.0) -> None:
        await asyncio.wait_for(self._ready.wait(), timeout)

    async def run(self) -> None:
        self.loop = asyncio.get_running_loop()
        self._stop_evt = asyncio.Event()
        await self._load_bs_snapshot()
        self._server = await asyncio.start_server(self._on_conn, self.cfg["host"], self.cfg["port"])
        log_json(self.name, "info", "listen", host=self.cfg["host"], port=self.cfg["port"],
                 addr=self.addr, http_port=self.cfg["http_port"])
        self._tasks = [
            asyncio.create_task(self._beacon_loop(), name="beacon"),
            asyncio.create_task(self._gossip_loop(), name="gossip"),
            asyncio.create_task(self._dialer_loop(), name="peers"),
            asyncio.create_task(self._bs_save_loop(), name="bs-save"),
        ]
        if self.cfg["http_port"]:
            self._start_http()
        self._ready.set()
        await self._stop_evt.wait()
        await self._shutdown()

    async def stop(self) -> None:
        if self._stop_evt is not None:
            self._stop_evt.set()

    async def _shutdown(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for t in self._tasks:
            t.cancel()
        for sc in list(self.sessions.values()):
            sc.close()
        self.peer_conns.clear()
        self._stop_http()
        await self._save_bs_snapshot()
        for pw in self._pow_ctxs.values():
            try:
                pw.close()
            except Exception:
                pass
        self._pow_ctxs.clear()
        self.ex.shutdown(wait=False)
        log_json(self.name, "info", "stopped")

    # --- connections ------------------------------------------------------------

    async def _on_conn(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        ip, port = ("?", 0) if not peer else (str(peer[0]), peer[1])
        sess = Sess(reader, writer, ip, port)
        self.sessions[sess.id] = sess
        try:
            await self._conn_reader(sess)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        except Exception as e:  # мусор в потоке — не роняем сервер
            log_json(self.name, "warn", "conn_error", err=repr(e), ip=ip)
        finally:
            self._unregister(sess)

    async def _conn_reader(self, sess: Sess) -> None:
        while not sess.closed:
            try:
                fr = await read_frame(sess.reader)
            except (asyncio.IncompleteReadError, ConnectionError):
                break
            await self._dispatch(sess, fr)

    def _unregister(self, sess: Sess) -> None:
        sess.close()
        self.sessions.pop(sess.id, None)
        if sess.addr:
            lst = self.online.get(sess.addr)
            if lst and sess in lst:
                lst.remove(sess)
                if not lst:
                    self.online.pop(sess.addr, None)

    async def _dispatch(self, sess: Sess, fr: W.Frame) -> None:
        h = _HANDLERS.get(fr.type)
        if h is None:
            return  # неизвестные типы (forward compat) — ignore
        if fr.type in RT_LIMITED and not self._rate_ok(sess):
            self.counters["rate_drop"] += 1
            log_json(self.name, "warn", "rate_drop", ip=sess.ip, ftype=hex(fr.type))
            if fr.type == W.F_MIX_ONION:
                await sess.send(reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(429, "rate"))]))
            return
        ret = await h(self, sess, fr)   # исключения глотать ненужно — пусть роняет
        if ret:
            if isinstance(ret, (bytes, bytearray)):
                await sess.send(bytes(ret))
            else:
                for rb in ret:
                    await sess.send(rb)

    # --- rate limit ---------------------------------------------------------------

    def _rate_ok(self, sess: Sess) -> bool:
        rate = float(self.cfg["rate_limit"])
        now = time.time()
        with self._bucket_lock:
            b = self._buckets.setdefault(sess.ip, {"t": rate, "at": now})
            b["t"] = min(rate, b["t"] + (now - b["at"]) * rate)
            b["at"] = now
            if b["t"] < 1.0:
                return False
            b["t"] -= 1.0
            return True

    # --- PoW ----------------------------------------------------------------------

    def _pow_ctx_for(self, round_num: int) -> JP.Pow:
        if self.pow_hour_seed not in self._pow_ctxs:
            if len(self._pow_ctxs) >= 3:
                old = next(iter(self._pow_ctxs))
                self._pow_ctxs.pop(old).close()
            self._pow_ctxs[self.pow_hour_seed] = JP.Pow(self.pow_hour_seed)
        return self._pow_ctxs[self.pow_hour_seed]

    def _verify_pow(self, round_num: int, payload_digest: bytes, cert: bytes,
                    profile: int, required_bits: int) -> bool:
        """verify по candidates seed(round−1..round+1); ключ RandomX — cfg (конст.)."""
        try:
            nonce, bits, cert_profile = W.dec_pow_cert(cert)
        except ValueError:
            return False
        if cert_profile != profile or bits < required_bits:
            return False
        if self.cfg["skip_pow"]:
            return True
        ctx = None
        try:
            ctx = self._pow_ctx_for(round_num)
        except JP.PowUnavailable as e:
            log_json(self.name, "warn", "pow_unavailable", err=str(e))
            return False
        for c in (round_num - 1, round_num, round_num + 1):
            seed = self.seeds.get(c)
            if seed is None:
                continue
            if JP.verify(ctx, seed, payload_digest, nonce, bits, required_bits):
                return True
        return False

    async def _mine(self, round_num: int, payload_digest: bytes, min_bits: int,
                    profile: int, budget_hint: int) -> tuple[int, int] | None:
        """PoW_node добыча: r=2³ политики бюджета; миграция в executor."""
        if self.cfg["skip_pow"]:
            return (0, min_bits + 1)
        seed = self.seeds.get(round_num)
        if seed is None:
            seed = self.seeds.get(round_num - 1) or self.seeds.get(round_num + 1)
        if seed is None:
            log_json(self.name, "warn", "mine_no_seed", rnd=round_num)
            return None
        try:
            ctx = self._pow_ctx_for(round_num)
        except JP.PowUnavailable as e:
            log_json(self.name, "warn", "pow_unavailable", err=str(e))
            return None
        loop = asyncio.get_running_loop()
        for attempt in range(3):
            budget = int(budget_hint * (2 ** attempt))
            res = await loop.run_in_executor(
                self.ex, lambda: JP.mine(seed, payload_digest, min_bits, budget, ctx=ctx))
            if res:
                return res[0], res[1]
        return None

    # --- handlers -----------------------------------------------------------------

    async def _h_ping(self, sess: Sess, fr: W.Frame) -> bytes | None:
        nonce = W.get(fr.tvs, W.T_NONCE) or b"jproto"
        return reply(W.F_PONG, tvs=[(W.T_NONCE, nonce)])

    async def _h_hello(self, sess: Sess, fr: W.Frame) -> bytes | None:
        addr = W.get(fr.tvs, W.T_ADDR)
        if addr and len(addr) == 32:
            sess.kind = "client"
            sess.addr = addr
            self.online.setdefault(addr, []).append(sess)
            log_json(self.name, "info", "client_hello", dest=addr.hex()[:16], ip=sess.ip)
        else:
            sess.kind = "node"
        caps = W.get(fr.tvs, W.T_CAPS) or W.u32(0)
        switch = [(W.T_POW_PAR, W.enc_pow_par(W.POW_TRANSPORT, self.cfg["transport_bits"], 2000)),
                  (W.T_POW_PAR, W.enc_pow_par(W.POW_NODE, self.cfg["node_bits"], int(self.cfg["pow_budget_ms"]))),
                  (W.T_POW_PAR, W.enc_pow_par(W.POW_READ, self.cfg["read_bits"], 200))]
        return reply(W.F_HELLO_OK, tvs=[(W.T_VER, W.u16(W.VERSION)),
                                        (W.T_CAPS, caps),
                                        (W.T_ADDR, self.addr),
                                        *switch])

    async def _h_seed_req(self, sess: Sess, fr: W.Frame) -> bytes | None:
        best = max(self.seeds) if self.seeds else None
        if best is None:
            return reply(W.F_SEED, tvs=[(W.T_ERR, W.enc_err(503, "no seed yet"))])
        prev_seed = self.seeds.get(best - 1)
        tvs = [(W.T_ROUND, W.u64(best)), (W.T_SEED, self.seeds[best])]
        if prev_seed:
            tvs += [(W.T_ROUND, W.u64(best - 1)), (W.T_SEED, prev_seed)]
        return reply(W.F_SEED, tvs=tvs)

    async def _h_dir_req(self, sess: Sess, fr: W.Frame) -> bytes | None:
        return self._dir_frame()

    def _dir_frame(self) -> bytes | None:
        vals = [e["entry_val"] for e in self.dir.values() if e.get("sig")]
        if not vals:
            return None
        digest = C.h_dirlist(b"".join(sorted(vals)))
        body = b""
        for v in vals:
            ent = self.dir[[a for a, e in self.dir.items() if e["entry_val"] == v][0]]
            body += W.build_tlv_bytes(W.T_NODE_ENTRY, v) + W.build_tlv_bytes(W.T_SIG, ent["sig"])
        return reply(W.F_DIR, tvs=[(W.T_DIR_DIGEST, digest), (W.T_NODE_LIST, body)])

    async def _h_dir(self, sess: Sess, fr: W.Frame) -> None:
        self._absorb_dir(W.get(fr.tvs, W.T_NODE_LIST) or b"")

    def _absorb_dir(self, body: bytes) -> int:
        """парсится список entry+sig-пар; возвращает число ВАЛИДНЫХ новых записей."""
        got = 0
        tvs = W.parse_tvs(body)
        for i in range(0, len(tvs) - 1, 2):
            tt, val = tvs[i]
            st, sig = tvs[i + 1]
            if tt != W.T_NODE_ENTRY or st != W.T_SIG:
                continue
            parsed = _parse_entry(val)
            if parsed is None:
                continue
            addr = C.h_dir(parsed["pk_kem"])
            if not C.dsa_verify(parsed["pk_dsa"], sig, C.h_dirlist(val)):
                log_json(self.name, "warn", "dir_bad_sig", addr=addr.hex()[:16])
                continue
            if addr not in self.dir:
                parsed["sig"] = sig
                parsed["entry_val"] = val
                parsed["addr"] = addr
                self.dir[addr] = parsed
                got += 1
                log_json(self.name, "info", "dir_add", addr=addr.hex()[:16],
                         peer=f"{parsed['host']}:{parsed['port']}")
        return got

    # --- mix (onion v2, wire.md §5) ---------------------------------------------------

    def _pow_common(self, pd: bytes, nonce: int, bits: int, profile: int,
                    required: int) -> bool:
        """verify по seeds раундов (n−1, n, n+1); ключ RandomX — статичный cfg."""
        if bits < required:
            return False
        if self.cfg["skip_pow"]:
            return True
        try:
            ctx = self._pow_ctx_for(0)
        except JP.PowUnavailable as e:
            log_json(self.name, "warn", "pow_unavailable", err=str(e))
            return False
        n = self.round_of_ts(time.time())
        for c in (n - 1, n, n + 1):
            seed = self.seeds.get(c)
            if seed is not None and JP.verify(ctx, seed, pd, nonce, bits, required):
                return True
        return False

    async def _h_mix(self, sess: Sess, fr: W.Frame) -> bytes | None:
        """Onion v2: pay = packet = kem_ct(1088) ‖ blob. TRANSPORT-PoW (T_POW,
        digest = h_pow(packet)) верифицирует entry-нода; промежуточные хопы
        просто форвардят после peel (NODE-PoW живёт в R, проверяет BS-нода)."""
        pay = W.get(fr.tvs, W.T_PAYLOAD)
        cert = W.get(fr.tvs, W.T_POW)
        if (not pay or not cert or len(cert) != 16
                or len(pay) < C.KEM_CT_LEN + R.BLOB_BASE):
            return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(400, "bad mix"))])
        try:
            nonce, bits, prof = W.dec_pow_cert(cert)
        except ValueError:
            return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(400, "cert"))])
        if not self._pow_common(JP.pow_digest(pay), nonce, bits,
                                W.POW_TRANSPORT, self.cfg["transport_bits"]):
            self.counters["pow_fail"] += 1
            log_json(self.name, "warn", "mix_drop_pow", ip=sess.ip, bits=bits)
            return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(401, "pow"))])
        self.counters["mix_in"] += 1

        try:
            ss = C.kem_decaps(self.sk_kem, pay[:C.KEM_CT_LEN])
            blob = pay[C.KEM_CT_LEN:]
            pt = C.aead_decrypt(ss, blob[:C.AEAD_NONCE_LEN], R.ONION_AD, blob[C.AEAD_NONCE_LEN:])
        except Exception as e:
            log_json(self.name, "warn", "mix_drop_layer", err=repr(e))
            return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(400, "layer"))])

        addr = pt[:W.ADDR_LEN]
        ctl = pt[W.ADDR_LEN] | (pt[W.ADDR_LEN + 1] << 8)
        if ctl == 0:
            rpl = pt[W.ADDR_LEN + 2:]
            if len(rpl) != R.RPL_LEN_FIXED:
                log_json(self.name, "warn", "final_bad_len", got=len(rpl))
                return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(400, "rlen"))])
            await self._on_final(rpl)
            return None
        if ctl != C.KEM_CT_LEN:
            log_json(self.name, "warn", "mix_bad_ctl", ctl=ctl)
            return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(400, "ctl"))])
        entry = self.dir.get(addr)
        if entry is None:
            log_json(self.name, "warn", "mix_unknown_next", nxt=addr.hex()[:16])
            return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(404, "next"))])
        next_pay = pt[W.ADDR_LEN + 2: W.ADDR_LEN + 2 + C.KEM_CT_LEN] + pt[W.ADDR_LEN + 2 + C.KEM_CT_LEN:]
        delay = random.uniform(*self.cfg["mix_delay"])
        await asyncio.sleep(delay)
        frame = W.build_frame(W.F_MIX_ONION, 0, [(W.T_PAYLOAD, next_pay)])
        self.counters["mix_fwd"] += 1
        log_json(self.name, "info", "mix_fwd", to=entry["addr"].hex()[:16],
                 delay_ms=int(delay * 1000))
        await self._forward_mix(entry, frame)
        return None

    async def _forward_mix(self, entry: dict, frame: bytes) -> None:
        """Либо переиспользуем persistent peer conn, либо fresh dial."""
        key = (entry["host"], entry["port"])
        sess = self.peer_conns.get(key)
        if sess and not sess.closed:
            await sess.send(frame)
            return
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(entry["host"], entry["port"]), 5.0)
        except Exception as e:
            log_json(self.name, "warn", "mix_dial_fail", to=key, err=repr(e))
            return
        fs = Sess(reader, writer, entry["host"], entry["port"], kind="node")
        self.sessions[fs.id] = fs
        await fs.send(frame)
        asyncio.create_task(self._conn_reader(fs))

    async def _on_final(self, rpl: bytes) -> None:
        """Финальный слой: R целиком. ONLINE — доставка клиенту (dev: всем
        HELLO-registered, вскрывает владелец sk); store-типы — NODE-PoW
        (nonce/bits/prof из заголовка R, digest = h_pow(R)) и вставка в BS
        по cell = h_cell(value)."""
        try:
            meta = W.recipient_header(rpl)
            parsed = R.parse(rpl)
        except ValueError as e:
            log_json(self.name, "warn", "final_bad_rec", err=str(e))
            return
        itype = meta["itype"]
        if itype == W.I_ONLINE:
            self.counters["mix_online"] += 1
            waiting = [sc for lst in self.online.values() for sc in lst if not sc.closed]
            if not waiting:
                log_json(self.name, "warn", "online_no_client")
                return
            log_json(self.name, "info", "online_deliver",
                     sessn=meta["session"], seq=meta["seq"])
            await waiting[0].send(reply(W.F_ONLINE_DELIVER,
                                        tvs=[(W.T_PAYLOAD, rpl)]))
            return
        if meta["pow_prof"] != W.POW_NODE or meta["pow_bits"] < self.cfg["node_bits"]:
            self.counters["pow_fail"] += 1
            log_json(self.name, "warn", "final_pow_weak", prof=meta["pow_prof"],
                     bits=meta["pow_bits"])
            return
        if not self.cfg["skip_pow"]:
            ok = self._pow_common(JP.pow_digest(rpl), meta["pow_nonce"],
                                  meta["pow_bits"], W.POW_NODE, self.cfg["node_bits"])
            if not ok:
                self.counters["pow_fail"] += 1
                log_json(self.name, "warn", "final_pow_fail")
                return
        value = parsed["ky_ct"] + parsed["aead_nonce"] + parsed["msg_ct"]
        cell = C.h_cell(value)
        ts = time.time()
        if itype == W.I_STORE_GLOBAL:
            ok = self._bs_insert(self.global_bs, cell, value, int(meta["pow_bits"]), ts,
                                 self.cfg["max_global_cells"], self.cfg["cell_size"])
            self.counters["mix_store_global"] += 1
        else:
            ok = self._bs_insert(self.local_bs, cell, value, int(meta["pow_bits"]), ts,
                                 self.cfg["max_local_cells"], self.cfg["cell_size"])
            self.counters["mix_store_local"] += 1
        self.counters["bs_store"] += 1
        log_json(self.name, "info", "bs_store", itype=itype, cell=cell.hex()[:16],
                 bits=int(meta["pow_bits"]), ok=ok)

    def _bs_insert(self, bs: dict, cell: bytes, value: bytes, bits: int, ts: float,
                   max_cells: int, cell_size: int) -> bool:
        lst = bs.get(cell)
        if lst is None:
            if len(bs) >= max_cells:
                log_json(self.name, "warn", "bs_cells_full", kind="local" if bs is self.local_bs else "global")
                return False
            bs[cell] = [{"v": value, "bits": bits, "ts": ts}]
            return True
        if len(lst) >= cell_size:
            now = time.time()
            worst_i, worst_s = None, None
            for i, r in enumerate(lst):
                sc = r["bits"] - (now - r["ts"]) // 3600
                if worst_s is None or sc < worst_s:
                    worst_i, worst_s = i, sc
            new_bits = bits - (now - ts) // 3600
            if new_bits <= (worst_s or 0):
                return False
            lst[worst_i] = {"v": value, "bits": bits, "ts": ts}
            return True
        lst.append({"v": value, "bits": bits, "ts": ts})
        return True

    async def _h_bs_store(self, sess: Sess, fr: W.Frame) -> bytes | None:
        idx = W.get(fr.tvs, W.T_CELL_IDX)
        rec = W.get(fr.tvs, W.T_CELL_REC)
        cert = W.get(fr.tvs, W.T_POW)
        if not idx or len(idx) != 32 or not rec or not cert or len(rec) < 1136:
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(400, "bad store"))])
        my_pd = JP.pow_digest(idx + rec)
        if not self._verify_pow(0, my_pd, cert, W.POW_TRANSPORT, self.cfg["transport_bits"]):
            # 0-раунд: для direct-store привязка к раунду опциональна (cert сам
            # привязан к cell+rec); если seedов нет — верить НЕЛЬЗЯ, drop.
            if not self.cfg["skip_pow"] and self.seeds:
                self.counters["pow_fail"] += 1
                log_json(self.name, "warn", "bs_store_pow", cell=idx.hex()[:16])
                return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(401, "pow"))])
        try:
            nonce, bits, profile = W.dec_pow_cert(cert)
        except ValueError:
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(400, "cert"))])
        ts = time.time()
        ok = self._bs_insert(self.local_bs, idx, rec[:len(rec) - 12], int(bits), ts,
                             self.cfg["max_local_cells"], self.cfg["cell_size"])
        self.counters["bs_store"] += 1
        log_json(self.name, "info", "bs_store_direct", cell=idx.hex()[:16],
                 bits=int(bits), ok=ok)
        return None

    async def _h_bs_read(self, sess: Sess, fr: W.Frame) -> bytes | None:
        idx = W.get(fr.tvs, W.T_CELL_IDX)
        cert = W.get(fr.tvs, W.T_POW)
        if not idx or len(idx) != 32 or not cert:
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(400, "bad read"))])
        pd = JP.pow_digest(idx)
        if not self._verify_pow(0, pd, cert, W.POW_READ, self.cfg["read_bits"]):
            if not self.cfg["skip_pow"] and self.seeds:
                self.counters["pow_fail"] += 1
                log_json(self.name, "warn", "bs_read_pow", cell=idx.hex()[:16])
                return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(401, "pow"))])
        self.counters["bs_read"] += 1
        now = time.time()
        recs = []
        for bs in (self.local_bs, self.global_bs):
            recs.extend(bs.get(idx) or [])
        recs.sort(key=lambda r: (-(r["bits"] - (now - r["ts"]) // 3600), r["ts"]))
        tvs = [(W.T_CELL_IDX, idx)]
        for r in recs[: self.cfg["cell_size"]]:
            tvs.append((W.T_CELL_REC, r["v"] + W.u32(int(r["bits"])) + W.u64(int(r["ts"]))))
        log_json(self.name, "info", "bs_read", cell=idx.hex()[:16], n=len(recs))
        return reply(W.F_BS_READ_RESP, tvs=tvs)

    async def _h_online_ack(self, sess: Sess, fr: W.Frame) -> None:
        log_json(self.name, "info", "online_ack", ip=sess.ip, dest=(sess.addr and sess.addr.hex()[:16]))

    # --- beacon v2 ------------------------------------------------------------------

    def round_of_ts(self, ts: float) -> int:
        return int(ts // self.cfg["round_len"])

    def _round_frac(self, n: int) -> float:
        rl = float(self.cfg["round_len"])
        return (time.time() - n * rl) / rl

    def _prev_seed(self, n: int) -> bytes:
        """seed(N−1): из цепочки либо genesis-константа (boot-раунд, согласованная
        у всех boot-кандидатов — DESIGN_NOTES §beacon)."""
        for c in (n - 1, n - 2):
            s = self.seeds.get(c)
            if s is not None:
                return s
        return C.GENESIS_SEED

    def _round_state(self, n: int) -> RoundState:
        st = self.round_states.get(n)
        if st is None:
            st = RoundState(n, self._prev_seed(n), self.pk_dsa)
            self.round_states[n] = st
            self._gc_rounds(n)
        return st

    def _gc_rounds(self, cur: int) -> None:
        for k in [k for k in self.round_states if k < cur - 3]:
            self.round_states.pop(k, None)
        for k in [k for k in self.seeds if k < cur - 8]:
            self.seeds.pop(k, None)

    def _valid_commits(self, st: RoundState) -> dict[bytes, bytes]:
        """коммиты с валидной ML-DSA sig («JPCOMMIT»‖N‖C), исключенные убраны."""
        out = {}
        for pk, (cval, sig) in st.commits.items():
            if pk in st.excluded:
                continue
            if not C.dsa_verify(pk, sig, b"JPCOMMIT" + W.u64(st.n) + cval):
                continue
            out[pk] = cval
        return out

    async def _beacon_loop(self) -> None:
        """hbdrand v2 (protocol.md §2): A commit [0,0.3R) → B reveal [0.3,0.6) →
        C finalize t0+0.6R; окна — LOCAL wall-clock."""
        tick = max(0.01, min(0.05, self.cfg["round_len"] / 20.0))
        while not self._stop_evt.is_set():
            await asyncio.sleep(tick)
            try:
                now = time.time()
                n = self.round_of_ts(now)
                frac = self._round_frac(n)
                st = self._round_state(n)
                if frac < self.cfg["commit_frac"]:
                    if not st.commit_sent:
                        st.commit_sent = True
                        self._bcast_commit(st)
                elif frac < self.cfg["reveal_frac"]:
                    if st.commit_sent and not st.reveal_sent:
                        st.reveal_sent = True
                        self._bcast_reveal(st)
                elif not st.finalized:
                    st.finalized = True
                    await self._finalize(n)
            except Exception as e:
                log_json(self.name, "error", "beacon_loop", err=repr(e))

    def _bcast_commit(self, st: RoundState) -> None:
        sig = C.dsa_sign(self.sk_dsa, b"JPCOMMIT" + W.u64(st.n) + st.commit)
        frame = W.build_frame(W.F_BEACON_COMMIT, 0, [
            (W.T_ROUND, W.u64(st.n)), (W.T_COMMIT, st.commit),
            (W.T_SIG, sig), (W.T_PK_DSA, self.pk_dsa)])
        self._bcast_nodes(frame)
        self.on_commit_frame(st.n, st.commit, sig, self.pk_dsa)  # своё ядёро
        log_json(self.name, "info", "beacon_commit", rnd=st.n)

    def _bcast_reveal(self, st: RoundState) -> None:
        sig = C.dsa_sign(self.sk_dsa, b"JPREVEAL" + W.u64(st.n) + st.v + st.r)
        frame = W.build_frame(W.F_BEACON_REVEAL, 0, [
            (W.T_ROUND, W.u64(st.n)), (W.T_SEED, st.v), (W.T_NONCE, st.r),
            (W.T_SIG, sig), (W.T_PK_DSA, self.pk_dsa)])
        self._bcast_nodes(frame)
        self.on_reveal_frame(st.n, st.v, st.r, sig, self.pk_dsa)  # своё вовнутрь
        log_json(self.name, "info", "beacon_reveal", rnd=st.n)

    def _bcast_nodes(self, frame: bytes) -> None:
        for sc in list(self.peer_conns.values()):
            if not sc.closed:
                asyncio.ensure_future(sc.send(frame))
        for sc in list(self.sessions.values()):
            if sc.kind == "node" and not sc.closed:
                asyncio.ensure_future(sc.send(frame))

    async def _finalize(self, n: int) -> None:
        st = self.round_states.get(n)
        prev = self._prev_seed(n)
        commits = self._valid_commits(st) if st else {}
        if len(commits) < 2:
            # Emergency (protocol.md §2.2.4): <2 коммитов — seed не двигается
            self.seeds[n] = prev
            log_json(self.name, "warn", "beacon_emergency", rnd=n, commits=len(commits))
            self._publish_seed(n, prev, [])
            return
        contrib = []
        for pk, (v, r, _sig) in (st and st.reveals.items() or []):
            cv = st.commit if pk == self.pk_dsa else commits.get(pk)
            if cv is None:
                continue
            if C.h_beacon(prev + W.u64(n) + pk + v + r) != cv:
                continue  # не биндинг — уже отфильтровано in on_reveal_frame
            contrib.append((pk, v))
        if not contrib:
            self.seeds[n] = prev
            log_json(self.name, "warn", "beacon_emergency_noreveal", rnd=n)
            self._publish_seed(n, prev, [])
            return
        contrib.sort(key=lambda t: t[0])            # по pk ЛЕКСИКОГРАФИЧЕСКИ
        seed = C.h_beacon(prev + W.u64(n) + b"".join(v for _, v in contrib))
        self.seeds[n] = seed
        self.counters["beacon_seed_pub"] += 1
        log_json(self.name, "info", "beacon_seed", rnd=n, k=len(contrib))
        self._publish_seed(n, seed, [pk for pk, _ in contrib])

    def _publish_seed(self, n: int, seed: bytes, pks: list[bytes]) -> None:
        tvs = [(W.T_ROUND, W.u64(n)), (W.T_SEED, seed)]
        tvs += [(W.T_PK_DSA, pk) for pk in pks]
        self._bcast_nodes(W.build_frame(W.F_BEACON_SEED, 0, tvs))

    def on_commit_frame(self, n: int, cval: bytes, sig: bytes, pk: bytes) -> None:
        st = self.round_states.get(n)
        if st is None:
            st = RoundState(n, self._prev_seed(n), self.pk_dsa)
            st.commit_sent = False   # баг-нотация: чужой раунд не наш — нота DESIGN
            self.round_states[n] = st
            self._gc_rounds(n)
        if pk in st.commits and st.commits[pk][0] != cval:
            st.excluded.add(pk)       # double-commit (§2.2.1) — изгой до рестарта
            log_json(self.name, "error", "double_commit", rnd=n, pk=pk.hex()[:16])
            return
        st.commits[pk] = (cval, sig)

    def on_reveal_frame(self, n: int, v: bytes, r: bytes, sig: bytes, pk: bytes) -> None:
        st = self.round_states.get(n)
        if st is None:
            self._round_state(n)
            st = self.round_states[n]
        if not C.dsa_verify(pk, sig, b"JPREVEAL" + W.u64(n) + v + r):
            log_json(self.name, "warn", "reveal_bad_sig", rnd=n)
            return
        cval = st.commit if pk == self.pk_dsa else (st.commits.get(pk, (None, None))[0])
        if cval is None:
            log_json(self.name, "info", "reveal_no_commit", rnd=n, pk=pk.hex()[:16])
            return
        prev = self._prev_seed(n)
        if C.h_beacon(prev + W.u64(n) + pk + v + r) != cval:
            log_json(self.name, "warn", "reveal_not_binding", rnd=n, pk=pk.hex()[:16])
            return
        st.reveals[pk] = (v, r, sig)

    async def _h_commit(self, sess: Sess, fr: W.Frame) -> None:
        n = W.as_u64(W.get(fr.tvs, W.T_ROUND))
        cval = W.get(fr.tvs, W.T_COMMIT)
        sig = W.get(fr.tvs, W.T_SIG)
        pk = W.get(fr.tvs, W.T_PK_DSA)
        if n is None or not cval or not sig or not pk or len(pk) != C.DSA_PK_LEN:
            return
        self.on_commit_frame(n, cval, sig, pk)

    async def _h_reveal(self, sess: Sess, fr: W.Frame) -> None:
        n = W.as_u64(W.get(fr.tvs, W.T_ROUND))
        v = W.get(fr.tvs, W.T_SEED)
        r = W.get(fr.tvs, W.T_NONCE)
        sig = W.get(fr.tvs, W.T_SIG)
        pk = W.get(fr.tvs, W.T_PK_DSA)
        if n is None or not v or not r or not sig or not pk or len(pk) != C.DSA_PK_LEN:
            return
        self.on_reveal_frame(n, v, r, sig, pk)

    async def _h_seed_publ(self, sess: Sess, fr: W.Frame) -> None:
        n = W.as_u64(W.get(fr.tvs, W.T_ROUND))
        seed = W.get(fr.tvs, W.T_SEED)
        if n is None or not seed or len(seed) != 32:
            return
        old = self.seeds.get(n)
        if old is not None and old != seed:
            log_json(self.name, "error", "seed_mismatch", rnd=n,
                     have=old.hex()[:16], got=seed.hex()[:16])
            return
        if old is None:
            self.seeds[n] = seed
            log_json(self.name, "info", "seed_update", rnd=n, src="net")

    # --- gossip (Global BS) ------------------------------------------------------------

    async def _gossip_loop(self) -> None:
        while not self._stop_evt.is_set():
            await asyncio.sleep(float(self.cfg["gossip_interval"]))
            try:
                await self._gossip_tick()
            except Exception as e:
                log_json(self.name, "error", "gossip_loop", err=repr(e))

    async def _gossip_tick(self) -> None:
        entries = [e for a, e in self.dir.items() if e["addr"] != self.addr]
        if not entries:
            return
        entry = random.choice(entries)
        newest: list[tuple] = []
        for cell, recs in list(self.global_bs.items()):
            for rec in recs:
                newest.append((cell, rec["v"], rec["bits"], rec["ts"]))
        newest.sort(key=lambda t: -t[3])
        bucket = newest[: int(self.cfg["gossip_bucket"])]
        if not bucket:
            return
        payload = b"".join(cell + C.h_rec(v) + W.u32(int(bits)) + W.u64(int(ts))
                           for cell, v, bits, ts in bucket)
        frame = W.build_frame(W.F_GOSSIP_PUSH, 0, [(W.T_ROUND, W.u64(self.round_of_ts(time.time()))),
                                                   (W.T_PAYLOAD, payload)])
        sess = self.peer_conns.get((entry["host"], entry["port"]))
        if sess and not sess.closed:
            await sess.send(frame)
            self.counters["gossip_push"] += 1

    async def _h_gossip_push(self, sess: Sess, fr: W.Frame) -> None:
        data = W.get(fr.tvs, W.T_PAYLOAD) or b""
        want: list[bytes] = []
        step = 32 + 32 + 4 + 8
        if self._stop_evt is None:
            return
        for i in range(0, len(data) - step + 1, step):
            cell, dig = data[i:i + 32], data[i + 32:i + 64]
            if not self._have_rec(cell, dig):
                want.append(dig)
        if want:
            fetch = W.build_frame(W.F_GOSSIP_FETCH, 0, [
                (W.T_ROUND, W.u64(self.round_of_ts(time.time()))),
                (W.T_PAYLOAD, b"".join(want))])
            await sess.send(fetch)

    def _have_rec(self, cell: bytes, dig: bytes) -> bool:
        for rec in self.global_bs.get(cell, []):
            if C.h_rec(rec["v"]) == dig:
                return True
        return False

    async def _h_gossip_fetch(self, sess: Sess, fr: W.Frame) -> None:
        data = W.get(fr.tvs, W.T_PAYLOAD) or b""
        if not data:
            return
        tvs: list[tuple[int, bytes]] = [(W.T_ROUND, W.u64(self.round_of_ts(time.time())))]
        sent = 0
        for i in range(0, len(data) - 32 + 1, 32):
            dig = data[i:i + 32]
            for cell, recs in list(self.global_bs.items()):
                for rec in recs:
                    if C.h_rec(rec["v"]) == dig:
                        tvs.append((W.T_CELL_IDX, cell))
                        tvs.append((W.T_CELL_REC, rec["v"] + W.u32(int(rec["bits"])) + W.u64(int(rec["ts"]))))
                        sent += 1
                        break
        if sent:
            await sess.send(W.build_frame(W.F_GOSSIP_DATA, 0, tvs))

    async def _h_gossip_data(self, sess: Sess, fr: W.Frame) -> None:
        tvs = fr.tvs
        i = 0
        while i < len(tvs) - 1:
            if tvs[i][0] != W.T_CELL_IDX or tvs[i + 1][0] != W.T_CELL_REC:
                i += 1
                continue
            cell = tvs[i][1]
            full = tvs[i + 1][1]
            if len(full) >= 32 + 1088 + 12:
                value, bits, ts = full[:len(full) - 12], int.from_bytes(full[-12:-8], "little"), int.from_bytes(full[-8:], "little")
                self._bs_insert(self.global_bs, cell, value, bits, float(ts),
                                self.cfg["max_global_cells"], self.cfg["cell_size"])
            i += 2

    # --- dialer / dir -----------------------------------------------------------------

    async def _dialer_loop(self) -> None:
        while not self._stop_evt.is_set():
            for host, port in list(self.cfg["peers"]):
                if self._stopping():
                    return
                key = (host, port)
                sess = self.peer_conns.get(key)
                if sess is None or sess.closed:
                    try:
                        await self._dial_peer(host, port)
                    except Exception as e:
                        log_json(self.name, "warn", "dial_fail", to=key, err=repr(e))
            await asyncio.sleep(1.0)

    def _stopping(self) -> bool:
        return self._stop_evt is not None and self._stop_evt.is_set()

    async def _dial_peer(self, host: str, port: int) -> None:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5.0)
        fs = Sess(reader, writer, host, port, kind="node")
        self.sessions[fs.id] = fs
        self.peer_conns[(host, port)] = fs
        hello = reply(W.F_HELLO, tvs=[(W.T_VER, W.u16(W.VERSION)),
                                      (W.T_CAPS, W.u32(W.CAPS_MIX | W.CAPS_BS | W.CAPS_BEACON | W.CAPS_GOSSIP)),
                                      (W.T_ADDR, self.addr)])
        await fs.send(hello)
        fr = await read_frame(reader)
        if fr is None or fr.type != W.F_HELLO_OK:
            fs.close()
            return
        self._absorb_dir(W.get(fr.tvs, W.T_NODE_LIST) or b"")
        dfx = self._dir_frame()
        if dfx:
            await fs.send(dfx)
        asyncio.create_task(self._conn_reader(fs))
        log_json(self.name, "info", "peer_up", to=f"{host}:{port}")

    # --- BS snapshot -------------------------------------------------------------------

    def _bs_path(self) -> str | None:
        d = self.cfg["data_dir"]
        return os.path.join(d, "bs_snapshot.json") if d else None

    async def _load_bs_snapshot(self) -> None:
        p = self._bs_path()
        if not p or not os.path.exists(p):
            return
        try:
            with open(p, "rb") as f:
                data = json.load(f)
            for name, bs in (("local", self.local_bs), ("global", self.global_bs)):
                for cell_hex, items in (data.get(name) or {}).items():
                    for rec in items:
                        bs[bytes.fromhex(cell_hex)].append(
                            {"v": bytes.fromhex(rec["v"]), "bits": int(rec["bits"]), "ts": float(rec["ts"])})
            log_json(self.name, "info", "bs_loaded", path=p)
        except Exception as e:
            log_json(self.name, "warn", "bs_load_fail", err=repr(e))

    async def _save_bs_snapshot(self) -> None:
        p = self._bs_path()
        if not p:
            return
        try:
            data = {"local": _bs_dump(self.local_bs), "global": _bs_dump(self.global_bs)}
            os.makedirs(self.cfg["data_dir"], exist_ok=True)
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, p)
        except Exception as e:
            log_json(self.name, "warn", "bs_save_fail", err=repr(e))

    async def _bs_save_loop(self) -> None:
        while not self._stop_evt.is_set():
            await asyncio.sleep(float(self.cfg["bs_save_s"]))
            await self._save_bs_snapshot()

    # --- HTTP --------------------------------------------------------------------------

    def _start_http(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        node = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):  # noqa: N802
                if self.path != "/jp":
                    self.send_error(404)
                    return
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                fut = None
                if node.loop:
                    try:
                        fut = asyncio.run_coroutine_threadsafe(node._http_handle(body), node.loop)
                        out = fut.result(15)
                    except Exception as e:
                        log_json(node.name, "warn", "http_err", err=repr(e))
                        out = b""
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_GET(self):  # noqa: N802
                if self.path != "/status":
                    self.send_error(404)
                    return
                try:
                    payload = json.dumps(node.status()).encode()
                    self.send_response(200)
                except Exception as e:  # pragma: no cover
                    log_json(node.name, "warn", "status_err", err=repr(e))
                    payload = b""
                    self.send_response(500)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        H.log_message = lambda *a, **kw: None   # тихие логи HTTP
        srv = ThreadingHTTPServer((self.cfg["http_host"], self.cfg["http_port"]), H)
        self._http = srv
        threading.Thread(target=srv.serve_forever, name=f"{self.name}-http", daemon=True).start()
        log_json(self.name, "info", "http_up", port=self.cfg["http_port"])

    def _stop_http(self) -> None:
        if self._http:
            self._http.shutdown()
            self._http.server_close()
            self._http = None

    async def _http_handle(self, body: bytes) -> bytes:
        hs = Sess(None, _NullWriter(), "http", 0, kind="http")
        try:
            fr = W.decode_frame(body)
        except Exception:
            return b""
        out = b""
        try:
            ret = await self._dispatch(hs, fr)
            if isinstance(ret, (bytes, bytearray)):
                out = bytes(ret)
        except Exception as e:
            log_json(self.name, "warn", "http_dispatch", err=repr(e))
        return out

    def status(self) -> dict:
        now = time.time()
        return {
            "name": self.name,
            "addr": self.addr.hex(),
            "port": self.cfg["port"],
            "http_port": self.cfg["http_port"],
            "peers": len(self.dir),
            "peer_conns": sum(1 for s in self.peer_conns.values() if not s.closed),
            "clients": sum(len(v) for v in self.online.values()),
            "round": self.round_of_ts(now),
            "seeds": {str(k): v.hex()[:16] for k, v in sorted(self.seeds.items())[-4:]},
            "local_cells": len(self.local_bs),
            "global_cells": len(self.global_bs),
            "local_recs": sum(len(v) for v in self.local_bs.values()),
            "global_recs": sum(len(v) for v in self.global_bs.values()),
            "counters": dict(self.counters),
            "uptime_s": round(now - self.started_at, 1),
        }


class _NullWriter:
    """Заглушка writer для HTTP pseudo-сессии."""

    def __init__(self) -> None:
        self._buf = b""

    def write(self, b) -> None:
        self._buf += b


# --- handlers registry# --- handlers registry ------------------------------------------------------------

_HANDLERS = {
    W.F_PING: Node._h_ping,
    W.F_HELLO: Node._h_hello,
    W.F_SEED_REQ: Node._h_seed_req,
    W.F_DIR_REQ: Node._h_dir_req,
    W.F_DIR: Node._h_dir,
    W.F_MIX_ONION: Node._h_mix,
    W.F_BS_STORE: Node._h_bs_store,
    W.F_BS_READ: Node._h_bs_read,
    W.F_ONLINE_ACK: Node._h_online_ack,
    W.F_BEACON_COMMIT: Node._h_commit,
    W.F_BEACON_REVEAL: Node._h_reveal,
    W.F_BEACON_SEED: Node._h_seed_publ,
    W.F_GOSSIP_PUSH: Node._h_gossip_push,
    W.F_GOSSIP_FETCH: Node._h_gossip_fetch,
    W.F_GOSSIP_DATA: Node._h_gossip_data,
}


def _parse_entry(val: bytes) -> dict | None:
    """T_NODE_ENTRY value → {pk_kem, pk_dsa, host, port, tls}."""
    try:
        tvs = W.parse_tvs(val)
        pk_kem = W.get(tvs, W.T_PK_KEM)
        pk_dsa = W.get(tvs, W.T_PK_DSA)
        tr = W.get(tvs, W.T_TRANSPORT)
        if not pk_kem or not pk_dsa or not tr:
            return None
        host, port, tls = W.dec_transport(tr)
        return {"pk_kem": pk_kem, "pk_dsa": pk_dsa, "host": host, "port": port,
                "tls": tls, "entry_val": val, "sig": None, "addr": None}
    except Exception:
        return None


def _bs_dump(bs: dict) -> dict:
    out = {}
    for cell, recs in bs.items():
        out[cell.hex()] = [{"v": r["v"].hex(), "bits": int(r["bits"]), "ts": float(r["ts"])} for r in recs]
    return out
