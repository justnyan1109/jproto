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
  * BS: Local (256 dev-ячеек) для local-store-типов; Global (1024) для
    I_STORE_GLOBAL; прямые пути F_BS_STORE (TRANSPORT PoW) и F_BS_READ
    (READ PoW); eviction score = bits − age_s//3600 внутри ячейки;
  * gossip: PUSH/FETCH/DATA для Global BS (digest = h_rec(value));
  * ONLINE-доставка зарегистрированным клиентам (HELLO c T_ADDR);
  * secchan (wire.md §7): сниффер первого кадра — F_SCH_HELLO → весь дальнейший
    трафик насыпанный; dial пиров — handshake по умолчанию (cfg secure_dial);
    plain-кадры клиентов разрешены (cfg plain_ok);
  * HTTP-обёртка: POST /jp (кадры в один ход) и GET /status;
  * JSON-lines логи в stderr;
  * rate limit 5 msg/s/IP на «тарифицируемые» типы кадров;
  * снимок BS в data_dir (bs_snapshot.json) при остановке и по таймеру.

Ключ PoW (seed_hour) — статичный cfg['pow_seed_hour'] (default DEV_SEED_HOUR);
привязка PoW к раунду живёт в seed_round во входе jppow.
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
from . import secchan as SC
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
    "secure_dial": True,        # нода↔нода: handshake secchan после TCP-dial
    "plain_ok": True,           # принимать plain-кадры от клиентов (dev-совместимо)
    "max_global_cells": 1024,
    "cell_size": 50,
    "bs_save_s": 60.0,

    # --- BS-контроллер (wire.md §6a; протокол.md §9) ---------------------------
    "tau_h": 168,               # score decay: −1 бит за τ («+1 бит ≈ +1 неделя»)
    "bs_min_bits": 6,           # пол admission (не конкурируем дешёвым входом)
    "bs_max_bits": 12,          # потолок битов (аппаратная граница майнинга)
    "bs_window_h": 48,          # окно оценки λ (24–72 ч по протоколу)
    "seff_start": 64,           # стартовый S_eff lbs (ячеек)
    "bs_max_mb": 64.0,          # бюджет памяти → предел ячеек (моно-рост до него)
    "bs_pin_cells": 0,          # >0 — оператор пинит размер lbs (авто off)
    "rec_size_hint": 1200,      # байт/запись для перевода бюджета в ячейки
}

# Тарифицируемые типы кадров (rate limit applies; beacon/gossip/ping свободны).
RT_LIMITED = {W.F_MIX_ONION, W.F_BS_STORE, W.F_BS_READ, W.F_SEED_REQ, W.F_DIR_REQ}


def log_json(node_name: str, lvl: str, ev: str, **kw) -> None:
    """JSON-lines в stderr (все события ноды/клиента)."""
    rec = {"ts": round(time.time(), 6), "lvl": lvl, "node": node_name, "ev": ev}
    rec.update({k: (v.hex() if isinstance(v, (bytes, bytearray)) and len(v) > 20
                    else v) for k, v in kw.items()})
    print(json.dumps(rec, ensure_ascii=False, default=str), file=sys.stderr, flush=True)


# --- session ------------------------------------------------------------------

class Sess:
    __slots__ = ["reader", "writer", "ip", "port", "kind", "addr", "closed", "id", "sec"]

    def __init__(self, reader, writer, ip: str, port: int, kind: str = "?"):
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.port = port
        self.kind = kind          # 'client' | 'node' | 'http' | '?'
        self.addr: bytes | None = None
        self.closed = False
        self.sec: SC.SecChan | None = None   # насыпанный канал (wire.md §7)
        self.id = id(self)

    async def send(self, frame: bytes) -> None:
        if self.closed:
            return
        if self.sec is not None:
            frame = self.sec.seal_bytes(frame)
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


read_frame = SC.read_frame     # async-ридер wire-кадров (общий с secchan)


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
                         "bs_read": 0, "bs_evict": 0, "bs_full": 0,
                         "bs_admitted": 0,
                         "beacon_seed_pub": 0, "gossip_push": 0}
        self._buckets: dict[str, dict] = {}      # ip → {tokens, last}
        self._bucket_lock = threading.Lock()

        # --- BS-контроллер (wire.md §6a): S_eff только ВВЕРХ (анонимность:
        # не сжимаем «стог сена»), bits_min только ВВЕРХ (не продаём дешёвый
        # вход) — оба с полами; оператор пинит bs_pin_cells → авто off.
        self.seff = int(self.cfg["bs_pin_cells"]) or int(self.cfg["seff_start"])
        self.bits_min = max(1, int(self.cfg["bs_min_bits"]))
        self.lam_ph = 0.0            # λ, записей/час (lbs, rolling)
        self._ctl_prev = (time.time(), 0)        # (ts, bs_admitted at prev tick)

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
            asyncio.create_task(self._phase_loop(), name="beacon-phase"),
            asyncio.create_task(self._bsctl_loop(), name="bs-ctl"),
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
            # Сниффер первого кадра: F_SCH_HELLO → secchan (все последующие кадры
            # насыпаны); любой другой кадр — plain (dev-совместимость клиентов).
            try:
                first = await read_frame(sess.reader)
            except ValueError as e:
                log_json(self.name, "warn", "conn_bad_frame", err=str(e), ip=ip)
                return
            if first is None:
                return
            if first.type == W.F_SCH_HELLO:
                try:
                    sess.sec = await SC.handshake_server(
                        sess.reader, sess.writer, self.sk_dsa, first_frame=first)
                except Exception as e:
                    log_json(self.name, "warn", "sch_server_fail", err=repr(e), ip=ip)
                    return
                log_json(self.name, "info", "sch_server_ok", ip=ip)
                await self._conn_reader(sess)
            elif self.cfg["plain_ok"]:
                await self._dispatch(sess, first)
                await self._conn_reader(sess)
            else:
                log_json(self.name, "warn", "plain_rejected", ftype=hex(first.type), ip=ip)
                return
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        except Exception as e:  # мусор в потоке — не роняем сервер
            log_json(self.name, "warn", "conn_error", err=repr(e), ip=ip)
        finally:
            self._unregister(sess)

    async def _conn_reader(self, sess: Sess) -> None:
        while not sess.closed:
            if sess.sec is not None:
                try:
                    fr = await sess.sec.recv_frame()
                except SC.SchError as e:
                    log_json(self.name, "warn", "sch_broken", err=str(e), ip=sess.ip)
                    sess.close()
                    break
                except (asyncio.IncompleteReadError, ConnectionError):
                    break
            else:
                try:
                    fr = await read_frame(sess.reader)
                except (asyncio.IncompleteReadError, ConnectionError):
                    break
                except ValueError as e:
                    log_json(self.name, "warn", "conn_bad_frame", err=str(e), ip=sess.ip)
                    sess.close()
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
        switch = [(W.T_POW_PAR, W.enc_pow_par(W.POW_TRANSPORT,
                                              max(int(self.cfg["transport_bits"]), self.bits_min), 2000)),
                  (W.T_POW_PAR, W.enc_pow_par(W.POW_NODE, self.cfg["node_bits"], int(self.cfg["pow_budget_ms"]))),
                  (W.T_POW_PAR, W.enc_pow_par(W.POW_READ, self.cfg["read_bits"], 200))]
        # TRANSPORT floor = admission floor (bits_min — поднимается контроллером;
        # клиенту решать «+бит» только на удержание выше published retention).
        return reply(W.F_HELLO_OK, tvs=[(W.T_VER, W.u16(W.VERSION)),
                                        (W.T_CAPS, caps),
                                        (W.T_ADDR, self.addr),
                                        (W.T_STOR_PAR, self._stor_par()),
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
        return reply(W.F_DIR, tvs=[(W.T_DIR_DIGEST, digest), (W.T_NODE_LIST, body),
                                   (W.T_STOR_PAR, self._stor_par())])

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
        """verify по seeds раундов (n−1, n, n+1); ключ RandomX — статичный cfg.
        profile — ОЖИДАЕМЫЙ профиль сертификата (cert с чужим профилем → False).
        skip_pow: dev-knob — не просить PoW вовсе (разрешает zero-cert)."""
        if self.cfg["skip_pow"]:
            return True
        if bits < required:
            return False
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
        if (not pay or (cert and len(cert) != 16)
                or len(pay) < C.KEM_CT_LEN + R.BLOB_BASE):
            return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(400, "bad mix"))])
        if cert is not None:
            # entry-кадр: TRANSPORT-PoW верифицируем (digest = h_pow(packet)).
            try:
                nonce, bits, prof = W.dec_pow_cert(cert)
            except ValueError:
                return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(400, "cert"))])
            if prof != W.POW_TRANSPORT or not self._pow_common(
                    JP.pow_digest(pay), nonce, bits,
                    W.POW_TRANSPORT, self.cfg["transport_bits"]):
                self.counters["pow_fail"] += 1
                log_json(self.name, "warn", "mix_drop_pow", ip=sess.ip, bits=bits)
                return reply(W.F_MIX_ACK, tvs=[(W.T_ERR, W.enc_err(401, "pow"))])
        else:
            # hop-кадр без cert: валидность даёт restore peel ниже; тарифицируем
            # тем же rate limit (RT_LIMITED). Указано в wire.md §5 v2.
            log_json(self.name, "info", "mix_hop_uncert", ip=sess.ip)
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
        """Либо переиспользуем persistent peer conn, либоfresh dial (в обоих
        случаях нода↔нода secchan при secure_dial)."""
        key = (entry["host"], entry["port"])
        sess = self.peer_conns.get(key)
        if sess and not sess.closed:
            await sess.send(frame)
            return
        try:
            fs = await self._dial_raw(entry["host"], entry["port"])
        except Exception as e:
            log_json(self.name, "warn", "mix_dial_fail", to=key, err=repr(e))
            return
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
                     sessn=meta["session"], seq=meta["seq"], n=len(waiting))
            # доставляем ВСЕМ HELLO-registered (DESIGN_NOTES): вскроет владелец
            # ключа (implicit rejection), остальные молча выкинут.
            frame = reply(W.F_ONLINE_DELIVER, tvs=[(W.T_PAYLOAD, rpl)])
            await asyncio.gather(*(sc.send(frame) for sc in waiting),
                                 return_exceptions=True)
            return
        if meta["pow_prof"] != W.POW_NODE or meta["pow_bits"] < self.cfg["node_bits"]:
            self.counters["pow_fail"] += 1
            log_json(self.name, "warn", "final_pow_weak", prof=meta["pow_prof"],
                     bits=meta["pow_bits"])
            return
        if not self.cfg["skip_pow"]:
            # NODE-digest КАНОНИЧНО: H(pow.1, R с обнулённым pow_nonce) —
            # nonce не может входить в собственный digest (wire.md §6).
            ok = self._pow_common(R.pow_digest_rpl(rpl), meta["pow_nonce"],
                                  meta["pow_bits"], W.POW_NODE, self.cfg["node_bits"])
            if not ok:
                self.counters["pow_fail"] += 1
                log_json(self.name, "warn", "final_pow_fail")
                return
        value = parsed["ky_ct"] + parsed["aead_nonce"] + parsed["msg_ct"]
        cell = R.cell_of(parsed)      # dest из заголовка R v2.1; 0^32 → h_cell(value)
        ts = time.time()
        if itype == W.I_STORE_GLOBAL:
            ok = self._bs_insert(self.global_bs, cell, value, int(meta["pow_bits"]), ts,
                                 self._cap_global(), self.cfg["cell_size"])
            self.counters["mix_store_global"] += 1
        else:
            ok = self._bs_insert(self.local_bs, cell, value, int(meta["pow_bits"]), ts,
                                 self._cap_local(), self.cfg["cell_size"])
            self.counters["mix_store_local"] += 1
        self.counters["bs_store"] += 1
        log_json(self.name, "info", "bs_store", itype=itype, cell=cell.hex()[:16],
                 bits=int(meta["pow_bits"]), ok=ok)

    def _budget_cells(self) -> int:
        """Операторский бюджет памяти → предел ячеек lbs."""
        return max(int(self.cfg["seff_start"]),
                   int(float(self.cfg["bs_max_mb"]) * 1e6 // max(1, self.cfg["rec_size_hint"])))

    def _cap_local(self) -> int:
        """S_eff lbs: пин оператора фиксирует, иначе авторазмер (моно-рост)."""
        pin = int(self.cfg["bs_pin_cells"])
        return pin if pin > 0 else self.seff

    def _cap_global(self) -> int:
        """gbs — федерационный срез: размер операторский (cfg), зажат бюджетом."""
        return min(int(self.cfg["max_global_cells"]), self._budget_cells())

    def _score(self, r: dict, now: float) -> float:
        """Score записи: bits − age/τ. τ_h=168 → «+1 бит ≈ +1 неделя»."""
        tau_s = float(self.cfg["tau_h"]) * 3600.0
        return float(r["bits"]) - (now - r["ts"]) / tau_s

    def _bs_insert(self, bs: dict, cell: bytes, value: bytes, bits: int, ts: float,
                   max_cells: int, cell_size: int) -> bool:
        local = bs is self.local_bs
        if local and bits < self.bits_min:
            # admission floor ноды (контроллер/пол): дешевле — отбой 402
            return False
        lst = bs.get(cell)
        now = time.time()
        if lst is None:
            if len(bs) >= max_cells:
                self.counters["bs_full"] += 1
                log_json(self.name, "warn", "bs_cells_full",
                         kind="local" if local else "global")
                return False
            bs[cell] = [{"v": value, "bits": bits, "ts": ts}]
            self.counters["bs_admitted"] += 1
            return True
        if len(lst) >= cell_size:
            self.counters["bs_evict"] += 1
            worst_i, worst_s = None, None
            for i, r in enumerate(lst):
                sc = self._score(r, now)
                if worst_s is None or sc < worst_s:
                    worst_i, worst_s = i, sc
            new_bits = bits - (now - ts) / float(self.cfg["tau_h"]) * 3600.0
            if new_bits <= (worst_s or 0):
                return False
            lst[worst_i] = {"v": value, "bits": bits, "ts": ts}
            self.counters["bs_admitted"] += 1
            return True
        lst.append({"v": value, "bits": bits, "ts": ts})
        self.counters["bs_admitted"] += 1
        return True

    # --- BS-контроллер: авторазмер S_eff, пол bits_min, метрики §6a ------------

    async def _bsctl_loop(self) -> None:
        cadence = max(300.0, min(float(self.cfg["bs_window_h"]) * 3600.0 / 8.0,
                                 3600.0))
        while not self._stop_evt.is_set():
            await asyncio.sleep(cadence)
            try:
                self._bs_ctl_tick()
            except Exception as e:
                log_json(self.name, "error", "bs_ctl", err=repr(e))

    def _bs_ctl_tick(self) -> None:
        now = time.time()
        t0, c0 = self._ctl_prev
        adm = self.counters["bs_admitted"]
        dt = max(1.0, now - t0)
        self.lam_ph = max(0.0, (adm - c0) / dt * 3600.0)    # записей/час, rolling
        self._ctl_prev = (now, adm)

        if self.cfg["bs_pin_cells"]:
            log_json(self.name, "info", "bs_ctl_pin",
                     seff=int(self.cfg["bs_pin_cells"]),
                     bits_min=self.bits_min, lam_ph=round(self.lam_ph, 2))
            return
        full = self.counters["bs_full"]
        self.counters["bs_full"] = 0
        cap = self._budget_cells()
        pressure = len(self.local_bs) / max(1, self.seff)
        grew = False
        # рост: полный (full>0) либо прогнозный (давка ≥0.8) — в потолок бюджета
        if (full > 0 or pressure >= 0.8) and self.seff * 2 <= cap:
            self.seff *= 2
            grew = True
        if full > 0 and self.seff * 2 > cap:
            # ёмкости не хватает ДАЖЕ до бюджета → поднимаем цену входа
            # (+1 бит ⇒ маржинальный спам ×2), не режем S_eff (анонимность)
            self.bits_min = min(int(self.cfg["bs_max_bits"]), self.bits_min + 1)
            log_json(self.name, "warn", "bs_bits_up", bits_min=self.bits_min)
        log_json(self.name, "info", "bs_ctl",
                 seff=self.seff, bits_min=self.bits_min, lam_ph=round(self.lam_ph, 2),
                 pressure=round(pressure, 2), grew=grew, full=full)

    def _retention_est_h(self) -> int:
        """Консервативная оценка удержания при min-сложности:
        T ≈ min(bits_min·τ, capacity/λ). λ<0.5/час → считаем score-ветку."""
        t_score = self.bits_min * max(1, int(self.cfg["tau_h"]))
        slots_total = (self._cap_local() + self._cap_global()) * int(self.cfg["cell_size"])
        if self.lam_ph > 0.5:
            t_load = slots_total / self.lam_ph
            return int(min(t_score, t_load))
        return int(t_score)

    def _stor_par(self) -> bytes:
        return W.enc_stor_par(self._cap_local(), self._cap_global(),
                              int(self.lam_ph * 24.0),
                              int(self.cfg["bs_window_h"]),
                              self.bits_min, int(self.cfg["tau_h"]),
                              self._retention_est_h(),
                              sum(len(v) for v in self.online.values()))

    async def _h_bs_store(self, sess: Sess, fr: W.Frame) -> bytes | None:
        idx = W.get(fr.tvs, W.T_CELL_IDX)
        rec = W.get(fr.tvs, W.T_CELL_REC)
        cert = W.get(fr.tvs, W.T_POW)
        # формат rec: value(len ≥ 1116 = ky+nonce+tag) ‖ score(u32) ‖ ts(u64);
        # последние 12 B клиентские, хранению не подлежат (нода перезапишет).
        min_rec = C.KEM_CT_LEN + C.AEAD_NONCE_LEN + C.AEAD_TAG_LEN + 12
        if not idx or len(idx) != 32 or not rec or not cert or len(rec) < min_rec:
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(400, "bad store"))])
        try:
            nonce, bits, profile = W.dec_pow_cert(cert)
        except ValueError:
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(400, "cert"))])
        # digest привязан к cell+rec → переиспользование cert для другой записи
        # исключено; раунд — окно (n−1, n, n+1), как везде (_pow_common).
        my_pd = JP.pow_digest(idx + rec)
        if profile != W.POW_TRANSPORT or not self._pow_common(
                my_pd, nonce, bits, W.POW_TRANSPORT,
                max(int(self.cfg["transport_bits"]), self.bits_min)):
            self.counters["pow_fail"] += 1
            log_json(self.name, "warn", "bs_store_pow", cell=idx.hex()[:16])
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(401, "pow"))])
        if not self.cfg["skip_pow"] and bits < self.bits_min:
            # admission floor контроллера: дешевле — отбой 402 (wire.md §6a)
            return reply(W.F_BS_READ_RESP,
                         tvs=[(W.T_ERR, W.enc_err(402, "bits_min"))])
        ts = time.time()
        ok = self._bs_insert(self.local_bs, idx, rec[:len(rec) - 12], int(bits), ts,
                             self._cap_local(), self.cfg["cell_size"])
        self.counters["bs_store"] += 1
        log_json(self.name, "info", "bs_store_direct", cell=idx.hex()[:16],
                 bits=int(bits), ok=ok)
        return None

    async def _h_bs_read(self, sess: Sess, fr: W.Frame) -> bytes | None:
        idx = W.get(fr.tvs, W.T_CELL_IDX)
        cert = W.get(fr.tvs, W.T_POW)
        if not idx or len(idx) != 32 or not cert:
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(400, "bad read"))])
        try:
            nonce, bits, profile = W.dec_pow_cert(cert)
        except ValueError:
            return reply(W.F_BS_READ_RESP, tvs=[(W.T_ERR, W.enc_err(400, "cert"))])
        pd = JP.pow_digest(idx)
        if profile != W.POW_READ or not self._pow_common(
                pd, nonce, bits, W.POW_READ, self.cfg["read_bits"]):
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
        """Метка раунда = floor(unix_ts / round_len): границы строго по
        стен-часу (epoch), произвольный round_len ДОЛЖЕН делить 3600 (10 s →
        6·60 = 360 раундов/час — BS- часовые ячейки выравниваются на часы)."""
        return int(ts // self.cfg["round_len"])

    def _round_frac(self, n: int) -> float:
        rl = float(self.cfg["round_len"])
        return (time.time() - n * rl) / rl

    def _prev_seed(self, n: int) -> bytes:
        """chain-seed для state(n): СИД РАУНДА n, опубликованная ровно на его
        границе (данные round n−1); до первой границы — genesis (короткая
        согласованная константа boot-цепочки, DESIGN_NOTES §beacon)."""
        s = self.seeds.get(n)
        if s is not None:
            return s
        for k in (n - 1, n - 2):
            s = self.seeds.get(k)
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
        """hbdrand v2 с привязкой к стен-часу. Границы раунда — wall-clock
        (k·round_len от epoch). Расписание раунда N:
            [0.0·R, 0.3)   commit(N)      (данные раунда N)
            [0.3·R, 0.6)   reveal(N)
            [0.6·R, 1.0)   слэк на поздние reveal
            БЕЗОПАСНОСТЬ ГРАНИЦЫ (т.е. ровно (N+1)·R): finalize → появляется
        seed(N+1). «Время, когда доступен новый сид» = круглые отметки k·R,
        и seed(k) привязан к PoW раунда k (см. _pow_common окно ±1).
        Синхронизация (фазы) несекретна — защищена подписями (wire.md §7)."""
        rl = float(self.cfg["round_len"])
        # boot: до первой границы seeds пуст — genesis-цепочка
        cur = self.round_of_ts(time.time())
        while not self._stop_evt.is_set():
            now = time.time()
            target = (self.round_of_ts(now) + 1) * rl
            await asyncio.sleep(min(max(0.05, target - now + 0.002), rl))
            if self._stop_evt.is_set():
                break
            nxt = self.round_of_ts(time.time())
            if nxt == cur:
                continue
            await self._finalize(cur)          # данные round cur → seed(cur+1)
            self._gc_rounds(nxt)
            cur = nxt
            st = self._round_state(cur)
            if not st.commit_sent:
                st.commit_sent = True
                self._bcast_commit(st)

    async def _phase_loop(self) -> None:
        """Фазы внутри раунда (commit/reveal) — по frac относительно границы."""
        tick = max(0.01, min(0.05, self.cfg["round_len"] / 20.0))
        while not self._stop_evt.is_set():
            await asyncio.sleep(tick)
            try:
                n = self.round_of_ts(time.time())
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
            except Exception as e:
                log_json(self.name, "error", "beacon_phase", err=repr(e))

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
        """Данные beacon-раунда n → seed метки n+1 (публикуется ровно на
        границе (n+1)·R — «круглое время доступности нового сида»)."""
        st = self.round_states.get(n)
        prev = self._prev_seed(n)
        commits = self._valid_commits(st) if st else {}
        label = n + 1
        if len(commits) < 2:
            # Emergency (protocol.md §2.2.4): <2 коммитов — seed не двигается
            self.seeds[label] = prev
            log_json(self.name, "warn", "beacon_emergency", rnd=label, commits=len(commits))
            self._publish_seed(label, prev, [])
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
            self.seeds[label] = prev
            log_json(self.name, "warn", "beacon_emergency_noreveal", rnd=label)
            self._publish_seed(label, prev, [])
            return
        contrib.sort(key=lambda t: t[0])            # по pk ЛЕКСИКОГРАФИЧЕСКИ
        seed = C.h_beacon(prev + W.u64(n) + b"".join(v for _, v in contrib))
        self.seeds[label] = seed
        self.counters["beacon_seed_pub"] += 1
        log_json(self.name, "info", "beacon_seed", rnd=label, k=len(contrib))
        self._publish_seed(label, seed, [pk for pk, _ in contrib])

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
                                self._cap_global(), self.cfg["cell_size"])
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
        fs = await self._dial_raw(host, port)
        self.peer_conns[(host, port)] = fs
        hello = reply(W.F_HELLO, tvs=[(W.T_VER, W.u16(W.VERSION)),
                                      (W.T_CAPS, W.u32(W.CAPS_MIX | W.CAPS_BS | W.CAPS_BEACON | W.CAPS_GOSSIP))])
        await fs.send(hello)
        if fs.sec is not None:
            fr = await fs.sec.recv_frame()
        else:
            fr = await read_frame(fs.reader)
        if fr is None or fr.type != W.F_HELLO_OK:
            fs.close()
            return
        self._absorb_dir(W.get(fr.tvs, W.T_NODE_LIST) or b"")
        dfx = self._dir_frame()
        if dfx:
            await fs.send(dfx)
        asyncio.create_task(self._conn_reader(fs))
        log_json(self.name, "info", "peer_up", to=f"{host}:{port}",
                 secured=fs.sec is not None)

    async def _dial_raw(self, host: str, port: int) -> Sess:
        """TCP-dial (+secchan при secure_dial). pin: валидный dir-entry этого
        host:port → жда́ем ровно его pk_dsa; иначе принимаем (TOFU, лог warn)."""
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5.0)
        fs = Sess(reader, writer, host, port, kind="node")
        self.sessions[fs.id] = fs
        if self.cfg["secure_dial"]:
            expect = None
            for e in self.dir.values():
                if e["addr"] != self.addr and e["host"] == host and e["port"] == port:
                    expect = e["pk_dsa"]
            try:
                fs.sec = await asyncio.wait_for(
                    SC.handshake_client(reader, writer, self.sk_kem, self.sk_dsa,
                                        expect_pk=expect), 10.0)
            except Exception as e:
                log_json(self.name, "warn", "sch_dial_fail", to=f"{host}:{port}",
                         err=repr(e))
                fs.close()
                raise
        return fs

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
            "sec_sessions": sum(1 for s in self.sessions.values() if s.sec),
            "round": self.round_of_ts(now),
            "seeds": {str(k): v.hex()[:16] for k, v in sorted(self.seeds.items())[-4:]},
            "local_cells": len(self.local_bs),
            "global_cells": len(self.global_bs),
            "local_recs": sum(len(v) for v in self.local_bs.values()),
            "global_recs": sum(len(v) for v in self.global_bs.values()),
            "seff": self._cap_local(),
            "bits_min": self.bits_min,
            "lam_ph": round(self.lam_ph, 3),
            "retention_est_h": self._retention_est_h(),
            "n_active": sum(len(v) for v in self.online.values()),
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
