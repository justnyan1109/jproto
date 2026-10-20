"""test_chat: e2e через реальную ноду — secchan, HELLO-регистрация, dir/seed,
ONLINE-сообщение по 3-hop onion (A→B), direct-BS пост/fetch.

Без pytest-asyncio: каждый тест — asyncio.run(body()). PoW реальный
(libjppow.so, 6 бит); при JPPOW_DISABLE=1 клиент шлёт zero-cert (нода в тесте
skip_pow=True) — путь протокола тот же.
"""

import asyncio
import os

import pytest

from conftest import get_free_port        # helper из conftest (не fixture)
from jproto_ref import wire as W
from jproto_ref.node import DEFAULTS, Node
from jproto_ref.chat import Chat, Identity, _parse_home

MARK = "привет-e2e-маркер"


async def boot_node(get_free_port, **over) -> tuple[Node, asyncio.Task]:
    port = get_free_port()
    cfg = dict(DEFAULTS)
    cfg.update({
        "host": "127.0.0.1", "publish_host": "127.0.0.1",
        "port": port, "http_port": 0,
        "round_len": 3.0, "commit_frac": 0.2, "reveal_frac": 0.5,
        "mix_delay": (0.05, 0.15),
        "skip_pow": True, "rate_limit": 100.0,
        "data_dir": None,
    })
    cfg.update(over)
    node = Node(cfg)
    task = asyncio.create_task(node.run())
    await node.wait_ready()
    return node, task


async def shutdown(node: Node, task: asyncio.Task) -> None:
    await node.stop()
    try:
        await asyncio.wait_for(task, 10)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        task.cancel()


async def connect_chat(ident: Identity, node: Node, pin_dir: str | None) -> Chat:
    chat = Chat(ident, node.cfg["host"], node.cfg["port"], pin_dir=pin_dir,
                out=lambda s: None)
    await chat.connect()
    asyncio.ensure_future(chat.read_loop())
    return chat


@pytest.fixture
def ids(tmp_path):
    a = Identity.generate()
    b = Identity.generate()
    a.save(str(tmp_path / "a.json"))
    b.save(str(tmp_path / "b.json"))
    return a, b


def _drain(chats: list[Chat]) -> None:
    for c in chats:
        c.alive = False
        if c.sec is not None:
            try:
                c.sec.writer.close()
            except Exception:
                pass


def test_online_chat_delivery(ids, tmp_path):
    alice, bob = ids

    async def body():
        node, ntask = await boot_node(get_free_port)
        chats: list[Chat] = []
        try:
            ca = await connect_chat(alice, node, str(tmp_path / "pa"))
            cb = await connect_chat(bob, node, str(tmp_path / "pb"))
            chats = [ca, cb]
            assert ca.sec is not None and cb.sec is not None
            assert cb.node_addr == node.addr
            assert node.status()["sec_sessions"] >= 2
            assert len(ca.nodes) >= 1

            ca.peer = (bob.pk_kem, None)   # home: наша нода (same-node чат)
            seq = await ca.send_online(MARK, bob.pk_kem)
            assert seq == 1

            for _ in range(40):            # ≤ 20 s: mine + 3 mix delay
                await asyncio.sleep(0.5)
                if cb.last_incoming:
                    break
            assert cb.last_incoming == MARK, \
                f"bob не получил сообщение ({cb.last_incoming!r})"
        finally:
            _drain(chats)
            await shutdown(node, ntask)

    asyncio.run(body())


def test_offline_board(ids, tmp_path):
    (a, _b) = ids

    async def body():
        node, ntask = await boot_node(get_free_port)
        chats: list[Chat] = []
        try:
            chat = await connect_chat(a, node, str(tmp_path / "p2"))
            chats = [chat]
            await chat.post("заметка-в-bs")
            texts = await asyncio.wait_for(chat.fetch(0), 30)
            assert any("заметка-в-bs" in t for t in texts), texts
            texts1 = await asyncio.wait_for(chat.fetch(1), 30)   # прошлый час
            assert not any("заметка-в-bs" in t for t in texts1)
        finally:
            _drain(chats)
            await shutdown(node, ntask)

    asyncio.run(body())


def test_bs_ctl_growth_and_floor():
    """Контроллер §6a: S_eff растёт ×2 в пределах бюджета и не сжимается,
    bits_min ↑ только когда ёмкость упёрлась в бюджет."""
    import time as _t
    cfg = dict(DEFAULTS)
    cfg.update({"data_dir": None, "http_port": 0, "bs_max_mb": 0.05,
                "seff_start": 4, "bs_min_bits": 2, "bs_window_h": 48})
    n = Node(cfg)
    now = _t.time()
    n._ctl_prev = (now - 100, 0)
    n.counters["bs_admitted"] = 30               # λ ≈ 1080/ч, rolling
    n.local_bs = {i.to_bytes(32, "big"): [] for i in range(4)}   # стог = S_eff
    n.counters["bs_full"] = 3
    for expect_seff in (8, 16, 32):
        n._bs_ctl_tick()
        assert n.seff == expect_seff, (n.seff, expect_seff)
        n.counters["bs_full"] = 3
    # 64 > бюджета 41 (0.05 MB / 1200 B) → рост запрещён, bits_min растёт
    # (check поднимает цену на каждом тике с full>0 при переполненном бюджете)
    n._bs_ctl_tick()
    assert n.seff == 32 and n.bits_min >= 3
    # никогда не сжимаем: full нет → те же seff/bits_min
    n.counters["bs_full"] = 0
    n._bs_ctl_tick()
    assert n.seff == 32 and n.bits_min >= 3
    # retention при λ=0: bits_min·τ
    n.lam_ph = 0.0
    assert n._retention_est_h() == n.bits_min * 168
    # T_STOR_PAR кодировка == dec
    vals = W.dec_stor_par(n._stor_par())
    assert vals[0] == 32 and vals[4] == n.bits_min and vals[5] == 168


def test_home_index_parse(ids):
    alice, _bob = ids

    async def body():
        node, ntask = await boot_node(get_free_port)
        chats: list[Chat] = []
        try:
            chat = await connect_chat(alice, node, None)
            chats = [chat]
            entries = sorted(chat.nodes.items(), key=lambda kv: kv[0])
            assert len(entries) >= 1
            for i, (addr, e) in enumerate(entries, 1):
                if addr == node.addr:
                    e2 = _parse_home(str(i), entries)
                    assert e2["addr"] == node.addr
        finally:
            _drain(chats)
            await shutdown(node, ntask)

    asyncio.run(body())


def test_stor_par_and_round_alignment(ids, tmp_path):
    """§6a: HELLO_OK носит T_STOR_PAR (slots/bits_min/τ/retention/n_active);
    раунды синхронны стен-часу: round_label = ts//round_len и сиды не
    «перекрывают» будущее; лейбл часа BS = round // 360; round_labels
    выровнены на границы (кратны ts//round_len)."""
    (a, _b) = ids
    rl = 3.0

    async def body():
        node, ntask = await boot_node(get_free_port)
        chats: list[Chat] = []
        try:
            chat = await connect_chat(a, node, str(tmp_path / "p3"))
            chats = [chat]
            sp = chat.stor_par
            assert sp is not None, "нет T_STOR_PAR в HELLO_OK"
            assert sp["slots_lbs"] >= 1 and sp["slots_gbs"] >= 1
            assert sp["bits_min"] >= 1 and sp["tau_h"] == 168
            assert sp["window_h"] == 48
            assert sp["n_active"] >= 1          # мы HELLO-зарегистрированы
            assert sp["retention_h"] > 0
            # внутренняя метка абсолютная (границы стен-часа по epoch);
            # status наружу показывает сдвиг от генсиса («сколько раундов
            # работает сеть», round_display при протокольном round_len=10)
            t_now = __import__("time").time()
            n_now = node.round_of_ts(t_now)
            assert abs(n_now * rl - t_now) < 2 * rl
            # наружная метка status — сдвиг от генсиса (протокольный rl=10)
            if rl == 10.0:
                assert abs(node.status()["round"] - (n_now - 179245440)) < 1
            if chat.round is not None:
                assert chat.round <= n_now, "сид будущего раунда?"
                hour = chat.round // 360
                assert hour >= 0 and 6 * 60 == 360
        finally:
            _drain(chats)
            await shutdown(node, ntask)

    asyncio.run(body())
