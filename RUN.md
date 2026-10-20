# RUN — что работает и как запустить (v1 dev, октябрь 2026)

## Что работает сейчас

| блок | состояние | где |
|---|---|---|
| C core: crypto (ML-KEM-768/ML-DSA-44/ChaCha20-Poly1305/SHAKE), wire-кодек, блокирующий TCP, PoW-shim (RandomX) | ✅ | `src/{crypto,framing,net,jppow}.c`, `build/libjppow.so` |
| C onion v2: msg→R (7028 B, PoW-поля в заголовке), сборка packet (3 слоя 10478 B / 4 слоя 11628 B), peel узлом | ✅ (unit-тест t_onion) | `src/{onion,client}.c` |
| C secchan: ML-KEM handshake (F_SCH_HELLO/OK, подписи JPCS1/JPCS2) + AEAD-кадры F_SCH_SEALED с seq-антиreplay | ✅ (unit-тест t_secchan; **в wire-путь ещё не вшит**) | `src/secchan.c` |
| io_uring TCP-движок + POSIX-shm SPSC очереди | ✅ (тесты t_uring/t_shm; ждут ноду) | `src/net_uring.c`, `src/shm.c` |
| Beacon hbdrand v2 (commit→reveal→seed, подписи, k=3) | ✅ py-нода; C-клиент читает seed | `python/jproto_ref/node.py` §beacon |
| Mix v2: entry PoW (TRANSPORT по целому packet) → peel → форвард; финал R: ONLINE-доставка / store (NODE-PoW из R) | ✅ py-нода (drив-клиент onion в jpc ещё не вшит) | node.py §mix |
| BS direct: F_BS_STORE (TRANSPORT PoW) / F_BS_READ (READ PoW), eviction, snapshot | ✅ py-нода | node.py §bs |
| Gossip Global BS (PUSH/FETCH/DATA, h_rec) | ✅ py-нода (plain) | node.py §gossip |
| Docker-федерация 3 ноды + host-клиент `jpc` | ✅ e2e ping/dir | `docker/compose.yml` |
| secchan в python-ноде, ref_client, jpc send/read-bs поверх onion, PoW-профили в e2e | ❌ TODO | — |

C-тесты: `make tests` (7/7: t_crypto, t_framing, t_onion, t_shm, t_uring, t_secchan, t_pow).
Python-тесты: `make -C python .venv && ...` — проще `cd python && .venv/bin/python -m pytest tests -q` (24 passed).

## Быстрый старт (docker-федерация)

```bash
make docker-up      # fedA/9101, fedB/9102, fedC/9103 (wire), 9201-9203 HTTP
make e2e-ping       # jpc ping → fedA: HELLO → HELLO_OK → SEED (текущий раунд)
build/jpc dir --node 127.0.0.1:9103   # директория (3 signed node-entry)
curl -s http://127.0.0.1:9202/status  # статус fedB (peers=3, seeds, counters)
make docker-logs    # JSON-lines логи
make docker-down
```

Пересборка образа после правок python/: `sudo docker compose -f docker/compose.yml build && sudo docker compose -f docker/compose.yml up -d`.

## Нода локально (без докера)

```bash
cd python
.venv/bin/python -m jproto_ref \
  --port 9100 --http-port 9200 --name fedA-dev \
  --peer 127.0.0.1:9102            # можно повторять
  --data-dir /tmp/jp-data \
  --pow-lib ../build/libjppow.so   # иначе PoW off (skip_pow через cfg)
```

Флаги ↔ env: `--port/JP_PORT`, `--http-port/JP_HTTP_PORT` (0=выкл), `--peer/JP_PEERS` (CSV HOST:PORT),
`--name/JP_NAME`, `--data-dir/JP_DATA_DIR` (деф. `/tmp/jp-data`), `--pow-lib/JPPOW_LIB`,
`--host/JP_HOST` (bind, деф. `0.0.0.0`), `--publish-host/JP_PUBLISH_HOST` (адрес в dir-entry, деф. `127.0.0.1`).
Без аргументов и без JP_* — справка, exit 0. Зависимости: `cryptography` (см. `python/requirements.txt`).

Beacon стартует с GENESIS-сид; через ~6 с от старта раунда появляется первый seed
(раунды по 10 s: commit 0–3 s, reveal 3–6 s, finalize 6 s). Одинокая нода →
seed «пролетает» (seed(n)=seed(n−1)), 3 ноды с peer'ами → полный k=3.
Сид для PoW-ключа часа — статичный DEV_SEED_HOUR (пока не привязан к beacon).

## C-клиент (host)

```bash
make                      # build/libjproto.a, build/jpc, все тесты
build/jpc keygen j.json   # ключи клиента (ML-KEM/ML-DSA + addr)
build/jpc ping  --node 127.0.0.1:9101
build/jpc dir   --node 127.0.0.1:9102
```

## Известные отклонения dev-scope (не баги, но помнить)

- **secchan не вшит в wire-путь**: beacon/gossip ходят plain-F_ кадрами.
  Канальный модуль готов и протестирован с обеих сторон (C: `src/secchan.c`,
  формат — docs/wire.md §7); интеграция в py-ноду (handshake до остальных кадров,
  `--plain` для dev) — следующий шаг.
- **ONLINE-доставка**: py-нода отдаёт R всем HELLO-registered клиентам — вскрывает
  только владелец sk; дест-адресации в R v2 нет (см. docs/wire.md §5).
- **cell = h_cell(value)** для BS (payload-derived); inbox-адресация получателя — TODO.
- py-kem sk = seed (64 B), C-sk = 2400 B expanded: interop по ключам нод — через pk
  в dir,匙 расшифровка у себя (не смешиваются до конвертера).
- PoW-либа: `JPPOW_LIB` пуст → нода работает, PoW pass-through (skip_pow), для
  честной транспортировки нужен mounted `libjppow.so` (в compose — `../build:ro`).
