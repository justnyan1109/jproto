# RUN — что работает и как запустить (v1 dev, октябрь 2026)

## Что работает сейчас

| блок | состояние | где |
|---|---|---|
| C core: crypto (ML-KEM-768/ML-DSA-44/ChaCha20-Poly1305/SHAKE), wire-кодек, блокирующий TCP, PoW-shim (RandomX) | ✅ | `src/{crypto,framing,net,jppow}.c`, `build/libjppow.so` |
| C onion v2: msg→R (7028 B, PoW-поля в заголовке), сборка packet (3 слоя 10478 B / 4 слоя 11628 B), peel узлом | ✅ (unit-тест t_onion) | `src/{onion,client}.c` |
| C secchan: ML-KEM handshake (F_SCH_HELLO/OK, подписи JPCS1/JPCS2) + AEAD-кадры F_SCH_SEALED с seq-антиreplay | ✅ (тесты: C t_secchan, py test_secchan) | `src/secchan.c`, `python/jproto_ref/secchan.py` |
| io_uring TCP-движок + POSIX-shm SPSC очереди | ✅ (тесты t_uring/t_shm; ждут ноду) | `src/net_uring.c`, `src/shm.c` |
| Beacon hbdrand v2 (commit→reveal→seed, подписи, k=3) | ✅ py-нода; C-клиент читает seed | `python/jproto_ref/node.py` §beacon |
| Mix v2: entry PoW (TRANSPORT по целому packet) → peel → форвард; финал R: ONLINE-доставка / store (NODE-PoW из R) | ✅ py-нода (onion-клиент в jpc ещё не вшит) | node.py §mix |
| BS direct: F_BS_STORE (TRANSPORT PoW) / F_BS_READ (READ PoW), eviction, snapshot | ✅ py-нода | node.py §bs |
| Gossip Global BS (PUSH/FETCH/DATA, h_rec) | ✅ py-нода (plain) | node.py §gossip |
| Docker-федерация 3 ноды + host-клиент `jpc` | ✅ e2e ping/dir | `docker/compose.yml` |
| secchan в wire-пути: нода сниффит F_SCH_HELLO → весь трафик насыпной; нода↔нода dial — secchan по умолчанию; gossip/beacon внутри | ✅ py-нода (+e2e docker) | node.py, e2e-chat логи `peer_up … secured: true` |
| Мессенджер-клиент `jchat` (py): keygen/run, HELLO-регистрация, dir+seed, ONLINE-сообщение по 3-hop onion с real PoW, offline-доска (direct-BS post/fetch), TOFU-pin ноды | ✅ py-tests + e2e-chat (host → docker fedA) | `python/jproto_ref/chat.py`, `tools/e2e_chat.py` |
| `jpc send/read-bs` (C) поверх onion | ❌ TODO | `tools/jpc.c` |

C-тесты: `make tests` (7/7: t_crypto, t_framing, t_onion, t_shm, t_uring, t_secchan, t_pow).
Python-тесты: `make -C python .venv && ...` — проще `cd python && .venv/bin/python -m pytest tests -q` (32 passed: wire/crypto/pow/secchan/chat-e2e).

## Быстрый старт (docker-федерация)

```bash
make docker-up      # fedA/9101, fedB/9102, fedC/9103 (wire), 9201-9203 HTTP
make e2e-ping       # jpc ping → fedA: HELLO → HELLO_OK → SEED (текущий раунд)
make e2e-chat       # alice⇄bob через fedA: secchan+onion+PoW, обмен сообщениями
build/jpc dir --node 127.0.0.1:9103   # директория (3 signed node-entry)
curl -s http://127.0.0.1:9202/status  # статус fedB (sec_sessions, counters)
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

## Мессенджер jchat (host, py-клиент)

```bash
cd python && .venv/bin/python -m jproto_ref.chat keygen me.json
.venv/bin/python -m jproto_ref.chat run --node 127.0.0.1:9101 --me me.json
```

Канал клиент↔нода: secchan (ML-KEM handshake; pk ноды TOFU-pin в
`~/.jproto/node_pins.json`; несоответствие = отказ — MITM не пройдёт).
Команды: `/nodes /to <me.json|PKHEX>[@нода] /msg ТЕКСТ /post /fetch /seed /quit`;
голый текст после `/to` = шорткат `/msg`. Сообщение: R v2 (ML-KEM к получателю)
→ onion 3 hop ([наша нода, случайная, home получателя]) → клиент сам майнит
TRANSPORT-PoW по seed'у раунда (seed'ы и pow-параметры — из HELLO_OK/SEED_DIR).
Скриптовый режим (интеграция): `oneshot --msg ... --expect ... --reply ...` —
использован `make e2e-chat` (`tools/e2e_chat.py`, два клиента поверх docker).

## Известные отклонения dev-scope (не баги, но помнить)

- **cert на entry только**: hop-кадры смеси идут без T_POW — TRANSPORT-PoW
  проверяет entry-нода; промежуточные хопы защищены только rate-limit
  5 msg/s/IP (кадр посредника отличим не всегда — «вход сертифицирован,
  дальше доверие по валидному peel»).
- **ONLINE-доставка**: py-нода отдаёт R всем HELLO-registered клиентам — вскрывает
  только владелец sk; дест-адресации в R v2 нет (см. docs/wire.md §5).
- **cell = h_cell(value)** для BS (payload-derived); inbox-адресация получателя — TODO.
- py-kem sk = seed (64 B), C-sk = expanded (2400/2560 B): interop — по pk из dir;
  расшифка у владельца своим sk (конвертер seed↔expanded — отдельно, позже).
- PoW-либа: `JPPOW_LIB` пуст → нода работает с PoW pass-through (skip_pow); для
  честной проверки PoW нужен mounted `libjppow.so` (в compose — `../build:ro`);
  jchat при недоступности .so шлёт zero-cert (принимается только skip_pow-нода).
- jppow_mine может завышать out_bits (баг digest_best): py-клиент пересчитывает
  фактические биты через jppow_hash — иначе verify ноды (правильно) отбрасывает.
