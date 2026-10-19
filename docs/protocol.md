# jproto — спецификация протокола (реализация)

База: https://github.com/justnyan1109/jproto (README). Этот документ фиксирует конкретные
решения реализации и является контрактом для C-библиотеки и Python reference-сервера.
Пункты «требуется уточнение» исходного README помечены `РЕШЕНО:`. Любой, кто реализует
тонкую деталь сверх этого документа, обязан обновить этот документ.

## 0. Крипто-примитивы

| Назначение | Алгоритм | Примечание |
|---|---|---|
| `H` | SHAKE256 (OpenSSL EVP) | все хэши; `H(x)` = SHAKE256(x, 32); domain separation = tag на входе |
| KEM сообщений/onion | ML-KEM-768 | pk 1184 B, ct 1088 B, sk 2400 B |
| Подписи узлов | ML-DSA-44 | pk 1312 B, sig 2420 B |
| AEAD | ChaCha20-Poly1305 (RFC8439), nonce 12 B | EVP_chacha20_poly1305_ietf |
| PoW | Argon2id (libargon2) | memory-hard, см. §3 |
| Транспорт TLS | TLS 1.3, группа `X25519MLKEM768` | опционально, та же структура кадра |

Шифрованные ключи и ключи сеансов после использования затираются (`sodium_memzero` / EVP zeroize).
AEAD никогда не используется с nonce повторно для одного ключа: nonce = 12 B CSPRNG + счётчик сессии.

Домены `H(tag, x)` (ASCII-строки, конкатенация = tag ‖ x):
`jproto.dir.1` — адрес узла/клиента, `jproto.h.1` — cell index, `jproto.beacon.1` — seed/commit,
`jproto.pow.1` — payload digest для PoW, `jproto.aad.1` — AAD AEAD, `jproto.mix.1` — onion-слои,
`jproto.dirlist.1` — дайджест директории, `jproto.msg.1` — AAD payload сообщения.

## 1. Идентичность

- **Клиент**: пара ML-KEM-768 `(pk_B, sk_B)`. Адрес клиента = `H(dir.1, pk_B)` (32 B).
- **Узел** (федерация): ML-KEM-768 pk для onion-слоёв + ML-DSA-44 pk для подписей.
- **Директория**: список записей узлов (addr, kem_pk, dsa_pk, transports…), каждая запись
  подписана ML-DSA-44 самим узлом. Клиент загружает директорию у любого узла и проверяет подписи.
  Bootstrap-файл + последующее мажоритарное обновление — вне MVP (по умолчанию: доверяем
  подписанным записям, полученным от ≥2 узлов).
- Мнемоника `РЕШЕНО:` клиент всегда выбирает маршрут из директории; первая нода — вход,
  третья нода — цель (home получателя / согласованная / BS).

## 2. Beacons (раундовый seed)

- Раунд `N = floor(unix_ts / 10)`, длина раунда `ROUND_LEN = 10 s`.
- Окно reveal: `[t0(N), t0(N)+3s]` — узел рассылает всем узлам
  `commit_i = SHAKE256(tag=beacon.1, seed(N-1) ‖ v_i ‖ r_i \| 32)`, где `v_i` — 32 B CSPRNG,
  `r_i` — 16 B salt.
- В окне `[t0(N)+3s, t0(N)+6s]` — рассылка `reveal_i = (v_i, r_i)` + `ML-DSA-44 sig_i`.
  Проверка: `SHAKE256(beacon.1, seed(N-1)‖v_i‖r_i) == commit_i` и подпись валидна.
- В `t0(N)+6s`: упорядочиваем `v` по addr узла (32 B лексикографически),
  `seed(N) = SHAKE256(beacon.1, seed(N-1) ‖ v_1 ‖ v_2 ‖ … ‖ v_k)` (_k_ = учтённые reveal).
  Не пришедшие к дедлайну reveal — игнорируются. Seed(N) публикуется (клиент может запросить).
- `seed_hour = seed(N − N mod 360)` (часовые раунды).
- Клиент запрашивает seed у любой ноды. Ответ содержит `seed(N)` и `seed(N-1)` ( concoction
  сервис при разъезде). Ожидание допускается в 1 раунд в любую сторону.

## 3. PoW (RandomX, memory-hard, анти-квант)

PoW построен на **RandomX** (реализация tevador, vendor в `vendor/RandomX`). RandomX:
исполнение случайных программ на VM, cache (2028 KiB / 256 MiB scratchpad) из Argon2id,
memory-latency-bound и data-dependent — неприводимо к обратимым схемам, поэтому
квантовый майнер не получает субквадратичного ускорения.

### Функция PoW

```
pow_digest:
    key       = seed_hour           (32 B)     # cache/dataset ключ
    input     = seed_round ‖ payload_digest ‖ nonce(u64 LE)
                                            # seed_round — 32 B текущего раунда
    digest    = RandomX_H(key, input)          # 32 B
```

- **Привязка к раунду**: раунд входит во `input`, поэтому решение валидно только
  в текущем (или ±1) раунде. Ключ = `seed_hour`, чтобы 256 MiB cache
  (324 ms инициализация) и dataset (2 GiB, ~3 мин) не пересчитывались каждый раунд.
- **payload_digest** = SHAKE256(pow.1, сериализованная полезная нагрузка сообщения).

### Budget-схема («универсальность» ПК/смартфонов)

Фикс difficulty невозможен (смартфон ≈ 30 ms/hash, ПК ≈ 10 ms/hash light-режима,
dataset-режим ~1.2 ms/hash). Поэтому:

1. **Вход** (`POW_TRANSPORT`, для online-доставки и store): узел принимает решение, если
   у него есть ≥ `TRANSPORT_MIN_BITS` (dev: 6) младших
   нулевых битов `digest` выше байтового префикса. Недостаток → reject.
   При 6 битах ПК тратит ~0.6–1.5 с бюджета (бюджет майнинга — параметр клиента).
2. **Время хранения** — бонус за maggiore работу: при store в ячейку узел вычисляет
   `bits = кол-во ведущих нулевых битов digest` и записывает их в score записи
   (см. ниже).
3. **PoW_node** — между mix-нодами (`POW_READ`-профиль, dev `NODE_MIN_BITS = 4`),
   генерирует сама нода-отправитель на пересылке.
4. **PoW_read** — на чтение BS (dev `READ_MIN_BITS = 2`, проверка от flood-запросов).

Майнер (клиент/нода): цикл nonce = 0,1,2,… (тред-пулы, per-thread начало из CSPRNG),
до достижения требуемых битов или бюджета; если бюджет исчерпан — берём лучший
nonce при ≥ min_bits.

- **score записи** (BS eviction, §6 jproto):

  ```
  score = bits − age_penalty
  age_penalty = floor(age_s / AGE_DECAY_S)   # dev: 3600 (штраф −1 бит в час)
  ```

  Правила: ячейка < 50 → вставить. Иначе вычислить score нового и всех записей
  ячейки; выкинуть min-score запись если `score(new) > min_score`, иначе reject
  (в смысле «хранится до вытеснения», по README — «TTL нет»).

- **Верификация** — 1 вызов RandomX (~10 ms light compiled VM): O(1) для узла,
  перебор только у майнера. 

### Режимы RandomX (реализация)

| Режим | RAM | скорость (данный ПК) | использование |
|---|---|---|---|
| `light` + JIT + AES-NI | 256 MiB cache + 2 MiB scratchpad/VM | ~10 ms/hash | клиент по умолчанию, верификация узла |
| `fast` (dataset) | 2 GiB dataset | ~1.2 ms/hash | mining-farm'ы, для майна не требует |
| интерпретируемый light | ~256 MiB, без JIT | ~100 ms/hash | fallback, если нет JIT |

Инициализация cache — 324 ms, по seed'у (округление до часа) у узла и клиента;
dataset для MVP **не используется**.


## 4. Кадр wire + транспорт

Транспорт: TCP (dev, plain) или TLS 1.3 + `X25519MLKEM768` (prod). Для тестов концепции —
HTTP-обёртка на Python (POST `/jp` с бинарным телом = тот же wire-кадр).

Кадр: `[varint u32 total][type u16][flags u16][body]`, little-endian.
varint: LEB128.
body: последовательность TLV: `[type u16][len u32][value]`.
Полный список типов — `docs/wire.md`.

## 5. Onion

Число слоёв зависит от цели (анти-корреляция узла-цели с клиентским входом):

| цель | слоёв | финальная нода |
|---|---|---|
| ONLINE-доставка | 3 | home(B) |
| STORE_LOCAL / OFFER / REPLY (offline) | 4 | home(B) — пишет в Local BS |
| STORE_GLOBAL | 4 | случайная фед. — пишет в Global BS |
| BS_READ | 0 | прямое подключение (MVP; позже — туннель) |

Все узлы берутся из директории, вход n1 ≠ home(B) и т.д. случайные.
Для каждого слоя `i ∈ {1..L}` клиент выполняет `Encaps(pk_i)` → `(ct_i, ss_i)`.

Слой `i`:
```
route_digest  = SHAKE256(mix.1, r1.addr ‖ … ‖ rL.addr ‖ round(N))
layer_i       = AEAD_Enc(ss_i, nonce = CSPRNG 12B, aad = route_digest ‖ u8(i),
                          plaintext = (next.addr[32B] | ct_{i+1} | next_layer_or_payload | padding)
```

`next.addr` слоя L = 32 B нулей (L-я нода — конечная). Каждый слой — фикс.
`INNER_PACKET_SIZE = 1280 B` (padding — CSPRNG), чтобы скрыть метаданные длины.
PoW_client прикрепляется к внешнему кадру: `F_MIX_ONION = [T_POW ‖ T_PAYLOAD]`.

При peel нода i+1 получает peeled остаток: `ct_{i+2}‖layer_{i+1}` — это F_MIX_ONION
с PoW_node (генерит нода i). Финальная нода L: ONLINE → отправка клиенту, иначе —
запись в соответствующий BS.

## 6. Payload (внутри слоя L)

`msg_ct = AEAD_Enc(ss_msg, nonce=CSPRNG12, aad = (sess u32, seq u32, reply_to u32?),
 plaintext = rec (recipient.body))`, где `ss_msg` — свежий ML-KEM-768 `Encaps(pk_B)`.
Запись `(ky_ct, nonce, ct_msg, ...)` полностью указана в README (§5/§7), извлечение входа
и проверка получателя операцией Decaps(sk_B).

Типы inner-message `I_*`: `ONLINE`, `STORE_LOCAL`, `STORE_GLOBAL`, `HANDSHAKE_OFFER`,
`HANDSHAKE_REPLY`. Их поля — `docs/wire.md` и §5 wire-структуры ( recipient-payload).

## 7. BS (blind storage)

- cell_index = `SHAKE256(h.1, seed_hour ‖ pk_B ‖ salt ‖ sess)` (32 B).
- Ячейка: до `CELL_SIZE = 50` записей; запись = `(ky_ct 1088, nonce 12, ct_msg, score, ts)`.
- При отсутствии salt/sess (первое сообщение) — `salt = 0 (64B)`, `sess = 0`.
- Local BS узла: до `LOCAL_CELLS = 4096` потенциальных ячеек (dev: 256), mmap-file.
- Global BS: `GLOBAL_CELLS` (dev: 1024), реплицируется по gossip.
- Записи приходят через 4-hop onion (см. §5). Чтение — direct подключение
  с PoW_read; позже — тоже через туннель.

## 7b. Адаптация mix-генерации PoW_node

- PoW_node генерирует нода-отправитель (узел i → узел i+1) и вкладывает его в
  кадр F_MIX_ONION к получателю вместо PoW_client (в C-конфиге профиль NODE).
  При over-quota (более 2 PoW за раунд от одного пира) — reject; (rate limit
  по IP/подписи).


## 8. PFS / приватность

- Per-Message KEM (ML-KEM-768 encapsulation каждого сообщения под pk получателя).
- Loss (FS) для offline-хранилища: когда session advance — CRT-«wipe» сессионных ключей
  (см. §6 jproto README).
- Mix latency: 1–3 с на rnод (постоянный jitter) против timing-корреляций.
- Padding: `INNER_PACKET_SIZE` фикс. в onion, pадding внутри payload.
- Кеш Drop: слойีย miss → без общей ошибки сквозной связи.

## 9. C-библиотека: слои

- `crypto.c` — все примитивы (`H`, ML-KEM, ML-DSA, AEAD), без io.
- `pow.c` — argon2id + multithreaded подбора соли.
- `framing.c` — TLV/varint codec.
- `onion.c` — сборка/разбор onion.
- `beacon.c` — клиент seeds + узел-участие (позже).
- `net_uring.c` — io_uring event-loop (TCP).
- `shm.c` — POSIX shm SPSC-ring для межпроцессного IPC.
- `client.c` — top API: `send_online`, `store_offline`, `fetch_bs`, `handshake_offer`.

## 10. Python reference (stage 1)

- `python/jproto_ref/`: узел = 4 функции (beacon, mix, Local BS, Global BS) + gossip.
- TCP-wire сервер (плайн) для интеграции с C-клиентом + HTTP `/jp` для быстрых тестов.
- Reference-client на Python для кросс-тестов (свой ML-KEM через `cryptography`/или EVP-CLI).
- Harness: `pytest`-сеть федераций на разных портах.

## 11. Стадии

1. [x] Crypto core C + self-tests (nist KAT для ML-KEM/KLS-DSA).
2. [ ] Wire codec (C + Python) + interop tests.
3. [ ] Python node (beacon/mix/BS/gossip) + C client lib.
4. [ ] Интеграция: 3 федерации (9001–9003), доставка online/offline, handshake.
5. [ ] PoW-тюнинг, io_uring benchmarking, TLS-транспорт опционально.

## 12. Константы

| имя | значение |
|---|---|
| ROUND_LEN | 10 s |
| COMMIT_WINDOW | 3 s |
| REVEAL_WINDOW | 3 s |
| SEED_BLOCKS_PER_HOUR | 360 |
| CELL_SIZE | 50 |
| INNER_PACKET_SIZE | 1280 |
| MAX_MSG_PAYLOAD | 8192 |
| FEDERATION_QUORUM | 3 узла в dir (dev) |
| Логирование | JSON-lines на stderr, `-v` |
