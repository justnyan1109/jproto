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

## 2. Beacons (раундовый seed) — hbdrand v2 (commit-reveal + подписи + проверяемость)

Требования: post-quantum (без EC/BLS), без отдельного координатора, клиенты могут
проверить seed сами по публичным данным, злоумышленник-меньшинство не может
grinding’ом сместить seed, DoS одной нодой останавливает только её вклад.

### 2.0. Транспорт beacon-фазы (директива)

`commit/reveal/seed` фреймы передаются **только внутри secchan** (шифрованный
ML-KEM-768+ChaCha20-Poly1305 канал нода↔нода, wire.md §7): распределённая
генерация сидов защищается шифрованием — пассивный наблюдатель не видит ни
значений v_i, ни кто/когда вносит вклад. Синхронизация раундов (окна,
границы на стен-часе) несекретна по своей природе — её достаточно
защищать ML-DSA-подписями.

### 2.1. Правила раунда

`N = floor(unix_ts/10)`; длина раунда `ROUND_LEN = 10 s` (обязана делить
3600 ⇒ BS-час = 6·60 = 360 раундов, границы на стен-часе); окно коммитов
`t0..t0+3s`, окно ревейлов `t0+3s .. t0+6s`, слэк до границы; финализация —
**ровно на границе `t0(N+1) = 10(N+1)`** (см. §2.2.4 и wire.md §8).

**Шаг A — commit** (в окне a): каждая нода рассылает всем НОДАМ
```
C_i  = SHAKE256(beacon.1, seed(N) ‖ N ‖ pk_i ‖ v_i ‖ r_i)       # 32 B
sig_commit = ML-DSA-44(sign, sk_i, "JPCOMMIT"‖N‖C_i)
кадр F_BEACON_COMMIT: T_ROUND, T_COMMIT(C_i), T_SIG, T_PK_DSA(pk_i)
```
`seed(N)` опубликована ровно на границе `10N` — к окну коммита раунда N
она доступна всем узлам (wall-clock sync). Сигнатура обязательна: она
перекрывает «подмену коммита после чужих» (grinding по составу) и даёт
доказуемый double-commit.

**Шаг B — reveal** (в окне b): reveal подтверждён коммитом:
```
reveal_i = (v_i, r_i), sig_reveal = ML-DSA-44(sk_i, "JPREVEAL"‖N‖v_i‖r_i)
кадр F_BEACON_REVEAL: T_ROUND, T_SEED(v_i), T_NONCE(r_i), T_SIG
participants: проверка SHAKE256(beacon.1, seed(N)‖N‖pk_i‖v_i‖r_i) == C_i,
наличие валидной commit-сигнатуры того же pk (mismatch → reject).
```

**Шаг C — финализация** (ровно на границе `10(N+1)`): участники round_N =
«легальные» reveal (свежая ML-DSA-44 sig + совпадающий commit). Упорядочим
v_i по лексикографическому pk_i:
```
seed(N+1) = SHAKE256(beacon.1, seed(N) ‖ N ‖ v_{1} ‖ v_{2} ‖ … ‖ v_{k})
```
где k — число подтверждённых (норм. k ≥ 2 при FEDERATION_QUORUM=3).
Публикация `F_BEACON_SEED` с меткой **N+1** ровно на границе: «время
доступности нового сида» — круглая отметка k·10s; метка сида совпадает
с раундом, в котором её используют PoW-привязки.

### 2.2. Анти-grinding / DoS / подмена

1. **Double-commit**: два разных C при одном pk (основано на валидной sig) —
   инцидент → pk изгоняется из квора до ручного рестарта (ЛОГ).
2. **Abstain в reveal**: нода вовремя не прислала reveal — её вклад просто
   пропускается в этом раунде (**k−1 участвует**). Цена — потеря «энтропии»,
   порог валидации всё равно держится большинством. В глобальном мониторинге
   замеряется «resp_rate», малый rate → узел понижается.
3. **Grind по времени**: reveal-кадры, прибывшие позже `t0+6s`, **не входят** в
   финализацию (жёсткое правило; до границы — слэк). Last-second «отложенный»
   reveal не даёт grinding-возможности: окно закрывается по стен-часу всех
   участников (NTP), систематически «глубокая» в окне b нода понижается по
   resp_rate (см. п.2).

4. **Emergency**: в мини-сетях, если valid commits < 2 — seed(N+1) = seed(N)
   (цепочка «стоит»), каждый узел ждёт до t0(N+1); раунд «пролетает».
   Изоляция этой ситуации: raiseng «emergency count»...
5. **Проверяемость публикации**: любой клиент скачивает seed(N) у любой ноды
   (кадр `F_BEACON_SEED`), проверяет: (a) все commit/reveal sig, (b) сортировку,
   (c) пересчит SHAKE-объединение и сверяет. → «seed честный» есть proof.

### 2.3. Получение seed клиентов

Клиент перед отправкой запрашивает seed у любой федерационной ноды.
Ответ содержит seed(N)/seed(N−1) (запас на небольшой clock skew −).
При недоступности seed — буфер отвечает треки.

### 2.4. Подпись свойств

| Свойство | где гарантируется |
|---|---|
| unПрedictable future seed | commit-фаза (v скрыт) |
| none-biasable joining | подписать commit невозможно дважды |
| связь рауnd ↔ определён маршрут | seed(N−1) в свяже |
| честный Public_entropy время | H(...) баланс CSPRNG всех нод |


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
- **payload_digest** зависит от профиля (см. wire.md §6):
  · TRANSPORT → SHAKE256(pow.1, onion-пакет целиком) — проверяет entry n1;
  · NODE → SHAKE256(pow.1, recipient-payload R, 7028 B) — проверяет BS-нода;
  · READ → SHAKE256(pow.1, read-запрос) — проверяет BS.

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

Все узлы берутся из директории, вход n1 ≠ home(B) и т.д. случайные. Для каждого
слоя клиент делает `Encaps(pk_i)` → `(ct_i, ss_i)`; пакет
`packet = ct_1 ‖ blob_1` целиком (бинарная сборка — wire.md §5):

```
blob_i  = nonce(12) ‖ AEAD(ss_i, AD = "jproto.onion.1", PT = PT_i)
PT_i    = next_addr(32) ‖ u16 ctl ‖ [ct_{i+1} 1088] ‖ blob_{i+1}
финал (i=L): next_addr = 0^32, ctl = 0, remainder = R (recipient-payload 7028)
```

Длины детерминированы (R фиксирован; msg паддится CSPRNG): `packet(3) = 10478 B`
(ONLINE), `packet(4) = 11628 B` (offline/BS). PoW TRANSPORT идёт TLV наружу
(`F_MIX_ONION = [T_POW ‖ T_PAYLOAD]`); PoW NODE — внутри заголовка R (nonce u64
на 12..20 байте), поэтому entry-нода не видит его, а BS-нода может пересчитать
независимо (score/квота хранения).

При peel нода i+1 получает `ct_{i+2}‖blob_{i+2}` (тот же формат F_MIX_ONION).
Финальная нода L: ONLINE → доставка адресату, иначе — запись в соответствующий BS
(после проверки PoW NODE по профилю).

## 6. Payload (внутри слоя L)

Recipient-payload R (7028 B, детальное поле-на-поле — wire.md §5):

```
hdr 24 B: 'JP', ver=1, itype, session u32, seq u32, pow_nonce u64, pow_bits, pow_prof, body_len u16
body: kyber_ct(1088) ‖ aead_nonce(12) ‖ msg_ct(+tag16)      [CSPRNG-паддинг до 7028]
msg_ct = AEAD(ss_msg, AD = itype‖session‖seq, msg),  ss_msg = свежий Encaps(pk_B)
```

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
| RPL_LEN_FIXED (R) | 7028 B |
| MSG_PAYLOAD_MAX | 5888 B |
| ONION packet (L=3 / L=4) | 10478 / 11628 B |
| MAX_ROUNDS_SK | ~память… dev | (в v1 — статический) |
| FEDERATION_QUORUM | 3 узла в dir (dev) |
| Логирование | JSON-lines на stderr, `-v` |
