# jproto — wire-формат v1

Все целые little-endian. Так как nonce/PoW и/или mix-пакеты прогоняются через RandomX,
регистр бости строго детерминирован; сериализация байтов фикс в этом документе.

## 1. Базовые структуры

### varint (LEB128)
`u64` → байты: 7 бит на байт от младших, старший бит 0 в последнем.

### Frame (кадр TCP-потока)
```
varint(total_len)   # длина части после varint, включая type+flags+body
u16 type            # F_* константы
u16 flags           # биты: 0x0001 NEEDS_ACK и т.п.
body                # последовательность TLV (см. ниже)
```

### TLV
```
u16 ttype           # T_* константы (0 = reserved, недопустим)
u32 tlen
value(tlen байт)
```
Неизвестные ttype получатель обязан игнорировать (forward compat). TLV
разрешены в любом порядке; получатель ищет TLV по ttype (не по позиции),
но продюсер обязан выдавать в описанном в §4 порядке.

## 2. Frame types (f-типы)

| Тип | имя | направление | описание |
|---|---|---|---|
| 0x0001 | F_HELLO | C↔node, node↔node | согласование вер. протока, capabilities |
| 0x0002 | F_HELLO_OK | → просящий | подтверждение + параметры (профили PoW и пр.) |
| 0x0010 | F_SEED_REQ | C→node | просьба текущего seed(N) и seed(N−1) + раунд |
| 0x0011 | F_SEED | node→C | seed(N), round(N), seed(N−1), round(N−1) |
| 0x0020 | F_DIR_REQ | C→node | запрос директории (federation list) |
| 0x0021 | F_DIR | node→C | список узлов + подписи (self-signed ML-DSA-44) |
| 0x0030 | F_MIX_ONION | C→node, node→node | onion-пакет + PoW_client (проверка на входной ноде), либо peeled слой + PoW_node |
| 0x0031 | F_MIX_ACK | узел i+1 → узел i (если flags NEEDS_ACK) | hop-статус: OK / STORE_DONE |
| 0x0040 | F_BS_STORE | C→BS-нода напрямую, либо через mix | запись в BS |
| 0x0041 | F_BS_READ | C→BS-нода напрямую | запрос ячейки (с PoW_read) |
| 0x0042 | F_BS_READ_RESP | BS-нода→C | записи ячейки (N× T_CELL_REC) |
| 0x0050 | F_ONLINE_DELIVER | home-нода→клиент | recipient-payload нерасшифрованным: ky_ct ‖ nonce ‖ msg_ct (opaque для узла) |
| 0x0051 | F_ONLINE_ACK | клиент→home-нода | подтверждение доставки (для MVP узел может игнорировать) |
| 0x0060 | F_BEACON_COMMIT | node↔node | commit узла: SHAKE256(beacon.1, seed(N−1)‖v‖r) подписи нет |
| 0x0061 | F_BEACON_REVEAL | node↔node | reveal (v, r) + ML-DSA-44 sig узла |
| 0x0062 | F_BEACON_SEED | node→C/node→node | финальный seed(N) + использованное упорядочение (pk-сортировка §2) |
| 0x0090 | F_SCH_HELLO | C→S | secchan handshake: T_PK_KEM, T_PK_DSA, T_SIG |
| 0x0091 | F_SCH_HELLO_OK | S→C | secchan handshake: T_KYBER_CT, T_PK_DSA, T_SIG |
| 0x0092 | F_SCH_SEALED | bidir | secchan насыпанный кадр: T_SEQ, T_MSG_CT |
| 0x0070 | F_GOSSIP_PUSH | node↔node | Global BS diff: список индексов ячеек + digest записей + score/ts |
| 0x0071 | F_GOSSIP_FETCH | node↔node | запрос нужных записей по digest |
| 0x0072 | F_GOSSIP_DATA | node↔node | ответы на FETCH (сами записи) |
| 0x0080 | F_PING | any | heartbeat/RTT, echo payload |
| 0x0081 | F_PONG | any | эхо |

## 3. TLV types (T-типы)

Общие:
```
T_PAYLOAD   0x0001   binary: основная полезная нагрузка (onion-слой / cyphertext и т.п.)
T_SEED      0x0002   32 B seed
T_ROUND     0x0003   u64 round N
T_PK_KEM    0x0004   1184 B ML-KEM-768 pk
T_PK_DSA    0x0005   1312 B ML-DSA-44 pk
T_SIG       0x0006   2420 B ML-DSA-44 sig
T_ADDR      0x0007   32 B address (digest pk)
T_NONCE     0x0008   8..32 B nonce/salt
T_TRANSPORT 0x0009   (host cstring, port u16, tls: bool) transport-адрес узла
T_TIMESTAMP 0x000A   u64 unix_ts (мс)
T_CELL_IDX  0x000B   32 B cell index
T_CELL_REC  0x000C   запись BS: ky_ct(1088) ‖ nonce12 ‖ ct_msg ‖ score(u32) ‖ ts(u64)
T_POW       0x000D   PoW cert: nonce(u64) ‖ bits(u8) ‖ profile(u8, зарезерв.)
T_POW_PAR   0x000E   параметры PoW round проф. (u8 profile, u8 bits, u32 budget_hint, u8 mode)
T_ERR       0x000F   код ошибки (u16) + строка (опционально)
T_KYBER_CT  0x0010   1088 B ct из Encaps (ML-KEM ct в сообщениях BS/online)
T_AEAD_NONC 0x0011   12 B nonce AEAD
T_MSG_CT    0x0012   AEAD ciphertext сообщения
T_SALT      0x0013   64 B salt (handshake)
T_SESSION   0x0014   u32 session number
T_SEQ       0x0015   u32 seq внутри сессии
T_NODE_LIST 0x0016   N× T_NODE_ENTRY (конкатенация вложенных TLV)
T_NODE_ENTRY 0x0017  вложенные TLV: T_ADDR ‖ T_PK_KEM ‖ T_PK_DSA ‖ T_TRANSPORT
T_ROUTE     0x0018   3 адреса маршрута по 32 B
T_VER       0x0019   u16 версия протокола / codec-теги
T_CAPS      0x001A   u32 capabilities bitmap
T_COMMIT    0x001B   32 B commit beacon-участника
T_DIR_DIGEST 0x001C  32 B digest директории
T_PAD       0x001F   padding (CSPRNG)
T_STOR_PAR  0x0022   статистика хранения ноды (24 B, §6a)
```

## 4. Состав кадров (минимальный список TLV)

- `F_HELLO`: `T_VER`, `T_CAPS`. Ответ `F_HELLO_OK`: `T_VER`, `T_CAPS`, `T_POW_PAR`× проф.
- `F_SEED_REQ`: `T_ROUND` (clock skew клиента). Ответ `F_SEED`: `T_ROUND` ∥ `T_SEED`
  (текущий) ∥ `T_ROUND` ∥ `T_SEED` (предыдущий).
- `F_DIR_REQ`: (пусто). Ответ `F_DIR`: `T_DIR_DIGEST` ∥ `T_NODE_LIST`. Каждая
  `T_NODE_ENTRY` подписана ML-DSA-44 самим узлом: sig поверх
  `H(dirlist.1, TLV_entry_bytes)`.
- `F_MIX_ONION`: `T_PAYLOAD` ∥ `T_POW` (порядок фактически свободный, TLV ищутся по типу).
  **Cert — только на entry**: первый hop клиента к ноде n1 несёт T_POW
  (профиль TRANSPORT, digest = H(pow.1, packet)); кадры hop→hop после peel идёт
  БЕЗ T_POW (sealed по secchan; тарифицируются rate-limit 5 msg/s/IP как entry).
  Опциональный POW_NODE внутри R — план BS-ноды, отдельный профиль (§6).
- `F_BS_STORE`: `T_CELL_IDX` ∥ `T_CELL_REC` ∥ `T_POW` (профиль TRANSPORT;
  digest = H(pow.1, idx ‖ rec), cert по seed раунда ±1). `T_CELL_REC` = value
  (≥ ky+nonce+tag) ‖ score(u32) ‖ ts(u64) — хвост 12 B клиентский, нода
  перезаписывает своим score при вставке.
- `F_BS_READ`: `T_CELL_IDX` ∥ `T_POW` (профиль READ). Ответ `F_BS_READ_RESP`:
  0..50× `T_CELL_REC` (в порядке убывания score).
- `F_ONLINE_DELIVER`: `T_PAYLOAD` = recipient-payload **неизменным** (узел не Decaps):
  kyber_ct(1088) ‖ nonce(12) ‖ msg_ct.
- `F_BS_READ_RESP` может содержать `T_ERR` при отказе (порог PoW и т.п.).

## 5. Onion-структура (binary)

Пакет целиком: `packet = kem_ct_i(1088) ‖ blob_i` (наружный F_MIX payload).
Слой после peel нодой i даёт PT_i, внутри которого всё для следующего hop'а:

```
blob_i    = aead_nonce(12) ‖ AEAD_ct(+tag 16),  AD = "jproto.onion.1" (14 B)
PT_i      = next_addr(32) ‖ u16 ctl ‖ [ct_{i+1}(1088) если ctl=1088] ‖ blob_{i+1}
финальный слой (i=L): next_addr = 0^32, ctl = 0 ⇒ remainder = R (recipient-payload)
```

Длины детерминированы базой R:

```
|R| (RPL_LEN_FIXED)         = 7028 B   (wire-константа, msg паддингом CSPRNG)
blob(depth d)               = 7090 + (d−1)*1150
packet(L)                   = 1088 + blob(L):  L=3 → 10478,  L=4 → 11628
```

`ctl = 1088` у промежуточных слоёв, `0` — у финального; это единственная метка
«последний слой» (контроль магии R catcher'ом BS/адресата).

Recipient-payload R (7028 B, **v2.1**):
```
hdr 24 B:   magic u16 'JP', ver u8=1, itype u8, session u32, seq u32,
            pow_nonce u64 LE, pow_bits u8, pow_prof u8, body_len u16
dest 32 B:  cell-индекс BS-ноды (0^32 = legacy: cell = h_cell(value))
body:       kyber_ct(1088) ‖ aead_nonce(12) ‖ msg_ct(msg+tag16)
tail:       CSPRNG padding до 7028 (в body_len не входит)
```
max длина msg сужена до **5856** B (−32 за счёт dest; |R| и длины
blob/packet не изменились: L3 → 10478, L4 → 11628). dest не входит в AD
сообщения — получатель расшифровывает как раньше; BS-нода кладёт запись в
`dest` без вычисления h_cell. dest зад отправитель до майнинга NODE-cert —
в «круг» дайджеста не попадает.

msg_ct = AEAD(ss_msg, AD = itype‖session‖seq (9 B), plaintext = msg), ss_msg —
свежий ML-KEM-768 `Encaps(pk_B)`. PoW-сертификаты: TRANSPORT-профиль (nonce/bits)
идёт TLV `T_POW` наружного кадра F_MIX_ONION (дайджест = H(pow.1, packet));
NODE-профиль живёт в заголовке R (дайджест — каноничный, с нулевым
pow_nonce — детали §6).

## 6. PoW cert (T_POW)

```
nonce    u64   LE
bits     u8
profile  u8    1=TRANSPORT 2=NODE 3=READ
```

Проверка RandomX-сертификата: `digest_Rx = RandomX_H(key = seed_hour(32),
input = seed_round(32) ‖ payload_digest(32) ‖ nonce)`, требование — ведущие
нулевые биты digest_Rx ≥ bits ≥ required(profile, round). Два места привязки:

| профиль | payload_digest = | кто проверяет | где nonce |
|---|---|---||
| TRANSPORT | H(pow.1, onion-пакет целиком) | entry-нода n1 (анти-flood) | TLV T_POW наружного кадра |
| NODE | H(pow.1, R с **обнулённым** байтовым полем 12..20) | BS-нода nL (storage-скора/квота) | байт 12..20 заголовка R |
| READ | H(pow.1, read-запрос) | BS при чтении | T_POW кадра запроса |

NODE-нормализация: nonce не может входить в свой собственный digest
(chicken-egg) — клиент майнит по R с нулевым pow_nonce, затем вписывает
найденное значение в байты 12..20; верификация обнуляет поле перед хэшем.
DEST (32 B, байты 24..56 R) известен до майнинга — в нормализацию не входит.

Пересчёт в payload_digest записи изменять нельзя — PoW сертифицирует
конкретный пакет (переиспользование с другим payload недопустимо).

## 6a. Опубликованная статистика хранения (T_STOR_PAR)

Каждая нода публикует параметры BS-таблиц в `F_HELLO_OK` (своя) и `F_DIR`
(своя свежая), TLV `T_STOR_PAR = 0x0022`, 24 B:

```
u32 slots_lbs          # S_eff локальной таблицы (ячеек; авторазмер или пин)
u32 slots_gbs          # ячеек федерационного среза
u32 lam_est_day        # λ: записей/день (rolling-окно)
u8  window_h           # окно оценки λ (24–72 ч)
u8  bits_min           # текущий пол admission (контроллер; ≥ опер. пола)
u16 tau_h              # score decay: −1 бит / τ (деф. 168 = неделя)
u32 retention_est_h    # ожидаемое удержание при min-сложности:
                       #   min(bits_min·τ, capacity/λ)
u32 n_active           # HELLO-registered клиентов (self-reported)
```

Клиентское решение (запись хочет жить T_want): `bits = bits_min +
⌈(T_want − retention_est_h)/τ⌉` при retention_est_h < T_want, иначе
bits_min. Контроллер ноды (моно-политики): S_eff только вверх (анонимный
«стог» не сжимается), bits_min только вверх; рост ×2 при давке ≥0.8 или
переполнении, bits_min+1 — когда бюджет памяти исчерпан.

## 7. Secchan — шифрованный канал (нода↔нода, клиент↔нода)

Директива: **beacon commit/reveal/gossip передаются только по secchan**;
синхронизация раундов (окна, тайминги) остаётся несекретной — её защищают
ML-DSA подписи, а не шифрование.

Рукопожатие (plaintext-кадры, ключи внутри):
```
C→S  F_SCH_HELLO:     T_PK_KEM(c 1184), T_PK_DSA(c 1312), T_SIG(c 2420)
                      sig_c = ML-DSA-44(sk_c, "JPCS1" ‖ kem_pk_c(1184))
S→C  F_SCH_HELLO_OK:  T_KYBER_CT(ct_s 1088), T_PK_DSA(s 1312), T_SIG(s 2420)
                      ct_s = Encaps(kem_pk_c)
                      sig_s = ML-DSA-44(sk_s, "JPCS2" ‖ kem_pk_c ‖ ct_s)
```
Вывод ключей (`ss` = Decaps(kem_sk_c, ct_s)):
```
th = SHAKE256(secch.1, kem_pk_c(1184) ‖ ct_s(1088))          # transcript 32 B
K  = SHAKE256(secch.1, ss(32) ‖ th(32)) → 88 B:
     c2s.key(32) ‖ c2s.nonce_base(12) ‖ s2c.key(32) ‖ s2c.nonce_base(12)
```
Насыпанный кадр `F_SCH_SEALED`: TLV `T_SEQ(u64 LE)` ∥ `T_MSG_CT`:
```
nonce = nonce_base; nonce[4..12] ^= u64_le(seq)
AD    = "JPSFR" ‖ u64_le(seq)      (13 B)
```
`seq` строго `+1` по каждому направлению (replay/loss → кадр отбрасывается,
соединение помечается испорченным). Плейнтекст `T_MSG_CT` = **полные байты
wire-кадра** (`varint(total)` + payload) — канальная прозрачность: всё, что
отправитель послал бы в plain TCP, зашифровывается как один blob. После
расшифровки принимающая сторона читает кадр обычным кодеком.

Принятие handshake (`F_SCH_HELLO` первым кадром соединения) переводит
соединение в sealed-режим целиком; любой другой первый кадр остаётся plain
(dev-совместимость клиентов, узкое место: plain_ok — конфиг ноды).

Клиент проверяет pk ноды по TOFU-pin (жёстко после первого контакта);
сервер проверяет только владение подписью клиента (транзитные пиры).


## 8. Beacon-кадры

- `F_BEACON_COMMIT`: `T_ROUND` ∥ `T_COMMIT(C_i 32)` ∥ `T_PK_DSA` ∥ `T_SIG`
  (sig = ML-DSA-44(sk_i, "JPCOMMIT" ‖ round ‖ C_i) — см. §2 protocol.md).
- `F_BEACON_REVEAL`: `T_ROUND` ∥ `T_SEED(v)` ∥ `T_NONCE(r 16)` ∥ `T_SIG`
  (sig = ML-DSA-44(sk_i, "JPREVEAL" ‖ round ‖ v ‖ r)).
- `F_BEACON_SEED`: `T_ROUND` ∥ `T_SEED` ∥ список участвовавших `T_PK_DSA`.

Все три типа передаются только через secchan (§7).

**Синхронизация с реальным временем:** метка раунда N = `⌊unix_ts/10⌋`
(границы строго на стен-часе, round_len обязан делить 3600 ⇒ BS-час =
6·60 = 360 раундов, ячейки доски меняются ровно на отметке часа).
Расписание раунда N: commit N в `[10N, 10N+3)`, reveal в `[10N+3, 10N+6)`,
слэк до границы; **finalize на границе ровно `10(N+1)`** — seed с меткой
N+1 публикуется в круглую отметку (данные раунда N → seed раунда N+1).
«Время доступности нового сида» = круглые отметки k·10s; PoW-привязки
верифицируются по окну (n−1, n, n+1).

## 9. Gossip (Global BS sync)

Global BS держит записи с адресацией по `cell_index` (32 B). Синхронизация push-моделью:

- `F_GOSSIP_PUSH`: `T_ROUND` (hour) ∥ N×(`T_CELL_IDX` ∥ `T_REC_DIGEST(32 H(rec*))` ∥
  score u32 ∥ ts u64). Смысл: «у меня есть эти записи, score у меня такой».
- `F_GOSSIP_FETCH`: список `T_REC_DIGEST`, которых у получателя от этого узла нет.
- `F_GOSSIP_DATA`: `T_CELL_IDX` ∥ `T_CELL_REC` × N.

`T_REC_DIGEST` — нужен новый ttype, добавляем:

```
T_REC_DIGEST 0x001E   32 B H(rec) записи BS
```

Правило слияния: при разных score/ts одной записи (случай коллизии digest почти
невозможен — digest определяет rec) приоритет по score; при равенстве — по ts.

