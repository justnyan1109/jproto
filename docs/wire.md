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
| 0x0062 | F_BEACON_SEED | node→C/node→node | финальный seed(N) + используемое упорядочение (addr-сортировка) |
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
```

## 4. Состав кадров (минимальный список TLV)

- `F_HELLO`: `T_VER`, `T_CAPS`. Ответ `F_HELLO_OK`: `T_VER`, `T_CAPS`, `T_POW_PAR`× проф.
- `F_SEED_REQ`: `T_ROUND` (clock skew клиента). Ответ `F_SEED`: `T_ROUND` ∥ `T_SEED`
  (текущий) ∥ `T_ROUND` ∥ `T_SEED` (предыдущий).
- `F_DIR_REQ`: (пусто). Ответ `F_DIR`: `T_DIR_DIGEST` ∥ `T_NODE_LIST`. Каждая
  `T_NODE_ENTRY` подписана ML-DSA-44 самим узлом: sig поверх
  `H(dirlist.1, TLV_entry_bytes)`.
- `F_MIX_ONION`: `T_POW` ∥ `T_PAYLOAD` (onion layer или peeled rest).
  Для hop→hop `T_POW` = PoW_node профиля POW_NODE; round берётся по seed(T_POW_PAR)?
  Нет: round входит во вход через peeled слой (§5).
- `F_BS_STORE`: `T_CELL_IDX` ∥ `T_CELL_REC` ∥ `T_POW` (профиль TRANSPORT).
- `F_BS_READ`: `T_CELL_IDX` ∥ `T_POW` (профиль READ). Ответ `F_BS_READ_RESP`:
  0..50× `T_CELL_REC` (в порядке убывания score).
- `F_ONLINE_DELIVER`: `T_PAYLOAD` = recipient-payload **неизменным** (узел не Decaps):
  kyber_ct(1088) ‖ nonce(12) ‖ msg_ct.
- `F_BS_READ_RESP` может содержать `T_ERR` при отказе (порог PoW и т.п.).

## 5. Onion-структура (binary)

Слой i — ровно `INNER_PACKET_SIZE = 1280` B (число слоёв L по цели — см. §5 protocol.md):
```
aead_nonce            12 B   CSPRNG на клиенте
layer_ct             1268 B  = AEAD(ss_i, AD = route_digest(32 B) ‖ u8(i),
                                PT = next_addr(32) [0^32 на слое L]
                                   ‖ u16 ct_len ‖ ct_{i+1} (1088 при i<L)
                                   ‖ inner_PT[до заполнения]
                                 ), padding доводит до 1268
route_digest = SHAKE256(mix.1, r1.addr ‖ … ‖ rL.addr ‖ round(N))
```
Внутренний plaintext слоя 3 (recipient-payload):
```
magic u16 = 0x4A50 ('JP')
ver   u8  = 1
itype  u8  = I_={1 ONLINE,2 STORE_LOCAL,3 STORE_GLOBAL,4 OFFER,5 REPLY}
session u32
seq    u32
body_len u16
body: kyber_ct(1088) ‖ nonce(12) ‖ msg_ct(body_len−1100)
padding CSPRNG до INNER_PACKET_SIZE
```
AAD слоя 3 опционально включает PoW cert (связь PoW ↔ payload: переиспользование
PoW cert с другой payload недопустимо). payload_digest для PoW считается
по recipient-payload (весь inner де-толщина) — по константному входу.

## 6. PoW cert (T_POW)
```
nonce    u64   LE
bits     u8
profile  u8    1=TRANSPORT 2=NODE 3=READ
reserved u8[6] = 0
```
Проверка узла: получить payload_digest ( определён §3 protocol.md), вычислить
`RandomX_H(seed_hour, seed_round ‖ payload_digest ‖ nonce)`, посчитать ведущие
нулевые биты → `bits ≥ required(profile, round)`.


## 7. Beacon-кадры

- `F_BEACON_COMMIT`: `T_ROUND` ∥ `T_COMMIT(32)`; подпись commit не нужна, но
  reveal подписывается (см. §2 protocol.md).
- `F_BEACON_REVEAL`: `T_ROUND` ∥ `T_SEED(v)` ∥ `T_NONCE(r 16)` ∥ `T_SIG`.
- `F_BEACON_SEED`: `T_ROUND` ∥ `T_SEED` ∥ список участвовавших `T_ADDR`.

## 8. Gossip (Global BS sync)

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

