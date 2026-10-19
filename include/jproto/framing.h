/* framing.h — wire-кодек по docs/wire.md: varint, TLV, frame. */
#ifndef JP_FRAMING_H
#define JP_FRAMING_H

#include "jproto/defs.h"

/* frame types (F_*) */
enum {
    F_HELLO = 0x0001, F_HELLO_OK = 0x0002,
    F_SEED_REQ = 0x0010, F_SEED = 0x0011,
    F_DIR_REQ = 0x0020, F_DIR = 0x0021,
    F_MIX_ONION = 0x0030, F_MIX_ACK = 0x0031,
    F_BS_STORE = 0x0040, F_BS_READ = 0x0041, F_BS_READ_RESP = 0x0042,
    F_ONLINE_DELIVER = 0x0050, F_ONLINE_ACK = 0x0051,
    F_BEACON_COMMIT = 0x0060, F_BEACON_REVEAL = 0x0061, F_BEACON_SEED = 0x0062,
    F_GOSSIP_PUSH = 0x0070, F_GOSSIP_FETCH = 0x0071, F_GOSSIP_DATA = 0x0072,
    F_PING = 0x0080, F_PONG = 0x0081,
    F_SCH_HELLO = 0x0090, F_SCH_HELLO_OK = 0x0091, F_SCH_SEALED = 0x0092,
};

/* tlv types (T_*) */
enum {
    T_PAYLOAD = 0x0001, T_SEED = 0x0002, T_ROUND = 0x0003,
    T_PK_KEM = 0x0004, T_PK_DSA = 0x0005, T_SIG = 0x0006, T_ADDR = 0x0007,
    T_NONCE = 0x0008, T_TRANSPORT = 0x0009, T_TIMESTAMP = 0x000A,
    T_CELL_IDX = 0x000B, T_CELL_REC = 0x000C,
    T_POW = 0x000D, T_POW_PAR = 0x000E, T_ERR = 0x000F,
    T_KYBER_CT = 0x0010, T_AEAD_NONC = 0x0011, T_MSG_CT = 0x0012,
    T_SALT = 0x0013, T_SESSION = 0x0014, T_SEQ = 0x0015,
    T_NODE_LIST = 0x0016, T_NODE_ENTRY = 0x0017, T_ROUTE = 0x0018,
    T_VER = 0x0019, T_CAPS = 0x001A, T_COMMIT = 0x001B,
    T_DIR_DIGEST = 0x001C, T_REC_DIGEST = 0x001E, T_PAD = 0x001F,
};

/* msg types (I_*) и профили PoW — в defs.h */

#define JP_TLV_MAX 255 /* TLV в кадре (упрощённо) */

/* ---- varint (LEB128) ---- */
size_t jp_varint_put(uint64_t v, uint8_t *out, size_t cap);
size_t jp_varint_get(const uint8_t *in, size_t inlen, uint64_t *out);
size_t jp_varint_len(uint64_t v);

/* ---- TLV writer ----
 * Простой cursor-местный писатель: jp_tlvw хранит buf/cap/len. */
typedef struct {
    uint8_t *buf; size_t cap, len; int err;
} jp_tlvw;

void jp_tlvw_init(jp_tlvw *w, uint8_t *buf, size_t cap);
void jp_tlv_put(jp_tlvw *w, uint16_t ttype, const void *val, size_t len);
void jp_tlv_u16(jp_tlvw *w, uint16_t ttype, uint16_t v);
void jp_tlv_u32(jp_tlvw *w, uint16_t ttype, uint32_t v);
void jp_tlv_u32be(jp_tlvw *w, uint16_t ttype, uint32_t v);

/* ---- frame read/parse ----
 * Кадр: [varint total][u16 type][u16 flags][body TLV...]
 * parse: возвращает JP_OK; разбирает TLV в массив. */
typedef struct {
    uint16_t ttype;
    const uint8_t *val;
    uint32_t len;
} jp_tlv;

typedef struct {
    uint16_t type, flags;
    jp_tlv tvs[JP_TLV_MAX];
    int n;
} jp_frame;

/* Разбор кадра из полного буфера (total должен совпадать). JP_ERR_FORMAT если криво. */
int jp_frame_parse(const uint8_t *in, size_t inlen, jp_frame *f);

/* Сборка кадра: пишет в out (varint+type+flags+body TLV).
 * tlv-список: указатели на исходные байты (не копируются — только в кадр). */
typedef struct {
    uint16_t type, flags;
    const jp_tlv *tvs; int n;
} jp_frame_bld;

size_t jp_frame_build(uint8_t *out, size_t cap, const jp_frame_bld *b);

/* поиск TLV */
const jp_tlv *jp_frame_find(const jp_frame *f, uint16_t ttype);

#endif
