/* framing.c — кодек wire (LE little-endian; TLV; varint LEB128). */
#include "jproto/framing.h"
#include <string.h>

size_t jp_varint_len(uint64_t v) {
    size_t n = 1;
    while (v >= 0x80) { v >>= 7; n++; }
    return n;
}

size_t jp_varint_put(uint64_t v, uint8_t *out, size_t cap) {
    size_t need = jp_varint_len(v);
    if (cap < need) return 0;
    size_t i = 0;
    while (v >= 0x80) { out[i++] = (uint8_t)(v | 0x80); v >>= 7; }
    out[i++] = (uint8_t)v;
    return need;
}

size_t jp_varint_get(const uint8_t *in, size_t inlen, uint64_t *out) {
    uint64_t v = 0; size_t shift = 0, i = 0;
    for (; i < inlen && i < 10; i++) {
        v |= ((uint64_t)(in[i] & 0x7F)) << shift;
        if (!(in[i] & 0x80)) { *out = v; return i + 1; }
        shift += 7;
    }
    return 0; /* недоделано / слишком длинно */
}

void jp_tlvw_init(jp_tlvw *w, uint8_t *buf, size_t cap) {
    w->buf = buf; w->cap = cap; w->len = 0; w->err = JP_OK;
}

static void w_mem(jp_tlvw *w, const void *src, size_t n) {
    if (w->err) return;
    if (w->len + n > w->cap) { w->err = JP_ERR_NOMEM; return; }
    if (src) memcpy(w->buf + w->len, src, n);
    w->len += n;
}

static void w_u16le(jp_tlvw *w, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)(v >> 8) };
    w_mem(w, b, 2);
}

static void w_u32le(jp_tlvw *w, uint32_t v) {
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    w_mem(w, b, 4);
}

void jp_tlv_put(jp_tlvw *w, uint16_t ttype, const void *val, size_t len) {
    if (ttype == 0 || len > 0xFFFFFFFFull) { w->err = JP_ERR_FORMAT; return; }
    w_u16le(w, ttype);
    w_u32le(w, (uint32_t)len);
    w_mem(w, val, len);
}

void jp_tlv_u16(jp_tlvw *w, uint16_t ttype, uint16_t v) {
    w_u16le(w, ttype); w_u32le(w, 2);
    uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)(v >> 8) };
    w_mem(w, b, 2);
}

void jp_tlv_u32(jp_tlvw *w, uint16_t ttype, uint32_t v) {
    w_u16le(w, ttype); w_u32le(w, 4);
    uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
    w_mem(w, b, 4);
}

void jp_tlv_u32be(jp_tlvw *w, uint16_t ttype, uint32_t v) {
    w_u16le(w, ttype); w_u32le(w, 4);
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    w_mem(w, b, 4);
}

/* ---- frame ---- */

static const uint8_t *ru16(const uint8_t *p, uint16_t *v) {
    *v = (uint16_t)(p[0] | (p[1] << 8));
    return p + 2;
}
static const uint8_t *ru32(const uint8_t *p, uint32_t *v) {
    *v = (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24));
    return p + 4;
}

int jp_frame_parse(const uint8_t *in, size_t inlen, jp_frame *f) {
    if (!in || inlen < 2) return JP_ERR_FORMAT;
    uint64_t total = 0;
    size_t vh = jp_varint_get(in, inlen, &total);
    if (vh == 0 || total < 4 || total > JP_FRAME_MAX) return JP_ERR_FORMAT;
    if (vh + total != inlen) return JP_ERR_FORMAT;   /* полный буфер кадра */
    const uint8_t *p = in + vh, *end = in + inlen;
    p = ru16(p, &f->type);
    p = ru16(p, &f->flags);
    f->n = 0;
    size_t need = 2;
    while (p + need <= end && f->n < JP_TLV_MAX) {
        uint16_t t; uint32_t l;
        p = ru16(p, &t); p = ru32(p, &l);
        if (t == 0 || (size_t)(end - p) < l) return JP_ERR_FORMAT;
        f->tvs[f->n].ttype = t;
        f->tvs[f->n].val = p;
        f->tvs[f->n].len = l;
        f->n++;
        p += l;
        if (p > end) return JP_ERR_FORMAT;
        if (p == end) break;
    }
    return (p == end) ? JP_OK : JP_ERR_FORMAT;
}

const jp_tlv *jp_frame_find(const jp_frame *f, uint16_t ttype) {
    for (int i = 0; i < f->n; i++)
        if (f->tvs[i].ttype == ttype) return &f->tvs[i];
    return NULL;
}

size_t jp_frame_build(uint8_t *out, size_t cap, const jp_frame_bld *b) {
    /* body size */
    size_t body = 0;
    for (int i = 0; i < b->n; i++) body += 6 + b->tvs[i].len;
    size_t need = jp_varint_len(4 + body) + 4 + body;
    if (cap < need) return 0;
    size_t i = jp_varint_put(4 + body, out, cap);
    out[i++] = (uint8_t)(b->type & 0xFF);
    out[i++] = (uint8_t)(b->type >> 8);
    out[i++] = (uint8_t)(b->flags & 0xFF);
    out[i++] = (uint8_t)(b->flags >> 8);
    for (int t = 0; t < b->n; t++) {
        const jp_tlv *v = &b->tvs[t];
        out[i++] = (uint8_t)(v->ttype & 0xFF);
        out[i++] = (uint8_t)(v->ttype >> 8);
        out[i++] = (uint8_t)(v->len & 0xFF);
        out[i++] = (uint8_t)((v->len >> 8) & 0xFF);
        out[i++] = (uint8_t)((v->len >> 16) & 0xFF);
        out[i++] = (uint8_t)((v->len >> 24) & 0xFF);
        if (v->len) { memcpy(out + i, v->val, v->len); i += v->len; }
    }
    return i;
}
