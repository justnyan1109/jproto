#include "jproto/framing.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t buf[4096];
    jp_tlvw w; jp_tlvw_init(&w, buf, sizeof buf);
    const char msg[] = "hello wire";
    jp_tlv_put(&w, T_PAYLOAD, msg, sizeof msg);
    jp_tlv_u16(&w, T_VER, JP_PROTO_VERSION);
    jp_tlv_u32(&w, T_ROUND, 12345);
    uint8_t addr[32]; memset(addr, 0xAB, 32);
    jp_tlv_put(&w, T_ADDR, addr, 32);
    assert(w.err == JP_OK);

    jp_frame_bld b = { .type = F_HELLO, .flags = 1, .tvs = NULL, .n = 0 };
    jp_tlv tlvs[16]; int n = 0;
    /* соберём TLV list в кусках из w.buf: человекоподобная «интерпретация»:
       парсим body как TLV sequence вручную */
    size_t off = 0;
    while (off < w.len) {
        tlvs[n].ttype = buf[off] | (buf[off+1] << 8);
        tlvs[n].len  = buf[off+2] | (buf[off+3] << 8) | (buf[off+4] << 16) | ((uint32_t)buf[off+5] << 24);
        tlvs[n].val  = buf + off + 6;
        off += 6 + tlvs[n].len; n++;
    }
    b.tvs = tlvs; b.n = n;

    uint8_t frame[4096]; size_t flen = jp_frame_build(frame, sizeof frame, &b);
    assert(flen > 0);
    jp_frame f;
    assert(jp_frame_parse(frame, flen, &f) == JP_OK);
    assert(f.type == F_HELLO && f.flags == 1 && f.n == 4);
    const jp_tlv *t = jp_frame_find(&f, T_PAYLOAD);
    assert(t && t->len == sizeof msg && !memcmp(t->val, msg, t->len));
    t = jp_frame_find(&f, T_VER);
    assert(t && t->len == 2 && t->val[0] == JP_PROTO_VERSION);
    t = jp_frame_find(&f, T_ROUND);
    uint32_t round = t->val[0] | (t->val[1]<<8) | (t->val[2]<<16) | ((uint32_t)t->val[3]<<24);
    assert(round == 12345);
    t = jp_frame_find(&f, T_ADDR);
    for (int i = 0; i < 32; i++) assert(t->val[i] == 0xAB);
    printf("t_framing: OK (%zu bytes frame)\n", flen);
    return 0;
}
