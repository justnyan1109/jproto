#include "jproto/onion.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t out[JP_INNER_PACKET_LEN];
    uint8_t kct[1088], nonce[12], msg[37];
    jp_random(kct, 1088); jp_random(nonce, 12); jp_random(msg, 37);
    /* msg_ct = len-фикс: nonce + payload уже отдельно, так что Здесь только ct */
    assert(jp_recipient_payload_encode(out, I_STORE_LOCAL, 7, 3, kct, nonce, msg, 37) == JP_OK);

    int it; uint32_t sess, seq; const uint8_t *pk2, *an, *mc; size_t ml;
    assert(jp_recipient_payload_decode(out, &it, &sess, &seq, &pk2, &an, &mc, &ml) == JP_OK);
    assert(it == I_STORE_LOCAL && sess == 7 && seq == 3 && ml == 37);
    assert(!memcmp(pk2, kct, 1088));
    assert(!memcmp(an, nonce, 12));
    assert(!memcmp(mc, msg, 37));

    /* payload_digest зависит от полного inner (вкл. padding) */
    uint8_t d1[32], copy[JP_INNER_PACKET_LEN];
    memcpy(copy, out, JP_INNER_PACKET_LEN);
    jp_payload_digest(out, d1);
    uint8_t d2[32];
    jp_payload_digest(copy, d2);
    assert(!memcmp(d1, d2, 32));

    assert(jp_onion_layer_count(I_ONLINE) == 3);
    assert(jp_onion_layer_count(I_STORE_GLOBAL) == 4);
    printf("t_onion: OK\n");
    return 0;
}
