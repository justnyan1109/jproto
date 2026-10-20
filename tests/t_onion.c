/* t_onion — msg→R→onion build/peel по полному маршруту, tamper-тест */
#include "jproto/client.h"
#include "jproto/crypto.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void mk_peer(jp_peer *p, uint8_t sk[JP_KEM768_SK_LEN]) {
    uint8_t pk[JP_KEM768_PK_LEN];
    assert(jp_kem768_keygen(pk, sk) == JP_OK);
    memcpy(p->kem_pk, pk, JP_KEM768_PK_LEN);
    jp_addr(pk, JP_KEM768_PK_LEN, p->addr);
}

int main(void) {
    /* маршрут 3 слоя: n1→n2→n3 получатель B */
    jp_peer n1, n2, n3, n4; uint8_t sk1[JP_KEM768_SK_LEN], sk2[JP_KEM768_SK_LEN],
        sk3[JP_KEM768_SK_LEN], sk4[JP_KEM768_SK_LEN], skb[JP_KEM768_SK_LEN];
    mk_peer(&n1, sk1); mk_peer(&n2, sk2); mk_peer(&n3, sk3); mk_peer(&n4, sk4);

    /* получатель B */
    jp_peer b; mk_peer(&b, skb);

    /* ---- msg → R ---- */
    const char *text = "hello jproto onion";
    uint8_t rpl[JP_RPL_LEN_FIXED];
    assert(jp_msg_pack(I_ONLINE, 0x11223344u, 7, 0x1234ull, 9, POW_PROFILE_TRANSPORT,
                       b.kem_pk, (const uint8_t *)text, strlen(text), NULL, rpl) == JP_OK);

    int ity; uint32_t sess, seq; uint64_t pn; uint8_t pb, pp;
    const uint8_t *kct, *an, *mct; size_t mct_len;
    assert(jp_recipient_payload_decode(rpl, &ity, &sess, &seq, &pn, &pb, &pp,
                                       &kct, &an, &mct, &mct_len, NULL) == JP_OK);
    assert(ity == I_ONLINE && sess == 0x11223344u && seq == 7 && pn == 0x1234);
    assert(pb == 9 && pp == POW_PROFILE_TRANSPORT && mct_len == strlen(text) + 16);

    /* sha digest зависит от nonce (майнинг-петля чувствительна) */
    uint8_t d1[JP_H_LEN], d2[JP_H_LEN], rpl2[JP_RPL_LEN_FIXED];
    assert(jp_msg_pack(I_ONLINE, 0x11223344u, 7, 0x1235ull, 9, POW_PROFILE_TRANSPORT,
                       b.kem_pk, (const uint8_t *)text, strlen(text), NULL, rpl2) == JP_OK);
    jp_payload_digest(rpl, d1); jp_payload_digest(rpl2, d2);
    assert(memcmp(d1, d2, JP_H_LEN) != 0);

    /* R v2.1: dest round-trip; NODE-digest нормализуется по нулевому nonce */
    uint8_t dest[JP_RPL_DEST_LEN], dest_out[JP_RPL_DEST_LEN];
    for (int i = 0; i < JP_RPL_DEST_LEN; i++) dest[i] = (uint8_t)(i * 7 + 1);
    uint8_t rpl_d[JP_RPL_LEN_FIXED];
    assert(jp_msg_pack(I_STORE_LOCAL, 1, 1, 0x1ull, 6, POW_PROFILE_NODE,
                       b.kem_pk, (const uint8_t *)text, strlen(text),
                       dest, rpl_d) == JP_OK);
    assert(jp_recipient_payload_decode(rpl_d, &ity, &sess, &seq, &pn, &pb, &pp,
                                       &kct, &an, &mct, &mct_len,
                                       dest_out) == JP_OK);
    assert(memcmp(dest_out, dest, JP_RPL_DEST_LEN) == 0);
    uint8_t dn[JP_H_LEN];
    jp_msg_pow_digest_node(rpl_d, dn);
    jp_msg_pow_digest_node(rpl, dn);  /* разные nonce-поля → разные digest */
    jp_msg_pow_digest_node(rpl2, d2);
    assert(memcmp(dn, d2, JP_H_LEN) != 0);
    {   /* zero-nonce R даёт тот же нормализованный digest */
        uint8_t rz[JP_RPL_LEN_FIXED];
        memcpy(rz, rpl, sizeof rz);
        memset(rz + 12, 0, 8);
        jp_msg_pow_digest_node(rz, d1);
        jp_msg_pow_digest_node(rpl, d2);   /* у rpl nonce=0x1234… */
        assert(memcmp(d1, d2, JP_H_LEN) == 0);  /* нормализация совпадает с zero */
    }

    /* ---- build L=3 ---- */
    assert(jp_onion_packet_len(3) == 10478);
    const jp_peer *route3[3] = { &n1, &n2, &n3 };
    uint8_t pkt[JP_ONION_MAX_LEN]; size_t pkt_len = 0;
    assert(jp_onion_build(rpl, route3, 3, pkt, &pkt_len) == JP_OK);
    assert(pkt_len == jp_onion_packet_len(3));

    /* ---- peel цепочки ---- */
    uint8_t nxt[JP_ONION_MAX_LEN]; size_t nxt_len = 0;
    uint8_t rpl_f[JP_RPL_LEN_FIXED]; int fin = 0; uint8_t addr_next[JP_ADDR_LEN];
    assert(jp_onion_peel(sk1, pkt, pkt_len, nxt, &nxt_len, addr_next, &fin, rpl_f) == JP_OK);
    assert(!fin && memcmp(addr_next, n2.addr, JP_ADDR_LEN) == 0);
    assert(nxt_len == jp_onion_packet_len(2));
    memcpy(pkt, nxt, nxt_len); pkt_len = nxt_len;

    assert(jp_onion_peel(sk2, pkt, pkt_len, nxt, &nxt_len, addr_next, &fin, rpl_f) == JP_OK);
    assert(!fin && memcmp(addr_next, n3.addr, JP_ADDR_LEN) == 0);
    assert(nxt_len == jp_onion_packet_len(1));
    memcpy(pkt, nxt, nxt_len); pkt_len = nxt_len;

    memset(rpl_f, 0xAA, sizeof rpl_f);
    assert(jp_onion_peel(sk3, pkt, pkt_len, nxt, &nxt_len, addr_next, &fin, rpl_f) == JP_OK);
    assert(fin && nxt_len == 0);
    assert(memcmp(rpl_f, rpl, JP_RPL_LEN_FIXED) == 0);

    /* раскрываем msg: decaps sk_B → aead decrypt */
    assert(jp_recipient_payload_decode(rpl_f, &ity, &sess, &seq, &pn, &pb, &pp,
                                       &kct, &an, &mct, &mct_len, NULL) == JP_OK);
    uint8_t ss[JP_KEM768_SS_LEN], msg[JP_MSG_PAYLOAD_MAX];
    assert(jp_kem768_decaps(skb, kct, ss) == JP_OK);
    uint8_t ad[9] = { (uint8_t)ity, (uint8_t)sess, (uint8_t)(sess >> 8),
                      (uint8_t)(sess >> 16), (uint8_t)(sess >> 24),
                      (uint8_t)seq, (uint8_t)(seq >> 8), (uint8_t)(seq >> 16),
                      (uint8_t)(seq >> 24) };
    assert(jp_aead_decrypt(ss, an, ad, sizeof ad, mct, mct_len, msg) == JP_OK);
    assert(memcmp(msg, text, strlen(text)) == 0);

    /* ---- build L=4 (I_STORE_GLOBAL), полная цепочка ---- */
    const char *st = "store-global-cell";
    uint8_t rpl4[JP_RPL_LEN_FIXED];
    assert(jp_msg_pack(I_STORE_GLOBAL, 0x55667788, 3, 0x777ull, 4, POW_PROFILE_NODE,
                       b.kem_pk, (const uint8_t *)st, strlen(st), NULL, rpl4) == JP_OK);
    assert(jp_onion_packet_len(4) == 11628);
    const jp_peer *route4[4] = { &n1, &n2, &n3, &n4 };
    assert(jp_onion_build(rpl4, route4, 4, pkt, &pkt_len) == JP_OK);
    assert(pkt_len == jp_onion_packet_len(4));

    uint8_t *sks[4] = { sk1, sk2, sk3, sk4 };
    for (int i = 0; i < 4; i++) {
        assert(jp_onion_peel(sks[i], pkt, pkt_len, nxt, &nxt_len, addr_next, &fin, rpl_f) == JP_OK);
        if (i < 3) {
            assert(!fin && nxt_len == jp_onion_packet_len(3 - i));
            assert(i < 3 && memcmp(addr_next, route4[i + 1]->addr, JP_ADDR_LEN) == 0);
            memcpy(pkt, nxt, nxt_len); pkt_len = nxt_len;
        } else {
            assert(fin && nxt_len == 0);
            assert(memcmp(rpl_f, rpl4, JP_RPL_LEN_FIXED) == 0);
        }
    }

    /* ---- tamper: битый байт / чужой sk не проходят peel ---- */
    uint8_t bad[JP_ONION_MAX_LEN];
    assert(jp_onion_build(rpl, route3, 3, pkt, &pkt_len) == JP_OK);
    memcpy(bad, pkt, pkt_len);
    bad[JP_KEM768_CT_LEN + 20] ^= 0x40;
    assert(jp_onion_peel(sk1, bad, pkt_len, nxt, &nxt_len, addr_next, &fin, rpl_f) != JP_OK);
    assert(jp_onion_peel(sk4, pkt, pkt_len, nxt, &nxt_len, addr_next, &fin, rpl_f) != JP_OK);

    printf("t_onion: OK (L3=%zu байт, L4=%zu байт)\n",
           jp_onion_packet_len(3), jp_onion_packet_len(4));
    return 0;
}
