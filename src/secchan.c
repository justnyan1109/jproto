/* secchan.c — ML-KEM-768 handshake + ChaCha20-Poly1305 канальные кадры. */
#include "jproto/secchan.h"
#include "jproto/crypto.h"
#include "jproto/framing.h"
#include "jproto/net.h"
#include <stdlib.h>
#include <string.h>

#define SIG_PFX_C "JPCS1"
#define SIG_PFX_S "JPCS2"
#define AD_PFX    "JPSFR"

struct jp_sch {
    int      fd;
    uint8_t  key_tx[32], ntx_base[12];
    uint8_t  key_rx[32], nrx_base[12];
    uint64_t tx_seq, rx_seq;   /* начинается с 0; в кадрах — с 1 */
};

jp_sch *jp_sch_new(void) {
    return calloc(1, sizeof(struct jp_sch));
}

void jp_sch_free(jp_sch *s) { free(s); }

static void nonce_seq(const uint8_t base[12], uint64_t seq, uint8_t out[12]) {
    memcpy(out, base, 12);
    for (int i = 0; i < 8; i++) out[4 + i] ^= (uint8_t)(seq >> (8 * i));
}

static void ad_seq(uint64_t seq, uint8_t out[13]) {
    memcpy(out, AD_PFX, 5);
    for (int i = 0; i < 8; i++) out[5 + i] = (uint8_t)(seq >> (8 * i));
}

static void keys_from(jp_sch *s, uint8_t ss[JP_KEM768_SS_LEN], uint8_t th[JP_H_LEN], int is_client) {
    uint8_t mb[64];
    memcpy(mb, ss, 32);
    memcpy(mb + 32, th, JP_H_LEN);
    uint8_t kb[88];
    jp_HX(JP_DOM_SECCH, mb, sizeof mb, kb, sizeof kb);
    jp_wipe(ss, JP_KEM768_SS_LEN);
    const uint8_t *c2s = kb, *s2c = kb + 44;
    memcpy(s->ntx_base, (is_client ? c2s : s2c) + 32, 12);
    memcpy(s->key_tx,  (is_client ? c2s : s2c), 32);
    memcpy(s->nrx_base, (is_client ? s2c : c2s) + 32, 12);
    memcpy(s->key_rx,  (is_client ? s2c : c2s), 32);
    jp_wipe(kb, sizeof kb);
    s->tx_seq = s->rx_seq = 0;
}

/* tl-хелперы */
static void tlv_fill(jp_tlv *t, uint16_t tt, const uint8_t *v, uint32_t len) {
    t->ttype = tt; t->val = v; t->len = len;
}

static int xmit_sig(const uint8_t dsa_sk[JP_DSA44_SK_LEN], const void *msg, size_t len,
                    uint8_t sig[JP_DSA44_SIG_LEN]) {
    return jp_dsa44_sign(dsa_sk, msg, len, sig) == JP_OK ? JP_OK : JP_ERR_CRYPTO;
}

/* ---------- клиент ---------- */
int jp_sch_client(jp_sch *s, int fd,
                  const uint8_t kem_sk[JP_KEM768_SK_LEN],
                  const uint8_t dsa_sk[JP_DSA44_SK_LEN]) {
    if (!s || fd < 0) return JP_ERR_FORMAT;
    s->fd = fd;

    uint8_t kem_pk[JP_KEM768_PK_LEN], dsa_pk[JP_DSA44_PK_LEN];
    if (jp_kem768_pk_from_sk(kem_sk, kem_pk) != JP_OK) return JP_ERR_CRYPTO;
    if (jp_dsa44_pk_from_sk(dsa_sk, dsa_pk) != JP_OK) return JP_ERR_CRYPTO;

    /* HELLO: pk_kem, pk_dsa, sig("JPCS1"+pk_kem) */
    uint8_t hm[5 + JP_KEM768_PK_LEN];
    memcpy(hm, SIG_PFX_C, 5);
    memcpy(hm + 5, kem_pk, JP_KEM768_PK_LEN);
    uint8_t sig[JP_DSA44_SIG_LEN];
    if (xmit_sig(dsa_sk, hm, sizeof hm, sig) != JP_OK) return JP_ERR_CRYPTO;

    jp_tlv tv[3];
    tlv_fill(&tv[0], T_PK_KEM, kem_pk, sizeof kem_pk);
    tlv_fill(&tv[1], T_PK_DSA, dsa_pk, sizeof dsa_pk);
    tlv_fill(&tv[2], T_SIG, sig, sizeof sig);
    jp_frame_bld fb = { .type = F_SCH_HELLO, .flags = 0, .tvs = tv, .n = 3 };
    int rc = jp_tcp_send_frame(fd, &fb);
    if (rc < 0) return rc;

    /* HELLO_OK */
    uint8_t fbuf[JP_FRAME_MAX];
    jp_frame f;
    if (jp_tcp_recv_frame(fd, &f, fbuf, sizeof fbuf) < 0) return JP_ERR_IO;
    if (f.type != F_SCH_HELLO_OK) return JP_ERR_FORMAT;
    const jp_tlv *tct = jp_frame_find(&f, T_KYBER_CT);
    const jp_tlv *tds = jp_frame_find(&f, T_PK_DSA);
    const jp_tlv *tsg = jp_frame_find(&f, T_SIG);
    if (!tct || tct->len != JP_KEM768_CT_LEN || !tds || tds->len != JP_DSA44_PK_LEN ||
        !tsg || tsg->len != JP_DSA44_SIG_LEN) return JP_ERR_FORMAT;

    uint8_t m2[5 + JP_KEM768_PK_LEN + JP_KEM768_CT_LEN];
    memcpy(m2, SIG_PFX_S, 5);
    memcpy(m2 + 5, kem_pk, JP_KEM768_PK_LEN);
    memcpy(m2 + 5 + JP_KEM768_PK_LEN, tct->val, JP_KEM768_CT_LEN);
    if (jp_dsa44_verify(tds->val, m2, sizeof m2, tsg->val) != JP_OK) return JP_ERR_CRYPTO;

    uint8_t ss[JP_KEM768_SS_LEN];
    if (jp_kem768_decaps(kem_sk, tct->val, ss) != JP_OK) return JP_ERR_CRYPTO;
    uint8_t th[JP_H_LEN];
    jp_H(JP_DOM_SECCH, m2 + 5, sizeof(m2) - 5, th);
    keys_from(s, ss, th, 1);
    return JP_OK;
}

/* ---------- сервер ---------- */
int jp_sch_server(jp_sch *s, int fd,
                  const uint8_t dsa_sk[JP_DSA44_SK_LEN]) {
    if (!s || fd < 0) return JP_ERR_FORMAT;
    s->fd = fd;

    uint8_t fbuf[JP_FRAME_MAX];
    jp_frame f;
    if (jp_tcp_recv_frame(fd, &f, fbuf, sizeof fbuf) < 0) return JP_ERR_IO;
    if (f.type != F_SCH_HELLO) return JP_ERR_FORMAT;
    const jp_tlv *tkm = jp_frame_find(&f, T_PK_KEM);
    const jp_tlv *tdc = jp_frame_find(&f, T_PK_DSA);
    const jp_tlv *tsg = jp_frame_find(&f, T_SIG);
    if (!tkm || tkm->len != JP_KEM768_PK_LEN || !tdc || tdc->len != JP_DSA44_PK_LEN ||
        !tsg || tsg->len != JP_DSA44_SIG_LEN) return JP_ERR_FORMAT;

    uint8_t m1[5 + JP_KEM768_PK_LEN];
    memcpy(m1, SIG_PFX_C, 5);
    memcpy(m1 + 5, tkm->val, JP_KEM768_PK_LEN);
    if (jp_dsa44_verify(tdc->val, m1, sizeof m1, tsg->val) != JP_OK) return JP_ERR_CRYPTO;

    uint8_t ct[JP_KEM768_CT_LEN], ss[JP_KEM768_SS_LEN];
    if (jp_kem768_encaps(tkm->val, ct, ss) != JP_OK) return JP_ERR_CRYPTO;

    uint8_t my_dsa_pk[JP_DSA44_PK_LEN];
    if (jp_dsa44_pk_from_sk(dsa_sk, my_dsa_pk) != JP_OK) return JP_ERR_CRYPTO;
    uint8_t m2[5 + JP_KEM768_PK_LEN + JP_KEM768_CT_LEN];
    memcpy(m2, SIG_PFX_S, 5);
    memcpy(m2 + 5, tkm->val, JP_KEM768_PK_LEN);
    memcpy(m2 + 5 + JP_KEM768_PK_LEN, ct, JP_KEM768_CT_LEN);
    uint8_t sig[JP_DSA44_SIG_LEN];
    if (xmit_sig(dsa_sk, m2, sizeof m2, sig) != JP_OK) return JP_ERR_CRYPTO;

    jp_tlv tv[3];
    tlv_fill(&tv[0], T_KYBER_CT, ct, sizeof ct);
    tlv_fill(&tv[1], T_PK_DSA, my_dsa_pk, sizeof my_dsa_pk);
    tlv_fill(&tv[2], T_SIG, sig, sizeof sig);
    jp_frame_bld fb = { .type = F_SCH_HELLO_OK, .flags = 0, .tvs = tv, .n = 3 };
    int rc = jp_tcp_send_frame(fd, &fb);
    if (rc < 0) return rc;

    uint8_t th[JP_H_LEN], thb[JP_KEM768_PK_LEN + JP_KEM768_CT_LEN];
    memcpy(thb, tkm->val, JP_KEM768_PK_LEN);
    memcpy(thb + JP_KEM768_PK_LEN, ct, JP_KEM768_CT_LEN);
    jp_H(JP_DOM_SECCH, thb, sizeof thb, th);
    keys_from(s, ss, th, 0);
    return JP_OK;
}

/* ---------- sealed кадры ---------- */
int jp_sch_send(jp_sch *s, const void *buf, size_t len) {
    if (!s || !buf || len == 0 || len > JP_SCH_MSG_MAX) return JP_ERR_FORMAT;
    uint64_t seq = ++s->tx_seq;

    uint8_t cn[12]; nonce_seq(s->ntx_base, seq, cn);
    uint8_t ad[13]; ad_seq(seq, ad);
    uint8_t *ct = malloc(len + JP_AEAD_TAG_LEN);
    if (!ct) return JP_ERR_NOMEM;
    int rc = jp_aead_encrypt(s->key_tx, cn, ad, sizeof ad, buf, len, ct);
    if (rc != JP_OK) { free(ct); return rc; }

    uint8_t seq8[8];
    for (int i = 0; i < 8; i++) seq8[i] = (uint8_t)(seq >> (8 * i));
    jp_tlv tv[2];
    tlv_fill(&tv[0], T_SEQ, seq8, sizeof seq8);
    tlv_fill(&tv[1], T_MSG_CT, ct, (uint32_t)(len + JP_AEAD_TAG_LEN));
    jp_frame_bld fb = { .type = F_SCH_SEALED, .flags = 0, .tvs = tv, .n = 2 };
    rc = jp_tcp_send_frame(s->fd, &fb);
    jp_wipe(ct, len + JP_AEAD_TAG_LEN);
    free(ct);
    if (rc < 0) return rc;
    return (int)len;
}

int jp_sch_recv(jp_sch *s, void *buf, size_t cap) {
    if (!s || !buf) return JP_ERR_FORMAT;
    uint8_t fbuf[JP_FRAME_MAX];
    jp_frame f;
    if (jp_tcp_recv_frame(s->fd, &f, fbuf, sizeof fbuf) < 0) return JP_ERR_IO;
    if (f.type != F_SCH_SEALED) return JP_ERR_FORMAT;
    const jp_tlv *tq = jp_frame_find(&f, T_SEQ);
    const jp_tlv *tc = jp_frame_find(&f, T_MSG_CT);
    if (!tq || tq->len != 8 || !tc || tc->len < JP_AEAD_TAG_LEN + 1)
        return JP_ERR_FORMAT;
    uint64_t seq = 0;
    for (int i = 7; i >= 0; i--) seq = (seq << 8) | tq->val[i];
    if (seq != s->rx_seq + 1) return JP_ERR_FORMAT;   /* replay/потеря → drop */

    uint8_t cn[12]; nonce_seq(s->nrx_base, seq, cn);
    uint8_t ad[13]; ad_seq(seq, ad);
    size_t pt_len = tc->len - JP_AEAD_TAG_LEN;
    if (pt_len > cap) return JP_ERR_FORMAT;
    if (jp_aead_decrypt(s->key_rx, cn, ad, sizeof ad, tc->val, tc->len, buf) != JP_OK)
        return JP_ERR_CRYPTO;
    s->rx_seq = seq;
    return (int)pt_len;
}
