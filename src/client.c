/* client.c — упаковка msg→R, сборка onion-пакета, peel (protocol.md §5). */
#include "jproto/client.h"
#include "jproto/crypto.h"
#include <string.h>

#define ONION_AD     JP_DOM_ONION
#define ONION_AD_LEN (sizeof(JP_DOM_ONION) - 1)

int jp_msg_pack(int itype, uint32_t session, uint32_t seq,
                uint64_t pow_nonce, uint8_t pow_bits, uint8_t pow_prof,
                const uint8_t recip_pk[JP_KEM768_PK_LEN],
                const uint8_t *msg, size_t msg_len,
                const uint8_t dest_cell[JP_RPL_DEST_LEN],
                uint8_t rpl_out[JP_RPL_LEN_FIXED]) {
    if (!msg || msg_len == 0 || msg_len > JP_MSG_PAYLOAD_MAX || !recip_pk || !rpl_out)
        return JP_ERR_FORMAT;

    uint8_t ct[JP_KEM768_CT_LEN], ss[JP_KEM768_SS_LEN], nonce[JP_AEAD_NONCE_LEN];
    if (jp_kem768_encaps(recip_pk, ct, ss) != JP_OK) return JP_ERR_CRYPTO;
    jp_random(nonce, JP_AEAD_NONCE_LEN);

    uint8_t ad[9];
    ad[0] = (uint8_t)itype;
    ad[1] = (uint8_t)session;        ad[2] = (uint8_t)(session >> 8);
    ad[3] = (uint8_t)(session >> 16); ad[4] = (uint8_t)(session >> 24);
    ad[5] = (uint8_t)seq;            ad[6] = (uint8_t)(seq >> 8);
    ad[7] = (uint8_t)(seq >> 16);    ad[8] = (uint8_t)(seq >> 24);

    uint8_t msgct[JP_MSG_PAYLOAD_MAX + JP_AEAD_TAG_LEN];
    int rc = jp_aead_encrypt(ss, nonce, ad, sizeof ad, msg, msg_len,
                             msgct);
    jp_wipe(ss, JP_KEM768_SS_LEN);
    if (rc != JP_OK) return rc;

    return jp_recipient_payload_encode(rpl_out, itype, session, seq,
                                       pow_nonce, pow_bits, pow_prof,
                                       ct, nonce, msgct, msg_len + JP_AEAD_TAG_LEN,
                                       dest_cell);
}

void jp_msg_pow_digest_node(const uint8_t rpl[JP_RPL_LEN_FIXED],
                            uint8_t out[JP_H_LEN]) {
    jp_payload_digest_node(rpl, out);
}

/* внутренний шаг: encaps до узла i и запаковка pt слоем i */
static int build_layer(const uint8_t *pt, size_t pt_len, const jp_peer *node,
                       uint8_t blob[JP_ONION_MAX_LEN], size_t *blob_len,
                       uint8_t kem_ct[JP_KEM768_CT_LEN]) {
    uint8_t ss[JP_KEM768_SS_LEN], nonce[JP_AEAD_NONCE_LEN];
    if (jp_kem768_encaps(node->kem_pk, kem_ct, ss) != JP_OK) return JP_ERR_CRYPTO;
    jp_random(nonce, JP_AEAD_NONCE_LEN);
    if (jp_aead_encrypt(ss, nonce, ONION_AD, ONION_AD_LEN, pt, pt_len,
                        blob + JP_AEAD_NONCE_LEN) != JP_OK) {
        jp_wipe(ss, JP_KEM768_SS_LEN);
        return JP_ERR_CRYPTO;
    }
    jp_wipe(ss, JP_KEM768_SS_LEN);
    memcpy(blob, nonce, JP_AEAD_NONCE_LEN);
    *blob_len = JP_AEAD_NONCE_LEN + pt_len + JP_AEAD_TAG_LEN;
    return JP_OK;
}

int jp_onion_build(const uint8_t rpl[JP_RPL_LEN_FIXED],
                   const jp_peer *route[], int total_layers,
                   uint8_t out[JP_ONION_MAX_LEN], size_t *out_len) {
    if (!rpl || !route || !out || !out_len) return JP_ERR_FORMAT;
    if (total_layers < 1 || total_layers > JP_ONION_MAX_LAYERS) return JP_ERR_FORMAT;
    for (int i = 0; i < total_layers; i++) if (!route[i]) return JP_ERR_FORMAT;

    uint8_t pt[JP_ONION_MAX_LEN];          /* scratch: PT текущего слоя */
    uint8_t prev_blob[JP_ONION_MAX_LEN];   /* blob(i+1) — вложен в PT_{i} */
    size_t  prev_blob_len = 0;
    uint8_t prev_ct[JP_KEM768_CT_LEN];

    for (int i = total_layers; i >= 1; i--) {
        size_t off = 0;
        if (i == total_layers) {
            /* финальный слой: PT = 0^32 ‖ 0x0000 ‖ R */
            memset(pt, 0, JP_ADDR_LEN + 2);
            off = JP_ADDR_LEN + 2;
            memcpy(pt + off, rpl, JP_RPL_LEN_FIXED);
            off += JP_RPL_LEN_FIXED;
        } else {
            /* PT_{i} = addr_{i+1} ‖ 1088 ‖ ct_{i+1} ‖ blob_{i+1} */
            memcpy(pt + off, route[i]->addr, JP_ADDR_LEN); off += JP_ADDR_LEN;
            pt[off++] = (uint8_t)(JP_KEM768_CT_LEN & 0xFF);
            pt[off++] = (uint8_t)(JP_KEM768_CT_LEN >> 8);
            memcpy(pt + off, prev_ct, JP_KEM768_CT_LEN); off += JP_KEM768_CT_LEN;
            memcpy(pt + off, prev_blob, prev_blob_len); off += prev_blob_len;
        }
        /* строим слой i от route[i-1]: blob_i, ct_i */
        uint8_t blob[JP_ONION_MAX_LEN];
        size_t  blob_len = 0;
        uint8_t kem_ct[JP_KEM768_CT_LEN];
        int rc = build_layer(pt, off, route[i - 1], blob, &blob_len, kem_ct);
        if (rc != JP_OK) return rc;

        if (i == 1) {
            /* out = ct_1 ‖ blob_1 */
            memcpy(out, kem_ct, JP_KEM768_CT_LEN);
            memcpy(out + JP_KEM768_CT_LEN, blob, blob_len);
            *out_len = JP_KEM768_CT_LEN + blob_len;
        } else {
            memcpy(prev_blob, blob, blob_len);
            prev_blob_len = blob_len;
            memcpy(prev_ct, kem_ct, JP_KEM768_CT_LEN);
        }
    }
    return JP_OK;
}

int jp_onion_peel(const uint8_t kem_sk[JP_KEM768_SK_LEN],
                  const uint8_t in[], size_t in_len,
                  uint8_t out[JP_ONION_MAX_LEN], size_t *out_len,
                  uint8_t next_addr[JP_ADDR_LEN], int *is_final,
                  uint8_t rpl_out[JP_RPL_LEN_FIXED]) {
    if (!in || !out_len || !is_final || !rpl_out) return JP_ERR_FORMAT;
    size_t blob_min = jp_onion_blob_len(1);
    if (in_len < JP_KEM768_CT_LEN + blob_min) return JP_ERR_FORMAT;
    size_t blob_len = in_len - JP_KEM768_CT_LEN;

    uint8_t ss[JP_KEM768_SS_LEN];
    if (jp_kem768_decaps(kem_sk, in, ss) != JP_OK) return JP_ERR_CRYPTO;

    uint8_t pt[JP_ONION_MAX_LEN];
    size_t pt_len = blob_len - JP_AEAD_NONCE_LEN - JP_AEAD_TAG_LEN;
    if (jp_aead_decrypt(ss, in + JP_KEM768_CT_LEN, ONION_AD, ONION_AD_LEN,
                        in + JP_KEM768_CT_LEN + JP_AEAD_NONCE_LEN,
                        blob_len - JP_AEAD_NONCE_LEN, pt) != JP_OK) {
        jp_wipe(ss, JP_KEM768_SS_LEN);
        return JP_ERR_CRYPTO;
    }
    jp_wipe(ss, JP_KEM768_SS_LEN);

    uint16_t ctl = (uint16_t)pt[JP_ADDR_LEN] | ((uint16_t)pt[JP_ADDR_LEN + 1] << 8);
    if (ctl == 0) {
        /* финал: remainder = R */
        *is_final = 1;
        *out_len = 0;
        if (next_addr) memcpy(next_addr, pt, JP_ADDR_LEN);
        size_t rpl_len = pt_len - (JP_ADDR_LEN + 2);
        if (rpl_len != JP_RPL_LEN_FIXED) return JP_ERR_FORMAT;
        memcpy(rpl_out, pt + JP_ADDR_LEN + 2, JP_RPL_LEN_FIXED);
        return JP_OK;
    }
    if (ctl != JP_KEM768_CT_LEN) return JP_ERR_FORMAT;
    if (pt_len < (size_t)(JP_ADDR_LEN + 2 + JP_KEM768_CT_LEN) + blob_min)
        return JP_ERR_FORMAT;
    *is_final = 0;
    if (next_addr) memcpy(next_addr, pt, JP_ADDR_LEN);
    const uint8_t *ct_next = pt + JP_ADDR_LEN + 2;
    const uint8_t *blob_next = ct_next + JP_KEM768_CT_LEN;
    size_t blob_next_len = pt_len - (JP_ADDR_LEN + 2 + JP_KEM768_CT_LEN);
    memcpy(out, ct_next, JP_KEM768_CT_LEN);
    memcpy(out + JP_KEM768_CT_LEN, blob_next, blob_next_len);
    *out_len = JP_KEM768_CT_LEN + blob_next_len;
    return JP_OK;
}
