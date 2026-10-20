/* onion.c — recipient-payload (R), длины blob-ов. */
#include "jproto/onion.h"
#include "jproto/crypto.h"
#include <string.h>

#define RPL_HDR_LEN JP_RPL_HDR_LEN
#define RPL_HDR_LEN_FULL JP_RPL_HDR_LEN_FULL
#define RPL_BODY_FIXED (JP_KEM768_CT_LEN + JP_AEAD_NONCE_LEN)

int jp_recipient_payload_encode(uint8_t out[JP_RPL_LEN_FIXED], int itype,
                                uint32_t session, uint32_t seq,
                                uint64_t pow_nonce, uint8_t pow_bits, uint8_t pow_prof,
                                const uint8_t kyber_ct[JP_KEM768_CT_LEN],
                                const uint8_t aead_nonce[JP_AEAD_NONCE_LEN],
                                const uint8_t *msg_ct, size_t msg_ct_len,
                                const uint8_t dest_cell[JP_RPL_DEST_LEN]) {
    if (!out || !kyber_ct || !aead_nonce) return JP_ERR_FORMAT;
    if (msg_ct_len == 0 || msg_ct_len > JP_MSG_PAYLOAD_MAX + JP_AEAD_TAG_LEN)
        return JP_ERR_FORMAT;
    size_t body = RPL_BODY_FIXED + msg_ct_len;
    if (RPL_HDR_LEN_FULL + body > JP_RPL_LEN_FIXED) return JP_ERR_FORMAT;

    out[0] = JP_RPL_MAGIC0; out[1] = JP_RPL_MAGIC1;
    out[2] = 1;
    out[3] = (uint8_t)itype;
    out[4] = (uint8_t)session;        out[5] = (uint8_t)(session >> 8);
    out[6] = (uint8_t)(session >> 16); out[7] = (uint8_t)(session >> 24);
    out[8] = (uint8_t)seq;             out[9] = (uint8_t)(seq >> 8);
    out[10] = (uint8_t)(seq >> 16);    out[11] = (uint8_t)(seq >> 24);
    for (int i = 0; i < 8; i++) out[12 + i] = (uint8_t)(pow_nonce >> (8 * i));
    out[20] = pow_bits;
    out[21] = pow_prof;
    out[22] = (uint8_t)body;           out[23] = (uint8_t)(body >> 8);
    if (dest_cell) memcpy(out + RPL_HDR_LEN, dest_cell, JP_RPL_DEST_LEN);
    else           memset(out + RPL_HDR_LEN, 0, JP_RPL_DEST_LEN);
    memcpy(out + RPL_HDR_LEN_FULL, kyber_ct, JP_KEM768_CT_LEN);
    memcpy(out + RPL_HDR_LEN_FULL + JP_KEM768_CT_LEN, aead_nonce, JP_AEAD_NONCE_LEN);
    if (msg_ct_len) memcpy(out + RPL_HDR_LEN_FULL + RPL_BODY_FIXED, msg_ct, msg_ct_len);
    jp_random(out + RPL_HDR_LEN_FULL + body, JP_RPL_LEN_FIXED - RPL_HDR_LEN_FULL - body);
    return JP_OK;
}

int jp_recipient_payload_decode(const uint8_t in[JP_RPL_LEN_FIXED], int *itype,
                                uint32_t *session, uint32_t *seq,
                                uint64_t *pow_nonce, uint8_t *pow_bits, uint8_t *pow_prof,
                                const uint8_t **kyber_ct, const uint8_t **aead_nonce,
                                const uint8_t **msg_ct, size_t *msg_ct_len,
                                uint8_t dest_cell[JP_RPL_DEST_LEN]) {
    if (!in || in[0] != JP_RPL_MAGIC0 || in[1] != JP_RPL_MAGIC1 || in[2] != 1)
        return JP_ERR_FORMAT;
    *itype = in[3];
    *session = (uint32_t)in[4] | ((uint32_t)in[5] << 8) |
               ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24);
    *seq = (uint32_t)in[8] | ((uint32_t)in[9] << 8) |
           ((uint32_t)in[10] << 16) | ((uint32_t)in[11] << 24);
    uint64_t pn = 0;
    for (int i = 7; i >= 0; i--) pn = (pn << 8) | in[12 + i];
    *pow_nonce = pn;
    *pow_bits = in[20];
    *pow_prof = in[21];
    size_t body = (size_t)in[22] | ((size_t)in[23] << 8);
    if (body < RPL_BODY_FIXED || (size_t)RPL_HDR_LEN_FULL + body > JP_RPL_LEN_FIXED)
        return JP_ERR_FORMAT;
    if (dest_cell) memcpy(dest_cell, in + RPL_HDR_LEN, JP_RPL_DEST_LEN);
    *kyber_ct = in + RPL_HDR_LEN_FULL;
    *aead_nonce = in + RPL_HDR_LEN_FULL + JP_KEM768_CT_LEN;
    *msg_ct = in + RPL_HDR_LEN_FULL + RPL_BODY_FIXED;
    *msg_ct_len = body - RPL_BODY_FIXED;
    return JP_OK;
}

void jp_payload_digest(const uint8_t rpl[JP_RPL_LEN_FIXED], uint8_t out[JP_H_LEN]) {
    jp_H(JP_DOM_POW, rpl, JP_RPL_LEN_FIXED, out);
}

void jp_payload_digest_node(const uint8_t rpl[JP_RPL_LEN_FIXED], uint8_t out[JP_H_LEN]) {
    /* NODE-профиль канонично: H(pow.1, R с обнулённым pow_nonce) — nonce
     * не может входить в собственный digest (chicken-egg). Клиент майнит по
     * zero-nonce R, верификация нормализует так же (wire.md §6). */
    uint8_t tmp[JP_RPL_LEN_FIXED];
    memcpy(tmp, rpl, JP_RPL_LEN_FIXED);
    memset(tmp + 12, 0, 8);
    jp_H(JP_DOM_POW, tmp, JP_RPL_LEN_FIXED, out);
    jp_wipe(tmp, sizeof tmp);
}

size_t jp_onion_blob_len(int depth_remaining) {
    if (depth_remaining < 1 || depth_remaining > JP_ONION_MAX_LAYERS) return 0;
    return (JP_AEAD_NONCE_LEN + JP_AEAD_TAG_LEN)      /* nonce + tag этого слоя */
         + (JP_ADDR_LEN + 2 + JP_RPL_LEN_FIXED)      /* PT-база финального слоя */
         + (size_t)(depth_remaining - 1) * JP_ONION_LAYER_ADD;
}

size_t jp_onion_packet_len(int total_layers) {
    size_t bl = jp_onion_blob_len(total_layers);
    return bl ? bl + JP_KEM768_CT_LEN : 0;
}

int jp_onion_layer_count(int itype) {
    switch (itype) {
        case I_ONLINE: return 3;
        case I_STORE_LOCAL: case I_STORE_GLOBAL:
        case I_OFFER: case I_REPLY: return 4;
        default: return 0;
    }
}
