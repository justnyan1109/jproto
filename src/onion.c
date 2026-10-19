/* onion.c — recipient-payload + подсобные функции onion. Полную сборку слоёв
 * реализует jp_onion_build (client.c); здесь — общие примитивы. */
#include "jproto/onion.h"
#include "jproto/crypto.h"
#include <string.h>

#define RPL_HDR_LEN (2 + 1 + 1 + 4 + 4 + 2)   /* magic,ver,itype,sess,seq,body_len */
#define RPL_BODY_FIXED (JP_KEM768_CT_LEN + JP_AEAD_NONCE_LEN)

int jp_recipient_payload_encode(uint8_t out[JP_INNER_PACKET_LEN], int itype,
                                uint32_t session, uint32_t seq,
                                const uint8_t kyber_ct[JP_KEM768_CT_LEN],
                                const uint8_t aead_nonce[JP_AEAD_NONCE_LEN],
                                const uint8_t *msg_ct, size_t msg_ct_len) {
    if (msg_ct_len > JP_MSG_PAYLOAD_MAX) return JP_ERR_FORMAT;
    size_t body = RPL_BODY_FIXED + msg_ct_len;
    if (RPL_HDR_LEN + body > JP_INNER_PACKET_LEN) return JP_ERR_FORMAT;
    out[0] = 'J'; out[1] = 'P';
    out[2] = 1;
    out[3] = (uint8_t)itype;
    out[4] = (uint8_t)(session & 0xFF); out[5] = (uint8_t)(session >> 8);
    out[6] = (uint8_t)(session >> 16); out[7] = (uint8_t)(session >> 24);
    out[8] = (uint8_t)(seq & 0xFF);    out[9] = (uint8_t)(seq >> 8);
    out[10] = (uint8_t)(seq >> 16);    out[11] = (uint8_t)(seq >> 24);
    out[12] = (uint8_t)(body & 0xFF);  out[13] = (uint8_t)(body >> 8);
    memcpy(out + RPL_HDR_LEN, kyber_ct, JP_KEM768_CT_LEN);
    memcpy(out + RPL_HDR_LEN + JP_KEM768_CT_LEN, aead_nonce, JP_AEAD_NONCE_LEN);
    if (msg_ct_len) memcpy(out + RPL_HDR_LEN + RPL_BODY_FIXED, msg_ct, msg_ct_len);
    /* CSPRNG padding (не входит в body) */
    jp_random(out + RPL_HDR_LEN + body, JP_INNER_PACKET_LEN - RPL_HDR_LEN - body);
    return JP_OK;
}

int jp_recipient_payload_decode(const uint8_t in[JP_INNER_PACKET_LEN], int *itype,
                                uint32_t *session, uint32_t *seq,
                                const uint8_t **kyber_ct,
                                const uint8_t **aead_nonce,
                                const uint8_t **msg_ct, size_t *msg_ct_len) {
    if (in[0] != 'J' || in[1] != 'P' || in[2] != 1) return JP_ERR_FORMAT;
    *itype = in[3];
    *session = in[4] | (in[5] << 8) | (in[6] << 16) | ((uint32_t)in[7] << 24);
    *seq = in[8] | (in[9] << 8) | (in[10] << 16) | ((uint32_t)in[11] << 24);
    size_t body = in[12] | (in[13] << 8);
    if (body < RPL_BODY_FIXED || RPL_HDR_LEN + body > JP_INNER_PACKET_LEN)
        return JP_ERR_FORMAT;
    *kyber_ct = in + RPL_HDR_LEN;
    *aead_nonce = in + RPL_HDR_LEN + JP_KEM768_CT_LEN;
    *msg_ct = in + RPL_HDR_LEN + RPL_BODY_FIXED;
    *msg_ct_len = body - RPL_BODY_FIXED;
    return JP_OK;
}

void jp_payload_digest(const uint8_t inner[JP_INNER_PACKET_LEN], uint8_t out[JP_H_LEN]) {
    jp_H(JP_DOM_POW, inner, JP_INNER_PACKET_LEN, out);
}

int jp_onion_layer_count(int itype) {
    switch (itype) {
        case I_ONLINE: return 3;
        default: return 4; /* STORE_LOCAL/GLOBAL/OFFER/REPLY — 4 слоя */
    }
}
