/* onion.h — сборка/peel onion-пакета (protocol.md §5, wire.md §5). */
#ifndef JP_ONION_H
#define JP_ONION_H

#include "jproto/defs.h"
#include "jproto/crypto.h"

#define JP_LAYER_BODY_LEN (JP_INNER_PACKET_LEN - JP_AEAD_NONCE_LEN) /* 1268 */

/* recipient-payload в слое L (wire.md §5):
 *   magic 'JP' u16, ver u8, itype u8, session u32, seq u32, body_len u16,
 *   body: kyber_ct(1088) ‖ aead_nonce(12) ‖ msg_ct(body_len−1100)
 *   padding CSPRNG до 1280 (в body_len не входит)                      */
int jp_recipient_payload_encode(uint8_t out[JP_INNER_PACKET_LEN], int itype,
                                uint32_t session, uint32_t seq,
                                const uint8_t kyber_ct[JP_KEM768_CT_LEN],
                                const uint8_t aead_nonce[JP_AEAD_NONCE_LEN],
                                const uint8_t *msg_ct, size_t msg_ct_len);
/* разбор: msg_ct указывает внутрь out (не копия) */
int jp_recipient_payload_decode(const uint8_t in[JP_INNER_PACKET_LEN], int *itype,
                                uint32_t *session, uint32_t *seq,
                                const uint8_t **kyber_ct,
                                const uint8_t **aead_nonce,
                                const uint8_t **msg_ct, size_t *msg_ct_len);

/* вычислить payload_digest для PoW: H(pow.1, recipient-payload целиком) */
void jp_payload_digest(const uint8_t inner[JP_INNER_PACKET_LEN], uint8_t out[JP_H_LEN]);

/* поддержка маршрута */
int jp_onion_layer_count(int itype); /* 3/4 по protocol.md §5 */

#endif
