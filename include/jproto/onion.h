/* onion.h — recipient-payload (R), длины blob'ов, peel.
 * Полную сборку маршрута делает jp_onion_build (client.c).
 * См. docs/protocol.md §5, docs/wire.md §5.
 */
#ifndef JP_ONION_H
#define JP_ONION_H

#include "jproto/defs.h"
#include "jproto/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* recipient-payload R (фиксированная длина JP_RPL_LEN_FIXED = 7028):
 *   hdr(24): 'JP' u16, ver u8=1, itype u8, session u32, seq u32,
 *            pow_nonce u64, pow_bits u8, pow_prof u8, body_len u16
 *   dest(32): cell-индекс BS-ноды (R v2.1); 0^32 = legacy (cell = h_cell(value))
 *   body:    ML-KEM-ct к адресату(1088) ‖ AEAD-nonce(12) ‖ AEAD-ct(msg+tag)
 *   остаток: CSPRNG padding до JP_RPL_LEN_FIXED;
 * TRANSPORT-digest = H(pow.1, packet целиком); NODE — каноничный
 * jp_payload_digest_node: H(pow.1, R с обнулённым pow_nonce) (wire.md §6). */
#define JP_RPL_MAGIC0 'J'
#define JP_RPL_MAGIC1 'P'

int jp_recipient_payload_encode(uint8_t out[JP_RPL_LEN_FIXED], int itype,
                                uint32_t session, uint32_t seq,
                                uint64_t pow_nonce, uint8_t pow_bits, uint8_t pow_prof,
                                const uint8_t kyber_ct[JP_KEM768_CT_LEN],
                                const uint8_t aead_nonce[JP_AEAD_NONCE_LEN],
                                const uint8_t *msg_ct, size_t msg_ct_len,
                                const uint8_t dest_cell[JP_RPL_DEST_LEN]);
/* разбор (msg_ct/dest указывают в in — при dest_cell=NULL dest не копируется) */
int jp_recipient_payload_decode(const uint8_t in[JP_RPL_LEN_FIXED], int *itype,
                                uint32_t *session, uint32_t *seq,
                                uint64_t *pow_nonce, uint8_t *pow_bits, uint8_t *pow_prof,
                                const uint8_t **kyber_ct, const uint8_t **aead_nonce,
                                const uint8_t **msg_ct, size_t *msg_ct_len,
                                uint8_t dest_cell[JP_RPL_DEST_LEN]);

/* payload_digest TRANSPORT: H(pow.1, packet целиком, JP_RPL_LEN_FIXED байт) */
void jp_payload_digest(const uint8_t rpl[JP_RPL_LEN_FIXED], uint8_t out[JP_H_LEN]);
/* payload_digest NODE (каноничный): zero-nonce R → H(pow.1, …) */
void jp_payload_digest_node(const uint8_t rpl[JP_RPL_LEN_FIXED], uint8_t out[JP_H_LEN]);

/* детерминированные длины (wire.md §5):
 *   blob(depth) = nonce(12) + AEAD_tag(16) + PT(depth); PT_L = addr(32)+ctl(2)+|R|,
 *   каждый внешний слой добавляет 1150 = 32+2+1088+12+16;
 *   packet(L) = kem_ct(1088) ‖ blob(L). */
size_t jp_onion_blob_len(int depth_remaining);  /* depth=L…1: blob от этого числа слоёв ниже */
size_t jp_onion_packet_len(int total_layers);   /* P = kem_ct(1088) ‖ blob(total_layers) */

/* тип маршрута: 3 слоя I_ONLINE, 4 — I_STORE_* / OFFER / REPLY */
int jp_onion_layer_count(int itype);

#ifdef __cplusplus
}
#endif
#endif
