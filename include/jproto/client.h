/* client.h — верхний C-клиент: сборка msg/onion пакета и peel.
 * Endpoint-потоки: docs/protocol.md §5/§6, wire.md §5/§6. */
#ifndef JP_CLIENT_H
#define JP_CLIENT_H

#include "jproto/defs.h"
#include "jproto/onion.h"

#ifdef __cplusplus
extern "C" {
#endif

/* узел маршрута: адрес + ML-KEM pk (по директории) */
typedef struct {
    uint8_t addr[JP_ADDR_LEN];
    uint8_t kem_pk[JP_KEM768_PK_LEN];
} jp_peer;

/* === упаковка msg → recipient-payload R (без слоёв) ===
 * АЕАД-шифрует msg ключом из ML-KEM encaps к pk адресата.
 * pow_* — поля PoW-сертификата (nonce подбирается клиентом майнером):
 * дайджест = H(pow.1, R с этим nonce), проверяет BS-hop. */
int jp_msg_pack(int itype, uint32_t session, uint32_t seq,
                uint64_t pow_nonce, uint8_t pow_bits, uint8_t pow_prof,
                const uint8_t recip_pk[JP_KEM768_PK_LEN],
                const uint8_t *msg, size_t msg_len,
                uint8_t rpl_out[JP_RPL_LEN_FIXED]);

/* === сборка полного onion-пакета ===
 * route[0..L-1] — от entry (n1) к выходному узлу (nL); R уже упакован.
 * out длина = jp_onion_packet_len(L) (детерминирована). */
int jp_onion_build(const uint8_t rpl[JP_RPL_LEN_FIXED],
                   const jp_peer *route[], int total_layers,
                   uint8_t out[JP_ONION_MAX_LEN], size_t *out_len);

/* === peel одного узла (применяет kem_sk этого узла) ===
 * in — packet [kem_ct ‖ blob]; выход:
 *   is_final=0 → out = следующий packet [ct_next ‖ blob'], next_addr = узел i+1;
 *   is_final=1 → rpl_out = R; out_len = 0; next_addr не заполняется. */
int jp_onion_peel(const uint8_t kem_sk[JP_KEM768_SK_LEN],
                  const uint8_t in[], size_t in_len,
                  uint8_t out[JP_ONION_MAX_LEN], size_t *out_len,
                  uint8_t next_addr[JP_ADDR_LEN], int *is_final,
                  uint8_t rpl_out[JP_RPL_LEN_FIXED]);

#ifdef __cplusplus
}
#endif
#endif
