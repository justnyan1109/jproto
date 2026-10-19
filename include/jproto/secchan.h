/* secchan.h — шифрованный канал нода↔нода и клиент↔нода (wire.md §7).
 *
 * Рукопожатие (plaintext-кадры, ключи внутри):
 *   C→S  F_SCH_HELLO:     T_PK_KEM(c), T_PK_DSA(c), T_SIG(c)
 *                         sig_c = ML-DSA-44(sk_c, "JPCS1" ‖ kem_pk_c)
 *   S→C  F_SCH_HELLO_OK:  T_KYBER_CT(ct_s), T_PK_DSA(s), T_SIG(s)
 *                         ct_s = encaps(kem_pk_c); sig_s = sign("JPCS2" ‖ kem_pk_c ‖ ct_s)
 *   keys: th  = H(secch.1, kem_pk_c ‖ ct_s)
 *         K   = SHAKE256(secch.1, ss ‖ th) → 88 B:
 *               c2s.key(32) ‖ c2s.nonce(12) ‖ s2c.key(32) ‖ s2c.nonce(12)
 * Насыпанный кадр F_SCH_SEALED: T_SEQ(u64 LE), T_MSG_CT
 *   nonce = base[4..12] XOR seq; AD = "JPSFR" ‖ seq(u64 LE); seq строго +1.
 *
 * Директива: beacon commit/reveal НОДЫ передают ТОЛЬКО через этот канал;
 * синхронизация раундов (окна) остаётся несекретной — её защищают подписи. */
#ifndef JP_SECCH_H
#define JP_SECCH_H

#include "jproto/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JP_SCH_MSG_MAX (JP_FRAME_MAX - 256)

typedef struct jp_sch jp_sch;

jp_sch *jp_sch_new(void);
void    jp_sch_free(jp_sch *s);

/* обе стороны блокирующие; fd уже подключён (jp_tcp_connect/accept) */
int jp_sch_client(jp_sch *s, int fd,
                  const uint8_t kem_sk[JP_KEM768_SK_LEN],
                  const uint8_t dsa_sk[JP_DSA44_SK_LEN]);
int jp_sch_server(jp_sch *s, int fd,
                  const uint8_t dsa_sk[JP_DSA44_SK_LEN]);

/* один кадр = один вызов; seq-защита от replay внутри */
int jp_sch_send(jp_sch *s, const void *buf, size_t len);
int jp_sch_recv(jp_sch *s, void *buf, size_t cap);

#ifdef __cplusplus
}
#endif
#endif
