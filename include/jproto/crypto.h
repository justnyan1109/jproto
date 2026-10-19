/* crypto.h — крипто-слой поверх OpenSSL 3.5+ EVP (PQC: ML-KEM-768, ML-DSA-44).
 * Смотри docs/protocol.md §0. Без IO, thread-safe (каждый вызов создаёт EVP ctx).
 */
#ifndef JP_CRYPTO_H
#define JP_CRYPTO_H

#include "jproto/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- H: SHAKE256(tag ‖ x, 32) ---- */
void jp_H(const char *tag, const uint8_t *in, size_t inlen, uint8_t out[JP_H_LEN]);
/* XOF-вариант: произвольная длина выхода */
void jp_HX(const char *tag, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

/* CSPRNG / затирание */
void jp_random(uint8_t *buf, size_t n);
void jp_wipe(void *p, size_t n);

/* ---- AEAD: ChaCha20-Poly1305 (key 32, nonce 12) ----
 * ct длина = pt_len + 16. Возвращает JP_OK / JP_ERR_CRYPTO. */
int jp_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                    const void *aad, size_t aadlen,
                    const void *pt, size_t ptlen, uint8_t *ct);
int jp_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                    const void *aad, size_t aadlen,
                    const void *ct, size_t ctlen, uint8_t *pt);

/* ---- ML-KEM-768 (raw форматы по wire) ---- */
int jp_kem768_keygen(uint8_t pk[JP_KEM768_PK_LEN], uint8_t sk[JP_KEM768_SK_LEN]);
int jp_kem768_encaps(const uint8_t pk[JP_KEM768_PK_LEN],
                     uint8_t ct[JP_KEM768_CT_LEN], uint8_t ss[JP_KEM768_SS_LEN]);
int jp_kem768_decaps(const uint8_t sk[JP_KEM768_SK_LEN],
                     const uint8_t ct[JP_KEM768_CT_LEN], uint8_t ss[JP_KEM768_SS_LEN]);

/* derive pk из raw sk (ML-KEM-768 / ML-DSA-44) */
int jp_kem768_pk_from_sk(const uint8_t sk[JP_KEM768_SK_LEN], uint8_t pk[JP_KEM768_PK_LEN]);
int jp_dsa44_pk_from_sk(const uint8_t sk[JP_DSA44_SK_LEN], uint8_t pk[JP_DSA44_PK_LEN]);

/* ---- ML-DSA-44 (подписи узлов; raw pk 1312 / sk 2560, sig 2420) ---- */
int jp_dsa44_keygen(uint8_t pk[JP_DSA44_PK_LEN], uint8_t sk[JP_DSA44_SK_LEN]);
int jp_dsa44_sign(const uint8_t sk[JP_DSA44_SK_LEN],
                  const uint8_t *msg, size_t len, uint8_t sig[JP_DSA44_SIG_LEN]);
int jp_dsa44_verify(const uint8_t pk[JP_DSA44_PK_LEN],
                    const uint8_t *msg, size_t len, const uint8_t sig[JP_DSA44_SIG_LEN]);

/* адрес = H(dir.1, pk) */
void jp_addr(const uint8_t *pk, size_t pklen, uint8_t out[JP_ADDR_LEN]);

#ifdef __cplusplus
}
#endif
#endif /* JP_CRYPTO_H */
