/* crypto.c — реализация на OpenSSL EVP. */
#include "jproto/crypto.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>

/* ---------- H (SHAKE256 domain-separated) ---------- */
void jp_H(const char *tag, const uint8_t *in, size_t inlen, uint8_t out[JP_H_LEN]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_shake256(), NULL);
    EVP_DigestUpdate(c, tag, strlen(tag));
    if (inlen) EVP_DigestUpdate(c, in, inlen);
    EVP_DigestFinalXOF(c, out, JP_H_LEN);
    EVP_MD_CTX_free(c);
}

void jp_random(uint8_t *buf, size_t n) {
    RAND_bytes(buf, (int)n);
}

void jp_wipe(void *p, size_t n) {
    OPENSSL_cleanse(p, n);
}

/* ---------- AEAD ---------- */
static const EVP_CIPHER *aead_cipher(void) {
    static const EVP_CIPHER *c;
    if (!c) {
        c = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", NULL); /* RFC8439, nonce 12 */
        if (!c) c = EVP_chacha20_poly1305();
    }
    return c;
}

int jp_aead_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                    const void *aad, size_t aadlen,
                    const void *pt, size_t ptlen, uint8_t *ct) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return JP_ERR_NOMEM;
    int ok = EVP_EncryptInit_ex(c, aead_cipher(), NULL, key, nonce);
    size_t tag_off = ptlen;
    int len = 0;
    if (ok && aadlen) ok = EVP_EncryptUpdate(c, NULL, &len, aad, (int)aadlen);
    if (ok && ptlen)  ok = EVP_EncryptUpdate(c, ct, &len, pt, (int)ptlen);
    if (ok) ok = EVP_EncryptFinal_ex(c, ct + tag_off, &len);
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, JP_AEAD_TAG_LEN, ct + tag_off);
    EVP_CIPHER_CTX_free(c);
    return ok ? JP_OK : JP_ERR_CRYPTO;
}

int jp_aead_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                    const void *aad, size_t aadlen,
                    const void *ct, size_t ctlen, uint8_t *pt) {
    if (ctlen < JP_AEAD_TAG_LEN) return JP_ERR_CRYPTO;
    size_t ptlen = ctlen - JP_AEAD_TAG_LEN;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return JP_ERR_NOMEM;
    int ok = EVP_DecryptInit_ex(c, aead_cipher(), NULL, key, nonce);
    int len = 0;
    if (ok && aadlen) ok = EVP_DecryptUpdate(c, NULL, &len, aad, (int)aadlen);
    if (ok && ptlen)  ok = EVP_DecryptUpdate(c, pt, &len, ct, (int)ptlen);
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, JP_AEAD_TAG_LEN,
                                     (void *)((const uint8_t *)ct + ptlen));
    if (ok) ok = EVP_DecryptFinal_ex(c, pt + ptlen, &len);
    EVP_CIPHER_CTX_free(c);
    return ok ? JP_OK : JP_ERR_CRYPTO;
}

static EVP_PKEY *kem768_from_raw_pk(const uint8_t pk[JP_KEM768_PK_LEN]) {
    return EVP_PKEY_new_raw_public_key_ex(NULL, "ML-KEM-768", NULL, pk, JP_KEM768_PK_LEN);
}

int jp_kem768_keygen(uint8_t pk[JP_KEM768_PK_LEN], uint8_t sk[JP_KEM768_SK_LEN]) {
    EVP_PKEY *p = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    if (!p) return JP_ERR_CRYPTO;
    size_t l1 = 0, l2 = 0;
    int ok1 = EVP_PKEY_get_raw_public_key(p, NULL, &l1);
    int ok2 = EVP_PKEY_get_raw_private_key(p, NULL, &l2);
    if (ok1 && ok2 && l1 == JP_KEM768_PK_LEN && l2 == JP_KEM768_SK_LEN) {
        ok1 = EVP_PKEY_get_raw_public_key(p, pk, &l1);
        ok2 = EVP_PKEY_get_raw_private_key(p, sk, &l2);
    }
    EVP_PKEY_free(p);
    if (!ok1 || !ok2 || l1 != JP_KEM768_PK_LEN || l2 != JP_KEM768_SK_LEN) return JP_ERR_CRYPTO;
    return JP_OK;
}

int jp_kem768_encaps(const uint8_t pk[JP_KEM768_PK_LEN],
                     uint8_t ct[JP_KEM768_CT_LEN], uint8_t ss[JP_KEM768_SS_LEN]) {
    EVP_PKEY *p = kem768_from_raw_pk(pk);
    if (!p) return JP_ERR_CRYPTO;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, p, NULL);
    int ok = 0;
    size_t ctlen = JP_KEM768_CT_LEN, sslen = JP_KEM768_SS_LEN;
    if (ctx && EVP_PKEY_encapsulate_init(ctx, NULL) > 0) {
        if (EVP_PKEY_encapsulate(ctx, ct, &ctlen, ss, &sslen) > 0 &&
            ctlen == JP_KEM768_CT_LEN && sslen == JP_KEM768_SS_LEN) ok = 1;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(p);
    if (!ok) return JP_ERR_CRYPTO;
    return JP_OK;
}

int jp_kem768_decaps(const uint8_t sk[JP_KEM768_SK_LEN],
                     const uint8_t ct[JP_KEM768_CT_LEN], uint8_t ss[JP_KEM768_SS_LEN]) {
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key_ex(NULL, "ML-KEM-768", NULL, sk, JP_KEM768_SK_LEN);
    if (!p) return JP_ERR_CRYPTO;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, p, NULL);
    int ok = 0;
    size_t sslen = JP_KEM768_SS_LEN; /* ct_len под ssdecaps==0 при decapsulate */
    if (ctx && EVP_PKEY_decapsulate_init(ctx, NULL) > 0) {
        if (EVP_PKEY_decapsulate(ctx, ss, &sslen, ct, JP_KEM768_CT_LEN) > 0 &&
            sslen == JP_KEM768_SS_LEN) ok = 1;
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(p);
    if (!ok) return JP_ERR_CRYPTO;
    return JP_OK;
}

/* ---------- ML-DSA-44 ---------- */

int jp_dsa44_keygen(uint8_t pk[JP_DSA44_PK_LEN], uint8_t sk[JP_DSA44_SK_LEN]) {
    EVP_PKEY *p = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44");
    if (!p) return JP_ERR_CRYPTO;
    size_t lp = 0, ls = 0;
    int okp = EVP_PKEY_get_raw_public_key(p, NULL, &lp);
    int oks = EVP_PKEY_get_raw_private_key(p, NULL, &ls);
    if (okp && oks && lp == JP_DSA44_PK_LEN && ls == JP_DSA44_SK_LEN) {
        okp = EVP_PKEY_get_raw_public_key(p, pk, &lp);
        oks = EVP_PKEY_get_raw_private_key(p, sk, &ls);
    }
    EVP_PKEY_free(p);
    return (okp && oks && lp == JP_DSA44_PK_LEN && ls == JP_DSA44_SK_LEN) ? JP_OK : JP_ERR_CRYPTO;
}

int jp_dsa44_sign(const uint8_t sk[JP_DSA44_SK_LEN],
                  const uint8_t *msg, size_t len, uint8_t sig[JP_DSA44_SIG_LEN]) {
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key_ex(NULL, "ML-DSA-44", NULL, sk, JP_DSA44_SK_LEN);
    if (!p) return JP_ERR_CRYPTO;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t siglen = JP_DSA44_SIG_LEN;
    int ok = EVP_DigestSignInit(c, NULL, NULL, NULL, p) > 0 &&
             EVP_DigestSign(c, sig, &siglen, msg, len) > 0 &&
             siglen == JP_DSA44_SIG_LEN;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(p);
    return ok ? JP_OK : JP_ERR_CRYPTO;
}

int jp_dsa44_verify(const uint8_t pk[JP_DSA44_PK_LEN],
                    const uint8_t *msg, size_t len, const uint8_t sig[JP_DSA44_SIG_LEN]) {
    EVP_PKEY *p = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-DSA-44", NULL, pk, JP_DSA44_PK_LEN);
    if (!p) return JP_ERR_CRYPTO;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit(c, NULL, NULL, NULL, p) > 0 &&
             EVP_DigestVerify(c, sig, JP_DSA44_SIG_LEN, msg, len) == 1;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(p);
    return ok ? JP_OK : JP_ERR_CRYPTO;
}

void jp_addr(const uint8_t *pk, size_t pklen, uint8_t out[JP_ADDR_LEN]) {
    jp_H(JP_DOM_DIR, pk, pklen, out);
}
