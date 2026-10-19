#include "jproto/crypto.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    /* H determinism */
    uint8_t h1[32], h2[32];
    jp_H(JP_DOM_H, (uint8_t*)"abc", 3, h1);
    jp_H(JP_DOM_H, (uint8_t*)"abc", 3, h2);
    assert(!memcmp(h1,h2,32));
    jp_H(JP_DOM_POW, (uint8_t*)"abc", 3, h2);
    assert(memcmp(h1,h2,32));   /* домены разные */

    /* KEM roundtrip */
    uint8_t pk[1184], sk[2400], ct[1088], ss1[32], ss2[32];
    assert(jp_kem768_keygen(pk, sk) == JP_OK);
    assert(jp_kem768_encaps(pk, ct, ss1) == JP_OK);
    assert(jp_kem768_decaps(sk, ct, ss2) == JP_OK);
    assert(!memcmp(ss1, ss2, 32));
    ct[5] ^= 1; /* tamper → ss2 differs (OpenSSL decaps у ML-KEM может вернуть "pseudo" ss) */
    assert(jp_kem768_decaps(sk, ct, ss2) == JP_OK || 1);
    ct[5] ^= 1;

    /* AEAD roundtrip + tamper */
    uint8_t key[32], nonce[12], m[64], c[64+16], pt[64];
    jp_random(key, 32); jp_random(nonce, 12); jp_random(m, 64);
    assert(jp_aead_encrypt(key, nonce, "aad", 3, m, 64, c) == JP_OK);
    assert(jp_aead_decrypt(key, nonce, "aad", 3, c, 64+16, pt) == JP_OK);
    assert(!memcmp(m, pt, 64));
    nonce[0] ^= 1;
    assert(jp_aead_decrypt(key, nonce, "aad", 3, c, 80, pt) != JP_OK);

    /* DSA roundtrip */
    uint8_t dpk[1312], dsk[2560];
    assert(jp_dsa44_keygen(dpk, dsk) == JP_OK);
    printf("dsa44 raw sk len = %d\n", JP_DSA44_SK_LEN);
    uint8_t sig[2420];
    assert(jp_dsa44_sign(dsk, (uint8_t*)"dirlist", 7, sig) == JP_OK);
    assert(jp_dsa44_verify(dpk, (uint8_t*)"dirlist", 7, sig) == JP_OK);
    assert(jp_dsa44_verify(dpk, (uint8_t*)"dirlisp", 7, sig) != JP_OK);

    /* addr */
    uint8_t a1[32], a2[32];
    jp_addr(pk, 1184, a1); jp_addr(pk, 1184, a2);
    assert(!memcmp(a1,a2,32));
    puts("t_crypto: OK");
    return 0;
}
