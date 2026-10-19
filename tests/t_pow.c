#include "jproto/jppow.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

static void shake256(const void *in, size_t len, uint8_t out[32]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_shake256(), NULL);
    EVP_DigestUpdate(c, in, len);
    EVP_DigestFinalXOF(c, out, 32);
    EVP_MD_CTX_free(c);
}

int main(void) {
    uint8_t sh[32], sr[32], pd[32], dg[32];
    shake256("seed_hour", 9, sh);
    shake256("seed_round", 10, sr);
    shake256("payload", 7, pd);
    jppow_ctx *c = jppow_init(sh);
    printf("vms=%d\n", jppow_add_vms(c, 2));
    uint64_t n = 0; int b = 0;
    int rc = jppow_mine(c, sr, pd, 6, 3000, 2, &n, dg, &b);
    printf("mine rc=%d bits=%d nonce=%llu\n", rc, b, (unsigned long long)n);
    printf("verify=%d\n", jppow_verify(c, sr, pd, n, b, 6));
    uint8_t pd2[32]; shake256("different", 9, pd2);
    printf("verify_bad=%d (expect -1)\n", jppow_verify(c, sr, pd2, n, b, 6));
    jppow_free(c);
    return 0;
}
