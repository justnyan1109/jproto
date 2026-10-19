#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <stdio.h>
int main(void){
    EVP_PKEY *p = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-768");
    if(!p){ puts("keygen NULL"); return 1; }
    size_t l=0;
    EVP_PKEY_get_raw_public_key(p,NULL,&l); printf("pub raw len=%zu\n",l);
    EVP_PKEY_get_raw_private_key(p,NULL,&l); printf("priv raw len=%zu\n",l);
    EVP_PKEY_free(p);
    unsigned char pk[2];
    p = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44");
    EVP_PKEY_get_raw_public_key(p,NULL,&l); printf("dsa pub raw len=%zu\n",l);
    EVP_PKEY_get_raw_private_key(p,NULL,&l); printf("dsa priv raw len=%zu\n",l);
    EVP_PKEY_free(p);
    return 0;
}
