#include "jproto/jppow.h"
#include <randomx.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static double ms_now(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1000.0+ts.tv_nsec/1e6;}
static uint64_t rng=0x123456789ABCDEF; static void shake(uint8_t o[32]){for(int i=0;i<8;i++){rng*=6364136223846793005ULL;rng+=1442695040888963407ULL;o[i*4]=rng>>24;o[i*4+1]=rng>>16;o[i*4+2]=rng>>8;o[i*4+3]=rng;}}
int main(int argc,char**argv){
    uint8_t sh[32],sr[32],pd[32],out[32]; shake(sh); shake(sr); shake(pd);
    jppow_ctx *c=jppow_init(sh);
    randomx_flags f = RANDOMX_FLAG_DEFAULT | RANDOMX_FLAG_JIT;
    if (argc>1 && argv[1][0]=='h') f |= RANDOMX_FLAG_HARD_AES;
    randomx_vm *vm = randomx_create_vm(f, (randomx_cache*)jppow_cache(c), NULL);
    uint8_t in[72]; memcpy(in,sr,32); memcpy(in+32,pd,32); memset(in+64,0,8);
    double t0=ms_now(); int N=50;
    for(int i=0;i<N;i++){ in[64]=i; randomx_calculate_hash(vm,in,72,out); }
    printf("flags=%#x  %.3f ms/hash\n", (unsigned)f,(ms_now()-t0)/N);
    randomx_destroy_vm(vm); jppow_free(c); return 0;
}
