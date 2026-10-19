#include "jproto/jppow.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
static double ms_now(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec*1000.0+ts.tv_nsec/1e6;}
static uint64_t rng=0x123456789ABCDEF; static void shake(uint8_t o[32]){for(int i=0;i<8;i++){rng*=6364136223846793005ULL;rng+=1442695040888963407ULL;o[i*4]=rng>>24;o[i*4+1]=rng>>16;o[i*4+2]=rng>>8;o[i*4+3]=rng;}}
int main(void){
    uint8_t sh[32],sr[32],pd[32],out[32]; shake(sh); shake(sr); shake(pd);
    jppow_ctx *c=jppow_init(sh); jppow_add_vms(c,1);
    double t0=ms_now(); int N=50;
    for(int i=0;i<N;i++) jppow_hash(c,0,sr,pd,1000+i,out);
    printf("jppow_hash: %.3f ms/hash\n",(ms_now()-t0)/N);
    /* прямой randomx эксперимент: same cache, flags explicit */
    extern void *randomx_alloc_cache(int);
    jppow_free(c); return 0;
}
