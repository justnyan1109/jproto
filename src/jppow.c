/* jppow.c — реализация PoW поверх RandomX. См. include/jproto/jppow.h */
#include "jproto/jppow.h"
#include <randomx.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>

#define MAX_VMS 64

struct jppow_ctx {
    randomx_cache *cache;
    randomx_vm    *vms[MAX_VMS];
    int            nvm;
    /* резервирование seed_hour на ключ */
    uint8_t        seed_hour[JPPOW_SEED_LEN];
};

static double ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static randomx_flags vm_flags(int i) {
    /* базовые: авто-детект машины (JIT, hard AES, argon2 vectorization), light-режим */
    randomx_flags f = randomx_get_flags();
    f |= RANDOMX_FLAG_JIT;   /* убедимся, что JIT не выключена по умолчанию */
#ifdef JPPOW_DEBUG
    fprintf(stderr, "jppow: vm_flags(%d) = %#x\n", i, (unsigned)f);
#endif
    (void)i;
    return f;
}

jppow_ctx *jppow_init(const uint8_t seed_hour[JPPOW_SEED_LEN]) {
    jppow_ctx *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    memcpy(c->seed_hour, seed_hour, JPPOW_SEED_LEN);
    c->cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
    if (!c->cache) { free(c); return NULL; }
    randomx_init_cache(c->cache, c->seed_hour, JPPOW_SEED_LEN);
    return c;
}

int jppow_add_vms(jppow_ctx *ctx, int nvm) {
    if (!ctx) return 0;
    for (int i = 0; i < nvm && ctx->nvm < MAX_VMS; i++) {
        randomx_vm *vm = randomx_create_vm(vm_flags(ctx->nvm), ctx->cache, NULL);
        if (!vm) break;
        ctx->vms[ctx->nvm++] = vm;
    }
    return ctx->nvm;
}

void *jppow_cache(jppow_ctx *ctx) { return ctx ? ctx->cache : NULL; }

void jppow_free(jppow_ctx *ctx) {
    if (!ctx) return;
    for (int i = 0; i < ctx->nvm; i++) randomx_destroy_vm(ctx->vms[i]);
    if (ctx->cache) randomx_release_cache(ctx->cache);
    free(ctx);
}

static void build_input(const uint8_t seed_round[JPPOW_SEED_LEN],
                        const uint8_t payload_digest[JPPOW_DIGEST_LEN],
                        uint64_t nonce, uint8_t in[JPPOW_INPUT_LEN]) {
    memcpy(in, seed_round, JPPOW_SEED_LEN);
    memcpy(in + JPPOW_SEED_LEN, payload_digest, JPPOW_DIGEST_LEN);
    for (int i = 0; i < 8; i++) in[64 + i] = (uint8_t)(nonce >> (8 * i));
}

int jppow_hash(jppow_ctx *ctx, int thread_id,
               const uint8_t seed_round[JPPOW_SEED_LEN],
               const uint8_t payload_digest[JPPOW_DIGEST_LEN],
               uint64_t nonce, uint8_t out[JPPOW_DIGEST_LEN]) {
    if (!ctx || thread_id < 0 || thread_id >= ctx->nvm) return -EINVAL;
    uint8_t in[JPPOW_INPUT_LEN];
    build_input(seed_round, payload_digest, nonce, in);
    randomx_calculate_hash(ctx->vms[thread_id], in, JPPOW_INPUT_LEN, out);
    return 0;
}

int jppow_leading_zero_bits(const uint8_t d[JPPOW_DIGEST_LEN]) {
    int bits = 0;
    for (int i = 0; i < JPPOW_DIGEST_LEN; i++) {
        if (d[i] != 0) { for (int b = 7; b >= 0; b--) { if (d[i] & (1u << b)) return bits; bits++; } break; }
        bits += 8;
    }
    return bits;
}

/* --- майнинг --- */

struct mine_job {
    jppow_ctx *ctx;
    const uint8_t *seed_round;
    const uint8_t *payload_digest;
    int  min_bits;
    double deadline_ms;
    int  tid;
    /* результат */
    uint64_t    counter;          /* сколько попыток сделал */
    uint64_t    nonce_best;
    uint8_t     digest_best[JPPOW_DIGEST_LEN];
    int         bits_best;
    int         done;             /* досрочно нашли min_bits */
};

static void *mine_thread(void *arg) {
    struct mine_job *j = arg;
    uint64_t base = ((uint64_t)j->tid << 56) ^ 0x9F4C7EA3D2B51F08ULL; /* per-tid пространство */
    uint8_t in[JPPOW_INPUT_LEN], out[JPPOW_DIGEST_LEN];
    int have_best = 0;
    for (uint64_t k = 0; ; k++) {
        if ((k & 31) == 0 && ms_now() > j->deadline_ms) break;
        uint64_t nonce = base + k;
        build_input(j->seed_round, j->payload_digest, nonce, in);
        randomx_calculate_hash(j->ctx->vms[j->tid], in, JPPOW_INPUT_LEN, out);
        j->counter = k + 1;
        int b = 0;
        for (int i = 0; i < JPPOW_DIGEST_LEN && b >= 0; i++) {
            if (out[i] != 0) { while (!(out[i] & 0x80)) { b++; out[i] <<= 1; } break; }
            b += 8;
        }
        if (b >= j->min_bits) {
            j->nonce_best = nonce;
            memcpy(j->digest_best, out, JPPOW_DIGEST_LEN);
            j->bits_best = b;
            j->done = 1;
            return j;
        }
        if (!have_best || b > j->bits_best) {
            have_best = 1;
            j->bits_best = b;
            j->nonce_best = nonce;
            memcpy(j->digest_best, out, JPPOW_DIGEST_LEN);
        }
    }
    return j;
}

int jppow_mine(jppow_ctx *ctx,
               const uint8_t seed_round[JPPOW_SEED_LEN],
               const uint8_t payload_digest[JPPOW_DIGEST_LEN],
               int min_bits, int budget_ms, int nthreads,
               uint64_t *out_nonce, uint8_t out_digest[JPPOW_DIGEST_LEN],
               int *out_bits) {
    if (!ctx || nthreads > ctx->nvm) nthreads = ctx ? ctx->nvm : 0;
    if (nthreads <= 0) return -EINVAL;
    double deadline = ms_now() + budget_ms;

    pthread_t th[MAX_VMS];
    struct mine_job jobs[MAX_VMS];
    for (int i = 0; i < nthreads; i++) {
        jobs[i].ctx = ctx; jobs[i].seed_round = seed_round;
        jobs[i].payload_digest = payload_digest;
        jobs[i].min_bits = min_bits;
        jobs[i].deadline_ms = deadline;
        jobs[i].tid = i;
        jobs[i].counter = 0; jobs[i].bits_best = -1; jobs[i].done = 0;
        pthread_create(&th[i], NULL, mine_thread, &jobs[i]);
    }
    uint64_t best_nonce = 0; int best_bits = -1; int best_tid = 0;
    /* ранний выход: ждём либо все, либо первый с done */
    for (int i = 0; i < nthreads; i++) {
        struct mine_job *r;
        pthread_join(th[i], (void**)&r);
        if (jobs[i].done && jobs[i].bits_best > best_bits) {
            best_bits = jobs[i].bits_best; best_nonce = jobs[i].nonce_best; best_tid = i;
        } else if (!jobs[i].done && jobs[i].bits_best > best_bits) {
            best_bits = jobs[i].bits_best; best_nonce = jobs[i].nonce_best; best_tid = i;
        }
    }
    if (best_bits < min_bits) return -1;
    *out_nonce = best_nonce;
    if (out_digest) memcpy(out_digest, jobs[best_tid].digest_best, JPPOW_DIGEST_LEN);
    if (out_bits) *out_bits = best_bits;
    return 0;
}

int jppow_verify(jppow_ctx *ctx,
                 const uint8_t seed_round[JPPOW_SEED_LEN],
                 const uint8_t payload_digest[JPPOW_DIGEST_LEN],
                 uint64_t nonce, int claimed_bits, int required_bits) {
    uint8_t out[JPPOW_DIGEST_LEN];
    if (jppow_hash(ctx, 0, seed_round, payload_digest, nonce, out) != 0) return -1;
    int b = jppow_leading_zero_bits(out);
    if (b < claimed_bits) return -1;         /* заявка завышена */
    if (required_bits >= 0 && b < required_bits) return -1;
    return 0;
}
