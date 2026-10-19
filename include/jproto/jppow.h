/* jppow — PoW поверх RandomX (общий для C-библиотеки и Python через ctypes).
 *
 * функция (см. docs/protocol.md §3):
 *   input  = seed_round(32) ‖ payload_digest(32) ‖ nonce(u64 LE)
 *   digest = RandomX_H(key = seed_hour(32), input)
 *   valid  = ведущие нулевые биты digest ≥ bits (или при budget-майне: вернуть		    		     \
 *            лучший найденный nonce ≥ min_bits, при исчерпании бюджета)
 */
#ifndef JPPOW_H
#define JPPOW_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JPPOW_DIGEST_LEN   32
#define JPPOW_SEED_LEN     32   /* seed_hour / seed_round */
#define JPPOW_INPUT_LEN    (32 + 32 + 8)

/* Профили (совпадают с wire T_POW.profile) */
#define JPPOW_PROFILE_TRANSPORT 1
#define JPPOW_PROFILE_NODE      2
#define JPPOW_PROFILE_READ      3

typedef struct jppow_ctx jppow_ctx;

/* Строит RandomX cache (256 MiB, internal Argon2id) от seed_hour. ~300-400 ms. */
jppow_ctx *jppow_init(const uint8_t seed_hour[JPPOW_SEED_LEN]);

/* Освободить ctx + все VM. */
void jppow_free(jppow_ctx *ctx);

/* Регистрирует nvm VM (scratchpad 2 MiB на VM) для многопоточного майнинга/проверки.
 * Возвращает число реально созданных VM. Повторные вызовы добавляют VM. */
int jppow_add_vms(jppow_ctx *ctx, int nvm);

/* Один хэш PoW. thread_id < число зарегистрированных VM. 0 = ок.
 * Ожидает payload_digest уже посчитанным (SHAKE256(pow.1, payload)). */
int jppow_hash(jppow_ctx *ctx, int thread_id,
               const uint8_t seed_round[JPPOW_SEED_LEN],
               const uint8_t payload_digest[JPPOW_DIGEST_LEN],
               uint64_t nonce, uint8_t out[JPPOW_DIGEST_LEN]);

/* Число ведущих нулевых битов digest. */
int jppow_leading_zero_bits(const uint8_t digest[JPPOW_DIGEST_LEN]);

/* Майнинг: budget_ms, до nthreads (молча 0..nvm-1). При успехе возвращает
 * nonce, digest и достигнутые биты в out_*; результат >= min_bits, либо
 * лучший найденный при исчерпании бюджета (если выше min_bits — иначе -1). */
int jppow_mine(jppow_ctx *ctx,
               const uint8_t seed_round[JPPOW_SEED_LEN],
               const uint8_t payload_digest[JPPOW_DIGEST_LEN],
               int min_bits, int budget_ms, int nthreads,
               uint64_t *out_nonce, uint8_t out_digest[JPPOW_DIGEST_LEN],
               int *out_bits);

/* Проверка сертификата: digest = RandomX(...) отского nonce; bits — заявка.
 * Возвращает 0 если пересчёт совпал и нулей >= required, иначе -1. */
int jppow_verify(jppow_ctx *ctx,
                 const uint8_t seed_round[JPPOW_SEED_LEN],
                 const uint8_t payload_digest[JPPOW_DIGEST_LEN],
                 uint64_t nonce, int claimed_bits, int required_bits);

/* Внутренний доступ к RandomX cache для интеграционных тестов/биндингов (может быть NULL). */
void *jppow_cache(jppow_ctx *ctx);

#ifdef __cplusplus
}
#endif
#endif /* JPPOW_H */
