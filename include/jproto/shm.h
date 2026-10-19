/* shm.h — lock-free SPSC-кольца в POSIX shared memory (локальный IPC:
 * клиентский процесс ↔ daemon, мультипроцесс-сообщениям; docs/protocol.md §9).
 *
 * Формат: shm_open(mapping) " JP_SHM_NAME_PREFIX / <name>"
 *   control: magic u32, ver u32, slot_size u32, slots u32,
 *            head u64 (producer), tail u64 (consumer)
 *   then slots: [len u32][data slot_size bytes]
 * Eventfd-пробуждение (для io_uring): attach может задать wakeup_fd.
 */
#ifndef JP_SHM_H
#define JP_SHM_H

#include "jproto/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JP_SHM_NAME_PREFIX  "jp-ring-"
#define JP_SHM_DEFAULT_SLOT 4096
#define JP_SHM_DEFAULT_SLOTS 256

typedef struct jp_shm jp_shm;

/* создать (creat) или удалить (unlink) кольцо */
jp_shm *jp_shm_create(const char *name, uint32_t slot_size, uint32_t slots);
void     jp_shm_unlink(const char *name);      /* удаляет файл shm (кольцо закрыто?) */

/* attach (опен на ro не обязателен — нужна запись head/tail) */
jp_shm *jp_shm_attach(const char *name);

void     jp_shm_release(jp_shm *s);            /* munmap (не unlink) */

/* wakeup fd: send() счётчиком будит читателя (eventfd; можно -1) */
int      jp_shm_set_wakeup(jp_shm *s, int wakeup_fd);

/* lock-free SPSC: отправить malloc-безопасно (len < slot_size).
 * Возврат JP_OK / JP_ERR_FULL (не блокирует!). */
int     jp_shm_send(jp_shm *s, const void *data, uint32_t len);

/* принять кадр следующего слота; JP_ERR_EMPTY если нет данных. */
int     jp_shm_recv(jp_shm *s, void *buf, uint32_t cap);

/* телеметрия (для тестов) */
uint64_t jp_shm_head(const jp_shm *s);
uint64_t jp_shm_tail(const jp_shm *s);

#ifdef __cplusplus
}
#endif
#endif
