/* net_uring.h — событийный io_uring TCP-движок (daemon/nodes; liburing 2.15+).
 *
 * Модель: одно ядро jp_ring на поток; операции ready → callback.
 * Буферы для read/write живут до срабатывания callback.
 * Semantics: callback получает (fd, nbytes>=0 или код<0, ud).
 * Accept/connect callback: (fd_new или код<0, ud).
 */
#ifndef JP_NET_URING_H
#define JP_NET_URING_H

#include "jproto/defs.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct jp_ring jp_ring;

jp_ring *jp_ring_new(unsigned entries);
void jp_ring_free(jp_ring *r);

/* --- слушать: c-bind на host:port; on_accept(fd, ud) на каждый accept.
 * Возвращает listen fd (для getsockname). port == 0 → авто. */
int jp_ring_listen(jp_ring *r, const char *host, int port, int backlog,
                   void (*on_accept)(int fd, void *ud), void *ud);
int jp_ring_port(int listen_fd);

/* --- connect: on_connect(fd или <0, ud) */
int jp_ring_connect(jp_ring *r, const char *host, int port,
                    void (*on_connect)(int fd, void *ud), void *ud);

/* --- read/write: IORING_OP_READ/WRITE; cb(nbytes или <0, ud) */
int jp_ring_read(jp_ring *r, int fd, void *buf, size_t len,
                 void (*cb)(int, void *), void *ud);
int jp_ring_write(jp_ring *r, int fd, const void *buf, size_t len,
                  void (*cb)(int, void *), void *ud);

/* --- задержка mix: cb(0, ud) через delay_ms */
int jp_ring_delay(jp_ring *r, int delay_ms, void (*cb)(int, void *), void *ud);

/* --- закрыть fd (в ring не оставляя зависших) */
void jp_ring_close(jp_ring *r, int fd);

/* --- главный цикл: ждать ≥1 завершений, диспетчеризовать cb; выходит по ate.
 * do_work вызывается ПОСЛЕ обработки каждого пакета завершений (входит фоновые таймеры).
 * Возврат: JP_OK обычно; JP_ERR_TIMEOUT если wait_ms вышел без событий (при wait_ms>0). */
int jp_ring_run(jp_ring *r, int wait_ms, int (*on_idle)(void *), void *ud);

/* --- прогулка по краям: сколько событийных операций в полёте */
unsigned jp_ring_inflight(const jp_ring *r);

#ifdef __cplusplus
}
#endif
#endif
