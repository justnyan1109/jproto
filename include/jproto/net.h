/* net.h — блокирующий TCP-транспорт кадрами (для CLI и тестов);
 * событийный io_uring движок — отдельно (net_uring.c). */
#ifndef JP_NET_H
#define JP_NET_H

#include "jproto/defs.h"
#include "jproto/framing.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Подключается к host:port (IPv4/IPv6). fd >= 0 при успехе. */
int jp_tcp_connect(const char *host, int port);
void jp_tcp_close(int fd);

/* Отправить один кадр (сборка внутри). Возвращает число байт кадра или код < 0. */
int jp_tcp_send_frame(int fd, const jp_frame_bld *b);

/* Принять один кадр в buf/cap, разобрать в f. Возвращает длину кадра или код < 0. */
int jp_tcp_recv_frame(int fd, jp_frame *f, uint8_t *buf, size_t cap);

/* raw: отправить/принять ровно n байт */
int jp_tcp_send_all(int fd, const void *buf, size_t n);
int jp_tcp_recv_all(int fd, void *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif
