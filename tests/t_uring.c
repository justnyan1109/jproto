#include "jproto/net_uring.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

static jp_ring *g;
static const char *payload = "jproto-uring-ping";
static int listen_fd = -1, listen_port = 0;
static int server_wrote = 0, client_got = 0, conn_fd = -1;

/* --- сервер --- */
static void on_srv_write(int n, void *ud);
static void on_srv_read(int n, void *ud);
static void on_accept(int fd, void *ud);

static void on_srv_write(int n, void *ud) {
    assert(n == (int)strlen(payload));
    (void)ud;
    server_wrote = 1;
}
static void on_srv_read(int n, void *ud) {
    char *buf = (char *)ud;   /* буфер из on_accept */
    int fd = conn_fd;
    assert(n == (int)strlen(payload));
    (void)fd;
    buf[n] = 0;
    assert(!strcmp(buf, payload));
    jp_ring_write(g, fd, buf, (size_t)n, on_srv_write, (void *)(intptr_t)fd);
}
static void on_accept(int fd, void *ud) {
    (void)ud;
    conn_fd = fd;
    char *buf = malloc(64);
    jp_ring_read(g, fd, buf, strlen(payload), on_srv_read, buf);
}

/* --- клиент --- */
static void on_cli_read(int n, void *ud);
static void on_cli_write(int n, void *ud);
static void on_connect(int fd, void *ud);

static void on_cli_read(int n, void *ud) {
    char *buf = (char *)ud;
    assert(n == (int)strlen(payload));
    buf[n] = 0;
    assert(!strcmp(buf, payload));
    client_got = 1;
}
static void on_cli_write(int n, void *ud) {
    int fd = (int)(intptr_t)ud;
    char *rb = malloc(64);
    if (n != (int)strlen(payload)) rb[0] = 1, (void)rb; /* глушим неиспользованное */
    jp_ring_read(g, fd, rb, strlen(payload), on_cli_read, rb);
}
static void on_connect(int fd, void *ud) {
    assert(fd >= 0 && (int)(intptr_t)ud == 777);
    jp_ring_write(g, fd, payload, strlen(payload), on_cli_write, (void *)(intptr_t)fd);
}

int main(void) {
    g = jp_ring_new(64);
    assert(g);
    listen_fd = jp_ring_listen(g, "127.0.0.1", 0, 8, on_accept, NULL);
    assert(listen_fd >= 0);
    listen_port = jp_ring_port(listen_fd);
    assert(listen_port > 0);

    int crc = jp_ring_connect(g, "127.0.0.1", listen_port, on_connect, (void *)(intptr_t)777);
    assert(crc > 0);

    int ticks = 0;
    while (!(server_wrote && client_got) && ticks < 100) {
        (void)jp_ring_run(g, 100, NULL, NULL);
        ticks++;
    }
    assert(server_wrote && client_got);
    printf("t_uring: OK (port=%d ticks=%d)\n", listen_port, ticks);

    jp_ring_close(g, conn_fd);
    jp_ring_close(g, listen_fd);
    jp_ring_free(g);
    return 0;
}
