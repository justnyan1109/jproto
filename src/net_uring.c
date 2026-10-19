/* net_uring.c — io_uring событийный TCP: accept/read/write/timeout на liburing. */
#include "jproto/net_uring.h"
#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define ALIGN_OF_REQ(req) ((struct req *)req)

/* SQE user_data type */
typedef struct req {
    int    op;        /* 1 accept, 2 read, 3 write, 4 timeout, 5 connect */
    int    fd;
    void (*cb)(int, void *);
    void  *ud;
    void  *buf;
    size_t len;
    size_t accum;     /* готово байт (для read/write re-arm) */
} req;

struct jp_ring {
    struct io_uring ring;
    unsigned        entries;
};

jp_ring *jp_ring_new(unsigned entries) {
    jp_ring *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    struct io_uring_params p = {0};
    if (io_uring_queue_init_params((int)entries, &r->ring, &p) != 0) { free(r); return NULL; }
    r->entries = entries;
    return r;
}

void jp_ring_free(jp_ring *r) {
    if (!r) return;
    io_uring_queue_exit(&r->ring);
    free(r);
}

/* one-shot accept SQE; rq переживает завершения */
static void accept_arm(jp_ring *r, req *rq) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe) return;
    io_uring_prep_accept(sqe, rq->fd, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, rq);
}

static void sock_opts(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

/* --- accept (one-shot + заново re-arm после каждого conn) --- */

int jp_ring_listen(jp_ring *r, const char *host, int port, int backlog,
                   void (*on_accept)(int fd, void *ud), void *ud) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -EINVAL;
    int lf = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        lf = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (lf < 0) continue;
        int one = 1;
        setsockopt(lf, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if (bind(lf, ai->ai_addr, ai->ai_addrlen) == 0 && listen(lf, backlog) == 0) break;
        close(lf); lf = -1;
    }
    freeaddrinfo(res);
    if (lf < 0) return -EADDRNOTAVAIL;
    sock_opts(lf);

    req *rq = calloc(1, sizeof *rq);
    rq->op = 0; rq->cb = on_accept; rq->ud = ud; rq->fd = lf;
    accept_arm(r, rq);
    return lf;
}

int jp_ring_port(int listen_fd) {
    struct sockaddr_in6 sa; socklen_t l = sizeof sa;
    if (getsockname(listen_fd, (struct sockaddr *)&sa, &l) != 0) return -errno;
    return ntohs(sa.sin6_family == AF_INET
                  ? ((struct sockaddr_in *)&sa)->sin_port
                  : sa.sin6_port);
}

int jp_ring_connect(jp_ring *r, const char *host, int port,
                    void (*on_connect)(int fd, void *ud), void *ud) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -EINVAL;

    req *rq = calloc(1, sizeof *rq);
    rq->op = 5; rq->cb = on_connect; rq->ud = ud;

    /* NB: io_uring connect fd-создаём сами (не в callback) */
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); free(rq); return -errno; }
    sock_opts(fd);
    rq->fd = fd;

    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe) { close(fd); free(rq); freeaddrinfo(res); return -EBUSY; }
    io_uring_prep_connect(sqe, fd, res->ai_addr, res->ai_addrlen);
    io_uring_sqe_set_data(sqe, rq);
    freeaddrinfo(res);
    return fd;
}

int jp_ring_read(jp_ring *r, int fd, void *buf, size_t len,
                 void (*cb)(int, void *), void *ud) {
    req *rq = calloc(1, sizeof *rq);
    rq->op = 2; rq->cb = cb; rq->ud = ud; rq->fd = fd; rq->buf = buf; rq->len = len;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe) { free(rq); return -EBUSY; }
    io_uring_prep_read(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, rq);
    return JP_OK;
}

int jp_ring_write(jp_ring *r, int fd, const void *buf, size_t len,
                  void (*cb)(int, void *), void *ud) {
    req *rq = calloc(1, sizeof *rq);
    rq->op = 3; rq->cb = cb; rq->ud = ud; rq->fd = fd; rq->buf = (void *)buf; rq->len = len;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe) { free(rq); return -EBUSY; }
    io_uring_prep_write(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, rq);
    return JP_OK;
}

/* докатывание коротких read/write: re-arm с накоплением */
static void req_rearm(jp_ring *r, req *rq, ssize_t done) {
    rq->accum += (size_t)done;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe) { rq->cb(-EBUSY, rq->ud); free(rq); return; }
    uint8_t *p = (uint8_t *)rq->buf;
    if (rq->op == 2) io_uring_prep_read(sqe, rq->fd, p + rq->accum, rq->len - rq->accum, 0);
    else             io_uring_prep_write(sqe, rq->fd, p + rq->accum, rq->len - rq->accum, 0);
    io_uring_sqe_set_data(sqe, rq);
}

int jp_ring_delay(jp_ring *r, int delay_ms, void (*cb)(int, void *), void *ud) {
    req *rq = calloc(1, sizeof *rq);
    rq->op = 4; rq->cb = cb; rq->ud = ud;
    struct io_uring_sqe *sqe = io_uring_get_sqe(&r->ring);
    if (!sqe) { free(rq); return -EBUSY; }
    struct __kernel_timespec ts = { .tv_sec = delay_ms / 1000,
                                    .tv_nsec = (long)(delay_ms % 1000) * 1000000L };
    io_uring_prep_timeout(sqe, &ts, 0 /*count*/, 0);
    io_uring_sqe_set_data(sqe, rq);
    return JP_OK;
}

void jp_ring_close(jp_ring *r, int fd) {
    close(fd);
    (void)r;
}

int jp_ring_run(jp_ring *r, int wait_ms, int (*on_idle)(void *), void *ud) {
    struct io_uring_cqe *cqe = NULL;
    struct __kernel_timespec ws = { .tv_sec = wait_ms / 1000,
                                    .tv_nsec = (long)(wait_ms % 1000) * 1000000L };
    int rc = io_uring_submit(&r->ring);
#ifdef JP_URING_DEBUG
    fprintf(stderr, "run: submit=%d sq_ready=%u infl=%u\n", rc,
            io_uring_sq_ready(&r->ring), jp_ring_inflight(r));
#endif
    if (rc < 0 && rc != -EINTR) return JP_ERR_IO;
    if (wait_ms >= 0)
        rc = io_uring_wait_cqes(&r->ring, &cqe, 1, &ws, NULL);
    else
        rc = io_uring_wait_cqe(&r->ring, &cqe);
    if (rc == -EINTR || rc == -ETIME) {
        if (on_idle) on_idle(ud);
        return JP_ERR_TIMEOUT;
    }
    if (rc < 0) return JP_ERR_IO;
    /* обрабатываем все доступные завершения */
    struct io_uring_cqe *cqes[64];
    unsigned count = io_uring_peek_batch_cqe(&r->ring, cqes, 64);
#ifdef JP_URING_DEBUG
    fprintf(stderr, "run: cqes=%u\n", count);
#endif
    for (unsigned i = 0; i < count; i++) {
        struct io_uring_cqe *c = cqes[i];
        req *rq = (req *)io_uring_cqe_get_data(c);
        int res = c->res;
        io_uring_cqe_seen(&r->ring, c);
        if (!rq) continue;
        /* accept: cb(new fd | err); в живьём listen — re-arm */
        if (rq->op == 0) {
            if (res >= 0) {
                if (rq->cb) rq->cb(res, rq->ud);
                accept_arm(r, rq);
            } else {
                if (rq->cb) rq->cb(res, rq->ud);
                free(rq);
            }
            continue;
        }
        if (rq->op == 4) {                          /* timeout/delay */
            if (res >= 0 || res == -ECANCELED) { if (rq->cb) rq->cb(res >= 0 ? 0 : res, rq->ud); }
            else if (rq->cb) rq->cb(res, rq->ud);
            free(rq);
            continue;
        }
        if (rq->op == 2 || rq->op == 3) {           /* read/write: all-semantics */
#ifdef JP_URING_DEBUG
            fprintf(stderr, "dis: op=%d res=%d accum=%zu\n", rq->op, res, rq->accum);
#endif
            if (res < 0) {
                if (rq->cb) rq->cb(res, rq->ud);
                free(rq);
                continue;
            }
            size_t done = (size_t)res;
            if (done == 0) {                        /* EOF при read */
                if (rq->cb) rq->cb(rq->op == 2 ? (int)rq->accum : (int)rq->accum, rq->ud);
                free(rq);
                continue;
            }
            if (done == rq->len - rq->accum) {      /* всё N */
                rq->accum += done;
                if (rq->cb) rq->cb((int)rq->accum, rq->ud);
                free(rq);
                continue;
            }
            req_rearm(r, rq, done);                 /* короткий → re-arm */
            continue;
        }
        /* connect */
        if (rq->cb) rq->cb(res < 0 ? res : rq->fd, rq->ud);
        free(rq);
    }
    return JP_OK;
}

unsigned jp_ring_inflight(const jp_ring *r) {
    return io_uring_sq_ready(&r->ring);
}
