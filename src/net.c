/* net.c — блокирующий транспорт кадрами. */
#include "jproto/net.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

int jp_tcp_connect(const char *host, int port) {
    signal(SIGPIPE, SIG_IGN);
    struct addrinfo hints = {0}, *res = NULL, *ai = NULL;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return JP_ERR_IO;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

void jp_tcp_close(int fd) { if (fd >= 0) close(fd); }

int jp_tcp_send_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
        if (r <= 0) { if (r < 0 && (errno == EINTR || errno == EAGAIN)) continue; return JP_ERR_IO; }
        p += r; n -= (size_t)r;
    }
    return JP_OK;
}

int jp_tcp_recv_all(int fd, void *buf, size_t n) {
    uint8_t *p = buf;
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r == 0) return JP_ERR_EOF;
        if (r < 0) { if (errno == EINTR || errno == EAGAIN) continue; return JP_ERR_IO; }
        p += r; n -= (size_t)r;
    }
    return JP_OK;
}

int jp_tcp_send_frame(int fd, const jp_frame_bld *b) {
    size_t body = 0;
    for (int i = 0; i < b->n; i++) body += 6 + b->tvs[i].len;
    uint64_t total = 4 + body;
    size_t vlen = jp_varint_len(total);
    uint8_t *buf = malloc(vlen + total);
    if (!buf) return JP_ERR_NOMEM;
    /* собрать без промежуточного копирования структуры: используем builder */
    int rc = 0;
    size_t flen = jp_frame_build(buf, vlen + total, b);
    if (flen != vlen + total) { rc = JP_ERR_FORMAT; goto out; }
    rc = jp_tcp_send_all(fd, buf, flen);
    if (rc == JP_OK) rc = (int)flen;
out:
    free(buf);
    return rc;
}

int jp_tcp_recv_frame(int fd, jp_frame *f, uint8_t *buf, size_t cap) {
    /* 1) varint-префикс накапливаем в buf[0..9] */
    size_t vlen = 0; uint64_t total = 0; size_t shift = 0;
    while (vlen < 10) {
        if (jp_tcp_recv_all(fd, buf + vlen, 1) != JP_OK) return JP_ERR_IO;
        total |= ((uint64_t)(buf[vlen] & 0x7F)) << shift;
        vlen++;
        if (!(buf[vlen - 1] & 0x80)) break;
        shift += 7;
    }
    if (vlen >= 10 || total < 4 || total - 4 > cap - vlen) return JP_ERR_FORMAT;
    /* 2) тело: type+flags+body сразу после varint, затем в buf целиком */
    if (jp_tcp_recv_all(fd, buf + vlen, (size_t)total) != JP_OK) return JP_ERR_IO;
    /* 3) парсим с нуля буфера */
    int rc = jp_frame_parse(buf, vlen + total, f);
    if (rc != JP_OK) return rc;
    return (int)(vlen + total);
}
