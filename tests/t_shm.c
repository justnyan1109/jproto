#include "jproto/shm.h"
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

/* SPSC через два thread'а */
static jp_shm *g;

static void *reader(void *arg) {
    (void)arg;
    uint8_t buf[4096];
    int got = 0;
    while (got < 100) {
        int n = jp_shm_recv(g, buf, sizeof buf);
        if (n == JP_ERR_EMPTY) continue;
        assert(n > 0);
        assert(buf[0] == (unsigned)(got & 0xFF));
        got++;
    }
    return NULL;
}

int main(void) {
    jp_shm_unlink("t1");
    jp_shm *s = jp_shm_create("t1", JP_SHM_DEFAULT_SLOT, JP_SHM_DEFAULT_SLOTS);
    assert(s);
    /* same-process attach тоже работает */
    jp_shm *a = jp_shm_attach("t1");
    assert(a);

    uint8_t msg[64];
    memset(msg, 0x55, sizeof msg);
    /* заполнение до FULL */
    int sent = 0;
    for (;;) {
        int rc = jp_shm_send(s, msg, sizeof msg);
        if (rc == JP_ERR_FULL) break;
        assert(rc == JP_OK);
        sent++;
    }
    assert(sent == JP_SHM_DEFAULT_SLOTS);
    assert((int)(jp_shm_head(s) - jp_shm_tail(s)) == JP_SHM_DEFAULT_SLOTS);

    /* приём всех */
    uint8_t out[4096];
    int recvd = 0;
    for (;;) {
        int n = jp_shm_recv(s, out, sizeof out);
        if (n == JP_ERR_EMPTY) break;
        assert(n == (int)sizeof msg && !memcmp(out, msg, sizeof msg));
        recvd++;
    }
    assert(recvd == JP_SHM_DEFAULT_SLOTS);
    assert(jp_shm_head(s) == jp_shm_tail(s));

    /* большой-len reject */
    assert(jp_shm_send(s, msg, JP_SHM_DEFAULT_SLOT) == JP_ERR_FORMAT);

    /* переполнение: следующий обычный send снова OK */
    assert(jp_shm_send(s, msg, sizeof msg) == JP_OK);
    assert(jp_shm_recv(s, out, sizeof out) == (int)sizeof msg);

    jp_shm_release(a);
    jp_shm_release(s);
    jp_shm_unlink("t1");

    /* threads test */
    jp_shm_unlink("t2");
    g = jp_shm_create("t2", 512, 64);
    assert(g);
    pthread_t th;
    pthread_create(&th, NULL, reader, NULL);
    for (int i = 0; i < 100; i++) {
        uint8_t m[2] = { (uint8_t)(i & 0xFF), 0x77 };
        for (;;) {
            int rc = jp_shm_send(g, m, sizeof m);
            if (rc == JP_OK) break;
            sched_yield();
        }
    }
    pthread_join(th, NULL);
    jp_shm_release(g);
    jp_shm_unlink("t2");

    printf("t_shm: OK\n");
    return 0;
}
