/* t_secchan — handshake + sealed-кадры через socketpair (два thread'а) */
#include "jproto/secchan.h"
#include "jproto/crypto.h"
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int afds[2];
static uint8_t ckem[JP_KEM768_SK_LEN], cdsa[JP_DSA44_SK_LEN];
static uint8_t sdsa[JP_DSA44_SK_LEN];

static const char *c2s1 = "commit-1";
static const char *c2s2 = "commit-2";
static const char *s2c1 = "seed-1";
static const char *s2c2 = "reveal-2";

static void *client_fn(void *arg) {
    (void)arg;
    jp_sch *c = jp_sch_new();
    assert(jp_sch_client(c, afds[0], ckem, cdsa) == JP_OK);

    char buf[JP_SCH_MSG_MAX];
    int n = jp_sch_recv(c, buf, sizeof buf);
    assert(n == (int)strlen(s2c1) && !memcmp(buf, s2c1, n));
    n = jp_sch_recv(c, buf, sizeof buf);
    assert(n == (int)strlen(s2c2) && !memcmp(buf, s2c2, n));

    assert(jp_sch_send(c, c2s1, strlen(c2s1)) == (int)strlen(c2s1));
    assert(jp_sch_send(c, c2s2, strlen(c2s2)) == (int)strlen(c2s2));

    jp_sch_free(c);
    return NULL;
}

int main(void) {
    uint8_t kpk[JP_KEM768_PK_LEN], dpk[JP_DSA44_PK_LEN];
    assert(jp_kem768_keygen(kpk, ckem) == JP_OK);
    assert(jp_dsa44_keygen(dpk, cdsa) == JP_OK);
    assert(jp_dsa44_keygen(dpk, sdsa) == JP_OK);

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, afds) == 0);
    pthread_t th;
    pthread_create(&th, NULL, client_fn, NULL);

    jp_sch *s = jp_sch_new();
    assert(jp_sch_server(s, afds[1], sdsa) == JP_OK);

    assert(jp_sch_send(s, s2c1, strlen(s2c1)) == (int)strlen(s2c1));
    assert(jp_sch_send(s, s2c2, strlen(s2c2)) == (int)strlen(s2c2));

    char buf[JP_SCH_MSG_MAX];
    int n = jp_sch_recv(s, buf, sizeof buf);
    assert(n == (int)strlen(c2s1) && !memcmp(buf, c2s1, n));
    n = jp_sch_recv(s, buf, sizeof buf);
    assert(n == (int)strlen(c2s2) && !memcmp(buf, c2s2, n));

    pthread_join(th, NULL);
    jp_sch_free(s);
    close(afds[0]); close(afds[1]);

    printf("t_secchan: OK\n");
    return 0;
}
