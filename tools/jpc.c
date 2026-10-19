/* jpc.c — минимальный C-клиент jproto (CLI, аналог python/jproto_ref/cli.py).
 *
 * Команды:
 *   jpc keygen  <file>              — генерирует ML-KEM-768 пару, пишет JSON (pk/sk hex) + Addr
 *   jpc ping  --node HOST:PORT      — HELLO + SEED_REQ; печатает seed/round
 *   jpc dir   --node HOST:PORT      — DIR_REQ; печатает список нод
 *
 * Ключи доступа: --key <file> (pk/sk); для нового — keygen.
 */
#include "jproto/crypto.h"
#include "jproto/net.h"
#include "jproto/framing.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void usage(void) {
    fprintf(stderr,
        "jpc — минимальный клиент jproto\n"
        " jpc keygen <file>              ключи клиента\n"
        " jpc ping    --node HOST:PORT   HELLO+SEED круг\n"
        " jpc dir     --node HOST:PORT   запрос директории\n");
}

/* ---------- keygen ---------- */
static int cmd_keygen(const char *path) {
    uint8_t pk[JP_KEM768_PK_LEN], sk[JP_KEM768_SK_LEN];
    if (jp_kem768_keygen(pk, sk) != JP_OK) { fprintf(stderr, "keygen fail\n"); return 1; }
    uint8_t addr[32]; jp_addr(pk, sizeof pk, addr);
    FILE *fh = fopen(path, "w");
    if (!fh) { fprintf(stderr, "write %s fail\n", path); return 1; }
    fprintf(fh, "{\n");
    fprintf(fh, "  \"name\": \"jpc\",\n");
    fprintf(fh, "  \"pk\": \"");
    for (size_t i = 0; i < sizeof pk; i++) fprintf(fh, "%02x", pk[i]);
    fprintf(fh, "\",\n");
    fprintf(fh, "  \"sk\": \"");
    for (size_t i = 0; i < sizeof sk; i++) fprintf(fh, "%02x", sk[i]);
    fprintf(fh, "\",\n");
    fprintf(fh, "  \"addr\": \"");
    for (int i = 0; i < 32; i++) fprintf(fh, "%02x", addr[i]);
    fprintf(fh, "\"\n}\n");
    fclose(fh);
    printf("keygen: %s (addr = ", path);
    for (int i = 0; i < 32; i++) printf("%02x", addr[i]);
    printf(")\n");
    return 0;
}

/* ---------- простой TLV builder-хелпер ---------- */
typedef struct { jp_tlv t[32]; int n; } jbld;
static void jbld_add(jbld *b, uint16_t ttype, const void *val, uint32_t len) {
    b->t[b->n].ttype = ttype; b->t[b->n].val = val; b->t[b->n].len = len; b->n++;
}

/* ---------- ping: HELLO → HELLO_OK → SEED_REQ → SEED ---------- */
static int cmd_ping(const char *node, const char *hostport) {
    (void)node;
    char host[256]; int port = 9100;
    if (!hostport) { fprintf(stderr, "war: --node обязателен\n"); return 1; }
    char *cp = strrchr(hostport, ':');
    if (!cp) { fprintf(stderr, "формат host:port\n"); return 1; }
    size_t hl = (size_t)(cp - hostport);
    if (hl >= sizeof host) hl = sizeof host - 1;
    memcpy(host, hostport, hl); host[hl] = 0;
    port = atoi(cp + 1);

    int fd = jp_tcp_connect(host, port);
    if (fd < 0) { fprintf(stderr, "подключение fail %s:%d\n", host, port); return 1; }

    uint8_t frame[JP_FRAME_MAX]; jp_frame f;

    /* HELLO */
    uint16_t ver = JP_PROTO_VERSION; uint32_t caps = 0;
    jbld hb; hb.n = 0;
    jbld_add(&hb, T_VER, &ver, 2);
    jbld_add(&hb, T_CAPS, &caps, 4);
    jp_frame_bld fb = { .type = F_HELLO, .flags = 0, .tvs = hb.t, .n = hb.n };
    if (jp_tcp_send_frame(fd, &fb) < 0) { fprintf(stderr, "send HELLO fail\n"); return 1; }
    if (jp_tcp_recv_frame(fd, &f, frame, sizeof frame) < 0 || f.type != F_HELLO_OK) {
        fprintf(stderr, "нет HELLO_OK\n"); return 1;
    }
    printf("HELLO_OK: proto=%d\n", JP_PROTO_VERSION);

    /* SEED_REQ */
    jbld sb; sb.n = 0;
    uint64_t round_req = 0;
    jbld_add(&sb, T_ROUND, &round_req, 8);
    jp_frame_bld sfb = { .type = F_SEED_REQ, .flags = 0, .tvs = sb.t, .n = sb.n };
    if (jp_tcp_send_frame(fd, &sfb) < 0) { fprintf(stderr, "send SEED_REQ fail\n"); return 1; }
    if (jp_tcp_recv_frame(fd, &f, frame, sizeof frame) < 0 || f.type != F_SEED) {
        fprintf(stderr, "нет F_SEED\n"); return 1;
    }
    const jp_tlv *ts = jp_frame_find(&f, T_SEED);
    const jp_tlv *tr = jp_frame_find(&f, T_ROUND);
    if (!ts || ts->len != 32) { fprintf(stderr, "кривой seed\n"); return 1; }
    printf("SEED: ");
    for (int i = 0; i < 32; i++) printf("%02x", ts->val[i]);
    if (tr && tr->len == 8) {
        uint64_t r = 0;
        for (int i = 7; i >= 0; i--) r = (r << 8) | tr->val[i];
        printf(" round=%llu", (unsigned long long)r);
    }
    printf("\n");
    jp_tcp_close(fd);
    return 0;
}

/* ---------- dir ---------- */
static int cmd_dir(const char *hostport) {
    char host[256]; int port = 9100;
    char *cp = strrchr(hostport, ':');
    if (!cp) { fprintf(stderr, "формат host:port\n"); return 1; }
    size_t hl = (size_t)(cp - hostport);
    if (hl >= sizeof host) hl = sizeof host - 1;
    memcpy(host, hostport, hl); host[hl] = 0;
    port = atoi(cp + 1);
    int fd = jp_tcp_connect(host, port);
    if (fd < 0) { fprintf(stderr, "подключение fail\n"); return 1; }
    uint8_t frame[JP_FRAME_MAX]; jp_frame f;
    jbld b; b.n = 0;
    jp_frame_bld fb = { .type = F_DIR_REQ, .flags = 0, .tvs = b.t, .n = b.n };
    if (jp_tcp_send_frame(fd, &fb) < 0) { fprintf(stderr, "send fail\n"); return 1; }
    if (jp_tcp_recv_frame(fd, &f, frame, sizeof frame) < 0 || f.type != F_DIR) {
        fprintf(stderr, "нет F_DIR\n"); return 1;
    }
    const jp_tlv *tl = jp_frame_find(&f, T_NODE_LIST);
    if (!tl) { fprintf(stderr, "нет T_NODE_LIST\n"); return 1; }
    printf("DIR(%u bytes list):\n", tl->len);
    /* T_NODE_ENTRY — вложенные TLV (addr, kem_pk, dsa_pk, transport) поверх
       «flat» интерпретации: перебор верхний у нас пока упрощен, спец-разбор позже */
    jp_tcp_close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    if (!strcmp(argv[1], "keygen")) {
        if (argc < 3) { usage(); return 1; }
        return cmd_keygen(argv[2]);
    }
    if (!strcmp(argv[1], "ping")) {
        const char *node = NULL;
        for (int i = 2; i < argc; i++)
            if (!strcmp(argv[i], "--node") && i + 1 < argc) node = argv[++i];
        return cmd_ping(node, node);
    }
    if (!strcmp(argv[1], "dir")) {
        const char *node = NULL;
        for (int i = 2; i < argc; i++)
            if (!strcmp(argv[i], "--node") && i + 1 < argc) node = argv[++i];
        return cmd_dir(node);
    }
    usage();
    return 1;
}
