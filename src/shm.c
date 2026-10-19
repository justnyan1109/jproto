/* shm.c — POSIX shm SPSC-кольца: lock-free head/tail (memory_order acquire/release),
 * фиксированные слоты. Имена: /dev/shm/jp-ring-<name>.
 *
 * Layout:
 *   0  u32 magic      8  u32 slot_size   16 u64 head (producer)   24 u64 tail
 *   4  u32 ver       12  u32 slots
 *   32 .. слоты: [u32 len][data ... slot_size-4]
 */
#include "jproto/shm.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#define _GNU_SOURCE
#include <stdatomic.h>

#define SHM_MAGIC 0x4A50524EU  /* "JPRN" */
#define SHM_VER   1

struct jp_shm {
    uint8_t  *map;
    size_t    map_len;
    int       fd;
    int       wakeup_fd;
    uint32_t  slot_size, slots;
    uint64_t *head;   /* producer counter */
    uint64_t *tail;   /* consumer counter */
    uint8_t  *slots0; /* база слотов */
    char     name[128];
};

static size_t shm_total_size(uint32_t slots, uint32_t slot_size) {
    return 32 + (size_t)slots * slot_size;
}

static int shm_name_to_path(const char *name, char *out, size_t cap) {
    /* внутри shm_open имя не может содержать '/' */
    if (strchr(name, '/')) return -1;
    int rc = snprintf(out, cap, "%s%s", JP_SHM_NAME_PREFIX, name);
    if (rc <= 0 || (size_t)rc >= cap) return -1;
    return 0;
}

jp_shm *jp_shm_create(const char *name, uint32_t slot_size, uint32_t slots) {
    if (!name || slot_size < 64 || slots < 2 || slots > 65536) { errno = EINVAL; return NULL; }
    char path[256];
    if (shm_name_to_path(name, path, sizeof path) != 0) { errno = EINVAL; return NULL; }

    int fd = shm_open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0 && errno == EEXIST) {
        /* уже существует: обнуляем (dev-политика) */
        shm_unlink(path);
        fd = shm_open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    }
    if (fd < 0) return NULL;
    size_t len = shm_total_size(slots, slot_size);
    if (ftruncate(fd, (off_t)len) != 0) { int e = errno; close(fd); errno = e; return NULL; }

    jp_shm *s = calloc(1, sizeof(*s));
    if (!s) { close(fd); return NULL; }
    s->map = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (s->map == MAP_FAILED) { int e = errno; free(s); close(fd); errno = e; return NULL; }
    s->map_len = len;
    s->fd = fd;
    s->wakeup_fd = -1;
    s->slot_size = slot_size;
    s->slots = slots;
    snprintf(s->name, sizeof s->name, "%s", name);

    /* control */
    uint32_t magic = SHM_MAGIC, ver = SHM_VER;
    memcpy(s->map + 0, &magic, 4);
    memcpy(s->map + 4, &ver, 4);
    memcpy(s->map + 8, &slot_size, 4);
    memcpy(s->map + 12, &slots, 4);
    uint64_t z = 0;
    memcpy(s->map + 16, &z, 8);   /* head */
    memcpy(s->map + 24, &z, 8);   /* tail */

    s->head = (uint64_t *)(s->map + 16);
    s->tail = (uint64_t *)(s->map + 24);
    s->slots0 = s->map + 32;
    return s;
}

void jp_shm_unlink(const char *name) {
    char path[256];
    if (shm_name_to_path(name, path, sizeof path) == 0) shm_unlink(path);
}

jp_shm *jp_shm_attach(const char *name) {
    char path[256];
    if (shm_name_to_path(name, path, sizeof path) != 0) { errno = EINVAL; return NULL; }
    int fd = shm_open(path, O_RDWR, 0);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 32) { close(fd); errno = EINVAL; return NULL; }

    jp_shm *s = calloc(1, sizeof(*s));
    if (!s) { close(fd); return NULL; }
    s->map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (s->map == MAP_FAILED) { int e = errno; free(s); close(fd); errno = e; return NULL; }
    s->map_len = (size_t)st.st_size;
    s->fd = fd;
    s->wakeup_fd = -1;

    uint32_t magic = 0, ver = 0;
    memcpy(&magic, s->map + 0, 4);
    memcpy(&ver, s->map + 4, 4);
    memcpy(&s->slot_size, s->map + 8, 4);
    memcpy(&s->slots, s->map + 12, 4);
    if (magic != SHM_MAGIC || ver != SHM_VER || s->slot_size < 64 || s->slots < 2) {
        munmap(s->map, s->map_len); free(s); close(fd); errno = EINVAL; return NULL;
    }
    if ((size_t)st.st_size != shm_total_size(s->slots, s->slot_size)) {
        munmap(s->map, s->map_len); free(s); close(fd); errno = EINVAL; return NULL;
    }
    s->head = (uint64_t *)(s->map + 16);
    s->tail = (uint64_t *)(s->map + 24);
    s->slots0 = s->map + 32;
    snprintf(s->name, sizeof s->name, "%s", name);
    return s;
}

void jp_shm_release(jp_shm *s) {
    if (!s) return;
    if (s->map && s->map != MAP_FAILED) munmap(s->map, s->map_len);
    if (s->fd >= 0) close(s->fd);
    free(s);
}

int jp_shm_set_wakeup(jp_shm *s, int wakeup_fd) {
    if (!s) return JP_ERR;
    s->wakeup_fd = wakeup_fd;
    return JP_OK;
}

static uint8_t *slot_ptr(jp_shm *s, uint64_t idx) {
    return s->slots0 + (size_t)(idx % s->slots) * s->slot_size;
}

int jp_shm_send(jp_shm *s, const void *data, uint32_t len) {
    if (!s || len > s->slot_size - 4) return JP_ERR_FORMAT;
    uint64_t h = atomic_load_explicit((atomic_ullong *)s->head, memory_order_relaxed);
    uint64_t t = atomic_load_explicit((atomic_ullong *)s->tail, memory_order_acquire);
    if (h - t >= s->slots) return JP_ERR_FULL;

    uint8_t *sl = slot_ptr(s, h);
    memcpy(sl, &len, 4);
    if (len) memcpy(sl + 4, data, len);
    atomic_store_explicit((atomic_ullong *)s->head, h + 1, memory_order_release);

    if (s->wakeup_fd >= 0) {
        uint64_t one = 1;
        (void)write(s->wakeup_fd, &one, sizeof one);
    }
    return JP_OK;
}

int jp_shm_recv(jp_shm *s, void *buf, uint32_t cap) {
    if (!s) return JP_ERR;
    uint64_t t = atomic_load_explicit((atomic_ullong *)s->tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit((atomic_ullong *)s->head, memory_order_acquire);
    if (t >= h) return JP_ERR_EMPTY;

    uint8_t *sl = slot_ptr(s, t);
    uint32_t len = 0;
    memcpy(&len, sl, 4);
    if (len > cap || len > s->slot_size - 4) return JP_ERR_FORMAT;
    if (len) memcpy(buf, sl + 4, len);
    atomic_store_explicit((atomic_ullong *)s->tail, t + 1, memory_order_release);
    return (int)len;
}

uint64_t jp_shm_head(const jp_shm *s) {
    uint64_t v;
    memcpy(&v, s->head, 8);
    return v;
}
uint64_t jp_shm_tail(const jp_shm *s) {
    uint64_t v;
    memcpy(&v, s->tail, 8);
    return v;
}
