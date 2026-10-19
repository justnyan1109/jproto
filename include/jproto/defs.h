/* defs.h — общие константы jproto (однозначно соответствуют docs/protocol.md §12) */
#ifndef JP_DEFS_H
#define JP_DEFS_H

#include <stdint.h>
#include <stddef.h>

#define JP_PROTO_VERSION     1u

/* размеры */
#define JP_H_LEN             32
#define JP_KEM768_PK_LEN     1184
#define JP_KEM768_SK_LEN     2400
#define JP_KEM768_CT_LEN     1088
#define JP_KEM768_SS_LEN     32
#define JP_DSA44_PK_LEN      1312
#define JP_DSA44_SK_LEN      2560
#define JP_DSA44_SIG_LEN     2420
#define JP_AEAD_NONCE_LEN    12
#define JP_AEAD_TAG_LEN      16

/* Beacon / раунды */
#define JP_ROUND_LEN_S       10
#define JP_COMMIT_WINDOW_S   3
#define JP_REVEAL_WINDOW_S   3
#define JP_ROUNDS_PER_HOUR   360

/* Onion / параметризация */
#define JP_INNER_PACKET_LEN  1280
#define JP_ONION_MAX_LAYERS  4
#define JP_ADDR_LEN          32
#define JP_SALT_LEN          64

/* BS */
#define JP_CELL_CAPACITY     50
#define JP_MSG_PAYLOAD_MAX   8192

/* домены H */
#define JP_DOM_DIR           "jproto.dir.1"
#define JP_DOM_H             "jproto.h.1"
#define JP_DOM_BEACON        "jproto.beacon.1"
#define JP_DOM_POW           "jproto.pow.1"
#define JP_DOM_AAD           "jproto.aad.1"
#define JP_DOM_MIX           "jproto.mix.1"
#define JP_DOM_DIRLIST       "jproto.dirlist.1"
#define JP_DOM_MSG           "jproto.msg.1"

/* вектор ошибок */
#define JP_OK                0
#define JP_ERR               (-1)
#define JP_ERR_NOMEM         (-2)
#define JP_ERR_CRYPTO        (-3)
#define JP_ERR_FORMAT        (-4)
#define JP_ERR_POW           (-5)
#define JP_ERR_IO            (-6)
#define JP_ERR_EOF           (-7)   /* peer закрыл соединение в ожидании данных */
#define JP_ERR_EMPTY         (-8)   /* shm: очередь пуста */
#define JP_ERR_FULL          (-9)   /* shm: очередь полна */
#define JP_ERR_TIMEOUT       (-10)

/* AAD… inner-message типы (I_*), слои onion (protocol.md §5) */
enum { I_ONLINE = 1, I_STORE_LOCAL = 2, I_STORE_GLOBAL = 3, I_OFFER = 4, I_REPLY = 5 };

/* профили PoW (T_POW.profile) */
enum { POW_PROFILE_TRANSPORT = 1, POW_PROFILE_NODE = 2, POW_PROFILE_READ = 3 };

#endif
