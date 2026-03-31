#ifndef ETOS_H
#define ETOS_H

#include <openssl/ssl.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETOS_ERROR -1
typedef int SOCKET;

/* ------------------------------------------------------------
   系统运行环境
   ------------------------------------------------------------ */

/** 环境初始化 */
int etos_init(void);

/** 环境清理 */
void etos_cleanup(void);

#define ETOS_PROXY_SOCKS5 1
#define ETOS_PROXY_HTTP 2
#define ETOS_PROXY_HTTPS 3

/* ------------------------------------------------------------
   网络 I/O 服务
   ------------------------------------------------------------ */

/** 创建 TCP 连接 */
SOCKET etos_socket_connect(const char *host, int port, int timeout_ms, int ttl,
                           int window, int scale);

/** 通过代理创建连接 (支持 SSL 输出) */
SOCKET etos_socket_connect_proxy(int type, const char *proxy_host,
                                 int proxy_port, int timeout_ms,
                                 const char *target_host, int target_port,
                                 const char *user, const char *password,
                                 bool ssl_verify, const char *sni_host,
                                 SSL **out_ssl);

/** 关闭传输通道 */
int etos_socket_shutdown(SOCKET fd, int how);

/** 设置阻塞或非阻塞模式 */
int etos_socket_set_blocking(SOCKET fd, bool blocking);

/** 关闭句柄 */
void etos_socket_close(SOCKET fd);

/** 检查连接状态 */
bool etos_socket_is_connect(SOCKET fd);

/** 发送保活心跳 */
void etos_socket_keepalive(SOCKET fd);

/** 发送原始数据 */
ssize_t etos_socket_send(SOCKET fd, const char *buf, ssize_t len, int flags);

/** 接收原始数据 */
ssize_t etos_socket_recv(SOCKET fd, char *buf, ssize_t len, int flags);

/** 发送 SSL 加密数据 */
ssize_t etos_socket_ssl_send(SSL *ssl, const char *buf, ssize_t len, int flags);

/** 接收 SSL 加密数据 */
ssize_t etos_socket_ssl_recv(SSL *ssl, char *buf, ssize_t len, int flags);

/** 获取最后一次网络错误码 */
int etos_socket_last_error(void);

/* ------------------------------------------------------------
   SSH 密钥管理
   ------------------------------------------------------------ */

typedef enum {
  KEY_TYPE_RSA = 1,
  KEY_TYPE_ECDSA = 2,
  KEY_TYPE_ED25519 = 3
} KeyType;

typedef enum {
  CIPHER_NONE = 0,
  CIPHER_AES128_CBC = 1,
  CIPHER_AES192_CBC = 2,
  CIPHER_AES256_CBC = 3
} CipherType;

typedef struct {
  char *private_key;
  char *public_key;
  KeyType key_type;
  int key_bits;
} SSHKeyPair;

typedef struct {
  KeyType key_type;
  int key_bits;
  CipherType cipher;
  const char *password;
  const char *comment;
} KeyGenOptions;

typedef enum {
  SSH_KEYGEN_SUCCESS = 0,
  SSH_KEYGEN_ERROR_OPENSSL = -1,
  SSH_KEYGEN_ERROR_MEMORY = -2,
  SSH_KEYGEN_ERROR_INVALID_PARAM = -3,
  SSH_KEYGEN_ERROR_GENERATION = -4,
  SSH_KEYGEN_ERROR_UNSUPPORTED = -5
} SSHKeyGenError;

/** 初始化密钥生成器 */
int etos_ssh_keygen_init(void);

/** 清理密钥生成器 */
void etos_ssh_keygen_cleanup(void);

/** 生成 SSH 密钥对 */
SSHKeyPair *etos_ssh_keygen_generate(const KeyGenOptions *options);

/** 释放密钥对内存 */
void etos_ssh_keygen_free(SSHKeyPair *keypair);

/** 获取错误信息 */
const char *etos_ssh_keygen_get_error(void);

/** 获取密钥类型名称 */
const char *etos_ssh_keygen_get_key_type_name(KeyType type);

/** 获取加密算法名称 */
const char *etos_ssh_keygen_get_cipher_name(CipherType cipher);

/** 验证私钥密码 */
bool etos_ssh_keygen_verify_password(const char *private_key,
                                     const char *password);

/** 提取二进制公钥数据 */
unsigned char *etos_ssh_extract_raw_public_key(const char *public_key,
                                               size_t *out_len);

/* ------------------------------------------------------------
   并发与同步控制
   ------------------------------------------------------------ */

#ifdef _WIN32
#include <windows.h>
typedef struct {
  CRITICAL_SECTION cs;
} etos_sync_mutex_t;
#else
#include <pthread.h>
typedef struct {
  pthread_mutex_t mutex;
} etos_sync_mutex_t;
#endif

#ifdef _WIN32
typedef struct {
  int32_t count;
  CRITICAL_SECTION lock;
  CONDITION_VARIABLE cv;
} etos_sync_waitgroup_t;
#else
#include <pthread.h>
typedef struct {
  int32_t count;
  pthread_mutex_t lock;
  pthread_cond_t cv;
} etos_sync_waitgroup_t;
#endif

/** 初始化互斥锁 */
void etos_sync_mutex_init(etos_sync_mutex_t *m);

/** 加锁 */
void etos_sync_mutex_lock(etos_sync_mutex_t *m);

/** 尝试加锁 */
int etos_sync_mutex_trylock(etos_sync_mutex_t *m);

/** 解锁 */
void etos_sync_mutex_unlock(etos_sync_mutex_t *m);

/** 销毁互斥锁 */
void etos_sync_mutex_destroy(etos_sync_mutex_t *m);

/** 初始化等待组 */
void etos_sync_waitgroup_init(etos_sync_waitgroup_t *wg);

/** 设置计数 */
void etos_sync_waitgroup_add(etos_sync_waitgroup_t *wg, int delta);

/** 标记任务完成 */
void etos_sync_waitgroup_done(etos_sync_waitgroup_t *wg);

/** 等待任务归零 */
void etos_sync_waitgroup_wait(etos_sync_waitgroup_t *wg);

/** 销毁等待组 */
void etos_sync_waitgroup_destroy(etos_sync_waitgroup_t *wg);

/* ------------------------------------------------------------
   原子操作
   ------------------------------------------------------------ */

/** 原子读取 */
int64_t etos_sync_atomic_load(volatile int64_t *addr);

/** 原子写入 */
void etos_sync_atomic_store(volatile int64_t *addr, int64_t value);

/** 原子加 */
int64_t etos_sync_atomic_add(volatile int64_t *addr, int64_t delta);

/** 原子减 */
int64_t etos_sync_atomic_sub(volatile int64_t *addr, int64_t delta);

/** 原子交换 */
int64_t etos_sync_atomic_exchange(volatile int64_t *addr, int64_t value);

/** 原子比较交换 (CAS) */
int64_t etos_sync_atomic_cas(volatile int64_t *addr, int64_t expected,
                             int64_t desired);

/* ------------------------------------------------------------
   BIP39 助记词生成
   ------------------------------------------------------------ */

/** 生成助记词 */
int etos_bip39_generate(int strength, char *out_mnemonic, size_t out_max_len);

/** 验证助记词 */
int etos_bip39_validate(const char *mnemonic);

/** 助记词转种子 */
int etos_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                                unsigned char *out_seed);

#ifdef __cplusplus
}
#endif

#endif // ETOS_H
