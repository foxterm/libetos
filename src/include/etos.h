#ifndef ETOS_H
#define ETOS_H

/**
 * ETOS (Enterprise Toolset Operating System) Core SDK
 */

#include <openssl/ssl.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETOS_ERROR -1
typedef int SOCKET;
// ============================================================
// [0x0100] 系统生命周期与全局配置 (System Runtime)
// ============================================================

/** @ordinal 101 - 环境初始化 (WSAStartup / 内部资源分配) */
int etos_init(void);
/** @ordinal 102 - 资源终结清理 (WSACleanup / 强制回收) */
void etos_cleanup(void);

// 定义代理类型内部常量
#define ETOS_PROXY_SOCKS5 1
#define ETOS_PROXY_HTTP 2
#define ETOS_PROXY_HTTPS 3
/* ============================================================
   [0x0200] 异步 IO 与网络引擎 (High-Level Networking)
   ============================================================ */

/** @ordinal 201 - 建立 TCP 连接，支持 TTL 与滑动窗口(Window/Scale)调优 */
SOCKET etos_socket_connect(const char *host, int port, int timeout_ms, int ttl,
                           int window, int scale);
/** @ordinal 202 - 建立代理隧道连接 (支持 SOCKS5/HTTP/HTTPS)，返回 FD 并可选返回
 * SSL 指针 */
SOCKET etos_socket_connect_proxy(int type, const char *proxy_host,
                                 int proxy_port, int timeout_ms,
                                 const char *target_host, int target_port,
                                 const char *user, const char *password,
                                 bool ssl_verify, const char *sni_host,
                                 SSL **out_ssl);

/** @ordinal 203 - 优雅关闭 Socket 通道 (how: 0=receive, 1=send, 2=both) */
int etos_socket_shutdown(SOCKET fd, int how);
/** @ordinal 204 - 切换阻塞 (true) 或非阻塞 (false) 模式 */
int etos_socket_set_blocking(SOCKET fd, bool blocking);
/** @ordinal 205 - 回收 Socket 句柄并关闭物理连接 */
void etos_socket_close(SOCKET fd);
// 判断 Socket FD 当前是否处于正常连接状态
bool etos_socket_is_connect(SOCKET fd);
// 心跳
void etos_socket_keepalive(SOCKET fd);
/** @ordinal 206 - 发送原始 TCP 数据 (成功返回字节数，失败返回 ETOS_ERROR) */
ssize_t etos_socket_send(SOCKET fd, const char *buf, ssize_t len, int flags);
/** @ordinal 207 - 接收原始 TCP 数据 (成功返回字节数，失败返回 ETOS_ERROR) */
ssize_t etos_socket_recv(SOCKET fd, char *buf, ssize_t len, int flags);
/** @ordinal 208 - 发送加密 SSL 数据 (仅限 HTTPS 模式使用) */
ssize_t etos_socket_ssl_send(SSL *ssl, const char *buf, ssize_t len, int flags);
/** @ordinal 209 - 接收加密 SSL 数据 (仅限 HTTPS 模式使用) */
ssize_t etos_socket_ssl_recv(SSL *ssl, char *buf, ssize_t len, int flags);
/** @ordinal 210 - 获取当前线程最后的 Winsock 错误代码 */
int etos_socket_last_error(void);

// ============================================================
// [0x0700] 安全与密码学：SSH 密钥生成 (Security & SSH Keygen)
// ============================================================

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
  char *private_key; /* PEM 格式私钥 */
  char *public_key;  /* OpenSSH 格式公钥 */
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

/** @ordinal 701 - 初始化 SSH 密钥库资源 */
int etos_ssh_keygen_init(void);
/** @ordinal 702 - 清理 SSH 密钥库资源 */
void etos_ssh_keygen_cleanup(void);
/** @ordinal 703 - 生成 SSH 密钥对 */
SSHKeyPair *etos_ssh_keygen_generate(const KeyGenOptions *options);
/** @ordinal 704 - 释放密钥对内存 */
void etos_ssh_keygen_free(SSHKeyPair *keypair);
/** @ordinal 705 - 获取密钥生成最后一条错误信息 */
const char *etos_ssh_keygen_get_error(void);
/** @ordinal 706 - 获取密钥类型名称字符串 */
const char *etos_ssh_keygen_get_key_type_name(KeyType type);
/** @ordinal 707 - 获取加密算法名称字符串 */
const char *etos_ssh_keygen_get_cipher_name(CipherType cipher);
/** @ordinal 708 - 验证私钥密码正确性 */
bool etos_ssh_keygen_verify_password(const char *private_key,
                                     const char *password);
/** @ordinal 709 - 提取公钥原始二进制数据 */
unsigned char *etos_ssh_extract_raw_public_key(const char *public_key,
                                               size_t *out_len);

// ============================================================
// [0x0500] 同步原语：并发编排 (WaitGroup Control)
// ============================================================
// ---------------------------------------------------------

// ---------------------------------------------------------
// 互斥锁类型定义
// ---------------------------------------------------------
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
// ---------------------------------------------------------
// 等候组类型定义
// ---------------------------------------------------------
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

/** @ordinal 401 - 初始化互斥锁 */
void etos_sync_mutex_init(etos_sync_mutex_t *m);
/** @ordinal 402 - 阻塞式加锁 */
void etos_sync_mutex_lock(etos_sync_mutex_t *m);
/** @ordinal 403 - 非阻塞式加锁 (成功返回 1，失败返回 0) */
int etos_sync_mutex_trylock(etos_sync_mutex_t *m);
/** @ordinal 404 - 释放锁 */
void etos_sync_mutex_unlock(etos_sync_mutex_t *m);
/** @ordinal 405 - 销毁互斥锁 */
void etos_sync_mutex_destroy(etos_sync_mutex_t *m);

/** @ordinal 501 - 初始化 WaitGroup */
void etos_sync_waitgroup_init(etos_sync_waitgroup_t *wg);
/** @ordinal 502 - 增加/减少计数器 */
void etos_sync_waitgroup_add(etos_sync_waitgroup_t *wg, int delta);
/** @ordinal 503 - 计数器减一 (Add(-1) 的封装) */
void etos_sync_waitgroup_done(etos_sync_waitgroup_t *wg);
/** @ordinal 504 - 阻塞直到计数器归零 */
void etos_sync_waitgroup_wait(etos_sync_waitgroup_t *wg);
/** @ordinal 505 - 销毁 WaitGroup */
void etos_sync_waitgroup_destroy(etos_sync_waitgroup_t *wg);

// ============================================================
// [0x0600] 内存屏障与原子操作 (Atomic Operations)
// ============================================================

/** @ordinal 601 - 原子加载：触发全内存屏障 */
int64_t etos_sync_atomic_load(volatile int64_t *addr);
/** @ordinal 602 - 原子存储：确保存储可见性 */
void etos_sync_atomic_store(volatile int64_t *addr, int64_t value);
/** @ordinal 611 - 原子加法 */
int64_t etos_sync_atomic_add(volatile int64_t *addr, int64_t delta);
/** @ordinal 612 - 原子减法 */
int64_t etos_sync_atomic_sub(volatile int64_t *addr, int64_t delta);
/** @ordinal 621 - 原子交换并返回旧值 */
int64_t etos_sync_atomic_exchange(volatile int64_t *addr, int64_t value);
/** @ordinal 622 - 原子比较并交换 (CAS) */
int64_t etos_sync_atomic_cas(volatile int64_t *addr, int64_t expected,
                             int64_t desired);

// ============================================================
// [0x0800] 确定性生成：BIP39 助记词 (Deterministic Entropy)
// ============================================================
/** @ordinal 801 - 根据熵值生成 BIP39 助记词 */
int etos_bip39_generate(int strength, char *out_mnemonic, size_t out_max_len);
/** @ordinal 802 - 验证助记词是否符合校验规则 */
int etos_bip39_validate(const char *mnemonic);
/** @ordinal 803 - 将助记词与盐值转换为 512 位种子 (out_seed 需预留 64 字节) */
int etos_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                                unsigned char *out_seed);

#ifdef __cplusplus
}
#endif

#endif // ETOS_H
