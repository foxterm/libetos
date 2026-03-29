#include "ssl.h"
#include "etos.h"
#include <errno.h>
// 添加这些头文件
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#define YIELD_THREAD() SwitchToThread()
#else
#include <sched.h>
#include <sys/socket.h>
#include <unistd.h>
#define YIELD_THREAD() sched_yield()
#endif

SSL_CTX *g_etos_ssl_ctx = NULL;
static volatile int64_t is_initialized = 0;

void etos_ssl_init(void) {
  if (etos_sync_atomic_add(&is_initialized, 1) > 1)
    return ;
  OPENSSL_init_ssl(
      OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (ctx) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_default_verify_paths(ctx);
    g_etos_ssl_ctx = ctx;
  } else {
    etos_sync_atomic_add(&is_initialized, -1);
  }
}

void etos_ssl_free(void) {
  if (etos_sync_atomic_add(&is_initialized, -1) == 0) {
    if (g_etos_ssl_ctx) {
      SSL_CTX_free(g_etos_ssl_ctx);
      g_etos_ssl_ctx = NULL;
    }
  }
}

char *etos_ssl_base64_encode(const char *input) {
  if (!input)
    return NULL;
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *mem = BIO_new(BIO_s_mem());
  BIO_push(b64, mem);
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(b64, input, (int)strlen(input));
  BIO_flush(b64);
  BUF_MEM *ptr;
  BIO_get_mem_ptr(mem, &ptr);
  char *out = (char *)malloc(ptr->length + 1);
  if (out) {
    memcpy(out, ptr->data, ptr->length);
    out[ptr->length] = '\0';
  }
  BIO_free_all(b64);
  return out;
}

int etos_ssl_peek(SSL *ssl, char *buf, int len) {
  if (!ssl || !buf || len <= 0)
    return -1;

  int rc = SSL_peek(ssl, buf, len);
  if (rc <= 0) {
    int err = SSL_get_error(ssl, rc);
    // 处理非阻塞：数据还没解密出来
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
      return -EAGAIN;
    // 处理对端关闭
    if (err == SSL_ERROR_ZERO_RETURN)
      return 0;
    return -1;
  }
  return rc;
}

ssize_t etos_ssl_send(SSL *ssl, const char *buf, ssize_t len, int flags) {
  if (!ssl || !buf || len <= 0)
    return ETOS_ERROR;

  (void)flags;

  ssize_t rc = SSL_write(ssl, buf, len);
  if (rc <= 0) {
    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
      return -EAGAIN;
    return ETOS_ERROR;
  }
  return rc;
}

ssize_t etos_ssl_recv(SSL *ssl, char *buf, ssize_t len, int flags) {
  if (!ssl || !buf || len <= 0)
    return ETOS_ERROR;

  ssize_t rc;
  if (flags & MSG_PEEK) {
    rc = SSL_peek(ssl, buf, len);
  } else {
    rc = SSL_read(ssl, buf, len);
  }

  if (rc <= 0) {
    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
      return -EAGAIN;
    if (err == SSL_ERROR_ZERO_RETURN)
      return 0;
    return ETOS_ERROR;
  }
  return rc;
}

// 创建
SSL* etos_new_ssl(void) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    SSL* ssl = SSL_new(ctx);
    return ssl;
}

// 回收
void etos_free_ssl(SSL* ssl) {
    if (ssl) {
        SSL_free(ssl);
    }
}
