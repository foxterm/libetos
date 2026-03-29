#ifndef ETOS_SSL_H
#define ETOS_SSL_H
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

// 全局变量声明 (extern)
extern SSL_CTX *g_etos_ssl_ctx;

void etos_ssl_init(void);
void etos_ssl_free(void);
ssize_t etos_ssl_send(SSL *ssl, const char *buf, ssize_t len, int flags);
ssize_t etos_ssl_recv(SSL *ssl, char *buf, ssize_t len, int flags);
char *etos_ssl_base64_encode(const char *input);

SSL* etos_new_ssl(void);
void etos_free_ssl(SSL* ssl);
#endif
