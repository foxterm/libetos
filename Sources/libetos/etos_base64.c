#include "etos_base64.h"
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

void etos_base64_free(void *ptr) {
  if (ptr) {
    free(ptr);
  }
}

char *etos_base64_encode_bytes(const unsigned char *data, size_t len) {
  if (!data)
    return NULL;

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  if (!b64 || !bio) {
    BIO_free_all(b64 ? b64 : bio);
    return NULL;
  }

  // 不插入换行符
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  if (BIO_write(bio, data, (int)len) <= 0 || BIO_flush(bio) <= 0) {
    BIO_free_all(bio);
    return NULL;
  }

  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(bio, &bufferPtr);

  char *out = (char *)malloc(bufferPtr->length + 1);
  if (out) {
    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = '\0';
  }

  BIO_free_all(bio);
  return out;
}

char *etos_base64_encode(const char *input) {
  if (!input)
    return NULL;
  return etos_base64_encode_bytes((const unsigned char *)input, strlen(input));
}

unsigned char *etos_base64_decode(const char *input, size_t *out_len) {
  if (!input)
    return NULL;

  size_t len = strlen(input);
  if (len == 0)
    return NULL;

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new_mem_buf((void *)input, (int)len);
  if (!b64 || !bio) {
    BIO_free_all(b64 ? b64 : bio);
    return NULL;
  }

  // 不期望换行符
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  // 分配最大可能的解密结果空间
  size_t max_out_len = (len / 4) * 3 + 1;
  unsigned char *out = (unsigned char *)malloc(max_out_len);
  if (!out) {
    BIO_free_all(bio);
    return NULL;
  }

  int decoded_bytes = BIO_read(bio, out, (int)len);
  BIO_free_all(bio);

  if (decoded_bytes < 0) {
    free(out);
    return NULL;
  }

  out[decoded_bytes] = '\0';
  if (out_len) {
    *out_len = (size_t)decoded_bytes;
  }

  return out;
}
