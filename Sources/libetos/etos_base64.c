#include "etos_base64.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *etos_base64_encode(const char *src) {
  if (!src)
    return NULL;

  size_t len = strlen(src);
  size_t out_len = 4 * ((len + 2) / 3);
  char *out = (char *)malloc(out_len + 1);
  if (!out)
    return NULL;

  size_t i = 0, j = 0;
  while (i < len) {
    uint32_t octet_a = i < len ? (unsigned char)src[i++] : 0;
    uint32_t octet_b = i < len ? (unsigned char)src[i++] : 0;
    uint32_t octet_c = i < len ? (unsigned char)src[i++] : 0;

    uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

    out[j++] = base64_table[(triple >> 18) & 0x3F];
    out[j++] = base64_table[(triple >> 12) & 0x3F];
    out[j++] = (i > len + 1) ? '=' : base64_table[(triple >> 6) & 0x3F];
    out[j++] = (i > len) ? '=' : base64_table[triple & 0x3F];
  }

  out[j] = '\0';
  return out;
}

unsigned char *etos_base64_decode(const char *src, size_t *out_len) {
  if (!src)
    return NULL;

  size_t len = strlen(src);
  if (len % 4 != 0)
    return NULL;

  size_t decoded_len = len / 4 * 3;
  if (len > 0 && src[len - 1] == '=')
    decoded_len--;
  if (len > 1 && src[len - 2] == '=')
    decoded_len--;

  unsigned char *out = (unsigned char *)malloc(decoded_len + 1);
  if (!out)
    return NULL;

  static const int d[] = {
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
      -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
      52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -0, -1, -1,
      -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
      -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};

  size_t i = 0, j = 0;
  while (i < len) {
    int a = (src[i] == '=') ? 0 : d[(unsigned char)src[i]];
    i++;
    int b = (src[i] == '=') ? 0 : d[(unsigned char)src[i]];
    i++;
    int c = (src[i] == '=') ? 0 : d[(unsigned char)src[i]];
    i++;
    int d_val = (src[i] == '=') ? 0 : d[(unsigned char)src[i]];
    i++;

    if (a < 0 || b < 0 || c < 0 || d_val < 0) {
      free(out);
      return NULL;
    }

    uint32_t triple = (a << 18) + (b << 12) + (c << 6) + d_val;

    if (j < decoded_len)
      out[j++] = (triple >> 16) & 0xFF;
    if (j < decoded_len)
      out[j++] = (triple >> 8) & 0xFF;
    if (j < decoded_len)
      out[j++] = triple & 0xFF;
  }

  out[decoded_len] = '\0';
  if (out_len)
    *out_len = decoded_len;
  return out;
}

void etos_base64_free(void *ptr) {
  if (ptr) {
    free(ptr);
  }
}
