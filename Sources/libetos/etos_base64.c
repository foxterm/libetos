#include "etos_base64.h"
#include <stdlib.h>
#include <string.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void etos_base64_free(void *ptr) {
  if (ptr) {
    free(ptr);
  }
}

char *etos_base64_encode_bytes(const unsigned char *data, size_t len) {
  if (!data)
    return NULL;

  size_t out_len = 4 * ((len + 2) / 3);
  char *out = (char *)malloc(out_len + 1);
  if (!out)
    return NULL;

  size_t i = 0, j = 0;
  for (; i + 2 < len; i += 3) {
    out[j++] = b64_table[(data[i] >> 2) & 0x3F];
    out[j++] = b64_table[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0F)];
    out[j++] = b64_table[((data[i + 1] & 0x0F) << 2) | ((data[i + 2] >> 6) & 0x03)];
    out[j++] = b64_table[data[i + 2] & 0x3F];
  }

  if (i < len) {
    out[j++] = b64_table[(data[i] >> 2) & 0x3F];
    if (i + 1 == len) {
      out[j++] = b64_table[(data[i] & 0x03) << 4];
      out[j++] = '=';
    } else {
      out[j++] = b64_table[((data[i] & 0x03) << 4) | ((data[i + 1] >> 4) & 0x0F)];
      out[j++] = b64_table[(data[i + 1] & 0x0F) << 2];
    }
    out[j++] = '=';
  }

  out[j] = '\0';
  return out;
}

char *etos_base64_encode(const char *input) {
  if (!input)
    return NULL;
  return etos_base64_encode_bytes((const unsigned char *)input, strlen(input));
}

static int b64_char_value(char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a' + 26;
  if (c >= '0' && c <= '9')
    return c - '0' + 52;
  if (c == '+')
    return 62;
  if (c == '/')
    return 63;
  return -1;
}

unsigned char *etos_base64_decode(const char *input, size_t *out_len) {
  if (!input)
    return NULL;

  size_t len = strlen(input);
  if (len % 4 != 0)
    return NULL;

  size_t padding = 0;
  if (len >= 1 && input[len - 1] == '=')
    padding++;
  if (len >= 2 && input[len - 2] == '=')
    padding++;

  size_t decoded_len = (len / 4) * 3 - padding;
  unsigned char *out = (unsigned char *)malloc(decoded_len + 1);
  if (!out)
    return NULL;

  size_t i = 0, j = 0;
  for (; i < len; i += 4) {
    int v1 = b64_char_value(input[i]);
    int v2 = b64_char_value(input[i + 1]);
    int v3 = (input[i + 2] == '=') ? 0 : b64_char_value(input[i + 2]);
    int v4 = (input[i + 3] == '=') ? 0 : b64_char_value(input[i + 3]);

    if (v1 < 0 || v2 < 0 || (input[i + 2] != '=' && v3 < 0) || (input[i + 3] != '=' && v4 < 0)) {
      free(out);
      return NULL;
    }

    out[j++] = (unsigned char)((v1 << 2) | (v2 >> 4));
    if (input[i + 2] != '=') {
      out[j++] = (unsigned char)(((v2 & 0x0F) << 4) | (v3 >> 2));
    }
    if (input[i + 3] != '=') {
      out[j++] = (unsigned char)(((v3 & 0x03) << 6) | v4);
    }
  }

  out[decoded_len] = '\0';
  if (out_len) {
    *out_len = decoded_len;
  }

  return out;
}
