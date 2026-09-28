#include "etos_buffer.h"
#include <stdlib.h>
#include <string.h>

etos_buffer_t *etos_buffer_create(size_t stride, size_t capacity) {
  if (stride == 0 || capacity == 0)
    return NULL;

  etos_buffer_t *buf = (etos_buffer_t *)calloc(1, sizeof(etos_buffer_t));
  if (!buf)
    return NULL;

  size_t total_size = stride * capacity;
  buf->ptr = calloc(1, total_size); // 零初始化内存
  if (!buf->ptr) {
    free(buf);
    return NULL;
  }

  buf->stride = stride;
  buf->capacity = capacity;
  buf->size = total_size;

  return buf;
}

void etos_buffer_copy_bytes(const etos_buffer_t *buf, void *dest, size_t count) {
  if (!buf || !buf->ptr || !dest || count == 0)
    return;

  // 边界保护：防止越界拷贝
  size_t copy_len = (count > buf->size) ? buf->size : count;
  memcpy(dest, buf->ptr, copy_len);
}

void etos_buffer_free(etos_buffer_t *buf) {
  if (buf) {
    if (buf->ptr) {
      free(buf->ptr);
      buf->ptr = NULL;
    }
    free(buf);
  }
}
