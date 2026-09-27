#include "etos_buffer.h"

etos_buffer_t *etos_buffer_create(size_t element_size, size_t capacity) {
  if (capacity == 0 || element_size == 0)
    return NULL;

  etos_buffer_t *buf = (etos_buffer_t *)malloc(sizeof(etos_buffer_t));
  if (!buf)
    return NULL;

  buf->size = element_size;
  buf->capacity = capacity;

  size_t total_bytes = element_size * capacity;
  // 使用 calloc 分配并初始化内存为 0
  buf->ptr = calloc(1, total_bytes);

  if (!buf->ptr) {
    free(buf);
    return NULL;
  }

  return buf;
}

void etos_buffer_free(etos_buffer_t *buf) {
  if (!buf)
    return;
  if (buf->ptr) {
    free(buf->ptr);
  }
  free(buf);
}

void etos_buffer_copy_bytes(etos_buffer_t *buf, void *out_target, size_t count) {
  if (!buf || !buf->ptr || !out_target)
    return;

  // 边界安全校验：防止读取超出分配的总字节数
  size_t max_bytes = buf->size * buf->capacity;
  size_t copy_bytes = (count > max_bytes) ? max_bytes : count;

  memcpy(out_target, buf->ptr, copy_bytes);
}
