#ifndef ETOS_BUFFER_H
#define ETOS_BUFFER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  void *ptr;       /* 内存块起始地址，Swift 依靠 ptr 映射 T.self */
  size_t stride;   /* 单个元素的大小 (MemoryLayout<T>.stride) */
  size_t capacity; /* 元素数量或总容量 */
  size_t size;     /* 总分配字节数 (stride * capacity) */
} etos_buffer_t;

/**
 * 创建固定容量的内存缓冲区
 * @param stride 单个元素字节大小
 * @param capacity 元素数量/容量
 */
etos_buffer_t *etos_buffer_create(size_t stride, size_t capacity);

/**
 * 拷贝缓冲区前 count 字节的数据到目标内存
 * @param buf 缓冲区指针
 * @param dest 目标内存首地址
 * @param count 拷贝字节数
 */
void etos_buffer_copy_bytes(const etos_buffer_t *buf, void *dest, size_t count);

/**
 * 释放 Buffer 资源
 */
void etos_buffer_free(etos_buffer_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* ETOS_BUFFER_H */
