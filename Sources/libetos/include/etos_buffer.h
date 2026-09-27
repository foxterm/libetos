#ifndef ETOS_BUFFER_h
#define ETOS_BUFFER_h

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 底层通用 Buffer 结构体
typedef struct {
  void *ptr;       // 指向实际分配内存的指针
  size_t size;     // 单个元素的字节大小 (stride)
  size_t capacity; // 元素的数量容量
} etos_buffer_t;

// 创建并初始化内存为 0 的 Buffer
etos_buffer_t *etos_buffer_create(size_t element_size, size_t capacity);

// 释放 Buffer 内存
void etos_buffer_free(etos_buffer_t *buf);

// 从 Buffer 拷贝数据
void etos_buffer_copy_bytes(etos_buffer_t *buf, void *out_target, size_t count);

#endif /* ETOS_BUFFER_h */
