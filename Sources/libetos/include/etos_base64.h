#ifndef ETOS_BASE64_H
#define ETOS_BASE64_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Base64 编码
 * @param src 输入字符串/字节流
 * @return 动态分配的 Base64 编码字符串，失败返回 NULL。用完后须调用 etos_base64_free 释放。
 */
char *etos_base64_encode(const char *src);

/**
 * Base64 解码
 * @param src Base64 编码字符串
 * @param out_len 输出解码后字节流的长度
 * @return 动态分配的解码数据缓冲区，失败返回 NULL。用完后须调用 etos_base64_free 释放。
 */
unsigned char *etos_base64_decode(const char *src, size_t *out_len);

/**
 * 释放 Base64 模块分配的内存
 */
void etos_base64_free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* ETOS_BASE64_H */
