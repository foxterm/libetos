#ifndef ETOS_BASE64_H
#define ETOS_BASE64_H

#include <stddef.h>

/**
 * @brief 释放由 etos_base64 模块分配的内存
 *
 * @param ptr 需要释放的指针
 */
void etos_base64_free(void *ptr);

/**
 * @brief 对以 \0 结尾的字符串进行 Base64 编码
 *
 * @param input 输入的字符串
 * @return char* 动态分配内存的编码字符串（需由 etos_base64_free() 释放），失败返回 NULL
 */
char *etos_base64_encode(const char *input);

/**
 * @brief 对任意二进制数据进行 Base64 编码
 *
 * @param data 输入数据指针
 * @param len 输入数据字节长度
 * @return char* 动态分配内存的编码字符串（需由 etos_base64_free() 释放），失败返回 NULL
 */
char *etos_base64_encode_bytes(const unsigned char *data, size_t len);

/**
 * @brief 对 Base64 字符串进行解码
 *
 * @param input Base64 编码字符串
 * @param out_len 输出解码后的字节长度
 * @return unsigned char* 动态分配内存的解码数据（需由 etos_base64_free() 释放），失败返回 NULL
 */
unsigned char *etos_base64_decode(const char *input, size_t *out_len);

#endif /* ETOS_BASE64_H */
