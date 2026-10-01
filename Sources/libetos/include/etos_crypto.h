#ifndef ETOS_CRYPTO_H
#define ETOS_CRYPTO_H

#include <stddef.h>

#define ETOS_AES_256_KEY_SIZE 32
#define ETOS_AES_GCM_IV_SIZE 12
#define ETOS_AES_GCM_TAG_SIZE 16

#define ETOS_OK 0
#define ETOS_ERR_INVALID_PARAM -1
#define ETOS_ERR_ALLOC_FAILED -2
#define ETOS_ERR_ENCRYPT_FAILED -3
#define ETOS_ERR_DECRYPT_FAILED -4
#define ETOS_ERR_AUTH_FAILED -5

/**
 * @brief 生成指定长度的强随机字节序列（常用于生成 Key 和 IV）
 * @param buf 输出缓冲区
 * @param len 需要生成的随机字节长度
 * @return 0 成功，非 0 失败
 */
int etos_crypto_rand_bytes(unsigned char *buf, size_t len);

/**
 * @brief 使用 AES-256-GCM 进行对称加密
 * @param plaintext 明文数据缓冲区
 * @param plaintext_len 明文长度
 * @param key 32字节密钥 (256-bit)
 * @param iv 12字节初始向量 (96-bit)
 * @param ciphertext 输出密文缓冲区（长度至少等于明文长度）
 * @param ciphertext_len 输出实际密文长度
 * @param tag 输出 16 字节认证标签 (Auth Tag)
 * @return 0 成功，非 0 失败
 */
int etos_aes_256_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                             const unsigned char key[ETOS_AES_256_KEY_SIZE],
                             const unsigned char iv[ETOS_AES_GCM_IV_SIZE],
                             unsigned char *ciphertext, size_t *ciphertext_len,
                             unsigned char tag[ETOS_AES_GCM_TAG_SIZE]);

/**
 * @brief 使用 AES-256-GCM 进行对称解密与身份校验
 * @param ciphertext 密文数据缓冲区
 * @param ciphertext_len 密文长度
 * @param tag 16 字节认证标签 (Auth Tag)
 * @param key 32字节密钥 (256-bit)
 * @param iv 12字节初始向量 (96-bit)
 * @param plaintext 输出明文缓冲区（长度至少等于密文长度）
 * @param plaintext_len 输出实际明文长度
 * @return 0 成功（且完整性校验通过），非 0 失败（如数据被篡改或参数错误）
 */
int etos_aes_256_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                             const unsigned char tag[ETOS_AES_GCM_TAG_SIZE],
                             const unsigned char key[ETOS_AES_256_KEY_SIZE],
                             const unsigned char iv[ETOS_AES_GCM_IV_SIZE],
                             unsigned char *plaintext, size_t *plaintext_len);

#endif
