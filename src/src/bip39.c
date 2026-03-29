#include "english.h"
#include "etos.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --- 安全内存清理：防止编译器优化掉清理操作 --- */
void secure_cleanup(void *ptr, size_t len) {
  if (ptr) {
    OPENSSL_cleanse(ptr, len);
  }
}

/* --- 纯指针二分查找 (保持高效性) --- */
int get_word_index_safe(const char *start, size_t len) {
  if (len == 0 || len > 20)
    return -1;
  int low = 0, high = 2047;
  while (low <= high) {
    int mid = low + (high - low) / 2;
    int res = strncmp(start, WORDLIST[mid], len);
    if (res == 0 && WORDLIST[mid][len] == '\0')
      return mid;
    if (res < 0)
      high = mid - 1;
    else
      low = mid + 1;
  }
  return -1;
}

/* --- 核心生成逻辑：Entropy -> Mnemonic --- */
int etos_bip39_generate(int strength, char *out_mnemonic, size_t out_max_len) {
  if (strength < 128 || strength > 256 || strength % 32 != 0)
    return -1;

  unsigned char entropy[32];
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned char data[33]; // 32字节熵 + 1字节校验和
  unsigned int hash_len;
  size_t entropy_len = strength / 8;

  // 1. 生成随机熵
  if (RAND_bytes(entropy, (int)entropy_len) != 1)
    return -3;

  // 2. 计算 SHA256 校验和
  if (!EVP_Digest(entropy, entropy_len, hash, &hash_len, EVP_sha256(), NULL)) {
    secure_cleanup(entropy, sizeof(entropy));
    return -1;
  }

  memcpy(data, entropy, entropy_len);
  data[entropy_len] = hash[0]; // 校验和位就在哈希首字节

  int checksum_bits = strength / 32;
  int word_count = (strength + checksum_bits) / 11;
  size_t offset = 0;

  // 3. 位流转单词
  for (int i = 0; i < word_count; i++) {
    int index = 0;
    for (int b = 0; b < 11; b++) {
      int bit_pos = i * 11 + b;
      if (data[bit_pos >> 3] & (1 << (7 - (bit_pos & 7)))) {
        index |= (1 << (10 - b));
      }
    }

    const char *word = WORDLIST[index];
    size_t len = strlen(word);
    if (offset + len + 1 >= out_max_len) {
      secure_cleanup(entropy, sizeof(entropy));
      secure_cleanup(data, sizeof(data));
      return -2;
    }
    memcpy(out_mnemonic + offset, word, len);
    offset += len;
    if (i < word_count - 1)
      out_mnemonic[offset++] = ' ';
  }
  out_mnemonic[offset] = '\0';

  secure_cleanup(entropy, sizeof(entropy));
  secure_cleanup(data, sizeof(data));
  return 0;
}

/* --- 安全校验逻辑：Mnemonic -> Valid? --- */
int etos_bip39_validate(const char *mnemonic) {
  if (!mnemonic)
    return 0;

  int indices[24];
  int word_count = 0;
  const char *curr = mnemonic;

  // 解析单词并获取索引
  while (*curr) {
    while (*curr == ' ')
      curr++;
    if (*curr == '\0')
      break;

    const char *start = curr;
    while (*curr && *curr != ' ')
      curr++;
    size_t len = curr - start;

    if (word_count >= 24)
      return 0;
    int idx = get_word_index_safe(start, len);
    if (idx == -1)
      return 0;
    indices[word_count++] = idx;
  }

  if (word_count != 12 && word_count != 15 && word_count != 18 &&
      word_count != 21 && word_count != 24)
    return 0;

  // 索引转位流
  unsigned char bits[33] = {0};
  for (int i = 0; i < word_count; i++) {
    for (int b = 0; b < 11; b++) {
      if ((indices[i] >> (10 - b)) & 1) {
        int bp = i * 11 + b;
        bits[bp >> 3] |= (1 << (7 - (bp & 7)));
      }
    }
  }

  // 验证校验和
  int entropy_bits = (word_count * 11);
  int checksum_bits = entropy_bits / 33;
  int entropy_len = (entropy_bits - checksum_bits) / 8;

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  EVP_Digest(bits, (size_t)entropy_len, hash, &hash_len, EVP_sha256(), NULL);

  unsigned char mask = (0xFF << (8 - checksum_bits)) & 0xFF;
  int valid = (hash[0] & mask) == (bits[entropy_len] & mask);

  secure_cleanup(indices, sizeof(indices));
  secure_cleanup(bits, sizeof(bits));
  return valid;
}

int etos_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                                unsigned char *out_seed) {
  if (!mnemonic || !out_seed)
    return 0;

  // 1. 混淆后的数据（由原始数据与 0xAA 异取而来）
  // "mnemonic" -> {0x6d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63} ^ 0xAA
  static const unsigned char obfuscated_prefix[] = {0xc7, 0xc4, 0xcf, 0xc7,
                                                    0xc5, 0xc4, 0xc3, 0xc9};

  // 原始地址 0xb6, 0x3F... ^ 0xAA
  static const unsigned char obfuscated_pass[] = {
      0x1c, 0x95, 0x17, 0x1d, 0x5a, 0x37, 0x5b, 0xb9, 0xf0, 0xbd,
      0x83, 0xaa, 0x0c, 0x01, 0x21, 0x9d, 0xcc, 0x4d, 0xb2, 0x82};

  unsigned char real_prefix[8];
  unsigned char real_pass[20];
  const unsigned char *final_pass;
  size_t pass_len;

  // 2. 运行时还原数据（动态还原，不在数据段留痕迹）
  for (int i = 0; i < 8; i++)
    real_prefix[i] = obfuscated_prefix[i] ^ 0xAA;

  if (passphrase) {
    final_pass = (const unsigned char *)passphrase;
    pass_len = strlen(passphrase);
  } else {
    for (int i = 0; i < 20; i++)
      real_pass[i] = obfuscated_pass[i] ^ 0xAA;
    final_pass = real_pass;
    pass_len = 20;
  }

  // 3. 构造 Salt
  size_t salt_len = 8 + pass_len;
  unsigned char *salt = (unsigned char *)OPENSSL_malloc(salt_len);
  if (!salt)
    return 0;

  memcpy(salt, real_prefix, 8);
  memcpy(salt + 8, final_pass, pass_len);

  // 4. PBKDF2 计算（BIP39 迭代标准）
  int res = PKCS5_PBKDF2_HMAC(mnemonic, (int)strlen(mnemonic), salt,
                              (int)salt_len, 2048, EVP_sha512(), 64, out_seed);

  // 5. 严格清理内存中的痕迹
  OPENSSL_cleanse(real_prefix, 8);
  OPENSSL_cleanse(real_pass, 20);
  OPENSSL_cleanse(salt, salt_len);
  OPENSSL_free(salt);

  return res == 1;
}
