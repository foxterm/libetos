#include "etos_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

int etos_crypto_rand_bytes(unsigned char *buf, size_t len) {
  if (!buf || len == 0) {
    return ETOS_ERR_INVALID_PARAM;
  }

  if (RAND_bytes(buf, (int)len) != 1) {
    return ETOS_ERR_ENCRYPT_FAILED;
  }

  return ETOS_OK;
}

int etos_aes_256_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                             const unsigned char key[ETOS_AES_256_KEY_SIZE],
                             const unsigned char iv[ETOS_AES_GCM_IV_SIZE],
                             unsigned char *ciphertext, size_t *ciphertext_len,
                             unsigned char tag[ETOS_AES_GCM_TAG_SIZE]) {
  EVP_CIPHER_CTX *ctx = NULL;
  int len = 0;
  int total_len = 0;
  int ret = ETOS_ERR_ENCRYPT_FAILED;

  if (!plaintext || !key || !iv || !ciphertext || !ciphertext_len || !tag) {
    return ETOS_ERR_INVALID_PARAM;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return ETOS_ERR_ALLOC_FAILED;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    goto cleanup;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ETOS_AES_GCM_IV_SIZE, NULL) != 1) {
    goto cleanup;
  }

  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    goto cleanup;
  }

  if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
    goto cleanup;
  }
  total_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
    goto cleanup;
  }
  total_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ETOS_AES_GCM_TAG_SIZE, tag) != 1) {
    goto cleanup;
  }

  *ciphertext_len = (size_t)total_len;
  ret = ETOS_OK;

cleanup:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

int etos_aes_256_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                             const unsigned char tag[ETOS_AES_GCM_TAG_SIZE],
                             const unsigned char key[ETOS_AES_256_KEY_SIZE],
                             const unsigned char iv[ETOS_AES_GCM_IV_SIZE],
                             unsigned char *plaintext, size_t *plaintext_len) {
  EVP_CIPHER_CTX *ctx = NULL;
  int len = 0;
  int total_len = 0;
  int ret = ETOS_ERR_DECRYPT_FAILED;

  if (!ciphertext || !tag || !key || !iv || !plaintext || !plaintext_len) {
    return ETOS_ERR_INVALID_PARAM;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return ETOS_ERR_ALLOC_FAILED;
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
    goto cleanup;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ETOS_AES_GCM_IV_SIZE, NULL) != 1) {
    goto cleanup;
  }

  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
    goto cleanup;
  }

  if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1) {
    goto cleanup;
  }
  total_len = len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ETOS_AES_GCM_TAG_SIZE, (void *)tag) != 1) {
    goto cleanup;
  }

  if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) > 0) {
    total_len += len;
    *plaintext_len = (size_t)total_len;
    ret = ETOS_OK;
  } else {
    ret = ETOS_ERR_AUTH_FAILED;
  }

cleanup:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

int etos_ed25519_sign(const unsigned char *msg, size_t msg_len,
                      const unsigned char priv_key[ETOS_ED25519_PRIVATE_KEY_LEN],
                      unsigned char sig[ETOS_ED25519_SIGNATURE_LEN]) {
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  size_t sig_len = ETOS_ED25519_SIGNATURE_LEN;
  int ret = ETOS_ERR_SIGN_FAILED;

  if (!msg || msg_len == 0 || !priv_key || !sig) {
    return ETOS_ERR_INVALID_PARAM;
  }

  /* 从 32 字节原始私钥加载 EVP_PKEY */
  pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv_key, ETOS_ED25519_PRIVATE_KEY_LEN);
  if (!pkey) {
    return ETOS_ERR_INVALID_PARAM;
  }

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    return ETOS_ERR_ALLOC_FAILED;
  }

  /* Ed25519 的 Digest 初始化(在 EVP_DigestSignInit 中 digest 参数传 NULL) */
  if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
    goto cleanup;
  }

  /* 计算签名(一步完成消息的传入与签名计算) */
  if (EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len) != 1) {
    goto cleanup;
  }

  if (sig_len == ETOS_ED25519_SIGNATURE_LEN) {
    ret = ETOS_OK;
  }

cleanup:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return ret;
}

int etos_ed25519_verify(const unsigned char *msg, size_t msg_len,
                        const unsigned char pub_key[ETOS_ED25519_PUBLIC_KEY_LEN],
                        const unsigned char sig[ETOS_ED25519_SIGNATURE_LEN]) {
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  int ret = ETOS_ERR_VERIFY_FAILED;

  if (!msg || msg_len == 0 || !pub_key || !sig) {
    return ETOS_ERR_INVALID_PARAM;
  }

  /* 从 32 字节原始公钥加载 EVP_PKEY */
  pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub_key, ETOS_ED25519_PUBLIC_KEY_LEN);
  if (!pkey) {
    return ETOS_ERR_INVALID_PARAM;
  }

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    return ETOS_ERR_ALLOC_FAILED;
  }

  /* 初始化验证上下文 */
  if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) != 1) {
    goto cleanup;
  }

  /* 执行签名校验 */
  if (EVP_DigestVerify(md_ctx, sig, ETOS_ED25519_SIGNATURE_LEN, msg, msg_len) == 1) {
    ret = ETOS_OK;
  } else {
    ret = ETOS_ERR_VERIFY_FAILED;
  }

cleanup:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return ret;
}
