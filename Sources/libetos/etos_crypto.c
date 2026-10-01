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
