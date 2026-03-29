#include "etos.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 内部错误信息 */
char g_error_msg[256] = {0};

/* 设置错误信息 */
void set_error(const char *format, ...) {
  va_list args;
  va_start(args, format);
  vsnprintf(g_error_msg, sizeof(g_error_msg), format, args);
  va_end(args);
  g_error_msg[sizeof(g_error_msg) - 1] = '\0';
}

/* 内部清理函数 */
void cleanup_keypair(SSHKeyPair *keypair) {
  if (keypair) {
    if (keypair->private_key)
      free(keypair->private_key);
    if (keypair->public_key)
      free(keypair->public_key);
    // if (keypair->fingerprint) free(keypair->fingerprint);
    free(keypair);
  }
}

/* 获取错误信息 */
const char *etos_ssh_keygen_get_error(void) {
  return g_error_msg[0] ? g_error_msg : "No error";
}

/* Base64编码实现 */
char *base64_encode(const unsigned char *data, size_t len) {
  if (!data || len == 0) {
    set_error("Invalid data for base64 encode");
    return NULL;
  }

  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *mem = BIO_new(BIO_s_mem());
  if (!b64 || !mem) {
    if (b64)
      BIO_free(b64);
    if (mem)
      BIO_free(mem);
    set_error("Failed to create BIO for base64");
    return NULL;
  }

  BIO *bio = BIO_push(b64, mem);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  if (BIO_write(bio, data, (int)len) <= 0) {
    BIO_free_all(bio);
    set_error("Failed to write data for base64 encoding");
    return NULL;
  }

  if (BIO_flush(bio) <= 0) {
    BIO_free_all(bio);
    set_error("Failed to flush BIO");
    return NULL;
  }

  BUF_MEM *bptr = NULL;
  BIO_get_mem_ptr(bio, &bptr);

  if (!bptr || bptr->length == 0) {
    BIO_free_all(bio);
    set_error("No data in base64 buffer");
    return NULL;
  }

  char *result = (char *)malloc(bptr->length + 1);
  if (!result) {
    BIO_free_all(bio);
    set_error("Memory allocation failed for base64");
    return NULL;
  }

  memcpy(result, bptr->data, bptr->length);
  result[bptr->length] = '\0';

  BIO_free_all(bio);
  return result;
}

/* 写入带长度的字符串到BIO */
bool write_length_string(BIO *bio, const char *str, size_t len) {
  if (!bio)
    return false;

  uint32_t net_len = htonl((uint32_t)len);
  if (BIO_write(bio, &net_len, 4) != 4) {
    set_error("Failed to write length to BIO");
    return false;
  }

  if (len > 0) {
    if (!str) {
      set_error("NULL string with non-zero length");
      return false;
    }
    if (BIO_write(bio, str, (int)len) != (int)len) {
      set_error("Failed to write string data to BIO");
      return false;
    }
  }
  return true;
}

/* 写入带长度的大整数到BIO */
bool write_length_bignum(BIO *bio, const BIGNUM *bn) {
  if (!bio || !bn) {
    set_error("Invalid parameters for write_length_bignum");
    return false;
  }

  int bn_len = BN_num_bytes(bn);
  if (bn_len <= 0) {
    set_error("Invalid BIGNUM length");
    return false;
  }

  uint32_t net_len = htonl((uint32_t)bn_len);
  if (BIO_write(bio, &net_len, 4) != 4) {
    set_error("Failed to write BIGNUM length");
    return false;
  }

  unsigned char *buffer = (unsigned char *)malloc(bn_len);
  if (!buffer) {
    set_error("Memory allocation failed for BIGNUM buffer");
    return false;
  }

  int actual_len = BN_bn2bin(bn, buffer);
  bool result = false;

  if (actual_len == bn_len && BIO_write(bio, buffer, bn_len) == bn_len) {
    result = true;
  } else {
    set_error("Failed to write BIGNUM data");
  }

  free(buffer);
  return result;
}

/* 写入带长度的二进制数据到BIO */
bool write_length_data(BIO *bio, const unsigned char *data, int len) {
  if (!bio)
    return false;

  if (len < 0) {
    set_error("Invalid data length: %d", len);
    return false;
  }

  uint32_t net_len = htonl((uint32_t)len);
  if (BIO_write(bio, &net_len, 4) != 4) {
    set_error("Failed to write data length");
    return false;
  }

  if (len > 0) {
    if (!data) {
      set_error("NULL data with non-zero length");
      return false;
    }
    if (BIO_write(bio, data, len) != len) {
      set_error("Failed to write binary data");
      return false;
    }
  }
  return true;
}

/* 获取加密算法 */
const EVP_CIPHER *get_cipher(CipherType cipher) {
  switch (cipher) {
  case CIPHER_AES128_CBC:
    return EVP_aes_128_cbc();
  case CIPHER_AES192_CBC:
    return EVP_aes_192_cbc();
  case CIPHER_AES256_CBC:
    return EVP_aes_256_cbc();
  case CIPHER_NONE:
  default:
    return NULL;
  }
}

/* 生成RSA密钥 */
/* 生成RSA密钥 - 使用libssh2的参数名 */
EVP_PKEY *generate_rsa_key(int bits) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* OpenSSL 3.0+ 使用新API */
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  OSSL_PARAM params[3];

  ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (!ctx) {
    set_error("Failed to create RSA context for OpenSSL 3.0: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    set_error("Failed to initialize RSA keygen for OpenSSL 3.0: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  /* 使用libssh2的参数名 */
  params[0] = OSSL_PARAM_construct_int("bits", &bits);

  /* 设置公共指数为65537，使用无符号整数 */
  unsigned int e = 65537;
  params[1] = OSSL_PARAM_construct_uint("e", &e);
  params[2] = OSSL_PARAM_construct_end();

  if (!EVP_PKEY_CTX_set_params(ctx, params)) {
    EVP_PKEY_CTX_free(ctx);
    set_error("Failed to set RSA parameters for OpenSSL 3.0: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    set_error("Failed to generate RSA key with OpenSSL 3.0: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  return pkey;

#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
  /* OpenSSL 1.1.x 使用旧API */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if (!ctx) {
    set_error("Failed to create RSA context: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  EVP_PKEY *pkey = NULL;
  bool success = false;

  do {
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      set_error("Failed to initialize RSA keygen: %s",
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
      set_error("Failed to set RSA key bits to %d: %s", bits,
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    /* 设置RSA公共指数为65537 */
    BIGNUM *e = BN_new();
    if (!e) {
      set_error("Failed to create BIGNUM for RSA exponent");
      break;
    }

    BN_set_word(e, 65537);

/* 在OpenSSL 1.1.x中，我们避免使用弃用警告 */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e) <= 0) {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
      BN_free(e);
      set_error("Failed to set RSA public exponent: %s",
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

    BN_free(e);

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      set_error("Failed to generate RSA key: %s",
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    success = true;
  } while (0);

  EVP_PKEY_CTX_free(ctx);

  if (!success && pkey) {
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }

  return pkey;
#else
  /* OpenSSL 1.0.x */
  set_error("OpenSSL 1.0.x is not supported");
  return NULL;
#endif
}

/* 生成ECDSA密钥 */
EVP_PKEY *generate_ecdsa_key(int bits) {
  int nid;
  switch (bits) {
  case 256:
    nid = NID_X9_62_prime256v1;
    break;
  case 384:
    nid = NID_secp384r1;
    break;
  case 521:
    nid = NID_secp521r1;
    break;
  default:
    set_error("Invalid ECDSA key bits: %d (valid: 256, 384, 521)", bits);
    return NULL;
  }

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
  if (!ctx) {
    set_error("Failed to create ECDSA context: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  EVP_PKEY *pkey = NULL;
  bool success = false;

  do {
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      set_error("Failed to initialize ECDSA keygen: %s",
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
      set_error("Failed to set ECDSA curve %d: %s", nid,
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      set_error("Failed to generate ECDSA key: %s",
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    success = true;
  } while (0);

  EVP_PKEY_CTX_free(ctx);

  if (!success && pkey) {
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }

  return pkey;
}

/* 生成ED25519密钥 */
EVP_PKEY *generate_ed25519_key(void) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && defined(EVP_PKEY_ED25519)
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (!ctx) {
    set_error("Failed to create ED25519 context: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  EVP_PKEY *pkey = NULL;
  bool success = false;

  do {
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
      set_error("Failed to initialize ED25519 keygen: %s",
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
      set_error("Failed to generate ED25519 key: %s",
                ERR_error_string(ERR_get_error(), NULL));
      break;
    }

    success = true;
  } while (0);

  EVP_PKEY_CTX_free(ctx);

  if (!success && pkey) {
    EVP_PKEY_free(pkey);
    pkey = NULL;
  }

  return pkey;
#else
  set_error("ED25519 requires OpenSSL 1.1.1 or later");
  return NULL;
#endif
}

/* 导出PEM私钥 */
char *export_private_key_pem(EVP_PKEY *pkey, const char *password,
                             CipherType cipher) {
  if (!pkey) {
    set_error("Invalid PKEY for export");
    return NULL;
  }

  BIO *bio = BIO_new(BIO_s_mem());
  if (!bio) {
    set_error("Failed to create BIO for private key: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  const EVP_CIPHER *cipher_evp = get_cipher(cipher);
  int result = 0;

  if (password && password[0] && cipher_evp) {
    /* 加密私钥 */
    result = PEM_write_bio_PrivateKey(bio, pkey, cipher_evp,
                                      (unsigned char *)password,
                                      (int)strlen(password), NULL, NULL);
  } else {
    /* 不加密私钥 */
    result = PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);
  }

  if (!result) {
    BIO_free(bio);
    set_error("Failed to write private key to PEM: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  char *data = NULL;
  long len = BIO_get_mem_data(bio, &data);
  if (len <= 0 || !data) {
    BIO_free(bio);
    set_error("Failed to get private key data from BIO");
    return NULL;
  }

  char *private_key = (char *)malloc(len + 1);
  if (!private_key) {
    BIO_free(bio);
    set_error("Memory allocation failed for private key");
    return NULL;
  }

  memcpy(private_key, data, len);
  private_key[len] = '\0';

  BIO_free(bio);
  return private_key;
}

/* 生成RSA公钥的OpenSSH格式 */
char *rsa_to_openssh(EVP_PKEY *pkey, const char *comment) {
  if (!pkey) {
    set_error("Invalid PKEY for RSA to OpenSSH");
    return NULL;
  }

  BIO *bio = NULL;
  char *public_key = NULL;
  char *b64 = NULL;
  bool success = false;

  /* 声明变量 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* OpenSSL 3.0+ 使用新的EVP_PKEY_get_bn_param */
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;

  /* 获取RSA参数 */
  if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) ||
      !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
    set_error("Failed to get RSA parameters (OpenSSL 3.0): %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }
#else
  /* OpenSSL 1.1.x 使用旧的API */
  RSA *rsa = EVP_PKEY_get0_RSA(pkey);
  if (!rsa) {
    set_error("Failed to get RSA from EVP_PKEY: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  const BIGNUM *n = NULL;
  const BIGNUM *e = NULL;
  const BIGNUM *d = NULL;
  RSA_get0_key(rsa, &n, &e, &d);
#endif

  if (!n || !e) {
    set_error("Failed to get RSA key components (n or e is NULL)");
    goto cleanup;
  }

  if (BN_num_bits(n) < 1024) {
    set_error("RSA key too small: %d bits (minimum 1024)", BN_num_bits(n));
    goto cleanup;
  }

  bio = BIO_new(BIO_s_mem());
  if (!bio) {
    set_error("Failed to create BIO for RSA public key: %s",
              ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }

  do {
    /* 写入密钥类型标识 */
    if (!write_length_string(bio, "ssh-rsa", 7)) {
      break;
    }

    /* 写入e */
    if (!write_length_bignum(bio, e)) {
      set_error("Failed to write RSA exponent to BIO");
      break;
    }

    /* 写入n */
    if (!write_length_bignum(bio, n)) {
      set_error("Failed to write RSA modulus to BIO");
      break;
    }

    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
      set_error("Failed to get RSA public key data from BIO");
      break;
    }

    /* Base64编码 */
    b64 = base64_encode((unsigned char *)data, (size_t)len);
    if (!b64) {
      set_error("Failed to base64 encode RSA public key");
      break;
    }

    /* 构建完整的OpenSSH公钥字符串 */
    const char *default_comment = "";
    const char *actual_comment =
        (comment && comment[0]) ? comment : default_comment;

    int public_key_len = 8 + strlen(b64) + 1 + strlen(actual_comment) + 1;
    public_key = (char *)malloc(public_key_len);
    if (!public_key) {
      set_error("Memory allocation failed for RSA public key");
      break;
    }

    snprintf(public_key, public_key_len, "ssh-rsa %s %s", b64, actual_comment);
    success = true;
  } while (0);

cleanup:
  if (bio)
    BIO_free(bio);
  if (b64)
    free(b64);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* 清理OpenSSL 3.0获取的BIGNUM */
  if (n)
    BN_free(n);
  if (e)
    BN_free(e);
#endif

  if (!success && public_key) {
    free(public_key);
    public_key = NULL;
  }

  return public_key;
}

/* 生成ECDSA公钥的OpenSSH格式 */
/* 生成ECDSA公钥的OpenSSH格式 - 兼容OpenSSL 3.0 */
char *ecdsa_to_openssh(EVP_PKEY *pkey, const char *comment) {
  if (!pkey) {
    set_error("Invalid PKEY for ECDSA to OpenSSH");
    return NULL;
  }

  int nid = 0;
  const char *curve_name = NULL;
  const char *key_type = NULL;
  unsigned char *point_buf = NULL;
  size_t point_len = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* OpenSSL 3.0+ 使用新API */
  char curve_name_str[256] = {0};
  size_t curve_name_len = sizeof(curve_name_str);

  /* 获取曲线名称 */
  if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                      curve_name_str, curve_name_len,
                                      &curve_name_len)) {
    set_error("Failed to get EC curve name (OpenSSL 3.0): %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  /* 将曲线名称映射到NID和OpenSSH格式 */
  if (strcmp(curve_name_str, "prime256v1") == 0 ||
      strcmp(curve_name_str, "secp256r1") == 0) {
    nid = NID_X9_62_prime256v1;
    curve_name = "nistp256";
    key_type = "ecdsa-sha2-nistp256";
  } else if (strcmp(curve_name_str, "secp384r1") == 0) {
    nid = NID_secp384r1;
    curve_name = "nistp384";
    key_type = "ecdsa-sha2-nistp384";
  } else if (strcmp(curve_name_str, "secp521r1") == 0) {
    nid = NID_secp521r1;
    curve_name = "nistp521";
    key_type = "ecdsa-sha2-nistp521";
  } else {
    set_error("Unsupported EC curve: %s", curve_name_str);
    return NULL;
  }

  /* 获取公钥点 */
  if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                       &point_len)) {
    set_error("Failed to get EC public key length (OpenSSL 3.0): %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  point_buf = (unsigned char *)malloc(point_len);
  if (!point_buf) {
    set_error("Memory allocation failed for EC point");
    return NULL;
  }

  if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, point_buf,
                                       point_len, &point_len)) {
    free(point_buf);
    set_error("Failed to get EC public key (OpenSSL 3.0): %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

#else
  /* OpenSSL 1.1.x 使用旧API */
  EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);
  if (!ec) {
    set_error("Failed to get EC key from EVP_PKEY: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  const EC_GROUP *group = EC_KEY_get0_group(ec);
  const EC_POINT *point = EC_KEY_get0_public_key(ec);

  if (!group || !point) {
    set_error("Failed to get EC group or point");
    return NULL;
  }

  /* 确定曲线名称 */
  nid = EC_GROUP_get_curve_name(group);

  switch (nid) {
  case NID_X9_62_prime256v1:
    curve_name = "nistp256";
    key_type = "ecdsa-sha2-nistp256";
    break;
  case NID_secp384r1:
    curve_name = "nistp384";
    key_type = "ecdsa-sha2-nistp384";
    break;
  case NID_secp521r1:
    curve_name = "nistp521";
    key_type = "ecdsa-sha2-nistp521";
    break;
  default:
    set_error("Unsupported EC curve: %d", nid);
    return NULL;
  }

  /* 编码公钥点 */
  point_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                 NULL, 0, NULL);
  if (point_len == 0) {
    set_error("Failed to get EC point length: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  point_buf = (unsigned char *)malloc(point_len);
  if (!point_buf) {
    set_error("Memory allocation failed for EC point");
    return NULL;
  }

  if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, point_buf,
                         point_len, NULL) != point_len) {
    free(point_buf);
    set_error("Failed to encode EC point: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }
#endif

  BIO *bio = BIO_new(BIO_s_mem());
  if (!bio) {
    free(point_buf);
    set_error("Failed to create BIO for ECDSA public key: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  char *public_key = NULL;
  char *b64 = NULL;
  bool success = false;

  do {
    /* 写入密钥类型标识 */
    if (!write_length_string(bio, key_type, strlen(key_type))) {
      set_error("Failed to write ECDSA key type");
      break;
    }

    /* 写入曲线名称 */
    if (!write_length_string(bio, curve_name, strlen(curve_name))) {
      set_error("Failed to write ECDSA curve name");
      break;
    }

    /* 写入公钥点 */
    if (!write_length_data(bio, point_buf, (int)point_len)) {
      set_error("Failed to write ECDSA public point");
      break;
    }

    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
      set_error("Failed to get ECDSA public key data from BIO");
      break;
    }

    b64 = base64_encode((unsigned char *)data, (size_t)len);
    if (!b64) {
      set_error("Failed to base64 encode ECDSA public key");
      break;
    }

    /* 构建完整的OpenSSH公钥字符串 */
    const char *default_comment = "";
    const char *actual_comment =
        (comment && comment[0]) ? comment : default_comment;

    int public_key_len = (int)strlen(key_type) + 1 + strlen(b64) + 1 +
                         strlen(actual_comment) + 1;
    public_key = (char *)malloc(public_key_len);
    if (!public_key) {
      set_error("Memory allocation failed for ECDSA public key");
      break;
    }

    snprintf(public_key, public_key_len, "%s %s %s", key_type, b64,
             actual_comment);
    success = true;
  } while (0);

  free(point_buf);
  BIO_free(bio);
  if (b64)
    free(b64);

  if (!success && public_key) {
    free(public_key);
    public_key = NULL;
  }

  return public_key;
}

/* 生成ED25519公钥的OpenSSH格式 */
char *ed25519_to_openssh(EVP_PKEY *pkey, const char *comment) {
#if OPENSSL_VERSION_NUMBER >= 0x10101000L && defined(EVP_PKEY_ED25519)
  if (!pkey) {
    set_error("Invalid PKEY for ED25519 to OpenSSH");
    return NULL;
  }

  size_t pubkey_len = 32;
  unsigned char pubkey[32];

  if (EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubkey_len) != 1 ||
      pubkey_len != 32) {
    set_error("Failed to get ED25519 raw public key: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  BIO *bio = BIO_new(BIO_s_mem());
  if (!bio) {
    set_error("Failed to create BIO for ED25519 public key: %s",
              ERR_error_string(ERR_get_error(), NULL));
    return NULL;
  }

  char *public_key = NULL;
  char *b64 = NULL;
  bool success = false;

  do {
    /* 写入密钥类型标识 */
    if (!write_length_string(bio, "ssh-ed25519", 11)) {
      set_error("Failed to write ED25519 key type");
      break;
    }

    /* 写入公钥 */
    if (!write_length_data(bio, pubkey, 32)) {
      set_error("Failed to write ED25519 public key");
      break;
    }

    char *data = NULL;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
      set_error("Failed to get ED25519 public key data from BIO");
      break;
    }

    b64 = base64_encode((unsigned char *)data, (size_t)len);
    if (!b64) {
      set_error("Failed to base64 encode ED25519 public key");
      break;
    }

    /* 构建完整的OpenSSH公钥字符串 */
    const char *default_comment = "";
    const char *actual_comment =
        (comment && comment[0]) ? comment : default_comment;

    int public_key_len = 12 + strlen(b64) + 1 + strlen(actual_comment) + 1;
    public_key = (char *)malloc(public_key_len);
    if (!public_key) {
      set_error("Memory allocation failed for ED25519 public key");
      break;
    }

    snprintf(public_key, public_key_len, "ssh-ed25519 %s %s", b64,
             actual_comment);
    success = true;
  } while (0);

  BIO_free(bio);
  if (b64)
    free(b64);

  if (!success && public_key) {
    free(public_key);
    public_key = NULL;
  }

  return public_key;
#else
  set_error("ED25519 requires OpenSSL 1.1.1 or later");
  return NULL;
#endif
}

/* 生成公钥的OpenSSH格式 */
char *export_public_key_openssh(EVP_PKEY *pkey, const char *comment) {
  if (!pkey) {
    set_error("Invalid PKEY for public key export");
    return NULL;
  }

  int type = EVP_PKEY_id(pkey);

  switch (type) {
  case EVP_PKEY_RSA:
    return rsa_to_openssh(pkey, comment);
  case EVP_PKEY_EC:
    return ecdsa_to_openssh(pkey, comment);
  case EVP_PKEY_ED25519:
    return ed25519_to_openssh(pkey, comment);
  default:
    set_error("Unsupported key type: %d", type);
    return NULL;
  }
}

/* 提取公钥原始数据 - 返回Base64解码后的原始字节数组 */
unsigned char *etos_ssh_extract_raw_public_key(const char *public_key,
                                               size_t *out_len) {
  if (!public_key || !public_key[0]) {
    set_error("Invalid public key");
    if (out_len)
      *out_len = 0;
    return NULL;
  }

  if (out_len)
    *out_len = 0;

  /* 找到Base64部分的开始和结束 */
  const char *b64_start = strchr(public_key, ' ');
  if (!b64_start) {
    set_error("Invalid public key format: no space found");
    return NULL;
  }
  b64_start++; /* 跳过空格 */

  const char *b64_end = strchr(b64_start, ' ');
  if (!b64_end) {
    b64_end = public_key + strlen(public_key);
  }

  size_t b64_len = b64_end - b64_start;
  if (b64_len == 0) {
    set_error("Empty Base64 data in public key");
    return NULL;
  }

  /* 计算Base64解码后的最大长度 */
  size_t max_decoded_len = (b64_len * 3) / 4 + 2;
  if (max_decoded_len > 4096) {
    set_error("Base64 data too large");
    return NULL;
  }

  /* Base64解码 */
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *mem = BIO_new_mem_buf(b64_start, (int)b64_len);
  if (!b64 || !mem) {
    if (b64)
      BIO_free(b64);
    if (mem)
      BIO_free(mem);
    set_error("Failed to create BIO for base64 decoding");
    return NULL;
  }

  BIO *bio = BIO_push(b64, mem);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  unsigned char *decoded = (unsigned char *)malloc(max_decoded_len);
  if (!decoded) {
    BIO_free_all(bio);
    set_error("Memory allocation failed");
    return NULL;
  }

  int decoded_len = BIO_read(bio, decoded, max_decoded_len);
  BIO_free_all(bio);

  if (decoded_len <= 0) {
    free(decoded);
    set_error("Failed to decode Base64 data");
    return NULL;
  }

  /* 重新分配内存到实际大小，避免浪费 */
  unsigned char *result = (unsigned char *)malloc(decoded_len);
  if (!result) {
    free(decoded);
    set_error("Memory allocation failed for result");
    return NULL;
  }

  memcpy(result, decoded, decoded_len);
  free(decoded);

  if (out_len)
    *out_len = decoded_len;

  return result;
}

/* 初始化库 */
int etos_ssh_keygen_init(void) {
  /* OpenSSL 1.1.0+ 会自动初始化，但为了兼容性，我们调用一次 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  /* OpenSSL 1.0.x 需要显式初始化 */
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
#endif

  g_error_msg[0] = '\0';

  /* 确保OpenSSL随机数生成器已初始化 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  if (!RAND_status()) {
    set_error("OpenSSL RNG not properly initialized");
    return SSH_KEYGEN_ERROR;
  }
#endif

  return SSH_KEYGEN_SUCCESS;
}

/* 清理库资源 */
void etos_ssh_keygen_cleanup(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EVP_cleanup();
  ERR_free_strings();
#endif
}

/* 生成SSH密钥对 */
SSHKeyPair *etos_ssh_keygen_generate(const KeyGenOptions *options) {
  if (!options) {
    set_error("Options cannot be NULL");
    return NULL;
  }

  /* 验证参数 */
  if (options->key_type < KEY_TYPE_RSA ||
      options->key_type > KEY_TYPE_ED25519) {
    set_error("Invalid key type: %d", options->key_type);
    return NULL;
  }

  /* 生成密钥 */
  EVP_PKEY *pkey = NULL;
  int key_bits = options->key_bits;

  switch (options->key_type) {
  case KEY_TYPE_RSA:
    pkey = generate_rsa_key(key_bits);
    break;
  case KEY_TYPE_ECDSA:
    pkey = generate_ecdsa_key(key_bits);
    break;
  case KEY_TYPE_ED25519:
    pkey = generate_ed25519_key();
    key_bits = 256; /* ED25519固定256位 */
    break;
  }

  if (!pkey) {
    return NULL; /* 错误信息已在生成函数中设置 */
  }

  /* 分配密钥对结构 */
  SSHKeyPair *keypair = (SSHKeyPair *)calloc(1, sizeof(SSHKeyPair));
  if (!keypair) {
    EVP_PKEY_free(pkey);
    set_error("Memory allocation failed for SSHKeyPair");
    return NULL;
  }

  keypair->key_type = options->key_type;
  keypair->key_bits = key_bits;

  /* 导出私钥 */
  keypair->private_key =
      export_private_key_pem(pkey, options->password, options->cipher);
  if (!keypair->private_key) {
    EVP_PKEY_free(pkey);
    cleanup_keypair(keypair);
    return NULL; /* 错误信息已在导出函数中设置 */
  }

  /* 导出公钥 */
  keypair->public_key = export_public_key_openssh(pkey, options->comment);
  if (!keypair->public_key) {
    EVP_PKEY_free(pkey);
    cleanup_keypair(keypair);
    return NULL; /* 错误信息已在导出函数中设置 */
  }

  // /* 计算指纹 */
  // keypair->fingerprint = calculate_fingerprint(keypair->public_key);
  // if (!keypair->fingerprint) {
  //     EVP_PKEY_free(pkey);
  //     cleanup_keypair(keypair);
  //     return NULL; /* 错误信息已在计算函数中设置 */
  // }

  EVP_PKEY_free(pkey);
  return keypair;
}

/* 释放密钥对内存 */
void etos_ssh_keygen_free(SSHKeyPair *keypair) { cleanup_keypair(keypair); }

/* 验证私钥密码 */
bool etos_ssh_keygen_verify_password(const char *private_key,
                                     const char *password) {
  if (!private_key) {
    set_error("Private key cannot be NULL");
    return false;
  }

  BIO *bio = BIO_new_mem_buf(private_key, -1);
  if (!bio) {
    set_error("Failed to create BIO for private key verification");
    return false;
  }

  EVP_PKEY *pkey = NULL;
  bool valid = false;

  do {
    if (password && password[0]) {
      /* 尝试用密码解密 */
      pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)password);
      if (!pkey) {
        set_error("Failed to decrypt private key with password");
        break;
      }
    } else {
      /* 尝试无密码加载 */
      pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
      if (!pkey) {
        set_error("Failed to load private key without password");
        break;
      }
    }

    valid = true;
  } while (0);

  if (pkey) {
    EVP_PKEY_free(pkey);
  }

  BIO_free(bio);
  return valid;
}

/* 获取密钥类型名称 */
const char *etos_ssh_keygen_get_key_type_name(KeyType type) {
  switch (type) {
  case KEY_TYPE_RSA:
    return "RSA";
  case KEY_TYPE_ECDSA:
    return "ECDSA";
  case KEY_TYPE_ED25519:
    return "ED25519";
  default:
    return "Unknown";
  }
}

/* 获取加密算法名称 */
const char *etos_ssh_keygen_get_cipher_name(CipherType cipher) {
  switch (cipher) {
  case CIPHER_NONE:
    return "none";
  case CIPHER_AES128_CBC:
    return "AES-128-CBC";
  case CIPHER_AES192_CBC:
    return "AES-192-CBC";
  case CIPHER_AES256_CBC:
    return "AES-256-CBC";
  default:
    return "unknown";
  }
}
