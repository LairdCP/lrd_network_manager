/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Boris Krasnovskiy <boris.krasnovskiy@lairdconnect.com>
 * Copyright (C) 2023 Laird Connectivity, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-crypto-impl.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include "libnm-glib-aux/nm-secret-utils.h"

/*****************************************************************************/

static gboolean
_get_cipher_info(NMCryptoCipherType cipher,
                 const EVP_CIPHER **out_cipher_mech,
                 guint8 *out_real_iv_len)
{
    switch (cipher) {
        case NM_CRYPTO_CIPHER_DES_EDE3_CBC:
             NM_SET_OUT(out_cipher_mech, EVP_des_ede3_cbc());
             break;
        case NM_CRYPTO_CIPHER_DES_CBC:
             NM_SET_OUT(out_cipher_mech, EVP_des_cbc());
             break;
        case NM_CRYPTO_CIPHER_AES_128_CBC:
             NM_SET_OUT(out_cipher_mech, EVP_aes_128_cbc());
             break;
        case NM_CRYPTO_CIPHER_AES_192_CBC:
             NM_SET_OUT(out_cipher_mech, EVP_aes_192_cbc());
             break;
        case NM_CRYPTO_CIPHER_AES_256_CBC:
             NM_SET_OUT(out_cipher_mech, EVP_aes_256_cbc());
             break;
        default:
            return FALSE;
    };

    NM_SET_OUT(out_real_iv_len, nm_crypto_cipher_get_info(cipher)->real_iv_len);
    return TRUE;
}

/*****************************************************************************/

gboolean
_nm_crypto_init(GError **error)
{
    static gboolean initialized = FALSE;

    if (initialized) {
        ERR_clear_error();
        return TRUE;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
#elif OPENSSL_VERSION_NUMBER < 0x30000000L
    if (1 != OPENSSL_init_crypto(0, NULL)) {
        g_set_error_literal(error,
                            _NM_CRYPTO_ERROR,
                            _NM_CRYPTO_ERROR_FAILED,
                            _("Failed to initialize the crypto engine."));
        return FALSE;
    }
#else
    if (OSSL_PROVIDER_load(NULL, "default") == NULL) {
        g_set_error_literal(error,
                            _NM_CRYPTO_ERROR,
                            _NM_CRYPTO_ERROR_FAILED,
                            _("Failed to initialize the crypto engine."));
        return FALSE;
    }
    OSSL_PROVIDER_load(NULL, "legacy");
#endif

    ERR_clear_error();
    initialized = TRUE;
    return TRUE;
}

guint8 *
_nmtst_crypto_decrypt(NMCryptoCipherType cipher,
                      const guint8      *data,
                      gsize              data_len,
                      const guint8      *iv,
                      gsize              iv_len,
                      const guint8      *key,
                      gsize              key_len,
                      gsize             *out_len,
                      GError           **error)
{
    EVP_CIPHER_CTX                       *ctx;
    const EVP_CIPHER                     *cipher_mech;
    nm_auto_clear_secret_ptr NMSecretPtr output = {0};
    guint8                               real_iv_len;
    int                                  len;

    if (!_nm_crypto_init(error))
        return NULL;

    if (!_get_cipher_info(cipher, &cipher_mech, &real_iv_len)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
                    _("Unsupported key cipher for decryption"));
        return NULL;
    }

    if (iv_len < real_iv_len) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_INVALID_DATA,
                    _("Invalid IV length (must be at least %u)."),
                    (guint) real_iv_len);
        return NULL;
    }

    output.len = data_len;
    output.bin = g_malloc(data_len);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to initialize the decryption cipher context"));
        return NULL;
    }

    if (1 != EVP_DecryptInit(ctx, cipher_mech, key, iv)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to decrypt the private key"));
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (1 != EVP_DecryptUpdate(ctx, output.bin, &len, data, data_len)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to decrypt the private key"));
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    output.len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, output.bin + len, &len)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                    _("Failed to decrypt the private key"));
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    output.len += len;

    EVP_CIPHER_CTX_free(ctx);

    *out_len = output.len;

    return g_steal_pointer(&output.bin);
}

guint8 *
_nmtst_crypto_encrypt(NMCryptoCipherType cipher,
                      const guint8      *data,
                      gsize              data_len,
                      const guint8      *iv,
                      gsize              iv_len,
                      const guint8      *key,
                      gsize              key_len,
                      gsize             *out_len,
                      GError           **error)
{
    EVP_CIPHER_CTX                       *ctx;
    const EVP_CIPHER                     *cipher_mech;
    nm_auto_clear_secret_ptr NMSecretPtr output = {0};
    int                                  len;

    nm_assert(iv_len);

    if (cipher == NM_CRYPTO_CIPHER_DES_CBC ||
        !_get_cipher_info(cipher, &cipher_mech, NULL)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_UNKNOWN_CIPHER,
                    _("Unsupported key cipher for encryption"));
        return NULL;
    }

    if (!_nm_crypto_init(error))
        return NULL;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
                    _("Failed to initialize the encryption cipher context"));
        return NULL;
    }

    if (1 != EVP_EncryptInit(ctx, cipher_mech, key, iv)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
                    _("Failed to initialize the encryption cipher"));
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    output.len = data_len + iv_len;
    output.bin = g_malloc(output.len);

    if (1 != EVP_EncryptUpdate(ctx, output.bin, &len, data, data_len)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
                    _("Failed to encrypt data"));
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    output.len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, output.bin + len, &len)) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_ENCRYPTION_FAILED,
                    _("Failed to encrypt data"));
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    output.len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    *out_len = output.len;

    return g_steal_pointer(&output.bin);
}

gboolean
_nm_crypto_verify_x509(const guint8 *data, gsize len, GError **error)
{
    BIO                 *bio;
    X509                *x;
    const unsigned char *p = data;

    g_return_val_if_fail(data != NULL, FALSE);

    if (!_nm_crypto_init(error))
        return FALSE;

    /* Try DER */
    x = d2i_X509(NULL, &p, len);
    if (x == NULL) {
        /* Try PEM */
        bio = BIO_new_mem_buf(data, len);
        x = PEM_read_bio_X509(bio, NULL, 0, NULL);
        BIO_free(bio);
    }

    if (x == NULL) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_INVALID_DATA,
                    _("Couldn't decode certificate."));

        return FALSE;
    }

    X509_free(x);
    return TRUE;
}

gboolean
_nm_crypto_verify_pkcs12(const guint8 *data,
                         gsize data_len,
                         const char *password,
                         GError **error)
{
    PKCS12              *p12;
    const unsigned char *p = data;

    g_return_val_if_fail(data != NULL, FALSE);

    if (!_nm_crypto_init(error))
        return FALSE;

    p12 = d2i_PKCS12(NULL, &p, data_len);
    if (p12 == NULL) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_INVALID_DATA,
                    _("Couldn't decode PKCS#12 file."));
        return FALSE;
    }

    if (1 != PKCS12_parse(p12, password ?: "", NULL, NULL, NULL)) {
        switch (ERR_GET_REASON(ERR_peek_last_error())) {
            case PKCS12_R_MAC_VERIFY_FAILURE:
            case PKCS12_R_PKCS12_CIPHERFINAL_ERROR:
                g_set_error(error,
                            _NM_CRYPTO_ERROR,
                            _NM_CRYPTO_ERROR_DECRYPTION_FAILED,
                            _("Couldn't decode PKCS#12 file: wrong password."));
                break;
            default:
                g_set_error(error,
                            _NM_CRYPTO_ERROR,
                            _NM_CRYPTO_ERROR_INVALID_DATA,
                            _("Couldn't decode PKCS#12 file."));
                break;
        }
        PKCS12_free(p12);
        return FALSE;
    }

    PKCS12_free(p12);

    return TRUE;
}

static int
password_cb(char *buf, int size, int rwflag, void *userdata)
{
    const char *passphrase = (const char *)userdata;
    size_t len;

    if (passphrase == NULL)
        return 0;

    len = strlen(passphrase);
    if (len > size)
        return -1;

    memcpy(buf, passphrase, len);

    return len;
}

gboolean
_nm_crypto_verify_pkcs8(const guint8 *data,
                        gsize         data_len,
                        gboolean      is_encrypted,
                        const char   *password,
                        GError      **error)
{
    BIO           *bio;
    EVP_PKEY      *pkey;

    g_return_val_if_fail(data != NULL, FALSE);

    if (!_nm_crypto_init(error))
        return FALSE;

    bio = BIO_new_mem_buf(data, data_len);

    if (is_encrypted) {
        pkey = d2i_PKCS8PrivateKey_bio(bio, NULL, password_cb, (void*)password);
    } else {
        pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    BIO_free(bio);

    if (pkey == NULL) {
        g_set_error(error,
                    _NM_CRYPTO_ERROR,
                    _NM_CRYPTO_ERROR_INVALID_DATA,
                    _("Couldn't decode PKCS#8 file."));
        return FALSE;
    }

    EVP_PKEY_free(pkey);

    return TRUE;
}

gboolean
_nm_crypto_randomize(void *buffer, gsize buffer_len, GError **error)
{
    if (!_nm_crypto_init(error))
        return FALSE;

    return 1 == RAND_bytes(buffer, buffer_len);
}
