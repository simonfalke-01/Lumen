/*
 * aes_gcm_wolfssl.c
 *
 * AES Galois Counter Mode backed by wolfCrypt.
 */

/*
 * Copyright (c) 2026 LizardByte project contributors.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "aes_gcm.h"
#include "alloc.h"
#include "err.h"
#include "cipher_test_cases.h"
#include "cipher_types.h"
#include "crypto_types.h"

#include <string.h>

#define GCM_IV_LEN 12
#define GCM_AUTH_TAG_LEN 16
#define GCM_AUTH_TAG_LEN_8 8

srtp_debug_module_t srtp_mod_aes_gcm = {
    0,
    "aes gcm wolfCrypt"
};

static srtp_err_status_t srtp_aes_gcm_wolfssl_alloc(srtp_cipher_t **c,
                                                     int key_len,
                                                     int tlen)
{
    srtp_aes_gcm_ctx_t *gcm;

    if (c == NULL ||
        (key_len != SRTP_AES_GCM_128_KEY_LEN_WSALT &&
         key_len != SRTP_AES_GCM_256_KEY_LEN_WSALT) ||
        (tlen != GCM_AUTH_TAG_LEN && tlen != GCM_AUTH_TAG_LEN_8)) {
        return srtp_err_status_bad_param;
    }

    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }

    gcm = (srtp_aes_gcm_ctx_t *)srtp_crypto_alloc(sizeof(*gcm));
    if (gcm == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }
    memset(gcm, 0, sizeof(*gcm));

    if (wc_AesInit(&gcm->aes, NULL, INVALID_DEVID) != 0) {
        srtp_crypto_free(gcm);
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_init_fail;
    }

    (*c)->state = gcm;
    (*c)->key_len = key_len;
    gcm->tag_len = tlen;
    gcm->dir = srtp_direction_any;

    if (key_len == SRTP_AES_GCM_128_KEY_LEN_WSALT) {
        (*c)->type = &srtp_aes_gcm_128;
        (*c)->algorithm = SRTP_AES_GCM_128;
        gcm->key_size = SRTP_AES_128_KEY_LEN;
    } else {
        (*c)->type = &srtp_aes_gcm_256;
        (*c)->algorithm = SRTP_AES_GCM_256;
        gcm->key_size = SRTP_AES_256_KEY_LEN;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_gcm_wolfssl_dealloc(srtp_cipher_t *c)
{
    if (c != NULL) {
        srtp_aes_gcm_ctx_t *ctx = (srtp_aes_gcm_ctx_t *)c->state;
        if (ctx != NULL) {
            wc_AesFree(&ctx->aes);
            octet_string_set_to_zero(ctx, sizeof(*ctx));
            srtp_crypto_free(ctx);
        }
        srtp_crypto_free(c);
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_gcm_wolfssl_context_init(void *cv,
                                                            const uint8_t *key)
{
    srtp_aes_gcm_ctx_t *ctx = (srtp_aes_gcm_ctx_t *)cv;

    if (ctx == NULL || key == NULL ||
        (ctx->key_size != SRTP_AES_128_KEY_LEN &&
         ctx->key_size != SRTP_AES_256_KEY_LEN)) {
        return srtp_err_status_bad_param;
    }

    ctx->aad_size = 0;
    ctx->dir = srtp_direction_any;
    wc_AesFree(&ctx->aes);
    if (wc_AesInit(&ctx->aes, NULL, INVALID_DEVID) != 0) {
        return srtp_err_status_init_fail;
    }
    if (wc_AesGcmSetKey(&ctx->aes, key, (word32)ctx->key_size) != 0) {
        return srtp_err_status_init_fail;
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_gcm_wolfssl_set_iv(
    void *cv,
    uint8_t *iv,
    srtp_cipher_direction_t direction)
{
    srtp_aes_gcm_ctx_t *ctx = (srtp_aes_gcm_ctx_t *)cv;

    if (ctx == NULL || iv == NULL ||
        (direction != srtp_direction_encrypt &&
         direction != srtp_direction_decrypt)) {
        return srtp_err_status_bad_param;
    }

    memcpy(ctx->iv, iv, sizeof(ctx->iv));
    ctx->aad_size = 0;
    ctx->dir = direction;
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_gcm_wolfssl_set_aad(void *cv,
                                                       const uint8_t *aad,
                                                       uint32_t aad_len)
{
    srtp_aes_gcm_ctx_t *ctx = (srtp_aes_gcm_ctx_t *)cv;

    if (ctx == NULL || (aad == NULL && aad_len != 0) ||
        aad_len > SRTP_WOLFSSL_GCM_MAX_AAD_SIZE - (uint32_t)ctx->aad_size) {
        return srtp_err_status_bad_param;
    }

    if (aad_len != 0) {
        memcpy(ctx->aad + ctx->aad_size, aad, aad_len);
        ctx->aad_size += (int)aad_len;
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_gcm_wolfssl_encrypt(void *cv,
                                                       unsigned char *buf,
                                                       unsigned int *enc_len)
{
    srtp_aes_gcm_ctx_t *ctx = (srtp_aes_gcm_ctx_t *)cv;
    int result;

    if (ctx == NULL || enc_len == NULL || (buf == NULL && *enc_len != 0) ||
        ctx->dir != srtp_direction_encrypt) {
        return srtp_err_status_bad_param;
    }

    result = wc_AesGcmEncrypt(&ctx->aes, buf, buf, (word32)*enc_len,
                              ctx->iv, sizeof(ctx->iv), ctx->tag,
                              (word32)ctx->tag_len, ctx->aad,
                              (word32)ctx->aad_size);
    ctx->aad_size = 0;
    return result == 0 ? srtp_err_status_ok : srtp_err_status_cipher_fail;
}

static srtp_err_status_t srtp_aes_gcm_wolfssl_get_tag(void *cv,
                                                       uint8_t *buf,
                                                       uint32_t *len)
{
    srtp_aes_gcm_ctx_t *ctx = (srtp_aes_gcm_ctx_t *)cv;

    if (ctx == NULL || buf == NULL || len == NULL ||
        ctx->dir != srtp_direction_encrypt) {
        return srtp_err_status_bad_param;
    }

    memcpy(buf, ctx->tag, (size_t)ctx->tag_len);
    *len = (uint32_t)ctx->tag_len;
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_gcm_wolfssl_decrypt(void *cv,
                                                       unsigned char *buf,
                                                       unsigned int *enc_len)
{
    srtp_aes_gcm_ctx_t *ctx = (srtp_aes_gcm_ctx_t *)cv;
    unsigned int text_len;
    int result;

    if (ctx == NULL || buf == NULL || enc_len == NULL ||
        ctx->dir != srtp_direction_decrypt ||
        *enc_len < (unsigned int)ctx->tag_len) {
        return srtp_err_status_bad_param;
    }

    text_len = *enc_len - (unsigned int)ctx->tag_len;
    result = wc_AesGcmDecrypt(&ctx->aes, buf, buf, (word32)text_len,
                              ctx->iv, sizeof(ctx->iv), buf + text_len,
                              (word32)ctx->tag_len, ctx->aad,
                              (word32)ctx->aad_size);
    ctx->aad_size = 0;
    if (result != 0) {
        octet_string_set_to_zero(buf, text_len);
        return srtp_err_status_auth_fail;
    }

    *enc_len = text_len;
    return srtp_err_status_ok;
}

static const char srtp_aes_gcm_128_wolfssl_description[] =
    "AES-128 GCM using wolfCrypt";
static const char srtp_aes_gcm_256_wolfssl_description[] =
    "AES-256 GCM using wolfCrypt";

const srtp_cipher_type_t srtp_aes_gcm_128 = {
    srtp_aes_gcm_wolfssl_alloc,
    srtp_aes_gcm_wolfssl_dealloc,
    srtp_aes_gcm_wolfssl_context_init,
    srtp_aes_gcm_wolfssl_set_aad,
    srtp_aes_gcm_wolfssl_encrypt,
    srtp_aes_gcm_wolfssl_decrypt,
    srtp_aes_gcm_wolfssl_set_iv,
    srtp_aes_gcm_wolfssl_get_tag,
    srtp_aes_gcm_128_wolfssl_description,
    &srtp_aes_gcm_128_test_case_0,
    SRTP_AES_GCM_128
};

const srtp_cipher_type_t srtp_aes_gcm_256 = {
    srtp_aes_gcm_wolfssl_alloc,
    srtp_aes_gcm_wolfssl_dealloc,
    srtp_aes_gcm_wolfssl_context_init,
    srtp_aes_gcm_wolfssl_set_aad,
    srtp_aes_gcm_wolfssl_encrypt,
    srtp_aes_gcm_wolfssl_decrypt,
    srtp_aes_gcm_wolfssl_set_iv,
    srtp_aes_gcm_wolfssl_get_tag,
    srtp_aes_gcm_256_wolfssl_description,
    &srtp_aes_gcm_256_test_case_0,
    SRTP_AES_GCM_256
};
