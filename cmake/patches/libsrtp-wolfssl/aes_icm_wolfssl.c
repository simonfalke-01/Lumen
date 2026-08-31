/*
 * aes_icm_wolfssl.c
 *
 * AES Integer Counter Mode backed by wolfCrypt.
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

#include "aes_icm_ext.h"
#include "alloc.h"
#include "err.h"
#include "cipher_test_cases.h"
#include "cipher_types.h"
#include "crypto_types.h"

#include <string.h>

srtp_debug_module_t srtp_mod_aes_icm = {
    0,
    "aes icm wolfCrypt"
};

static srtp_err_status_t srtp_aes_icm_wolfssl_alloc(srtp_cipher_t **c,
                                                     int key_len,
                                                     int tlen)
{
    srtp_aes_icm_ctx_t *icm;
    (void)tlen;

    if (c == NULL ||
        (key_len != SRTP_AES_ICM_128_KEY_LEN_WSALT &&
         key_len != SRTP_AES_ICM_192_KEY_LEN_WSALT &&
         key_len != SRTP_AES_ICM_256_KEY_LEN_WSALT)) {
        return srtp_err_status_bad_param;
    }

    *c = (srtp_cipher_t *)srtp_crypto_alloc(sizeof(srtp_cipher_t));
    if (*c == NULL) {
        return srtp_err_status_alloc_fail;
    }

    icm = (srtp_aes_icm_ctx_t *)srtp_crypto_alloc(sizeof(*icm));
    if (icm == NULL) {
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_alloc_fail;
    }
    memset(icm, 0, sizeof(*icm));

    if (wc_AesInit(&icm->aes, NULL, INVALID_DEVID) != 0) {
        srtp_crypto_free(icm);
        srtp_crypto_free(*c);
        *c = NULL;
        return srtp_err_status_init_fail;
    }

    (*c)->state = icm;
    (*c)->key_len = key_len;
    if (key_len == SRTP_AES_ICM_128_KEY_LEN_WSALT) {
        (*c)->algorithm = SRTP_AES_ICM_128;
        (*c)->type = &srtp_aes_icm_128;
        icm->key_size = SRTP_AES_128_KEY_LEN;
    } else if (key_len == SRTP_AES_ICM_192_KEY_LEN_WSALT) {
        (*c)->algorithm = SRTP_AES_ICM_192;
        (*c)->type = &srtp_aes_icm_192;
        icm->key_size = SRTP_AES_192_KEY_LEN;
    } else {
        (*c)->algorithm = SRTP_AES_ICM_256;
        (*c)->type = &srtp_aes_icm_256;
        icm->key_size = SRTP_AES_256_KEY_LEN;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_icm_wolfssl_dealloc(srtp_cipher_t *c)
{
    if (c == NULL) {
        return srtp_err_status_bad_param;
    }
    if (c->state != NULL) {
        srtp_aes_icm_ctx_t *ctx = (srtp_aes_icm_ctx_t *)c->state;
        wc_AesFree(&ctx->aes);
        octet_string_set_to_zero(ctx, sizeof(*ctx));
        srtp_crypto_free(ctx);
    }
    srtp_crypto_free(c);
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_icm_wolfssl_context_init(void *cv,
                                                            const uint8_t *key)
{
    srtp_aes_icm_ctx_t *ctx = (srtp_aes_icm_ctx_t *)cv;

    if (ctx == NULL || key == NULL ||
        (ctx->key_size != SRTP_AES_128_KEY_LEN &&
         ctx->key_size != SRTP_AES_192_KEY_LEN &&
         ctx->key_size != SRTP_AES_256_KEY_LEN)) {
        return srtp_err_status_bad_param;
    }

    v128_set_to_zero(&ctx->counter);
    v128_set_to_zero(&ctx->offset);
    memcpy(&ctx->counter, key + ctx->key_size, SRTP_SALT_LEN);
    memcpy(&ctx->offset, key + ctx->key_size, SRTP_SALT_LEN);
    ctx->offset.v8[SRTP_SALT_LEN] = 0;
    ctx->offset.v8[SRTP_SALT_LEN + 1] = 0;
    ctx->counter.v8[SRTP_SALT_LEN] = 0;
    ctx->counter.v8[SRTP_SALT_LEN + 1] = 0;

    ctx->bytes_in_buffer = 0;
    if (wc_AesSetKey(&ctx->aes, key, (word32)ctx->key_size, NULL,
                     AES_ENCRYPTION) != 0) {
        return srtp_err_status_init_fail;
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_aes_icm_wolfssl_set_iv(
    void *cv,
    uint8_t *iv,
    srtp_cipher_direction_t direction)
{
    srtp_aes_icm_ctx_t *ctx = (srtp_aes_icm_ctx_t *)cv;
    v128_t nonce;
    (void)direction;

    if (ctx == NULL || iv == NULL) {
        return srtp_err_status_bad_param;
    }

    v128_copy_octet_string(&nonce, iv);
    v128_xor(&ctx->counter, &ctx->offset, &nonce);
    ctx->bytes_in_buffer = 0;
    return srtp_err_status_ok;
}

static void srtp_aes_icm_wolfssl_advance(srtp_aes_icm_ctx_t *ctx)
{
    (void)wc_AesEncryptDirect(&ctx->aes, ctx->keystream_buffer.v8,
                              ctx->counter.v8);
    ctx->bytes_in_buffer = (int)sizeof(v128_t);
    if (++ctx->counter.v8[15] == 0) {
        ++ctx->counter.v8[14];
    }
}

static srtp_err_status_t srtp_aes_icm_wolfssl_crypt(void *cv,
                                                     unsigned char *buf,
                                                     unsigned int *len)
{
    srtp_aes_icm_ctx_t *ctx = (srtp_aes_icm_ctx_t *)cv;
    unsigned int bytes_to_crypt;
    unsigned int blocks_required;
    unsigned int block_index;
    unsigned int index;

    if (ctx == NULL || buf == NULL || len == NULL) {
        return srtp_err_status_bad_param;
    }

    bytes_to_crypt = *len;
    blocks_required =
        (bytes_to_crypt > (unsigned int)ctx->bytes_in_buffer)
            ? (bytes_to_crypt - (unsigned int)ctx->bytes_in_buffer + 15U) / 16U
            : 0U;
    block_index = ((unsigned int)ctx->counter.v8[14] << 8U) |
                  (unsigned int)ctx->counter.v8[15];
    if (blocks_required > 0xffffU - block_index) {
        return srtp_err_status_terminus;
    }

    while (bytes_to_crypt != 0) {
        unsigned int available;
        unsigned int take;
        unsigned int offset;

        if (ctx->bytes_in_buffer == 0) {
            srtp_aes_icm_wolfssl_advance(ctx);
        }
        available = (unsigned int)ctx->bytes_in_buffer;
        take = bytes_to_crypt < available ? bytes_to_crypt : available;
        offset = (unsigned int)sizeof(v128_t) - available;
        for (index = 0; index < take; ++index) {
            buf[index] ^= ctx->keystream_buffer.v8[offset + index];
        }
        buf += take;
        bytes_to_crypt -= take;
        ctx->bytes_in_buffer -= (int)take;
    }
    return srtp_err_status_ok;
}

static const char srtp_aes_icm_128_wolfssl_description[] =
    "AES-128 counter mode using wolfCrypt";
static const char srtp_aes_icm_192_wolfssl_description[] =
    "AES-192 counter mode using wolfCrypt";
static const char srtp_aes_icm_256_wolfssl_description[] =
    "AES-256 counter mode using wolfCrypt";

const srtp_cipher_type_t srtp_aes_icm_128 = {
    srtp_aes_icm_wolfssl_alloc,
    srtp_aes_icm_wolfssl_dealloc,
    srtp_aes_icm_wolfssl_context_init,
    0,
    srtp_aes_icm_wolfssl_crypt,
    srtp_aes_icm_wolfssl_crypt,
    srtp_aes_icm_wolfssl_set_iv,
    0,
    srtp_aes_icm_128_wolfssl_description,
    &srtp_aes_icm_128_test_case_0,
    SRTP_AES_ICM_128
};

const srtp_cipher_type_t srtp_aes_icm_192 = {
    srtp_aes_icm_wolfssl_alloc,
    srtp_aes_icm_wolfssl_dealloc,
    srtp_aes_icm_wolfssl_context_init,
    0,
    srtp_aes_icm_wolfssl_crypt,
    srtp_aes_icm_wolfssl_crypt,
    srtp_aes_icm_wolfssl_set_iv,
    0,
    srtp_aes_icm_192_wolfssl_description,
    &srtp_aes_icm_192_test_case_0,
    SRTP_AES_ICM_192
};

const srtp_cipher_type_t srtp_aes_icm_256 = {
    srtp_aes_icm_wolfssl_alloc,
    srtp_aes_icm_wolfssl_dealloc,
    srtp_aes_icm_wolfssl_context_init,
    0,
    srtp_aes_icm_wolfssl_crypt,
    srtp_aes_icm_wolfssl_crypt,
    srtp_aes_icm_wolfssl_set_iv,
    0,
    srtp_aes_icm_256_wolfssl_description,
    &srtp_aes_icm_256_test_case_0,
    SRTP_AES_ICM_256
};
