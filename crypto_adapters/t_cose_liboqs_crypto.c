/*
 *  t_cose_openssl_crypto.c
 *
 * Copyright 2025, Hannes Tschofenig
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 12/24/2025.
 */


#include "t_cose_crypto.h" /* The interface this code implements */
#include "t_cose_util.h"
#include "t_cose/t_cose_pqc_sig_alg.h"
#include "oqs/oqs.h"
#include <string.h>


bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id)
{
    return t_cose_find_pqc_alg(cose_algorithm_id) != NULL;
}


enum t_cose_err_t t_cose_crypto_sig_size(int32_t            cose_algorithm_id,
                                         struct t_cose_key  signing_key,
                                         size_t            *sig_size)
{
    (void)signing_key;
    const struct t_cose_pqc_alg *params = t_cose_find_pqc_alg(cose_algorithm_id);
    if(params == NULL) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }
    *sig_size = params->sig_len;
    return T_COSE_SUCCESS;
}


enum t_cose_err_t t_cose_crypto_sign(int32_t                cose_algorithm_id,
                                     struct t_cose_key      signing_key,
                                    void                  *crypto_context,
                                    struct q_useful_buf_c  hash_to_sign,
                                    struct q_useful_buf    buffer_for_signature,
                                    struct q_useful_buf_c *signature)
{
    (void)crypto_context;
    const struct t_cose_pqc_alg *params = t_cose_find_pqc_alg(cose_algorithm_id);
    if(params == NULL) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    if(signing_key.key.buffer.len != params->sec_key_len) {
        return T_COSE_ERR_INVALID_ARGUMENT;
    }

    if(buffer_for_signature.len < params->sig_len) {
        return T_COSE_ERR_SIG_BUFFER_SIZE;
    }

    OQS_SIG *sig = OQS_SIG_new(params->oqs_alg_id);
    if(!sig) {
        return T_COSE_ERR_FAIL;
    }

    size_t sig_len = 0;
    OQS_STATUS rc = OQS_SIG_sign(sig,
                                 (uint8_t *)buffer_for_signature.ptr,
                                 &sig_len,
                                 hash_to_sign.ptr,
                                 hash_to_sign.len,
                                 signing_key.key.buffer.ptr);
    OQS_SIG_free(sig);

    if(rc != OQS_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    signature->ptr = buffer_for_signature.ptr;
    signature->len = sig_len;
    return T_COSE_SUCCESS;
}


enum t_cose_err_t t_cose_crypto_verify(int32_t               cose_algorithm_id,
                                       struct t_cose_key     verification_key,
                                      void                 *crypto_context,
                                      struct q_useful_buf_c tbs_hash,
                                      struct q_useful_buf_c signature)
{
    (void)crypto_context;
    const struct t_cose_pqc_alg *params = t_cose_find_pqc_alg(cose_algorithm_id);
    if(params == NULL) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    if(verification_key.key.buffer.len != params->pub_key_len) {
        return T_COSE_ERR_INVALID_ARGUMENT;
    }

    OQS_SIG *sig = OQS_SIG_new(params->oqs_alg_id);
    if(!sig) {
        return T_COSE_ERR_FAIL;
    }

    OQS_STATUS rc = OQS_SIG_verify(sig,
                                   tbs_hash.ptr,
                                   tbs_hash.len,
                                   signature.ptr,
                                   signature.len,
                                   verification_key.key.buffer.ptr);
    OQS_SIG_free(sig);

    return rc == OQS_SUCCESS ? T_COSE_SUCCESS : T_COSE_ERR_SIG_VERIFY;
}


/* Hash / HMAC are not supported in this minimal adapter.
 * They return unsupported so callers can fail gracefully.
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id)
{
    (void)hash_ctx;
    (void)cose_hash_alg_id;
    return T_COSE_ERR_UNSUPPORTED_HASH;
}

void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash)
{
    (void)hash_ctx;
    (void)data_to_hash;
}

enum t_cose_err_t t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                                            struct q_useful_buf buffer_to_hold_result,
                                            struct q_useful_buf_c *hash_result)
{
    (void)hash_ctx;
    (void)buffer_to_hold_result;
    (void)hash_result;
    return T_COSE_ERR_UNSUPPORTED_HASH;
}


enum t_cose_err_t t_cose_crypto_hmac_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                           struct t_cose_key          signing_key,
                                           const int32_t              cose_alg_id)
{
    (void)hmac_ctx;
    (void)signing_key;
    (void)cose_alg_id;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

void t_cose_crypto_hmac_update(struct t_cose_crypto_hmac *hmac_ctx,
                               struct q_useful_buf_c      payload)
{
    (void)hmac_ctx;
    (void)payload;
}

enum t_cose_err_t t_cose_crypto_hmac_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                            struct q_useful_buf        tag_buf,
                                            struct q_useful_buf_c     *tag)
{
    (void)hmac_ctx;
    (void)tag_buf;
    (void)tag;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


enum t_cose_err_t t_cose_crypto_sign_eddsa(struct t_cose_key      signing_key,
                                           void                  *crypto_context,
                                           struct q_useful_buf_c  tbs,
                                           struct q_useful_buf    signature_buffer,
                                           struct q_useful_buf_c *signature)
{
    (void)signing_key;
    (void)crypto_context;
    (void)tbs;
    (void)signature_buffer;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


enum t_cose_err_t t_cose_crypto_verify_eddsa(struct t_cose_key     verification_key,
                                             void                 *crypto_context,
                                             struct q_useful_buf_c tbs,
                                             struct q_useful_buf_c signature)
{
    (void)verification_key;
    (void)crypto_context;
    (void)tbs;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}
