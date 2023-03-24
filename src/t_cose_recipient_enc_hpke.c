/**
 * \file t_cose_recipient_enc_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef T_COSE_DISABLE_HPKE

#include <stdint.h>
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_recipient_enc.h"
#include "t_cose/t_cose_recipient_enc_hpke.h" /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "hpke.h"


/**
 * \brief Given a COSE HPKE algorithm id this function returns the
 *        HPKE algorithm structure, the key length (in bits) and
 *        the COSE algorithm ID.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully produced the HPKE algorithm structure.
 * \retval T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG
 *         The supported key exchange algorithm is not supported.
 */
enum t_cose_err_t
t_cose_crypto_convert_hpke_algorithms(
                int32_t                            hpke_cose_algorithm_id,
                struct t_cose_crypto_hpke_suite_t *hpke_suite,
                size_t                            *key_bitlen,
                int64_t                           *cose_algorithm_id)
{
    switch (hpke_cose_algorithm_id) {
    case T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
         *key_bitlen = 128;
         *cose_algorithm_id = T_COSE_ALGORITHM_A128GCM;
         hpke_suite->kem_id = HPKE_KEM_ID_P256;
         hpke_suite->kdf_id = HPKE_KDF_ID_HKDF_SHA256;
         hpke_suite->aead_id = HPKE_AEAD_ID_AES_GCM_128;
         break;
    case T_COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
         *key_bitlen = 256;
         *cose_algorithm_id = T_COSE_ALGORITHM_A256GCM;
         hpke_suite->kem_id = HPKE_KEM_ID_P521;
         hpke_suite->kdf_id = HPKE_KDF_ID_HKDF_SHA512;
         hpke_suite->aead_id = HPKE_AEAD_ID_AES_GCM_256;
         break;
    default:
         return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    return(T_COSE_SUCCESS);
}


/**
 * \brief HPKE Encrypt Wrapper
 *
 * \param[in] suite               HPKE ciphersuite
 * \param[in] pkR                 pkR buffer
 * \param[in] pkE                 pkE buffer
 * \param[in] plaintext           Plaintext buffer
 * \param[in] ciphertext          Ciphertext buffer
 * \param[out] ciphertext_len     Length of the produced ciphertext
 *
 * \retval T_COSE_SUCCESS
 *         HPKE encrypt operation was successful.
 * \retval T_COSE_ERR_HPKE_ENCRYPT_FAIL
 *         Encrypt operation failed.
 */

enum t_cose_err_t
t_cose_crypto_hpke_encrypt(struct t_cose_crypto_hpke_suite_t  suite,
                           struct q_useful_buf_c              pkR,
                           struct t_cose_key                  pkE,
                           struct q_useful_buf_c              plaintext,
                           struct q_useful_buf                ciphertext,
                           size_t                             *ciphertext_len)
{
    int             ret;
    hpke_suite_t    hpke_suite;

    hpke_suite.aead_id = suite.aead_id;
    hpke_suite.kdf_id = suite.kdf_id;
    hpke_suite.kem_id = suite.kem_id;

    ret = mbedtls_hpke_encrypt(
            HPKE_MODE_BASE,                     // HPKE mode
            hpke_suite,                         // ciphersuite
            NULL, 0, NULL,                      // PSK
            pkR.len,                            // pkR length
            pkR.ptr,                            // pkR
            0,                                  // skI
            plaintext.len,                      // plaintext length
            plaintext.ptr,                      // plaintext
            0, NULL,                            // Additional data
            0, NULL,                            // Info
            (psa_key_handle_t)
            pkE.key.handle,                   // skE handle
            0, NULL,                            // pkE
            ciphertext_len,                     // ciphertext length
            (uint8_t *) ciphertext.ptr);        // ciphertext

    if (ret != 0) {
        return(T_COSE_ERR_HPKE_ENCRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}


/*
 * See documentation in t_cose_recipient_enc_hpke.h
 */
static enum t_cose_err_t
t_cose_create_recipient_hpke2(
                           struct t_cose_recipient_enc_hpke *context,
                           int32_t                cose_algorithm_id,
                           struct t_cose_key      recipient_key,
                           struct q_useful_buf_c  plaintext,
                           QCBOREncodeContext    *encrypt_ctx)
{
    size_t                 key_bitlen;
    int64_t                algorithm_id;
    QCBORError             ret = QCBOR_SUCCESS;
    UsefulBufC             scratch;
    QCBOREncodeContext     hpke_sender_info;
    uint8_t                ephemeral_buf[100] = {0};
    struct q_useful_buf    e_buf = {ephemeral_buf, sizeof(ephemeral_buf)};
    uint8_t                encrypted_cek[T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH)];
    size_t                 encrypted_cek_len = T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    UsefulBufC             cek_encrypted_cbor;
    size_t                 pkR_len = T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkR[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    size_t                 pkE_len = T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkE[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    enum t_cose_err_t      return_value;
    struct t_cose_crypto_hpke_suite_t hpke_suite;
    struct t_cose_key      ephemeral_key;

    (void)cose_algorithm_id; // TODO: use this or get rid of it
    (void)recipient_key; // TODO: use this or get rid of it

    if (context == NULL || encrypt_ctx == NULL) {
        return(T_COSE_ERR_INVALID_ARGUMENT);
    }

    return_value = t_cose_crypto_convert_hpke_algorithms(context->cose_algorithm_id,
                                                    &hpke_suite,
                                                    &key_bitlen,
                                                    &algorithm_id);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Create ephemeral key */
    return_value = t_cose_crypto_generate_key(&ephemeral_key,
                                              context->cose_algorithm_id);
    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Export pkR */
    return_value = t_cose_crypto_export_public_key(
                         context->pkR,
                         (struct q_useful_buf) {.ptr=pkR, .len=pkR_len},
                         &pkR_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Export pkE */
    return_value = t_cose_crypto_export_public_key(
                         ephemeral_key,
                         (struct q_useful_buf) {.ptr=pkE, .len=pkE_len},
                         &pkE_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* HPKE encryption */
    return_value = t_cose_crypto_hpke_encrypt(
                        hpke_suite,
                        (struct q_useful_buf_c) {.ptr = pkR, .len = pkR_len},
                        ephemeral_key,
                        plaintext,
                        (struct q_useful_buf) {.ptr = encrypted_cek, .len = encrypted_cek_len},
                        &encrypted_cek_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Create recipient array */
    QCBOREncode_OpenArray(encrypt_ctx);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(encrypt_ctx);

    QCBOREncode_OpenMap(encrypt_ctx);

    QCBOREncode_AddInt64ToMapN(encrypt_ctx,
                               T_COSE_HEADER_PARAM_ALG,
                               T_COSE_ALGORITHM_HPKE_v1_BASE);

    QCBOREncode_CloseMap(encrypt_ctx);

    QCBOREncode_CloseBstrWrap2(encrypt_ctx,
                               false,
                               &scratch);

    /* Add unprotected Header */
    QCBOREncode_OpenMap(encrypt_ctx);

    /* Create HPKE_sender_info structure
     *
     *  HPKE_sender_info = [
     *     kem_id : uint,       ; kem identifier
     *     kdf_id : uint,       ; kdf identifier
     *     aead_id : uint,      ; aead identifier
     *     enc : bstr,          ; encapsulated key
     *  ]
     */
    QCBOREncode_Init(&hpke_sender_info, e_buf);

    /* Open HPKE_sender_info array */
    QCBOREncode_OpenArray(&hpke_sender_info);

    /* -- add kem id */
    QCBOREncode_AddUInt64(&hpke_sender_info,
                          hpke_suite.kem_id);

    /* -- add kdf id */
    QCBOREncode_AddUInt64(&hpke_sender_info,
                          hpke_suite.kdf_id);

    /* -- add aead id */
    QCBOREncode_AddUInt64(&hpke_sender_info,
                          hpke_suite.aead_id);

    /* -- add enc */
    QCBOREncode_AddBytes(&hpke_sender_info,
                         (struct q_useful_buf_c)
                         {
                           pkE,
                           pkE_len
                         }
                        );

    /* Close HPKE_sender_info array */
    QCBOREncode_CloseArray(&hpke_sender_info);

    /* Finish HPKE_sender_info array */
    ret = QCBOREncode_Finish(&hpke_sender_info, &scratch);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    /* Add HPKE_sender_info to unprotected map */
    QCBOREncode_AddBytesToMapN(encrypt_ctx,
                               T_COSE_HEADER_ALG_PARAM_HPKE_SENDER_INFO,
                               (struct q_useful_buf_c)
                               {
                                 scratch.ptr,
                                 scratch.len
                               }
                              );

    /* Add kid to unprotected map  */
    QCBOREncode_AddBytesToMapN(encrypt_ctx,
                               T_COSE_HEADER_PARAM_KID,
                               context->kid);

    /* Close unprotected map */
    QCBOREncode_CloseMap(encrypt_ctx);

    /* Convert to UsefulBufC structure */
    cek_encrypted_cbor.len = encrypted_cek_len;
    cek_encrypted_cbor.ptr = encrypted_cek;

    /* Add encrypted CEK */
    QCBOREncode_AddBytes(encrypt_ctx, cek_encrypted_cbor);

    /* Close recipient array */
    QCBOREncode_CloseArray(encrypt_ctx);

    return(T_COSE_SUCCESS);
}


enum t_cose_err_t
t_cose_recipient_create_hpke_cb_private(struct t_cose_recipient_enc  *me_x,
                         struct q_useful_buf_c         cek,
                         QCBOREncodeContext           *cbor_encoder)
{
    enum t_cose_err_t err;
    struct t_cose_recipient_enc_hpke *me;

    me = (struct t_cose_recipient_enc_hpke *)me_x;

    err = t_cose_create_recipient_hpke2(me,
                                       0,
                                       me->pkR,
                                       cek,
                                       cbor_encoder);

    return err;
}




#else

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_enc_hpke_placeholder(void) {}

#endif /* T_COSE_DISABLE_HPKE */
