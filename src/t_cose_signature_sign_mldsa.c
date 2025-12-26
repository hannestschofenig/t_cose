#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor.h"
#include "qcbor/UsefulBuf.h"
#include "oqs/oqs.h"
#include <string.h>

enum t_cose_err_t t_cose_signature_sign(
    int32_t cose_algorithm_id,
    struct q_useful_buf_c protected_parameters,
    struct q_useful_buf_c payload,
    struct t_cose_key signing_key,
    struct q_useful_buf buffer_to_hold_result,
    struct q_useful_buf_c *result)
{
    const uint8_t *private_key = (const uint8_t *)signing_key.key.buffer.ptr;
    size_t private_key_len = signing_key.key.buffer.len;
    uint8_t temp_msg[1024];
    size_t sig_len = 0;
    size_t msg_len;
    OQS_SIG *sig;
    OQS_STATUS rc;

    if (cose_algorithm_id != T_COSE_ALGORITHM_ML_DSA_44) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    if (private_key_len != OQS_SIG_ml_dsa_44_length_secret_key) {
        return T_COSE_ERR_FAIL;
    }

    if (protected_parameters.len + payload.len > sizeof(temp_msg)) {
        return T_COSE_ERR_TOO_SMALL;
    }

    memcpy(temp_msg, protected_parameters.ptr, protected_parameters.len);
    memcpy(temp_msg + protected_parameters.len, payload.ptr, payload.len);
    msg_len = protected_parameters.len + payload.len;

    sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) {
        return T_COSE_ERR_FAIL;
    }

    rc = OQS_SIG_sign(sig,
                        (uint8_t *)buffer_to_hold_result.ptr,
                        &sig_len,
                        temp_msg,
                        msg_len,
                        private_key);

    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    result->ptr = buffer_to_hold_result.ptr;
    result->len = sig_len;

    return T_COSE_SUCCESS;
}
