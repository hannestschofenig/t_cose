#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor.h"
#include "qcbor/UsefulBuf.h"
#include "oqs/oqs.h"
#include <stdbool.h>
#include <string.h>

static bool get_mldsa_params(int32_t cose_algorithm_id,
                             const char **oqs_alg_id,
                             size_t *secret_key_len)
{
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ML_DSA_44:
        *oqs_alg_id = OQS_SIG_alg_ml_dsa_44;
        *secret_key_len = OQS_SIG_ml_dsa_44_length_secret_key;
        return true;
    case T_COSE_ALGORITHM_ML_DSA_65:
        *oqs_alg_id = OQS_SIG_alg_ml_dsa_65;
        *secret_key_len = OQS_SIG_ml_dsa_65_length_secret_key;
        return true;
    case T_COSE_ALGORITHM_ML_DSA_87:
        *oqs_alg_id = OQS_SIG_alg_ml_dsa_87;
        *secret_key_len = OQS_SIG_ml_dsa_87_length_secret_key;
        return true;
    default:
        return false;
    }
}

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
    const char *oqs_alg_id = NULL;
    size_t expected_sk_len = 0;

    if (!get_mldsa_params(cose_algorithm_id, &oqs_alg_id, &expected_sk_len)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    if (private_key_len != expected_sk_len) {
        return T_COSE_ERR_FAIL;
    }

    if (protected_parameters.len + payload.len > sizeof(temp_msg)) {
        return T_COSE_ERR_TOO_SMALL;
    }

    memcpy(temp_msg, protected_parameters.ptr, protected_parameters.len);
    memcpy(temp_msg + protected_parameters.len, payload.ptr, payload.len);
    msg_len = protected_parameters.len + payload.len;

    sig = OQS_SIG_new(oqs_alg_id);
    if (!sig) {
        return T_COSE_ERR_FAIL;
    }

    if (buffer_to_hold_result.len < sig->length_signature) {
        OQS_SIG_free(sig);
        return T_COSE_ERR_TOO_SMALL;
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
