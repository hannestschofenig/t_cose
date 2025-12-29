#include "t_cose/t_cose_ml_dsa_signer.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_signature_sign.h"
#include "oqs/oqs.h"
#include "t_cose/t_cose_common.h"
#include <stdbool.h>
#include <string.h>

static bool get_mldsa_params(int32_t cose_alg_id,
                             const char **oqs_alg_id,
                             size_t *secret_key_len)
{
    switch (cose_alg_id) {
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

enum t_cose_err_t t_cose_ml_dsa_signer(struct t_cose_key signing_key,
                                int32_t cose_alg_id,
                                struct q_useful_buf_c protected_parameters,
                                struct q_useful_buf_c payload,
                                struct q_useful_buf buffer_for_output,
                                struct q_useful_buf_c *result)
{
    size_t sig_len;
    OQS_SIG *oqs_sig;
    int ret;
    const char *oqs_alg_id = NULL;
    size_t secret_key_len = 0;


    if (!get_mldsa_params(cose_alg_id, &oqs_alg_id, &secret_key_len)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    if (signing_key.key.buffer.len != secret_key_len) {
        return T_COSE_ERR_INVALID_ARGUMENT;
    }

    sig_len = buffer_for_output.len;

    // Initialize ML-DSA signer
    oqs_sig = OQS_SIG_new(oqs_alg_id);
    if (!oqs_sig) {
        return T_COSE_ERR_SIG_FAIL;
    }

    // CHECK: Is buffer big enough?
    if (buffer_for_output.len < oqs_sig->length_signature) {
        OQS_SIG_free(oqs_sig);
        return T_COSE_ERR_TOO_SMALL;
    }

    // Sign using the payload
    ret = OQS_SIG_sign(oqs_sig,
                        buffer_for_output.ptr,
                        &sig_len,
                        payload.ptr,
                        payload.len,
                        signing_key.key.buffer.ptr);

    OQS_SIG_free(oqs_sig);

    if (ret != OQS_SUCCESS) {
        return T_COSE_ERR_SIG_FAIL;
    }

    *result = (struct q_useful_buf_c){
        .ptr = buffer_for_output.ptr,
        .len = sig_len
    };

    return T_COSE_SUCCESS;
}
