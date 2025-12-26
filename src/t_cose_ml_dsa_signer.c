#include "t_cose/t_cose_ml_dsa_signer.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_signature_sign.h"
#include "oqs/oqs.h"
#include "t_cose/t_cose_common.h"
#include <string.h>

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


    if (cose_alg_id != T_COSE_ALGORITHM_ML_DSA_44) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    sig_len = buffer_for_output.len;

    // Initialize ML-DSA signer
    oqs_sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!oqs_sig) {
        return T_COSE_ERR_SIG_FAIL;
    }

    // CHECK: Is buffer big enough?
    if (buffer_for_output.len < oqs_sig->length_signature) {
        OQS_SIG_free(oqs_sig);
        return T_COSE_ERR_SIG_FAIL;
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
