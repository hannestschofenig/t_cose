// t_cose_signature_verify_mldsa.c

#include "t_cose/t_cose_signature_verify.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_signature_verify_mldsa.h"
#include "t_cose_crypto.h"
#include "qcbor/qcbor.h"
#include "qcbor/UsefulBuf.h"
#include <string.h>

enum t_cose_err_t
t_cose_signature_verify_mldsa_cb(struct t_cose_signature_verify *me_x,
                                 uint32_t option_flags,
                                 const struct t_cose_sign_inputs *sign_inputs,
                                 const struct t_cose_parameter *parameter_list,
                                 const struct q_useful_buf_c signature)
{
    struct t_cose_signature_verify_mldsa *me =
                          (struct t_cose_signature_verify_mldsa *)me_x;
    int32_t                      cose_algorithm_id;
    enum t_cose_err_t            return_value;
    struct q_useful_buf_c        kid;


    if (sign_inputs->payload.ptr == NULL || signature.ptr == NULL)
        return T_COSE_ERR_SIG_VERIFY;

    /* --- Check the algorithm --- */
    cose_algorithm_id = t_cose_param_find_alg_id_prot(parameter_list);
    if(cose_algorithm_id == T_COSE_ALGORITHM_NONE) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }
    if(cose_algorithm_id != T_COSE_ALGORITHM_ML_DSA_44) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if(option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }

    /* --- Check kid --- */
    /* Kid verification is not done in decode only mode. */
    kid = t_cose_param_find_kid(parameter_list);
    if(!q_useful_buf_c_is_null(me->verification_kid)) {
        if(q_useful_buf_c_is_null(kid)) {
            return T_COSE_ERR_NO_KID;
        }
        if(q_useful_buf_compare(kid, me->verification_kid)) {
            return T_COSE_ERR_KID_UNMATCHED;
        }
    }

    return_value = t_cose_crypto_verify(cose_algorithm_id,
                                        me->verification_key,
                                        NULL,
                                        sign_inputs->payload,
                                        signature);

Done:
    return return_value;

}




/*
 * Public function. See t_cose_signature_verify_mldsa.h
 */
void
t_cose_signature_verify_mldsa_init(struct t_cose_signature_verify_mldsa *me,
                                   uint32_t option_flags)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident   = RS_IDENT(TYPE_RS_VERIFIER, 'E');
    me->s.verify_cb  = t_cose_signature_verify_mldsa_cb;
    me->option_flags = option_flags;

}
