#ifndef T_COSE_ML_DSA_SIGNER_H
#define T_COSE_ML_DSA_SIGNER_H

#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_key.h"

enum t_cose_err_t t_cose_ml_dsa_signer(struct t_cose_key signing_key,
                                int32_t cose_alg_id,
                                struct q_useful_buf_c protected_parameters,
                                struct q_useful_buf_c payload,
                                struct q_useful_buf buffer_for_output,
                                struct q_useful_buf_c *result);

#endif /* T_COSE_ML_DSA_SIGNER_H */
