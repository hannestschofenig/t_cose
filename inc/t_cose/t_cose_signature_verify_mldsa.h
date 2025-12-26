/*
 * t_cose_signature_verify_mldsa.h
 *
 * Copyright (c) 2025, Hannes Tschofenig. All rights reserved.
 * Created by Hannes Tschofenig on 11/01/25.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_signature_verify_mldsa_h
#define t_cose_signature_verify_mldsa_h

#include "t_cose/t_cose_signature_verify.h"
#include "t_cose_parameters.h"
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * Verification context.
 */
struct t_cose_signature_verify_mldsa {
    /* Private data structure */

    /* t_cose_signature_verify must be the first item for the
     * polymorphism to work.  This structure,
     * t_cose_signature_verify_mldsa, will sometimes be uses as a
     * t_cose_signature_verify.
     */
    struct t_cose_signature_verify  s;
    struct t_cose_key               verification_key;
    uint32_t                        option_flags;

    struct q_useful_buf_c           verification_kid;
};


// TODO: get rid of option_flags?
void
t_cose_signature_verify_mldsa_init(struct t_cose_signature_verify_mldsa *me,
                                   uint32_t                option_flags);


static void
t_cose_signature_verify_mldsa_set_key(struct t_cose_signature_verify_mldsa *me,
                                      struct t_cose_key verification_key,
                                      struct q_useful_buf_c verification_kid);

static void
t_cose_signature_verify_mldsa_set_special_param_decoder(struct t_cose_signature_verify_mldsa *me,
                                                t_cose_param_special_decode_cb               *decode_cb,
                                                void                                         *decode_ctx);

static struct t_cose_signature_verify *
t_cose_signature_verify_from_mldsa(struct t_cose_signature_verify_mldsa *context);




/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

static inline void
t_cose_signature_verify_mldsa_set_key(struct t_cose_signature_verify_mldsa *me,
                                      struct t_cose_key verification_key,
                                      struct q_useful_buf_c verification_kid)
{
    me->verification_key = verification_key;
    me->verification_kid = verification_kid;
}

static inline void
t_cose_signature_verify_mldsa_set_special_param_decoder(struct t_cose_signature_verify_mldsa *me,
                                                        t_cose_param_special_decode_cb       *decode_cb,
                                                        void      *decode_ctx)
{
    struct t_cose_signature_verify *me_x = t_cose_signature_verify_from_mldsa(me);
    me_x->special_param_decode_cb  = decode_cb;
    me_x->special_param_decode_ctx = decode_ctx;
}


static inline struct t_cose_signature_verify *
t_cose_signature_verify_from_mldsa(struct t_cose_signature_verify_mldsa *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}


#ifdef __cplusplus
}
#endif

#endif /* t_cose_signature_verify_mldsa_h */
