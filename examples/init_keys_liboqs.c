/*
 * init_keys_liboqs.c
 *
 * Copyright 2025, Hannes Tschofenig. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_key.h"
#include "init_keys.h"
#include "oqs/oqs.h"
#include "example_keys.h"


#ifndef ML_DSA_KEYS_H
#define ML_DSA_KEYS_H

/*
 * Public function, see init_key.h
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair)
{
    OQS_SIG *sig;

    /* Select the key bytes based on the algorithm and 
     * retrieve the data from example_keys.c
     */
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ML_DSA_44:
        sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (!sig) {
            return T_COSE_ERR_FAIL;
        }
        key_pair->key.buffer.ptr = (uint8_t *)ml_dsa_44_private_key;
        key_pair->key.buffer.len = sizeof(ml_dsa_44_private_key);
        return T_COSE_SUCCESS;
    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }
}


/*
 * Public function, see init_keys.h
 */
void free_fixed_signing_key(struct t_cose_key key_pair)
{
    // Nothing to release here since we are using a static const-array
    (void)key_pair;
}


/*
 * Public function, see init_key.h
 */
enum t_cose_err_t
init_fixed_test_verification_key(int32_t       cose_algorithm_id,
                            struct t_cose_key *key_pair)
{
    OQS_SIG *sig;

    /* Select the key bytes based on the algorithm and 
     * retrieve the data from example_keys.c
     */
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ML_DSA_44:
        sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (!sig) {
            return T_COSE_ERR_FAIL;
        }
        key_pair->key.buffer.ptr = (uint8_t *)ml_dsa_44_public_key;
        key_pair->key.buffer.len = sizeof(ml_dsa_44_public_key);
        return T_COSE_SUCCESS;
    default:
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }
}


/*
 * Public function, see init_keys.h
 */
void free_fixed_verification_key(struct t_cose_key key_pair)
{
    // Nothing to release here since we are using a static const-array
    (void)key_pair;
}


#endif // ML_DSA_KEYS_H

