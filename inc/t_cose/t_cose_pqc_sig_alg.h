/*
 * t_cose_pqc_sig_alg.h
 *
 * Shared parameter table for PQC signature algorithms handled via liboqs.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef T_COSE_PQC_ALG_H
#define T_COSE_PQC_ALG_H

#include <stddef.h>
#include "t_cose/t_cose_standard_constants.h"
#include <stdint.h>

struct t_cose_pqc_alg {
    int32_t      cose_alg_id;
    const char  *display_name;
    const char  *oqs_alg_id;
    size_t       sig_len;
    size_t       pub_key_len;
    size_t       sec_key_len;
};

const struct t_cose_pqc_alg *t_cose_get_pqc_algs(size_t *count);
const struct t_cose_pqc_alg *t_cose_find_pqc_alg(int32_t cose_alg_id);

#endif /* T_COSE_PQC_ALG_H */
