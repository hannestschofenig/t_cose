#include "t_cose/t_cose_pqc_sig_alg.h"
#include "oqs/oqs.h"

static const struct t_cose_pqc_alg pqc_algs[] = {
    { T_COSE_ALGORITHM_ML_DSA_44, "ML-DSA-44",
      OQS_SIG_alg_ml_dsa_44,
      OQS_SIG_ml_dsa_44_length_signature,
      OQS_SIG_ml_dsa_44_length_public_key,
      OQS_SIG_ml_dsa_44_length_secret_key },
    { T_COSE_ALGORITHM_ML_DSA_65, "ML-DSA-65",
      OQS_SIG_alg_ml_dsa_65,
      OQS_SIG_ml_dsa_65_length_signature,
      OQS_SIG_ml_dsa_65_length_public_key,
      OQS_SIG_ml_dsa_65_length_secret_key },
    { T_COSE_ALGORITHM_ML_DSA_87, "ML-DSA-87",
      OQS_SIG_alg_ml_dsa_87,
      OQS_SIG_ml_dsa_87_length_signature,
      OQS_SIG_ml_dsa_87_length_public_key,
      OQS_SIG_ml_dsa_87_length_secret_key },
    { T_COSE_ALGORITHM_FN_DSA_512, "FN-DSA-512",
      OQS_SIG_alg_falcon_512,
      OQS_SIG_falcon_512_length_signature,
      OQS_SIG_falcon_512_length_public_key,
      OQS_SIG_falcon_512_length_secret_key },
    { T_COSE_ALGORITHM_FN_DSA_1024, "FN-DSA-1024",
      OQS_SIG_alg_falcon_1024,
      OQS_SIG_falcon_1024_length_signature,
      OQS_SIG_falcon_1024_length_public_key,
      OQS_SIG_falcon_1024_length_secret_key },
    { T_COSE_ALGORITHM_SLH_DSA_SHA2_128S, "SLH-DSA-SHA2-128s",
      OQS_SIG_alg_sphincs_sha2_128s_simple,
      OQS_SIG_sphincs_sha2_128s_simple_length_signature,
      OQS_SIG_sphincs_sha2_128s_simple_length_public_key,
      OQS_SIG_sphincs_sha2_128s_simple_length_secret_key },
    { T_COSE_ALGORITHM_SLH_DSA_SHAKE_128S, "SLH-DSA-SHAKE-128s",
      OQS_SIG_alg_sphincs_shake_128s_simple,
      OQS_SIG_sphincs_shake_128s_simple_length_signature,
      OQS_SIG_sphincs_shake_128s_simple_length_public_key,
      OQS_SIG_sphincs_shake_128s_simple_length_secret_key },
    { T_COSE_ALGORITHM_SLH_DSA_SHA2_128F, "SLH-DSA-SHA2-128f",
      OQS_SIG_alg_sphincs_sha2_128f_simple,
      OQS_SIG_sphincs_sha2_128f_simple_length_signature,
      OQS_SIG_sphincs_sha2_128f_simple_length_public_key,
      OQS_SIG_sphincs_sha2_128f_simple_length_secret_key },
};

const struct t_cose_pqc_alg *t_cose_get_pqc_algs(size_t *count)
{
    if (count) {
        *count = sizeof(pqc_algs) / sizeof(pqc_algs[0]);
    }
    return pqc_algs;
}

const struct t_cose_pqc_alg *t_cose_find_pqc_alg(int32_t cose_alg_id)
{
    size_t count = 0;
    const struct t_cose_pqc_alg *algs = t_cose_get_pqc_algs(&count);

    for (size_t i = 0; i < count; i++) {
        if (algs[i].cose_alg_id == cose_alg_id) {
            return &algs[i];
        }
    }
    return NULL;
}
