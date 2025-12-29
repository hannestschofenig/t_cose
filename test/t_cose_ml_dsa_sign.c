#include "t_cose/t_cose_sign1_sign.h"
#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_signature_sign.h"
#include "oqs/oqs.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>


void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0)
            printf("\n");
    }
    printf("\n");
}
void print_as_c_array(const char* name, const uint8_t* data, size_t len) {
    printf("uint8_t %s[] = {\n", name);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02X%s", data[i], (i < len - 1) ? ", " : "");
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("};\nsize_t %s_len = sizeof(%s);\n\n", name, name);
}

static bool read_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if(!f) {
        return false;
    }
    if(fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }
    long sz = ftell(f);
    if(sz < 0) {
        fclose(f);
        return false;
    }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if(!buf) {
        fclose(f);
        return false;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if(got != (size_t)sz) {
        free(buf);
        return false;
    }
    *out = buf;
    *out_len = (size_t)sz;
    return true;
}

static bool write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if(!f) {
        return false;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return written == len;
}

static bool alg_from_priv_len(size_t len, int32_t *alg, const char **name)
{
    if(len == OQS_SIG_ml_dsa_44_length_secret_key) {
        *alg  = T_COSE_ALGORITHM_ML_DSA_44;
        *name = "ML-DSA-44";
        return true;
    }
    if(len == OQS_SIG_ml_dsa_65_length_secret_key) {
        *alg  = T_COSE_ALGORITHM_ML_DSA_65;
        *name = "ML-DSA-65";
        return true;
    }
    if(len == OQS_SIG_ml_dsa_87_length_secret_key) {
        *alg  = T_COSE_ALGORITHM_ML_DSA_87;
        *name = "ML-DSA-87";
        return true;
    }
    return false;
}

int main(int argc, char **argv) {
    if(argc < 3 || argc > 4) {
        printf("Usage: %s <priv-file> <payload-file> [signed-output]\n", argv[0]);
        return 1;
    }

    const char *priv_path    = argv[1];
    const char *payload_path = argv[2];
    const char *output_path  = argc == 4 ? argv[3] : NULL;

    uint8_t *priv_buf = NULL;
    size_t priv_len = 0;
    if(!read_file(priv_path, &priv_buf, &priv_len)) {
        printf("Failed to read private key file: %s\n", priv_path);
        return 1;
    }

    int32_t alg_id = 0;
    const char *alg_name = NULL;
    if(!alg_from_priv_len(priv_len, &alg_id, &alg_name)) {
        printf("Unsupported private key size: %zu bytes. Expected %zu (ML-DSA-44), %zu (ML-DSA-65), or %zu (ML-DSA-87).\n",
               priv_len,
               (size_t)OQS_SIG_ml_dsa_44_length_secret_key,
               (size_t)OQS_SIG_ml_dsa_65_length_secret_key,
               (size_t)OQS_SIG_ml_dsa_87_length_secret_key);
        free(priv_buf);
        return 1;
    }

    uint8_t *payload_buf = NULL;
    size_t payload_len = 0;
    if(!read_file(payload_path, &payload_buf, &payload_len)) {
        printf("Failed to read payload file: %s\n", payload_path);
        free(priv_buf);
        return 1;
    }

    struct t_cose_sign1_sign_ctx sign_ctx;
    struct t_cose_key signing_key;
    struct q_useful_buf_c kid = NULL_Q_USEFUL_BUF_C; // Q_USEFUL_BUF_FROM_SZ_LITERAL("key-id");
    struct q_useful_buf_c payload = {payload_buf, payload_len};
    enum t_cose_err_t result;

    UsefulBuf_MAKE_STACK_UB(signature_buf, OQS_SIG_ml_dsa_87_length_signature + 512);
    struct q_useful_buf_c signed_cose;

    signing_key.key.buffer.ptr = priv_buf;
    signing_key.key.buffer.len = priv_len;

    t_cose_sign1_sign_init(&sign_ctx, 0, alg_id);
    t_cose_sign1_set_signing_key(&sign_ctx, signing_key, kid);

    result = t_cose_sign1_sign(&sign_ctx, payload, signature_buf, &signed_cose);

    if (result == T_COSE_SUCCESS) {
        printf("Signature succeeded! Algorithm: %s, Signed COSE size: %zu bytes\n",
               alg_name, signed_cose.len);
        if(output_path) {
            if(!write_file(output_path, signed_cose.ptr, signed_cose.len)) {
                printf("Failed to write signed payload to %s\n", output_path);
                free(payload_buf);
                return 1;
            }
            printf("Signed COSE written to %s\n", output_path);
        } else {
            printf("Signed COSE (hex):\n");
            print_hex((const uint8_t *)signed_cose.ptr, signed_cose.len);
        }
    } else {
        printf("Signature failed with error: %d\n", result);
    }

    free(payload_buf);
    free(priv_buf);
    return 0;
}
