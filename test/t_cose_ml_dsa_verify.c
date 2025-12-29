#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_common.h"
#include "qcbor/UsefulBuf.h"
#include "oqs/oqs.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct file_buffer {
    uint8_t *data;
    size_t   len;
};


static const char *t_cose_err_str(enum t_cose_err_t err)
{
    switch (err) {
    case T_COSE_SUCCESS: return "T_COSE_SUCCESS";
    case T_COSE_ERR_UNSUPPORTED_SIGNING_ALG: return "T_COSE_ERR_UNSUPPORTED_SIGNING_ALG";
    case T_COSE_ERR_UNSUPPORTED_HASH: return "T_COSE_ERR_UNSUPPORTED_HASH";
    case T_COSE_ERR_SIG_BUFFER_SIZE: return "T_COSE_ERR_SIG_BUFFER_SIZE";
    case T_COSE_ERR_NO_ALG_ID: return "T_COSE_ERR_NO_ALG_ID";
    case T_COSE_ERR_NO_KID: return "T_COSE_ERR_NO_KID";
    case T_COSE_ERR_SIG_VERIFY: return "T_COSE_ERR_SIG_VERIFY";
    case T_COSE_ERR_INVALID_ARGUMENT: return "T_COSE_ERR_INVALID_ARGUMENT";
    default: return "T_COSE_ERR_UNKNOWN";
    }
}


static void free_file_buffer(struct file_buffer *buf)
{
    if (buf->data != NULL) {
        free(buf->data);
        buf->data = NULL;
        buf->len = 0;
    }
}


static int read_file(const char *path, struct file_buffer *out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "Failed to seek %s: %s\n", path, strerror(errno));
        fclose(f);
        return -1;
    }

    long size = ftell(f);
    if (size < 0) {
        fprintf(stderr, "Failed to get size of %s: %s\n", path, strerror(errno));
        fclose(f);
        return -1;
    }
    rewind(f);

    out->data = malloc((size_t)size);
    if (!out->data) {
        fprintf(stderr, "Out of memory while reading %s\n", path);
        fclose(f);
        return -1;
    }

    size_t read = fread(out->data, 1, (size_t)size, f);
    fclose(f);
    if (read != (size_t)size) {
        fprintf(stderr, "Failed to read %s completely\n", path);
        free_file_buffer(out);
        return -1;
    }

    out->len = (size_t)size;
    return 0;
}


static int32_t mldsa_alg_from_pub_len(size_t len, const char **name)
{
    if (len == OQS_SIG_ml_dsa_44_length_public_key) {
        if (name) {
            *name = "ML-DSA-44";
        }
        return T_COSE_ALGORITHM_ML_DSA_44;
    }
    if (len == OQS_SIG_ml_dsa_65_length_public_key) {
        if (name) {
            *name = "ML-DSA-65";
        }
        return T_COSE_ALGORITHM_ML_DSA_65;
    }
    if (len == OQS_SIG_ml_dsa_87_length_public_key) {
        if (name) {
            *name = "ML-DSA-87";
        }
        return T_COSE_ALGORITHM_ML_DSA_87;
    }

    return 0;
}


int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pub-file> <signed-file>\n", argv[0]);
        return 1;
    }

    const char *pub_path = argv[1];
    const char *signed_path = argv[2];

    struct file_buffer pub_key = {0};
    struct file_buffer signed_cose_buf = {0};
    struct q_useful_buf_c payload = {0};
    const char *alg_name = NULL;
    int exit_code = 1;

    if (read_file(pub_path, &pub_key) != 0) {
        goto cleanup;
    }

    if (read_file(signed_path, &signed_cose_buf) != 0) {
        goto cleanup;
    }

    int32_t cose_alg_id = mldsa_alg_from_pub_len(pub_key.len, &alg_name);
    if (cose_alg_id == 0) {
        fprintf(stderr, "Unsupported public key size: %zu bytes. "
                        "Expected %zu (ML-DSA-44), %zu (ML-DSA-65), or %zu (ML-DSA-87).\n",
                pub_key.len,
                (size_t)OQS_SIG_ml_dsa_44_length_public_key,
                (size_t)OQS_SIG_ml_dsa_65_length_public_key,
                (size_t)OQS_SIG_ml_dsa_87_length_public_key);
        goto cleanup;
    }

    struct t_cose_sign1_verify_ctx verify_ctx;
    struct t_cose_key verify_key = {0};
    struct q_useful_buf_c signed_cose = {
        .ptr = signed_cose_buf.data,
        .len = signed_cose_buf.len
    };

    verify_key.key.buffer.ptr = pub_key.data;
    verify_key.key.buffer.len = pub_key.len;

    t_cose_sign1_verify_init(&verify_ctx, 0);
    t_cose_sign1_set_verification_key(&verify_ctx, verify_key);

    enum t_cose_err_t result = t_cose_sign1_verify(&verify_ctx, signed_cose, &payload, NULL);

    if (result == T_COSE_SUCCESS) {
        printf("Verification succeeded with %s\n", alg_name);
        printf("Message (%zu bytes): %.*s\n",
               payload.len,
               (int)payload.len,
               (const char *)payload.ptr);
        exit_code = 0;
    } else {
        printf("Verification failed with error %d (%s)\n", result, t_cose_err_str(result));
    }

cleanup:
    free_file_buffer(&pub_key);
    free_file_buffer(&signed_cose_buf);
    return exit_code;
}
