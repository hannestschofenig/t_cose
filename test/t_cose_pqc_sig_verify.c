#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_pqc_sig_alg.h"
#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor_decode.h"
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


struct cose_pub_key {
    int32_t alg_id;
    struct q_useful_buf_c pub;
};

static bool parse_cose_pub(const uint8_t *buf, size_t len, struct cose_pub_key *out)
{
    UsefulBufC input = {.ptr = buf, .len = len};
    QCBORDecodeContext dc;
    QCBORItem item;
    bool have_pub = false;
    int32_t alg = 0;

    QCBORDecode_Init(&dc, input, QCBOR_DECODE_MODE_NORMAL);

    if(QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS || item.uDataType != QCBOR_TYPE_MAP) {
        return false;
    }

    while(QCBORDecode_GetNext(&dc, &item) == QCBOR_SUCCESS) {
        if(item.uLabelType == QCBOR_TYPE_INT64 && item.label.int64 == 3 && item.uDataType == QCBOR_TYPE_INT64) {
            alg = (int32_t)item.val.int64;
        } else if(item.uLabelType == QCBOR_TYPE_INT64 && item.label.int64 == -1 && item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            out->pub = item.val.string;
            have_pub = true;
        }
    }
    if(QCBORDecode_Finish(&dc) != QCBOR_SUCCESS) {
        return false;
    }
    if(!have_pub) {
        return false;
    }
    out->alg_id = alg;
    return true;
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

    struct cose_pub_key cose_pub = {0};
    if(!parse_cose_pub(pub_key.data, pub_key.len, &cose_pub)) {
        fprintf(stderr, "Failed to parse COSE_Key public key\n");
        goto cleanup;
    }

    const struct t_cose_pqc_alg *entry = t_cose_find_pqc_alg(cose_pub.alg_id);
    if(!entry) {
        fprintf(stderr, "Unsupported algorithm id in key: %d\n", cose_pub.alg_id);
        goto cleanup;
    }
    alg_name = entry->display_name;
    if(cose_pub.pub.len != entry->pub_key_len) {
        fprintf(stderr, "Public key length mismatch for %s: got %zu, expected %zu\n",
                alg_name, cose_pub.pub.len, entry->pub_key_len);
        goto cleanup;
    }

    struct t_cose_sign1_verify_ctx verify_ctx;
    struct t_cose_key verify_key = {0};
    struct q_useful_buf_c signed_cose = {
        .ptr = signed_cose_buf.data,
        .len = signed_cose_buf.len
    };

    verify_key.key.buffer.ptr = (uint8_t *)cose_pub.pub.ptr;
    verify_key.key.buffer.len = cose_pub.pub.len;

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
