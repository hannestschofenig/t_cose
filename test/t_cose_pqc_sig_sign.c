#include "t_cose/t_cose_sign1_sign.h"
#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_pqc_sig_alg.h"
#include "qcbor/qcbor_decode.h"
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

struct cose_priv_key {
    int32_t alg_id;
    struct q_useful_buf_c priv;
};

static bool parse_cose_priv(const uint8_t *buf, size_t len, struct cose_priv_key *out)
{
    UsefulBufC input = {.ptr = buf, .len = len};
    QCBORDecodeContext dc;
    QCBORItem item;
    bool have_priv = false;
    int32_t alg = 0;

    QCBORDecode_Init(&dc, input, QCBOR_DECODE_MODE_NORMAL);

    if(QCBORDecode_GetNext(&dc, &item) != QCBOR_SUCCESS || item.uDataType != QCBOR_TYPE_MAP) {
        return false;
    }

    while(QCBORDecode_GetNext(&dc, &item) == QCBOR_SUCCESS) {
        if(item.uLabelType == QCBOR_TYPE_INT64 && item.label.int64 == 3 && item.uDataType == QCBOR_TYPE_INT64) {
            alg = (int32_t)item.val.int64;
        } else if(item.uLabelType == QCBOR_TYPE_INT64 && item.label.int64 == -2 && item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            out->priv = item.val.string;
            have_priv = true;
        }
    }
    if(QCBORDecode_Finish(&dc) != QCBOR_SUCCESS) {
        return false;
    }
    if(!have_priv) {
        return false;
    }
    out->alg_id = alg;
    return true;
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

    struct cose_priv_key cose_priv = {0};
    if(!parse_cose_priv(priv_buf, priv_len, &cose_priv)) {
        printf("Failed to parse COSE_Key private key\n");
        free(priv_buf);
        return 1;
    }

    int32_t alg_id = 0;
    const char *alg_name = NULL;
    const struct t_cose_pqc_alg *entry = t_cose_find_pqc_alg(cose_priv.alg_id);
    if(!entry) {
        printf("Unsupported algorithm id in key: %d\n", cose_priv.alg_id);
        free(priv_buf);
        return 1;
    }
    alg_id = entry->cose_alg_id;
    alg_name = entry->display_name;
    if(cose_priv.priv.len != entry->sec_key_len) {
        printf("Private key length mismatch for %s: got %zu, expected %zu\n",
               alg_name, cose_priv.priv.len, entry->sec_key_len);
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

    size_t sig_buf_len = entry->sig_len + 512; /* room for CBOR wrapping */
    uint8_t *sig_storage = malloc(sig_buf_len);
    if(!sig_storage) {
        printf("Out of memory\n");
        free(payload_buf);
        free(priv_buf);
        return 1;
    }
    struct q_useful_buf signature_buf = {sig_storage, sig_buf_len};
    struct q_useful_buf_c signed_cose;

    signing_key.key.buffer.ptr = (uint8_t *)cose_priv.priv.ptr;
    signing_key.key.buffer.len = cose_priv.priv.len;

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
    free(sig_storage);
    return 0;
}
