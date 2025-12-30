#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "oqs/oqs.h"
#include "t_cose/t_cose_pqc_sig_alg.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_spiffy_decode.h"

static bool
write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if(!f) {
        return false;
    }
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return written == len;
}

int main(int argc, char *argv[])
{
    if(argc != 5) {
        fprintf(stderr,
                "Usage: %s <ALG-NAME> <kid-string> <pub-file> <priv-file>\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    const char *alg_name  = argv[1];
    const char *kid_str   = argv[2];
    const char *pub_path  = argv[3];
    const char *priv_path = argv[4];

    size_t kid_out_len = strlen(kid_str);
    uint8_t *kid_buf = malloc(kid_out_len);
    if(!kid_buf) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    memcpy(kid_buf, kid_str, kid_out_len);

    const struct t_cose_pqc_alg *params = NULL;
    size_t count = 0;
    const struct t_cose_pqc_alg *algs = t_cose_get_pqc_algs(&count);
    for(size_t i = 0; i < count; i++) {
        if(strcmp(alg_name, algs[i].display_name) == 0) {
            params = &algs[i];
            break;
        }
    }
    if(params == NULL) {
        fprintf(stderr, "Unsupported algorithm name: %s\n", alg_name);
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(params->oqs_alg_id);
    if(sig == NULL) {
        fprintf(stderr, "Failed to create OQS_SIG for %s\n", alg_name);
        return EXIT_FAILURE;
    }

    uint8_t *pub_key  = malloc(params->pub_key_len);
    uint8_t *priv_key = malloc(params->sec_key_len);
    if(pub_key == NULL || priv_key == NULL) {
        fprintf(stderr, "Out of memory\n");
        OQS_SIG_free(sig);
        free(pub_key);
        free(priv_key);
        free(kid_buf);
        return EXIT_FAILURE;
    }

    if(OQS_SIG_keypair(sig, pub_key, priv_key) != OQS_SUCCESS) {
        fprintf(stderr, "Key generation failed for %s\n", alg_name);
        OQS_SIG_free(sig);
        free(pub_key);
        free(priv_key);
        free(kid_buf);
        return EXIT_FAILURE;
    }

    /* Encode public COSE_Key */
    {
        UsefulBuf buf_pub;
        UsefulBufC encoded_pub;
        size_t needed = params->pub_key_len + kid_out_len + 32; /* rough */
        uint8_t *tmp = malloc(needed);
        if(!tmp) {
            fprintf(stderr, "Out of memory\n");
            OQS_SIG_free(sig);
            free(pub_key);
            free(priv_key);
            free(kid_buf);
            return EXIT_FAILURE;
        }
        buf_pub.ptr = tmp;
        buf_pub.len = needed;
        QCBOREncodeContext ec;
        QCBOREncode_Init(&ec, buf_pub);
        QCBOREncode_OpenMap(&ec);
        QCBOREncode_AddInt64ToMapN(&ec, 1, 7); /* kty = AKP */
        QCBOREncode_AddInt64ToMapN(&ec, 3, params->cose_alg_id);
        QCBOREncode_AddBytesToMapN(&ec, -1, (UsefulBufC){pub_key, params->pub_key_len});
        QCBOREncode_AddBytesToMapN(&ec, 2, (UsefulBufC){kid_buf, kid_out_len});
        QCBOREncode_CloseMap(&ec);
        if(QCBOREncode_Finish(&ec, &encoded_pub) != QCBOR_SUCCESS) {
            fprintf(stderr, "Failed to encode public COSE_Key\n");
            free(tmp);
            OQS_SIG_free(sig);
            free(pub_key);
            free(priv_key);
            free(kid_buf);
            return EXIT_FAILURE;
        }
        if(!write_file(pub_path, encoded_pub.ptr, encoded_pub.len)) {
            fprintf(stderr, "Failed to write public key to %s\n", pub_path);
            free(tmp);
            OQS_SIG_free(sig);
            free(pub_key);
            free(priv_key);
            free(kid_buf);
            return EXIT_FAILURE;
        }
        free(tmp);
    }

    /* Encode private COSE_Key (includes public part) */
    {
        UsefulBuf buf_priv;
        UsefulBufC encoded_priv;
        size_t needed = params->pub_key_len + params->sec_key_len + kid_out_len + 64;
        uint8_t *tmp = malloc(needed);
        if(!tmp) {
            fprintf(stderr, "Out of memory\n");
            OQS_SIG_free(sig);
            free(pub_key);
            free(priv_key);
            free(kid_buf);
            return EXIT_FAILURE;
        }
        buf_priv.ptr = tmp;
        buf_priv.len = needed;
        QCBOREncodeContext ec;
        QCBOREncode_Init(&ec, buf_priv);
        QCBOREncode_OpenMap(&ec);
        QCBOREncode_AddInt64ToMapN(&ec, 1, 7); /* kty = AKP */
        QCBOREncode_AddInt64ToMapN(&ec, 3, params->cose_alg_id);
        QCBOREncode_AddBytesToMapN(&ec, -1, (UsefulBufC){pub_key, params->pub_key_len});
        QCBOREncode_AddBytesToMapN(&ec, -2, (UsefulBufC){priv_key, params->sec_key_len});
        QCBOREncode_AddBytesToMapN(&ec, 2, (UsefulBufC){kid_buf, kid_out_len});
        QCBOREncode_CloseMap(&ec);
        if(QCBOREncode_Finish(&ec, &encoded_priv) != QCBOR_SUCCESS) {
            fprintf(stderr, "Failed to encode private COSE_Key\n");
            free(tmp);
            OQS_SIG_free(sig);
            free(pub_key);
            free(priv_key);
            free(kid_buf);
            return EXIT_FAILURE;
        }
        if(!write_file(priv_path, encoded_priv.ptr, encoded_priv.len)) {
            fprintf(stderr, "Failed to write private key to %s\n", priv_path);
            free(tmp);
            OQS_SIG_free(sig);
            free(pub_key);
            free(priv_key);
            free(kid_buf);
            return EXIT_FAILURE;
        }
        free(tmp);
    }

    OQS_SIG_free(sig);
    /* Zeroize private key material before freeing. */
    memset(priv_key, 0, params->sec_key_len);
    free(pub_key);
    free(priv_key);
    free(kid_buf);

    printf("Generated %s key pair:\n", alg_name);
    printf("  public key:  %s (COSE_Key)\n", pub_path);
    printf("  private key: %s (COSE_Key, incl. public)\n", priv_path);
    return EXIT_SUCCESS;
}
