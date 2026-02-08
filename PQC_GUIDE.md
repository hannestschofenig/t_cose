# Guide for using PQC Signatures in T_COSE (ML-DSA, FN-DSA, SLH-DSA)

## Build the code

cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCRYPTO_PROVIDER=liboqs
cmake --build build --target t_cose_pqc_sig_sign -j$(nproc)
cmake --build build --target t_cose_pqc_sig_verify -j$(nproc)
cmake --build build --target gen_pqc_sig_keys -j$(nproc)

Note: `gen_pqc_sig_keys` expects a plaintext `kid`:

```
./build/gen_pqc_sig_keys <ALG-NAME> <kid-string> <pub-file> <priv-file>
```

## Create Message

echo "hello" > payload.txt


## ML-DSA-44 EXAMPLE

./build/gen_pqc_sig_keys ML-DSA-44 my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin


## ML-DSA-65 EXAMPLE

./build/gen_pqc_sig_keys ML-DSA-65 my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin


## ML-DSA-87 EXAMPLE

./build/gen_pqc_sig_keys ML-DSA-87 my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin

## FN-DSA-512 (Falcon-512) EXAMPLE

./build/gen_pqc_sig_keys FN-DSA-512 my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin

## FN-DSA-1024 (Falcon-1024) EXAMPLE

./build/gen_pqc_sig_keys FN-DSA-1024 my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin

## SLH-DSA-SHA2-128s EXAMPLE

./build/gen_pqc_sig_keys SLH-DSA-SHA2-128s my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin

## SLH-DSA-SHAKE-128s EXAMPLE

./build/gen_pqc_sig_keys SLH-DSA-SHAKE-128s my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin

## SLH-DSA-SHA2-128f EXAMPLE

./build/gen_pqc_sig_keys SLH-DSA-SHA2-128f my-key-id pub.bin priv.bin

./build/t_cose_pqc_sig_sign priv.bin payload.txt signed.bin

./build/t_cose_pqc_sig_verify pub.bin signed.bin

## Inspect COSE/CBOR

```
python3 test/pretty_print.py pub.bin               # uses default test/cose_pqc.cddl
python3 test/pretty_print.py signed.bin
python3 test/pretty_print.py pub.bin test/cose_pqc.cddl # supply your own CDDL
```

The tool annotates labels (kty/kid/alg/pub/priv) and algorithm names from the
CDDL, formats byte strings as hex with wrapping (~72 chars), and indents
maps/lists similar to RFC 8610 diagnostic notation.

## Test Runner (run_tests)

The test runner is implemented in `test/run_tests.c`. It aggregates the
individual unit tests (e.g., sign/verify, MAC, parameters) and reports results.

## Test Programs Overview

In this repo, the following test/utility programs are commonly built:

```
gen_pqc_sig_keys       # generate PQC key pairs as COSE_Key (public + private)
t_cose_pqc_sig_sign    # sign a payload using a COSE_Key private key
t_cose_pqc_sig_verify  # verify a COSE_Sign1 using a COSE_Key public key
```

## PQC Smoke Test Script

For quick end-to-end testing across multiple PQC algorithms, use the
provided script:

```
test/pqc_sig_smoke.sh
```

It generates keys, signs a small payload, and verifies the signature for:
ML-DSA, FN-DSA, and SLH-DSA. You can pass a build directory as the first
argument (default is `build`).

## COSE ML-DSA C# Implementierung

This example uses the output of the https://github.com/hannestschofenig/CoseMldsaSign1Demo demo, stored in `test/data/COSE_ML_DSA_Example.txt`.

Use the helper script to extract the COSE_Sign1 and SPKI public key, convert
the public key to COSE_Key, and run verification:

```
python3 test/verify_cose_mldsa_example.py
./build/t_cose_pqc_sig_verify COSE_ML_DSA_Example.pub.cbor COSE_ML_DSA_Example.signed.bin
```

Since this implementation utilizes a different COSE ML-DSA implementation it serves as an interop test case.