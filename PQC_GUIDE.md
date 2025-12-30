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
