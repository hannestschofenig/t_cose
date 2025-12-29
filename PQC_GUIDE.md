# Guide for using ML-DSA in T_COSE

## Build the code

cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DCRYPTO_PROVIDER=liboqs
cmake --build build --target t_cose_ml_dsa_sign -j$(nproc)
cmake --build build --target t_cose_ml_dsa_verify -j$(nproc)
cmake --build build --target gen_mldsa_keys -j$(nproc)

## Create Message

echo "hello" > payload.txt


## ML-DSA-44 EXAMPLE

./build/gen_mldsa_keys ML-DSA-44 pub.bin priv.bin

./build/t_cose_ml_dsa_sign priv.bin payload.txt signed.bin

./build/t_cose_ml_dsa_verify pub.bin signed.bin


## ML-DSA-65 EXAMPLE

./build/gen_mldsa_keys ML-DSA-65 pub.bin priv.bin

./build/t_cose_ml_dsa_sign priv.bin payload.txt signed.bin

./build/t_cose_ml_dsa_verify pub.bin signed.bin


## ML-DSA-87 EXAMPLE

./build/gen_mldsa_keys ML-DSA-87 pub.bin priv.bin

./build/t_cose_ml_dsa_sign priv.bin payload.txt signed.bin

./build/t_cose_ml_dsa_verify pub.bin signed.bin

