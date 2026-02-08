#!/usr/bin/env bash
set -euo pipefail

build_dir="${1:-build}"

if [[ ! -x "$build_dir/gen_pqc_sig_keys" || ! -x "$build_dir/t_cose_pqc_sig_sign" || ! -x "$build_dir/t_cose_pqc_sig_verify" ]]; then
  echo "Missing PQC tools in $build_dir. Build with:"
  echo "  cmake -S . -B $build_dir -DCRYPTO_PROVIDER=liboqs"
  echo "  cmake --build $build_dir --target gen_pqc_sig_keys t_cose_pqc_sig_sign t_cose_pqc_sig_verify"
  exit 1
fi

work_dir="${WORK_DIR:-/tmp/pqc_sig_smoke}"
rm -rf "$work_dir"
mkdir -p "$work_dir"

echo "Running PQC sign/verify smoke tests in $work_dir"

payload="$work_dir/payload.txt"
echo "hello" > "$payload"

algorithms=(
  ML-DSA-44
  ML-DSA-65
  ML-DSA-87
  FN-DSA-512
  FN-DSA-1024
  SLH-DSA-SHA2-128s
  SLH-DSA-SHAKE-128s
  SLH-DSA-SHA2-128f
)

for alg in "${algorithms[@]}"; do
  kid="${alg}-kid"
  pub="$work_dir/${alg}.pub.cbor"
  priv="$work_dir/${alg}.priv.cbor"
  signed="$work_dir/${alg}.signed.cbor"

  echo "[${alg}] generate keys"
  "$build_dir/gen_pqc_sig_keys" "$alg" "$kid" "$pub" "$priv" >/dev/null

  echo "[${alg}] sign"
  "$build_dir/t_cose_pqc_sig_sign" "$priv" "$payload" "$signed" >/dev/null

  echo "[${alg}] verify"
  "$build_dir/t_cose_pqc_sig_verify" "$pub" "$signed" >/dev/null

done

echo "All PQC smoke tests passed."
