#!/bin/sh
# End-to-end circuit test: build a witness from the real sample token, solve the circuit, and
# check the public outputs match what the witness generator predicts. Runs several identity /
# wallet combinations. Requires nargo on PATH.
# Usage: sh test/e2e.sh   (from circuit/)
set -e
cd "$(dirname "$0")/.."
F=test/fixtures

check() { # $1 label, $2 expected substring, $3 haystack
  if echo "$3" | grep -q -- "$2"; then echo "  ok   $1"; else echo "  FAIL $1: expected $2"; echo "$3"; exit 1; fi
}

run_case() { # $1 label, $2 type, $3 value, $4 wallet (or "" for none)
  echo "case: $1"
  if [ -n "$4" ]; then W="--wallet $4"; else W=""; fi
  EXPECTED=$(python3 scripts/gen_prover.py \
    --jwt "$(cat $F/sample_token.jwt)" --pubkey $F/privy_es256_public.pem \
    --type "$2" --value "$3" $W -o Prover.toml)
  ACTUAL=$(nargo execute e2e_witness 2>&1)
  x_hi=$(echo "$EXPECTED" | sed -n 's/.*signer_x_hi\/lo *= \(0x[0-9a-f]*\) \/ \(0x[0-9a-f]*\)/\1/p')
  ih=$(echo "$EXPECTED" | sed -n 's/.*identity_hash *= 0x\([0-9a-f]*\)/\1/p')
  wh=$(echo "$EXPECTED" | sed -n 's/.*wallet_hash *= 0x\([0-9a-f]*\).*/\1/p')
  iat=$(echo "$EXPECTED" | sed -n 's/.*iat *= \([0-9]*\)/\1/p')
  check "witness solved"   "successfully solved"                                "$ACTUAL"
  check "signer_x_hi"      "signer_x_hi: $x_hi"                                 "$ACTUAL"
  check "identity_hash_hi" "identity_hash_hi: 0x$(echo $ih | cut -c1-32)"       "$ACTUAL"
  check "identity_hash_lo" "identity_hash_lo: 0x$(echo $ih | cut -c33-64)"      "$ACTUAL"
  if [ -n "$4" ]; then
    check "wallet_hash_hi" "wallet_hash_hi: 0x$(echo $wh | cut -c1-32)"         "$ACTUAL"
    check "wallet_hash_lo" "wallet_hash_lo: 0x$(echo $wh | cut -c33-64)"        "$ACTUAL"
  else
    check "wallet_hash zero" "wallet_hash_hi: 0x00, wallet_hash_lo: 0x00"       "$ACTUAL"
  fi
  check "iat"              "iat: $iat"                                          "$ACTUAL"
}

run_case "email + ethereum wallet"        email        test-9988@privy.io 0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98
run_case "github + solana wallet"         github_oauth dephizee            EXnVUEeELHiYynvjoQ9YhgxfMSDJC6tJm7VkFQY2b8Wj
run_case "github + ethereum wallet 1/5"   github_oauth dephizee            0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98
run_case "github + ethereum wallet 2/5"   github_oauth dephizee            0x899BA183F2c55BF9C627D9Af2984fbdED2E64311
run_case "github + ethereum wallet 3/5"   github_oauth dephizee            0xA7CabE96d97044f74Be883d7cf33DD63f574c84e
run_case "github + ethereum wallet 4/5"   github_oauth dephizee            0xf1707D8CB99339d3B7Bea0b1A2ac3c9C01B8Ab3d
run_case "github + ethereum wallet 5/5"   github_oauth dephizee            0xdA90b3C11F5AA8698F5D9356f29541D46E32840d
run_case "email, wallet slot empty"       email        test-9988@privy.io ""
run_case "wallet as the identity itself"  wallet       0x899BA183F2c55BF9C627D9Af2984fbdED2E64311 0xdA90b3C11F5AA8698F5D9356f29541D46E32840d
echo "all e2e cases passed"
