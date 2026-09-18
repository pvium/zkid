#!/bin/sh
# Copy the latest proof produced by `bb prove ... -o target/proof_email` in ../circuit
# into test/fixtures, and regenerate the Solidity verifier from its verification key.
set -e
export PATH="$HOME/.bb:$PATH"
cd "$(dirname "$0")/.."
SRC=../circuit/target/proof_email
cp "$SRC/proof" test/fixtures/email.proof
cp "$SRC/public_inputs" test/fixtures/email.public_inputs
cp "$SRC/vk_hash" test/fixtures/vk_hash
cp ../circuit/test/fixtures/sample_token.jwt test/fixtures/sample_token.jwt
cp ../circuit/test/fixtures/privy_es256_public.pem test/fixtures/privy_es256_public.pem
bb write_solidity_verifier -k "$SRC/vk" -o src/PviumZKVerifier.sol
# bb names the contract HonkVerifier; we ship it as PviumZKVerifier.
sed -i '' 's|^contract HonkVerifier is BaseZKHonkVerifier|contract PviumZKVerifier is BaseZKHonkVerifier|' src/PviumZKVerifier.sol
echo "fixtures and verifier refreshed"
