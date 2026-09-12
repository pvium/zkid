#!/bin/sh
# Pull the latest vk and sample proof from ../../circuit after re-proving there.
set -e
cd "$(dirname "$0")/.."
C=../../circuit
cp $C/target/proof_email/vk src/pvium_identity.vk
cp $C/target/proof_email/proof test/fixtures/email.proof
cp $C/target/proof_email/public_inputs test/fixtures/email.public_inputs
cp $C/test/fixtures/privy_es256_public.pem $C/test/fixtures/sample_token.jwt test/fixtures/
echo "synced vk and fixtures from circuit"
