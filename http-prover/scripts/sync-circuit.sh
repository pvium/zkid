#!/bin/sh
# Copy the compiled circuit and its verification key from ../circuit into ./circuit.
set -e
cd "$(dirname "$0")/.."
mkdir -p circuit
cp ../circuit/target/pvium_identity.json circuit/pvium_identity.json
cp ../circuit/target/proof_email/vk circuit/vk
cp ../circuit/version.json circuit/version.json
echo "synced circuit artifacts"
