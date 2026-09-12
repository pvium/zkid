#!/bin/sh
# Copy the Solidity sources from ../../contracts/src into ./contracts so they ship in the npm
# package and can be imported like `@pvium/zk-verifier/contracts/IPviumIdentity.sol`.
# Source of truth is the Hardhat project; this copy is generated (gitignored) at build time.
set -e
cd "$(dirname "$0")/.."
rm -rf contracts && mkdir -p contracts
cp ../../contracts/src/*.sol contracts/
echo "synced $(ls contracts | wc -l | tr -d ' ') Solidity files"
