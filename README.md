# Pvium ZK

Zero-knowledge circuits and proof tooling for Pvium.

| Folder | Purpose |
| --- | --- |
| `circuit/` | Circuit source, compiled artifacts (r1cs/wasm/zkey), and trusted setup outputs |
| `sdks/node/` | npm package `@pvium/zk-verifier`: verify attestations off-chain; ships the Solidity sources too |
| `http-prover/` | Attestation service: token in, proof out (Express + noir_js + native bb) |
| `contracts/` | Smart contracts that verify proofs on-chain |
