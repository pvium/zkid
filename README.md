# Pvium ZK

Zero-knowledge circuits and proof tooling for Pvium.

**[P2ID.md](P2ID.md)** is the protocol specification: how an identity (email, social handle, phone,
wallet) maps to a chain-agnostic address, the identity type ids, and how a claim works.

| Folder | Purpose |
| --- | --- |
| `circuit/` | Noir circuit: proves a Privy identity token contains a linked account and wallet |
| `sdks/node/` | npm package `@pvium/zkid`: verify attestations off-chain, derive P2ID addresses; ships the Solidity sources too |
| `http-prover/` | Attestation service: token in, proof out (Express + noir_js + native bb) |
| `contracts/` | On-chain verification, per-identity vaults and the vault factory |
