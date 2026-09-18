# Verifying an attestation from Dart / Flutter

`verify_attestation.dart` turns the attestation JSON the Pvium API returns into a read-only
`eth_call` to `PviumIdentity.verifyIdentityHashes` and interprets the result. It depends only on
`package:crypto`; JSON-RPC goes over `dart:io`, so it drops into a Flutter app unchanged (swap
`HttpClient` for your HTTP layer if you prefer).

```sh
dart pub get
dart run verify_attestation.dart <rpcUrl> <PviumIdentity address> attestation.json email you@example.com
```

## The transformation

| Attestation JSON field | Becomes |
| --- | --- |
| `proof` (base64) | `bytes` |
| `publicInputs` (base64, 352 bytes) | `bytes32[11]`: split into 32-byte words in order |
| `identityType` + the identity you resolved | `uint8` type id and `bytes32 identityHash = sha256("p2id.identity.v1" ‖ id ‖ lowercase(value))` |
| `wallet` | `bytes32 walletHash`: same formula with type 12 over the lowercase `0x…` string |
| `circuitVersion` | selects which `PviumIdentity` deployment to call (one per version; immutable) |

Only hashes are sent to the RPC node; the raw email never leaves the device. The function
selector is `0x53825cfc`. A successful call returns `issuedAt` (uint64, when Privy issued the
token). A revert carries a custom error whose 4-byte selector the example maps to a name:
`WalletMismatch`, `IdentityMismatch`, `IdentityTypeMismatch`, `NoWallet`, `UnknownSigner`,
`InvalidProof`, `WrongPublicInputCount`.

The Hardhat test "eth_call from the backend attestation JSON" performs the identical steps in
TypeScript, so the two stay in agreement.

## Residual trust

`eth_call` trusts the RPC node to execute honestly. Query two independent providers and require
both to agree if that matters for your use; the calls are read-only and cost no gas.
