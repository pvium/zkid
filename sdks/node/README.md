# @pvium/zk-verifier

Verify that an identity (email, social handle) and a wallet address belong to the same Privy
user, from a Pvium attestation, without trusting Pvium's server or the network. Works in Node
and the browser; ships the circuit's verification key so nothing else is needed.

```sh
yarn add @pvium/zk-verifier
```

## Usage

When you resolve an identity through Pvium you get back an attestation: a zero-knowledge proof,
its public inputs, and the wallet address it binds. Verify it locally:

```ts
import { verifyIdentity } from '@pvium/zk-verifier';

const result = await verifyIdentity({
  attestation,                        // { proof, publicInputs, wallet } as returned by Pvium
  signer: { jwksUrl: 'https://auth.privy.io/api/v1/apps/<pvium-app-id>/jwks.json' }, // or a pinned PEM
  identityType: 'email',              // Privy account type: 'email', 'github_oauth', 'twitter_oauth', …
  identityValue: 'you@example.com',   // the identity you asked Pvium to resolve
});

if (result.valid) {
  result.wallet;    // proven to be linked to that identity in the same Privy account
  result.issuedAt;  // unix seconds: when Privy issued the token the proof was made from
} else {
  result.reason;    // 'wallet mismatch' | 'identity value mismatch' | 'not signed by a trusted key' | 'invalid proof' | …
}
```

A valid result means: a Privy-signed identity token, signed by `signer`, contained both the
identity you named and `result.wallet` as linked accounts of one user. Neither Pvium nor anyone
in the network path can substitute a wallet the user never linked. The SDK does every hash
comparison itself; you only supply what you asked for and what you got back.

**Freshness is your policy.** `issuedAt` is the attestation time. A claim flow might require it
within the last hour; a payment lookup might accept 30 days. The SDK does not enforce an age.

`signer` is the trust anchor. Pin the PEM from the Privy dashboard in your code, or point at a
JWKS URL you trust; with a JWKS every P-256 key served is accepted, which covers rotation.

## Exports

| Export | Purpose |
| --- | --- |
| `verifyIdentity(input)` | the check above |
| `IdentityType` | enum of identity ids, if you prefer it over the string names |
| `shutdown()` | release the WASM verifier when your process is done |
| `VK_SHA256` | hash of the bundled verification key, to confirm it matches a deployed verifier |

Proof bytes and public inputs may be passed as `Uint8Array` or base64 strings.

## Solidity

The same check on chain. The package ships the contract sources, so import them the way you
import OpenZeppelin:

```solidity
import {IPviumIdentity} from "@pvium/zk-verifier/contracts/IPviumIdentity.sol";

contract PayByEmail {
    IPviumIdentity constant PVIUM = IPviumIdentity(0x…); // Pvium's deployment on this chain

    function pay(bytes calldata proof, bytes32[] calldata inputs, bytes calldata email, address wallet) external payable {
        uint64 issuedAt = PVIUM.verifyIdentity(proof, inputs, 0 /* email */, email, wallet);
        require(block.timestamp - issuedAt < 30 days, "attestation too old");
        payable(wallet).transfer(msg.value);
    }
}
```

`verifyIdentity` reverts unless the attestation binds exactly that identity and wallet, and returns
when Privy issued the token. `verifyIdentityNonEvm` takes the wallet as a string for other chains;
`verifyIdentityHashes` takes pre-hashed values when the raw identity must stay out of calldata.
The Honk verifier call costs about 4.4M gas.

## Versioning

The verification key is tied to one circuit build, and `@aztec/bb.js` is pinned to the exact
Barretenberg version that produced it (`5.0.0-nightly.20260522`). Attestations from a different
circuit build will not verify. When the circuit changes:

```sh
yarn sync    # copy the new vk and sample proof from ../../circuit
yarn test    # rebuild (re-embeds the vk) and run tests
```

and publish a new package version alongside the redeployed verifier contract.

## Development

```sh
yarn install
yarn test
```

Tests live in `test/` with a sample proof, its public inputs, a real (expired) Privy identity token
for a test user, and Privy's public key from its JWKS.
