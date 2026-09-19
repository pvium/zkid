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
import { verifyIdentity, AttestationSigner } from '@pvium/zk-verifier';

const result = await verifyIdentity({
  attestation,                        // { proof, publicInputs, wallet, circuitVersion } as returned by Pvium
  signer: AttestationSigner.Production, // or .Sandbox, a JWKS URL, a PEM; see "Trusted signers"
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

## Trusted signers

`signer` is the trust anchor: whose token signature the attestation must carry.

| `signer` | Use |
| --- | --- |
| `AttestationSigner.Production` (or `'production'`) | Pvium's production Privy app. Keys are pinned in the SDK (`PVIUM_ENVIRONMENTS.production.keys`), so verification needs no network call; the app's JWKS is consulted only if an attestation names a key that was rotated in after this SDK release. |
| `AttestationSigner.Sandbox` (or `'sandbox'`) | Same for Pvium's sandbox app. A sandbox attestation never verifies as `'production'`, and vice versa. |
| a JWKS URL string, or `{ jwksUrl }` | Any JWKS; every P-256 key it serves is accepted. For self-hosted provers with your own Privy app. |
| PEM string or `{ x, y }` | One specific key you control. |

`PVIUM_ENVIRONMENTS` is exported so you can read the app ids, JWKS URLs and pinned keys. Keys
rotated *out* by Privy stay trusted until an SDK release drops them; keys rotated *in* are picked
up live. Upgrade the SDK when Pvium announces a key change.

## With the Pvium SDK

Resolving payees with `@pvium/sdk` returns an attestation summary per identity-addressed payee;
`payouts.getAttestation` fetches the proof and the result is exactly what `verifyIdentity` takes:

```ts
import { PviumClient } from '@pvium/sdk';
import { verifyIdentity, AttestationSigner } from '@pvium/zk-verifier';

const pvium = new PviumClient({ apiKey: process.env.PVIUM_API_KEY!, environment: 'production' });
const { resolved } = await pvium.payouts.resolveRecipients(batchId, payees);

for (const r of resolved.filter((r) => r.attestation)) {
  const attestation = await pvium.payouts.getAttestation(r.attestation!);
  const result = await verifyIdentity({
    attestation,
    signer: AttestationSigner.Production,
    identityType: attestation.identityType,   // Privy type, no mapping
    identityValue: r.identityValue!,
  });
  if (!result.valid) throw new Error(`${r.identityValue}: ${result.reason}`);
  // result.wallet is r.receiver, proven; result.issuedAt is the attestation time (your policy)
}
```

Payees with `attestation: null` are wallet payees or identities whose proof is still being
generated; re-resolve later or apply your own policy.

## Exports

| Export | Purpose |
| --- | --- |
| `verifyIdentity(input)` | the check above |
| `AttestationSigner` | `Production` / `Sandbox` typed signer choice |
| `IdentityType` | enum of identity ids, if you prefer it over the string names |
| `shutdown()` | release the WASM verifier when your process is done |
| `CIRCUIT_VERSION`, `VK_SHA256` | the circuit version this release verifies, and its vk hash |
| `p2idAddress(input)`, `identityHash(type, value)`, `P2ID_SCHEME`, `P2ID_SCHEMES` | chain-agnostic P2ID address derivation, see below |

Proof bytes and public inputs may be passed as `Uint8Array` or base64 strings.

## P2ID addresses

An identity's P2ID v1 address is the address of its vault. It is deterministic, can be computed
before the vault exists, and is **the same on every EVM chain**, like any wallet address:

```ts
import { p2idAddress, identityHash } from '@pvium/zkid';
// in a browser, import from '@pvium/zkid/p2id' instead: same functions, without the proof verifier

const to = await p2idAddress({ identityType: 'email', identityValue: 'you@example.com' });
const salt = await identityHash('email', 'you@example.com'); // the vault's CREATE2 salt / commitment

// the sandbox stack (testnets, sandbox Privy app) has its own factory and addresses
const test = await p2idAddress({ identityType: 'email', identityValue: 'you@example.com', environment: 'sandbox' });

// against another factory (a local deployment, a fork)
const t = await p2idAddress({ identityType: 'github_oauth', identityValue: 'octocat', factory: '0xFactory…' });
```

The derivation is `keccak256(0xff ‖ factory ‖ identityHash ‖ keccak256(P2IDVault creationCode))`
with `identityHash = sha256("p2id.identity.v1" ‖ typeId ‖ normalize(value))`; `normalize`
lowercases everything except phone numbers and non-`0x` wallet addresses. The factory is deployed
through the deterministic deployment proxy (`contracts/scripts/deploy-deterministic.ts`), so it sits
at one address on every chain, which is why no chain id appears anywhere above.

The constants come from an address **scheme**, named by a domain: `P2ID_SCHEME` is the current one
(`p2id.vault.v1`) and `P2ID_SCHEMES` holds every scheme this release knows, each with its
`identityDomain`, `vaultInitCodeHash` and a factory per environment (`production`, the default, and
`sandbox`). A change to the vault ships as the next
scheme; older ones stay, so an address issued earlier can still be derived by passing
`scheme: 'p2id.vault.v1'`.

### Identity types

`identityType` accepts the Privy type name or the numeric id (`IdentityType`). The id, not the
name, is what gets hashed, so a platform rename can never move an address. The table is
append-only: ids are never reassigned.

| Id | Type | Value field | Lowercased |
| ---: | --- | --- | :---: |
| 0 | `email` | `address` | yes |
| 1 | `phone` | `number` | no |
| 2 | `google_oauth` | `email` | yes |
| 3 | `twitter_oauth` (X) | `username` | yes |
| 4 | `discord_oauth` | `username` | yes |
| 5 | `github_oauth` | `username` | yes |
| 6 | `linkedin_oauth` | `email` | yes |
| 7 | `apple_oauth` | `email` | yes |
| 8 | `telegram` | `username` | yes |
| 9 | `tiktok_oauth` | `username` | yes |
| 10 | `instagram_oauth` | `username` | yes |
| 11 | `farcaster` | `username` | yes |
| 12 | `wallet` | `address` | only `0x…` |

Handles are written without a leading `@`; phone numbers are E.164 with the `+`. The same email
under `email`, `google_oauth`, `linkedin_oauth` and `apple_oauth` is four different identities.
The full specification is in [P2ID.md](https://github.com/pvium/zkid/blob/main/P2ID.md).

A plain ERC-20 transfer to that address is claimable by the identity's owner once anyone deploys
the vault on that chain; use the factory's `fund()` when you need refund rights or a funding
constraint. Chains whose CREATE2 rule differs from Ethereum's (zkSync Era) are not covered.

## Solidity

The same check on chain. The package ships the contract sources, so import them the way you
import OpenZeppelin:

```solidity
import {IPviumIdentity} from "@pvium/zk-verifier/contracts/interfaces/IPviumIdentity.sol";

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

Each SDK release verifies exactly one circuit version (`CIRCUIT_VERSION`, with its vk embedded), and
`@aztec/bb.js` is pinned to the Barretenberg that built it (`5.0.0-nightly.20260522`). Attestations
carry `circuitVersion`; pass it through and a mismatch is reported by name rather than as an
opaque "invalid proof". A circuit change ships as a new SDK version. When the circuit changes:

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
