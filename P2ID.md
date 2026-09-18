# P2ID: pay to any identity

P2ID derives deterministic EVM vault addresses from identities: email addresses, social handles,
phone numbers and wallet addresses. Anyone can derive an address and send ERC-20 tokens to it
before the vault is deployed. Claims pay a wallet linked to the identity in a Privy identity
token, verified through a zero-knowledge proof.

This specification defines address derivation, identity encoding, versioning and claim semantics.
The circuit (`circuit/`), Solidity library (`contracts/src/lib/PviumHash.sol`), prover
(`http-prover/`) and SDK (`sdks/node/`) must implement the same rules.

## Address derivation

```
v            = lowercase(value)   unless the type is phone, or the type is wallet and the
                                  value does not start with "0x" (then v = value)

identityHash = SHA-256( "p2id.identity.v1" ‖ byte(typeId) ‖ v )

p2id         = last 20 bytes of Keccak-256( 0xff ‖ factory ‖ identityHash ‖ vaultInitCodeHash )
```

| Symbol | Meaning | Size |
| --- | --- | --- |
| `"p2id.identity.v1"` | ASCII domain prefix | 16 bytes |
| `typeId` | identity type id, see the table below | 1 byte |
| `value` | the identity as UTF-8; lowercasing is ASCII only (`A`–`Z`) | 1–128 bytes |
| `factory` | `PviumP2IdVaultFactory` address for the scheme and environment | 20 bytes |
| `vaultInitCodeHash` | Keccak-256 of the `P2IDVault` creation bytecode | 32 bytes |

`‖` denotes byte concatenation. The address formula uses CREATE2 with `identityHash` as the
salt and is independent of whether the vault has been deployed. Addresses are displayed with
an EIP-55 checksum.

The same `identityHash` serves as the proof's identity commitment and the vault's stored
commitment, binding address derivation and claim verification to one identity.

### Schemes and versions

Identity hashing and vault addressing use independently versioned domains:

| Domain | Versions | Changes when |
| --- | --- | --- |
| `p2id.identity.vN` | the identity hash: prefix, type table, normalisation | the commitment changes (needs a new circuit) |
| `p2id.vault.vN` | the address: `factory` and `vaultInitCodeHash` | the vault bytecode or the factory changes |

Each address scheme specifies its identity domain. A vault update can introduce
`p2id.vault.v2` without changing the circuit or existing proofs. The scheme domain also
determines the factory's namespace and deployment salt: `keccak256("p2id.vault.v1")`.

The constants of every scheme are in [`sdks/node/src/p2id.json`](sdks/node/src/p2id.json), keyed
by domain. Once a factory is recorded, the scheme entry is immutable; the build rejects vault
bytecode that does not match its recorded hash. Changes require a new scheme entry and an
update to `current`. Older entries must remain available for address derivation and claims
under their original schemes.

### Example

```
type  = email (0)
value = "Test-9988@Privy.io"          →  v = "test-9988@privy.io"

identityHash = SHA-256( "p2id.identity.v1" ‖ 0x00 ‖ "test-9988@privy.io" )
             = 0xbcda0f09fa9732b2bfdea38199486b654a84e8e06085d7e364af8137f8d7deaf

factory           = 0x1111111111111111111111111111111111111111      (illustrative)
vaultInitCodeHash = 0xe77177c8928780958d3dd9349c9e58ed44081f738fb54dec4e46d043aad778d5
p2id              = 0xA6aAdfCFEfaD0761490178BD639DBD1f3f895C90
```

The identity-hash preimage is 35 bytes:

```
70 32 69 64 2e 69 64 65 6e 74 69 74 79 2e 76 31          "p2id.identity.v1"     16 bytes
00                                                       typeId 0 (email)        1 byte
74 65 73 74 2d 39 39 38 38 40 70 72 69 76 79 2e 69 6f    "test-9988@privy.io"   18 bytes
```

`typeId` is encoded as one raw byte: `0x00` for email, `0x05` for github_oauth and `0x0c` for
wallet. The preimage contains no ABI padding, separators or length prefixes. In Solidity,
with `v` already normalised:

```solidity
sha256(abi.encodePacked("p2id.identity.v1", uint8(typeId), v))
```

With the SDK:

```ts
import { p2idAddress } from '@pvium/zkid';
const to = await p2idAddress({ identityType: 'email', identityValue: 'you@example.com' });
```

## Identity types

An identity is the pair `(type, value)`. Identical values under different types produce
distinct commitments and addresses; for example, GitHub `octocat` and TikTok `octocat`.

| Id | Type (Privy `linked_accounts[].type`) | Value field | Example value | Lowercased |
| ---: | --- | --- | --- | :---: |
| 0 | `email` | `address` | `you@example.com` | yes |
| 1 | `phone` | `number` | `+15551234567` | no |
| 2 | `google_oauth` | `email` | `you@gmail.com` | yes |
| 3 | `twitter_oauth` (X) | `username` | `jack` | yes |
| 4 | `discord_oauth` | `username` | `wumpus` | yes |
| 5 | `github_oauth` | `username` | `octocat` | yes |
| 6 | `linkedin_oauth` | `email` | `you@example.com` | yes |
| 7 | `apple_oauth` | `email` | `you@icloud.com` | yes |
| 8 | `telegram` | `username` | `durov` | yes |
| 9 | `tiktok_oauth` | `username` | `charlidamelio` | yes |
| 10 | `instagram_oauth` | `username` | `instagram` | yes |
| 11 | `farcaster` | `username` | `dwr` | yes |
| 12 | `wallet` | `address` | `0xA01b…0f98`, or a base58 address | only `0x…` |

Value conventions:

- Handles are written without a leading `@`. Phone numbers are in E.164 form with the `+`, exactly
  as Privy stores them.
- The same email under `email`, `google_oauth`, `linkedin_oauth` and `apple_oauth` represents
  four distinct identities. The payer must select the intended type.
- EVM wallet addresses are hashed as their lowercase `0x…` hex string. Base58 (Solana) addresses
  are case-sensitive and are hashed as they are.

### Type identifiers

Numeric identifiers keep commitments stable when platform names or SDK aliases change.
SDKs map supported names to identifiers before hashing. The one-byte encoding provides an
unambiguous type boundary and reduces hashing constraints in the circuit.

The type table is **append-only**. New types receive the next identifier; existing identifiers
must never be reassigned or reused, including those of discontinued platforms. The table is defined in
[`circuit/src/identity.nr`](circuit/src/identity.nr) and mirrored in
[`contracts/src/lib/PviumHash.sol`](contracts/src/lib/PviumHash.sol),
[`sdks/node/src/identity.ts`](sdks/node/src/identity.ts) and
[`http-prover/src/identity.ts`](http-prover/src/identity.ts).

## Chains and environments

Address derivation contains no chain identifier. The factory uses the deterministic deployment
proxy (`contracts/scripts/deploy-deterministic.ts`) with the scheme's deployment salt. Within
one scheme and environment, identical factory addresses and vault bytecode produce identical
vault addresses across supported chains. Chains with different CREATE2 semantics are outside
the scope of this specification.

A vault must be deployed on each chain before funds can be claimed. Anyone may call
`factory.deploy(identityHash)`; tokens transferred before deployment remain at the derived address.

Pvium defines two environments with separate factories and Privy apps: `production` for mainnets
and `sandbox` for testnets. Each identity has a separate address in each environment for a given
scheme. SDKs default to production.

## Claims and policy

1. The identity owner authenticates with Privy. The prover produces a proof that a token signed
   by Privy's key contains the specified linked identity and a linked wallet. The proof does
   not disclose the token or identity value to the verifier.
2. The vault accepts claims through the deposit's verifier, subject to the factory's current
   policy. The verifier checks the vault's identity commitment and resolves the wallet from
   the signed token. The vault pays that wallet.
3. Proof freshness is tracked per vault and verifier using the token's issue time. Presenting
   a newer proof updates the recorded wallet and causes older proofs to be rejected under that
   verifier. `refreshProof` permits this update without claiming funds.

Direct ERC-20 transfers create no deposit record or refund right. They are claimed through the
factory's default verifier. Recorded deposits specify a verifier and may include a constraint
that must be satisfied to claim; unclaimed deposits can be refunded by their funder after the
refund window.

The factory's policy governs verifier eligibility and fees; policy replacement requires a
public timelock. The vault caps fees at 1% of the gross payout and charges no fee on refunds.
Recorded deposits fix the fee rate at funding; direct transfers use the rate at claim time.
Policy restrictions may block claims but cannot redirect payouts away from the wallet resolved
by the verifier.

See [`contracts/README.md`](contracts/README.md) for the contracts and
[`sdks/node/README.md`](sdks/node/README.md) for verification and address derivation in code.
