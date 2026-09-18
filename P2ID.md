# P2ID: paying an identity

A P2ID address is an ordinary EVM address that belongs to an identity (an email, a social handle,
a phone number, a wallet) rather than to a key. Anyone can compute it from the identity alone,
send ERC-20 tokens to it on any EVM chain, and only the person who controls that identity can
claim them, by proving it in zero knowledge from their Privy identity token.

This document is the specification. The circuit (`circuit/`), the Solidity library
(`contracts/src/lib/PviumHash.sol`), the prover (`http-prover/`) and the SDK (`sdks/node/`) all
implement exactly this and are tested against each other.

## The address

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
| `factory` | the `PviumP2IdVaultFactory` address, the same on every chain | 20 bytes |
| `vaultInitCodeHash` | Keccak-256 of the `P2IDVault` creation bytecode | 32 bytes |

`‖` is byte concatenation. The second line is CREATE2 with the identity hash as the salt, so the
address is the address of the identity's vault, whether or not the vault has been deployed yet.
Addresses are displayed with an EIP-55 checksum.

The identity hash is also the commitment a proof binds to and the value a vault stores, so the
address, the claim check and the proof all agree on one number.

### Schemes and versions

Two things are versioned, independently, and both by a dotted domain:

| Domain | Versions | Changes when |
| --- | --- | --- |
| `p2id.identity.vN` | the identity hash: prefix, type table, normalisation | the commitment changes (needs a new circuit) |
| `p2id.vault.vN` | the address: `factory` and `vaultInitCodeHash` | the vault bytecode or the factory changes |

An address scheme names the identity domain it builds on, so a vault fix can ship as
`p2id.vault.v2` without touching the circuit or anyone's proofs. The scheme domain is an input,
not only a label: `keccak256("p2id.vault.v1")` is the factory's namespace and the salt it is
deployed with.

The constants of every scheme are in [`sdks/node/src/p2id.json`](sdks/node/src/p2id.json), keyed
by domain. Entries are history: once a scheme's factory is recorded it is frozen, the build fails
if the vault bytecode no longer matches it, and the fix is to add the next scheme and make it
`current`. Older schemes are never removed, so an address issued under one can always be derived
and claimed.

### Example

```
type  = email (0)
value = "Test-9988@Privy.io"          →  v = "test-9988@privy.io"

identityHash = SHA-256( "p2id.identity.v1" ‖ 0x00 ‖ "test-9988@privy.io" )
             = 0xbcda0f09fa9732b2bfdea38199486b654a84e8e06085d7e364af8137f8d7deaf

factory           = 0x1111111111111111111111111111111111111111      (illustrative)
vaultInitCodeHash = 0xedeb17b2cad352aa707895e12dddf28ba5ced700b2feaf31d26c3ee221d84768
p2id              = 0xdFb0272b2178A35D2ad0693F51b5Dd23659C3235
```

The preimage, byte for byte (35 bytes here):

```
70 32 69 64 2e 69 64 65 6e 74 69 74 79 2e 76 31          "p2id.identity.v1"     16 bytes
00                                                       typeId 0 (email)        1 byte
74 65 73 74 2d 39 39 38 38 40 70 72 69 76 79 2e 69 6f    "test-9988@privy.io"   18 bytes
```

`typeId` is a single raw byte: `0x00` for email, `0x05` for github_oauth, `0x0c` for wallet. It is
not the ASCII digit (`"0"` would be `0x30`), not padded to 32 bytes as ABI encoding would, and
there is no separator or length prefix anywhere. In Solidity this is
`sha256(abi.encodePacked("p2id.identity.v1", uint8(typeId), value))`.

With the SDK:

```ts
import { p2idAddress } from '@pvium/zkid';
const to = await p2idAddress({ identityType: 'email', identityValue: 'you@example.com' });
```

## Identity types

The identity is the pair (type, value). The value alone is only a string: `octocat` on GitHub and
`octocat` on TikTok are different people, and the type keeps their addresses apart.

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

Notes on values:

- Handles are written without a leading `@`. Phone numbers are in E.164 form with the `+`, exactly
  as Privy stores them.
- The same email under `email`, `google_oauth`, `linkedin_oauth` and `apple_oauth` is four
  different identities, because they are four different ways of having verified it. A payer
  chooses which one they are paying.
- EVM wallet addresses are hashed as their lowercase `0x…` hex string. Base58 (Solana) addresses
  are case-sensitive and are hashed as they are.

### Why a numeric id and not the name

- **Names change, numbers do not.** If `twitter_oauth` becomes `x_oauth`, a name-based hash would
  move every such address. With an id, the name is only a label: type 3 stays type 3.
- **One spelling.** `twitter`, `Twitter`, `X` and `twitter_oauth` would be four hashes for one
  account. A number has one form. SDKs accept the friendly name and map it to the id before hashing.
- **Fixed width.** One byte needs no separator between type and value, so there is no parsing
  ambiguity and no delimiter to escape.
- **Cheaper in the circuit**, where every hashed byte costs constraints.

### Rules for this table

The table is part of the protocol and is **append-only**: a new platform gets the next id, and an
existing id is never reassigned or reused, even if a platform disappears. It is defined in
[`circuit/src/identity.nr`](circuit/src/identity.nr) and mirrored in
[`contracts/src/lib/PviumHash.sol`](contracts/src/lib/PviumHash.sol),
[`sdks/node/src/identity.ts`](sdks/node/src/identity.ts) and
[`http-prover/src/identity.ts`](http-prover/src/identity.ts).

## Chain-agnostic

Nothing in the formula names a chain. The factory is deployed through the deterministic deployment
proxy (`contracts/scripts/deploy-deterministic.ts`, salted with the scheme domain), so it has one address on every EVM chain, and
so does every identity's vault. A vault must still be deployed on each chain where it is claimed;
anyone can do that with `factory.deploy(identityHash)`, and tokens sent to the address beforehand
are claimable once it is. Chains whose CREATE2 rule differs from Ethereum's (zkSync Era) are not
covered.

Pvium runs two environments, each a separate stack with its own factory: `production` on mainnets
and `sandbox` on testnets, backed by different Privy apps. The same identity therefore has one
production address and one sandbox address; SDKs default to production.

## Claiming

1. The owner signs in with Privy; the prover turns their identity token into a proof that the
   token, signed by Privy's key, contains a linked account of that type and value and a linked
   wallet, without revealing the token or the value.
2. The proof is presented to the vault under a verifier from the factory's approved registry.
   The verifier checks the proof is for this vault's identity hash and returns the wallet that the
   circuit read out of the signed token; the vault pays that wallet.
3. A newer proof retires every older one for that vault, so moving to a new wallet is one call.

See [`contracts/README.md`](contracts/README.md) for the contracts and
[`sdks/node/README.md`](sdks/node/README.md) for verification and address derivation in code.
